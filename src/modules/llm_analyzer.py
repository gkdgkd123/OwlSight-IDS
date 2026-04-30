"""
Module 4: LLM 深度研判模块（异步消费者 Worker）
功能：从 Redis 队列消费任务，调用 LLM API 进行深度研判，支持速率控制和失败重试

改造要点：
  - BRPOP 阻塞消费 llm_task_queue
  - 速率控制（避免 API 限流）
  - 失败重试机制
  - 队列积压监控
  - 优雅停机
"""
import json
import redis
import os
import time
import threading
from string import Template
from typing import Dict, Any, Optional
from pathlib import Path
from ..utils import sanitize_text, setup_logger
from ..config.config import RedisConfig, LLMConfig
from ..config.redis_factory import RedisConnectionFactory

# Prompt 模板路径
PROMPT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "prompts" / "llm_analyst.md"


class LLMAnalyzer:
    """LLM 深度研判模块 - 异步消费者 Worker"""

    def __init__(self, redis_config: RedisConfig, llm_config: LLMConfig):
        self.redis_config = redis_config
        self.llm_config = llm_config
        self.logger = setup_logger("LLMAnalyzer")

        self.redis_client = RedisConnectionFactory.get_client_with_retry(redis_config)

        # 加载 Prompt 模板
        self.prompt_template = self._load_prompt_template()

        self.running = False
        self.llm_queue_name = "llm_task_queue"
        self.failed_queue_name = "llm_failed_queue"

        # 速率控制（避免 API 限流）
        self.rate_limit_requests = 10  # 每分钟最多 10 次请求
        self.rate_limit_window = 60.0  # 60 秒窗口
        self.request_timestamps = []  # 请求时间戳列表
        self.rate_lock = threading.Lock()

        # 统计计数器
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_processed': 0,
            'success': 0,
            'failed': 0,
            'malicious_detected': 0,
            'benign_detected': 0
        }

        # 优雅停机信号（由外部调用 stop() 触发，不在此注册 signal）
        self.shutdown_event = threading.Event()

        # 根据配置选择使用 API 或本地模型
        if llm_config.use_api:
            self.logger.info(f"LLM 深度研判模块初始化完成（API 模式 - 异步消费者）")
            self.logger.info(f"  API 地址: {llm_config.api_base_url}")
            self.logger.info(f"  模型: {llm_config.api_model}")
            self.logger.info(f"  速率限制: {self.rate_limit_requests} 请求/分钟")
            self.logger.info(f"  消费队列: {self.llm_queue_name}")
            self.openai_client = self._init_openai_client()
        else:
            self.logger.info("LLM 深度研判模块初始化完成（本地模型模式）")
            self.tokenizer = None
            self.model = None
            self.vector_store = None
            self._load_local_model()
            if llm_config.use_rag:
                self._load_vector_store()

    def request_shutdown(self):
        """外部调用：请求优雅停机"""
        self.logger.info("收到停机请求，准备优雅停机...")
        self.shutdown_event.set()
        self.running = False

    def _wait_for_rate_limit(self):
        """速率控制：等待直到可以发送请求"""
        with self.rate_lock:
            current_time = time.time()

            # 清理过期的时间戳（超过窗口时间）
            self.request_timestamps = [
                ts for ts in self.request_timestamps
                if current_time - ts < self.rate_limit_window
            ]

            # 如果达到速率限制，等待
            if len(self.request_timestamps) >= self.rate_limit_requests:
                oldest_ts = self.request_timestamps[0]
                wait_time = self.rate_limit_window - (current_time - oldest_ts)
                if wait_time > 0:
                    self.logger.warning(
                        f"达到速率限制 ({self.rate_limit_requests} 请求/分钟)，等待 {wait_time:.1f}s"
                    )
                    time.sleep(wait_time)
                    # 重新清理时间戳
                    current_time = time.time()
                    self.request_timestamps = [
                        ts for ts in self.request_timestamps
                        if current_time - ts < self.rate_limit_window
                    ]

            # 记录本次请求时间戳
            self.request_timestamps.append(time.time())

    def _check_queue_health(self):
        """检查队列健康状态"""
        try:
            queue_len = self.redis_client.llen(self.llm_queue_name)
            failed_len = self.redis_client.llen(self.failed_queue_name)

            if queue_len > 100:
                self.logger.warning(f"[QUEUE-ALERT] 任务队列积压严重: {queue_len} 个待处理任务")
            elif queue_len > 50:
                self.logger.warning(f"[QUEUE-ALERT] 任务队列积压: {queue_len} 个待处理任务")

            if failed_len > 10:
                self.logger.error(f"[QUEUE-ALERT] 失败队列积压: {failed_len} 个失败任务")

            return queue_len, failed_len
        except Exception as e:
            self.logger.error(f"检查队列健康状态失败: {e}")
            return 0, 0

    def _init_openai_client(self):
        """初始化 API 配置（使用 requests）"""
        if not self.llm_config.api_key:
            self.logger.error("API Key 未设置，请设置环境变量 LLM_API_KEY")
            return None

        self.logger.info("API 配置初始化成功")
        return True  # 返回 True 表示配置成功

    def _load_prompt_template(self) -> Optional[Template]:
        """加载 Prompt 模板文件（使用 $variable 语法，避免与 JSON 花括号冲突）"""
        try:
            if not PROMPT_TEMPLATE_PATH.exists():
                self.logger.warning(f"Prompt 模板不存在: {PROMPT_TEMPLATE_PATH}，使用内置默认 Prompt")
                return None
            content = PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8")
            self.logger.info(f"Prompt 模板加载成功: {PROMPT_TEMPLATE_PATH}")
            return Template(content)
        except Exception as e:
            self.logger.error(f"加载 Prompt 模板失败: {e}")
            return None

    def _load_local_model(self):
        """加载本地 Qwen 模型"""
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch

            model_path = self.llm_config.model_path
            if not Path(model_path).exists():
                self.logger.warning(f"模型路径不存在: {model_path}，将使用 Dummy 模式")
                return

            self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_path,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True
            )
            self.logger.info(f"Qwen 模型加载成功: {model_path}")
        except Exception as e:
            self.logger.error(f"加载 Qwen 模型失败: {e}")
            self.model = None

    def _load_vector_store(self):
        """加载向量库（仅本地模式）"""
        try:
            from langchain_community.vectorstores import Chroma
            from langchain_community.embeddings import HuggingFaceEmbeddings

            vector_db_path = self.llm_config.vector_db_path
            if not Path(vector_db_path).exists():
                self.logger.warning(f"向量库路径不存在: {vector_db_path}")
                return

            embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
            self.vector_store = Chroma(
                persist_directory=vector_db_path,
                embedding_function=embeddings
            )
            self.logger.info(f"向量库加载成功: {vector_db_path}")
        except Exception as e:
            self.logger.error(f"加载向量库失败: {e}")
            self.vector_store = None

    def _sanitize_features(self, features_json: str) -> Dict[str, Any]:
        """清洗特征数据"""
        try:
            features = json.loads(features_json)
            sanitized = {}
            for key, value in features.items():
                if isinstance(value, (int, float)):
                    sanitized[key] = value
                elif isinstance(value, str):
                    sanitized[key] = sanitize_text(value, max_length=200)
            return sanitized
        except Exception as e:
            self.logger.error(f"特征清洗失败: {e}")
            return {}

    def _features_to_natural_language(self, features: Dict[str, Any]) -> str:
        """将特征转换为自然语言描述"""
        descriptions = []

        # IAT 特征分析
        iat_mean = features.get("iat_mean", 0)
        iat_std = features.get("iat_std", 0)

        if iat_mean < 0.01:
            descriptions.append(f"数据包到达时间间隔极短（平均 {iat_mean*1000:.2f}ms），疑似快速扫描或自动化攻击")
        elif iat_mean > 5.0:
            descriptions.append(f"数据包到达时间间隔很长（平均 {iat_mean:.2f}s），可能是慢速扫描或人工操作")

        if iat_std < 0.001 and features.get("packet_count", 0) > 5:
            descriptions.append(f"包间隔标准差极小（{iat_std*1000:.3f}ms），行为极度规律，疑似机器定时通信")

        # 包长特征分析
        pkt_len_mean = features.get("pkt_len_mean", 0)
        pkt_len_std = features.get("pkt_len_std", 0)

        if pkt_len_mean < 100:
            descriptions.append(f"平均包长很小（{pkt_len_mean:.1f} bytes），可能是探测流量或控制流量")
        elif pkt_len_mean > 1000:
            descriptions.append(f"平均包长较大（{pkt_len_mean:.1f} bytes），可能包含大量数据传输")

        # 流量规模分析
        bytes_sent = features.get("bytes_sent", 0)
        packet_count = features.get("packet_count", 0)
        duration = features.get("duration", 0)

        if bytes_sent > 50000:
            descriptions.append(f"总传输字节数较大（{bytes_sent/1024:.1f} KB），可能存在数据外泄风险")

        if packet_count > 0:
            descriptions.append(f"在早期阶段捕获到 {packet_count} 个数据包，持续时间 {duration:.2f} 秒")

        # TCP 特征分析
        syn_count = features.get("syn_count", 0)
        ack_count = features.get("ack_count", 0)
        fin_count = features.get("fin_count", 0)
        rst_count = features.get("rst_count", 0)

        if syn_count > 5 and syn_count == packet_count:
            descriptions.append(f"全部为 SYN 包（{syn_count} 个），典型的端口扫描特征")
        elif syn_count > 0 and ack_count == 0:
            descriptions.append(f"有 {syn_count} 个 SYN 包但无 ACK 响应，TCP 三次握手未完成")
        elif syn_count > 0 and ack_count > 0:
            descriptions.append(f"完整的 TCP 握手（SYN={syn_count}, ACK={ack_count}），连接已建立")

        if rst_count > 0:
            descriptions.append(f"存在 {rst_count} 个 RST 包，连接被重置")
        if fin_count > 0:
            descriptions.append(f"存在 {fin_count} 个 FIN 包，连接正常关闭")

        is_early_flow = (fin_count == 0 and rst_count == 0 and packet_count < 10)
        if is_early_flow:
            descriptions.append("连接尚未关闭（无 FIN/RST）且包数较少，属于早期流，结果可能不完整")

        # 速率特征分析
        packets_per_second = features.get("packets_per_second", 0)
        if packets_per_second > 100:
            descriptions.append(f"包速率很高（{packets_per_second:.1f} 包/秒），可能是 DoS 攻击")

        return "；".join(descriptions) if descriptions else "流量特征正常"

    def _build_prompt(self, features_text: str, xgb_score: float, anomaly_score: float, decision_type: str) -> str:
        """构建 LLM Prompt（优先使用外部模板，回退到内置默认）"""

        # 构建上下文描述
        if decision_type == "ZERODAY_HUNT":
            context = (
                f"**Detection Source**: ML Alert Only (no Suricata)\n"
                f"- XGBoost score: {xgb_score:.3f} (< 0.5, model considers SAFE)\n"
                f"- Isolation Forest anomaly score: {anomaly_score:.3f} (> 0.75, EXTREMELY anomalous)\n\n"
                f"**Key Finding**: XGBoost considers this flow safe, but Isolation Forest detected "
                f"an extremely anomalous behavioral pattern. This contradiction suggests a possible "
                f"**unknown variant attack or 0day threat** — the behavior is not in known attack training "
                f"sets, but the statistical features significantly deviate from normal traffic."
            )
        else:
            context = (
                f"**Detection Source**: ML Alert Only (no Suricata)\n"
                f"- XGBoost score: {xgb_score:.3f} (0.5-0.9 gray zone, needs deep analysis)\n"
                f"- Isolation Forest anomaly score: {anomaly_score:.3f}\n\n"
                f"**Key Finding**: This flow is in the gray zone — neither clearly malicious nor "
                f"clearly normal. Requires semantic deep analysis."
            )

        # 优先使用外部模板
        if self.prompt_template is not None:
            return self.prompt_template.substitute(
                context=context,
                features_text=features_text,
            )

        # 回退到内置默认 Prompt
        prompt = f"""你是一个专业的网络安全分析专家，擅长识别网络攻击和异常行为。

【检测背景】
{context}

【流量特征分析】
{features_text}

请以严格的 JSON 格式输出分析结果。"""

        return prompt

    def _call_llm_api(self, prompt: str) -> Dict[str, Any]:
        """调用 LLM API（使用 requests，带速率控制）"""
        if not self.openai_client:
            return self._dummy_result("API 配置未初始化")

        try:
            import requests

            # 速率控制
            self._wait_for_rate_limit()

            self.logger.info(f"调用 LLM API: {self.llm_config.api_model}")

            # 构建请求
            url = f"{self.llm_config.api_base_url}/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.llm_config.api_key}"
            }

            payload = {
                "model": self.llm_config.api_model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are OwlSight-L2, an expert cybersecurity analyst. Always respond with valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.3,
                "max_tokens": 4096
            }

            # 发送请求
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()

            # 解析响应（兼容推理模型：content 可能在 reasoning_content 中）
            response_data = response.json()
            message = response_data["choices"][0]["message"]
            content = message.get("content", "") or ""
            reasoning = message.get("reasoning_content", "") or ""

            if not content and reasoning:
                # 推理模型将结果放在 reasoning_content 中
                content = reasoning
                self.logger.info(f"LLM API 响应成功（推理模型），内容长度: {len(content)}")
            else:
                self.logger.info(f"LLM API 响应成功，内容长度: {len(content)}")

            # 解析 JSON
            json_start = content.find("{")
            json_end = content.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                json_str = content[json_start:json_end]
                result = json.loads(json_str)
                return result
            else:
                self.logger.warning("LLM 输出未包含有效 JSON")
                return self._dummy_result("LLM 输出格式错误")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"LLM API 请求失败: {e}")
            raise  # 抛出异常以便重试逻辑处理
        except Exception as e:
            self.logger.error(f"LLM API 调用失败: {e}")
            raise

    def _call_local_llm(self, prompt: str) -> Dict[str, Any]:
        """调用本地 LLM 模型"""
        if not self.model or not self.tokenizer:
            return self._dummy_result("本地模型未加载")

        try:
            inputs = self.tokenizer(prompt, return_tensors="pt", max_length=self.llm_config.max_length, truncation=True)
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

            outputs = self.model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.3,
                do_sample=True
            )

            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

            # 解析 JSON
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
                return result
            else:
                self.logger.warning("本地 LLM 输出未包含有效 JSON")
                return self._dummy_result("本地模型输出格式错误")

        except Exception as e:
            self.logger.error(f"本地 LLM 推理失败: {e}")
            return self._dummy_result(f"本地推理异常: {str(e)}")

    def _dummy_result(self, reason: str) -> Dict[str, Any]:
        """返回 Dummy 结果"""
        return {
            "reasoning": reason,
            "verdict": "unknown",
            "severity": "Info",
            "threat_type": "Unknown",
            "is_successful_attack": "unknown",
            "success_evidence": "",
            # 兼容旧字段
            "is_malicious": False,
            "attack_type": "Unknown",
            "confidence": 0.5,
            "reason": reason,
            "threat_level": "Unknown",
            "recommended_action": "Monitor",
            "key_indicators": [],
            "mitre_techniques": [],
            "explanation_for_non_expert": reason,
        }

    def _process_task(self, task_data: Dict[str, Any]) -> bool:
        """处理单个任务，返回是否成功"""
        flow_key = task_data.get("flow_key")
        decision = task_data.get("decision")

        try:
            self.logger.info(f"[WORKER] 开始处理任务 | Flow: {flow_key} | Decision: {decision}")

            # 提取特征
            features_json = task_data.get("features", "{}")
            features = self._sanitize_features(features_json)

            # 提取双模型得分
            xgb_score = task_data.get("xgb_score", 0.0)
            anomaly_score = task_data.get("anomaly_score", 0.0)

            # 转换为自然语言
            features_text = self._features_to_natural_language(features)

            # 构建 Prompt
            prompt = self._build_prompt(features_text, xgb_score, anomaly_score, decision)

            # 调用 LLM
            if self.llm_config.use_api:
                result = self._call_llm_api(prompt)
            else:
                result = self._call_local_llm(prompt)

            # 记录日志
            verdict = result.get("verdict", "unknown")
            severity = result.get("severity", "Unknown")
            is_successful = result.get("is_successful_attack", "unknown")
            self.logger.info(
                f"[LLM] 深度研判完成 {flow_key} | "
                f"决策: {decision} | "
                f"判定: {verdict} | "
                f"严重性: {severity} | "
                f"攻击成功: {is_successful} | "
                f"置信度: {result.get('confidence', 0):.2f} | "
                f"建议: {result.get('recommended_action')}"
            )

            # 写入 Redis（使用 Pipeline 保证原子性 + 刷新 TTL）
            try:
                pipe = self.redis_client.pipeline()
                pipe.hset(flow_key, "llm_result", json.dumps(result, ensure_ascii=False))
                # 新 schema 字段
                pipe.hset(flow_key, "llm_verdict", str(result.get("verdict", "unknown")))
                pipe.hset(flow_key, "llm_severity", str(result.get("severity", "Info")))
                pipe.hset(flow_key, "llm_threat_type", str(result.get("threat_type", "Unknown")))
                pipe.hset(flow_key, "llm_is_successful_attack", str(result.get("is_successful_attack", "unknown")))
                # 兼容旧字段（is_malicious 由 verdict 推导）
                is_malicious = result.get("is_malicious", verdict in ("malicious", "suspicious"))
                pipe.hset(flow_key, "llm_is_malicious", str(is_malicious))
                pipe.hset(flow_key, "llm_confidence", str(result.get("confidence", 0.0)))
                pipe.hset(flow_key, "llm_attack_type", result.get("attack_type", result.get("threat_type", "Unknown")))
                pipe.hset(flow_key, "llm_threat_level", result.get("threat_level", result.get("severity", "Unknown")))
                pipe.expire(flow_key, 300)  # LLM 结果保留 5 分钟
                pipe.execute()
            except Exception as e:
                self.logger.error(f"写入 LLM 结果到 Redis 失败: {e}")
                raise

            # 更新统计
            with self.stats_lock:
                self.stats['total_processed'] += 1
                self.stats['success'] += 1
                if is_malicious:
                    self.stats['malicious_detected'] += 1
                else:
                    self.stats['benign_detected'] += 1

            return True

        except Exception as e:
            self.logger.error(f"处理任务失败 {flow_key}: {e}")
            with self.stats_lock:
                self.stats['total_processed'] += 1
                self.stats['failed'] += 1
            return False

    def _retry_failed_task(self, task_json: str, max_retries: int = 3):
        """重试失败的任务"""
        task_data = json.loads(task_json)
        retry_count = task_data.get("retry_count", 0)

        if retry_count >= max_retries:
            self.logger.error(f"任务重试次数超限 ({max_retries})，放弃处理: {task_data.get('flow_key')}")
            # 移到失败队列
            self.redis_client.lpush(self.failed_queue_name, task_json)
            return

        # 增加重试计数
        task_data["retry_count"] = retry_count + 1
        task_data["last_error_time"] = time.time()

        # 重新入队（放到队列尾部）
        self.redis_client.rpush(self.llm_queue_name, json.dumps(task_data))
        self.logger.warning(f"任务重新入队 (重试 {retry_count + 1}/{max_retries}): {task_data.get('flow_key')}")

    def start(self):
        """启动消费者 Worker"""
        self.running = True
        self.logger.info("LLM 消费者 Worker 启动")

        last_health_check = time.time()
        health_check_interval = 30.0  # 每 30 秒检查一次队列健康
        consecutive_errors = 0
        max_consecutive_errors = 5

        try:
            while self.running and not self.shutdown_event.is_set():
                try:
                    # 定期健康检查
                    current_time = time.time()
                    if current_time - last_health_check >= health_check_interval:
                        self._check_queue_health()
                        self._print_stats()
                        last_health_check = current_time

                    # BRPOP 阻塞消费（超时 1 秒，避免无法响应停机信号）
                    result = self.redis_client.brpop(self.llm_queue_name, timeout=1)
                    consecutive_errors = 0  # 成功则重置

                    if result is None:
                        continue  # 超时，继续循环

                    queue_name, task_json = result
                    task_data = json.loads(task_json)

                    # 处理任务
                    success = self._process_task(task_data)

                    # 失败则重试
                    if not success:
                        self._retry_failed_task(task_json)

                except (redis.ConnectionError, redis.TimeoutError) as e:
                    consecutive_errors += 1
                    self.logger.error(
                        f"Redis 连接异常 (连续第 {consecutive_errors} 次): {e}"
                    )

                    if consecutive_errors >= max_consecutive_errors:
                        self.logger.critical(
                            f"Redis 连续失败 {max_consecutive_errors} 次，尝试重建连接..."
                        )
                        try:
                            from ..config.redis_factory import RedisConnectionFactory
                            self.redis_client = RedisConnectionFactory.get_client_with_retry(
                                self.redis_config, max_retries=3
                            )
                            consecutive_errors = 0
                            self.logger.info("Redis 重建连接成功")
                        except Exception as reconnect_err:
                            self.logger.critical(
                                f"Redis 重建连接失败: {reconnect_err}，等待 10s 后重试"
                            )
                            time.sleep(10)
                    else:
                        # 指数退避
                        backoff = min(2 ** consecutive_errors, 30)
                        time.sleep(backoff)

                except Exception as e:
                    self.logger.error(f"消费循环未知异常: {e}")
                    time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("收到中断信号，停止消费者")
        finally:
            self.stop()

    def stop(self):
        """停止消费者 Worker"""
        self.running = False
        self._print_stats()
        try:
            self.redis_client.close()
        except Exception:
            pass
        self.logger.info("LLM 消费者 Worker 停止")

    def _print_stats(self):
        """打印统计信息"""
        with self.stats_lock:
            if self.stats['total_processed'] > 0:
                success_rate = self.stats['success'] / self.stats['total_processed'] * 100
                self.logger.info(
                    f"[STATS] 累计处理: {self.stats['total_processed']} | "
                    f"成功: {self.stats['success']} ({success_rate:.1f}%) | "
                    f"失败: {self.stats['failed']} | "
                    f"检出恶意: {self.stats['malicious_detected']} | "
                    f"检出正常: {self.stats['benign_detected']}"
                )


if __name__ == "__main__":
    import sys
    import time
    from ..utils import generate_five_tuple_key

    # 检查 API Key
    api_key = os.getenv("LLM_API_KEY")
    if not api_key:
        print("[ERROR] 环境变量 LLM_API_KEY 未设置")
        print("请先设置环境变量后再测试 LLM 消费者")
        print("\n示例: export LLM_API_KEY=your_api_key")
        sys.exit(1)

    print(f"[OK] 检测到 API Key: {api_key[:10]}...")

    # 测试配置
    redis_cfg = RedisConfig(host="localhost", port=6379)
    llm_cfg = LLMConfig(
        use_api=True,
        api_base_url="https://new.timefiles.online/v1",
        api_key=api_key,
        api_model="claude-opus-4-6"
    )

    analyzer = LLMAnalyzer(redis_cfg, llm_cfg)

    print("=" * 60)
    print("测试 1: 模拟向队列发送任务")
    print("=" * 60)

    # 模拟 Module 3 发送的任务
    test_tasks = [
        {
            "flow_key": generate_five_tuple_key("192.168.1.30", 9012, "10.0.0.3", 8080, "TCP"),
            "decision": "ZERODAY_HUNT",
            "timestamp": time.time(),
            "xgb_score": 0.35,
            "anomaly_score": 0.88,
            "packet_count": 10,
            "features": json.dumps({
                "iat_mean": 0.005,
                "iat_std": 0.001,
                "pkt_len_mean": 64,
                "pkt_len_std": 10,
                "bytes_sent": 640,
                "packet_count": 10,
                "duration": 0.05,
                "syn_count": 10,
                "packets_per_second": 200
            }),
            "suricata_alert": False,
            "signature": "",
            "severity": 0
        },
        {
            "flow_key": generate_five_tuple_key("192.168.1.40", 3456, "10.0.0.4", 22, "TCP"),
            "decision": "LLM_ANALYZE",
            "timestamp": time.time(),
            "xgb_score": 0.7,
            "anomaly_score": 0.5,
            "packet_count": 15,
            "features": json.dumps({
                "iat_mean": 0.1,
                "iat_std": 0.05,
                "pkt_len_mean": 512,
                "pkt_len_std": 100,
                "bytes_sent": 7680,
                "packet_count": 15,
                "duration": 1.5,
                "syn_count": 1,
                "packets_per_second": 10
            }),
            "suricata_alert": False,
            "signature": "",
            "severity": 0
        }
    ]

    for task in test_tasks:
        analyzer.redis_client.lpush(analyzer.llm_queue_name, json.dumps(task))
        print(f"发送任务: {task['flow_key']} | Decision: {task['decision']}")

    print(f"\n队列长度: {analyzer.redis_client.llen(analyzer.llm_queue_name)}")

    print("\n" + "=" * 60)
    print("测试 2: 启动消费者处理任务（按 Ctrl+C 停止）")
    print("=" * 60)

    try:
        analyzer.start()
    except KeyboardInterrupt:
        print("\n测试结束")

    print("\n" + "=" * 60)
    print("检查处理结果:")
    print("=" * 60)
    for task in test_tasks:
        flow_key = task['flow_key']
        result = analyzer.redis_client.hget(flow_key, "llm_result")
        is_malicious = analyzer.redis_client.hget(flow_key, "llm_is_malicious")
        attack_type = analyzer.redis_client.hget(flow_key, "llm_attack_type")

        print(f"\nFlow: {flow_key}")
        print(f"  Decision: {task['decision']}")
        print(f"  LLM 判定恶意: {is_malicious}")
        print(f"  攻击类型: {attack_type}")
        if result:
            result_obj = json.loads(result)
            print(f"  置信度: {result_obj.get('confidence', 0):.2f}")
            print(f"  威胁等级: {result_obj.get('threat_level')}")
            print(f"  建议措施: {result_obj.get('recommended_action')}")

