"""
Module 2: 早流特征提取与双模型推理模块
功能：旁路监听网卡，基于"包数(N=10) 或 时间(T=3s)"双重触发，提取流特征并进行 XGBoost + Isolation Forest 双模型推理
架构：XGBoost (监督学习，识别已知攻击) + Isolation Forest (无监督学习，检测异常行为/0day)
"""
import time
import json
import redis
import threading
import numpy as np
from typing import Dict, List, Any, Optional
from collections import defaultdict, OrderedDict
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP
from ..utils import generate_five_tuple_key, generate_trace_id, setup_logger
from ..config.config import RedisConfig, ScapyConfig, XGBoostConfig
from ..config.redis_factory import RedisConnectionFactory


class FlowStatistics:
    """流统计信息"""

    def __init__(self):
        self.packet_lengths: List[int] = []
        self.timestamps: List[float] = []
        self.tcp_flags: List[int] = []
        self.flow_start_time: float = time.time()
        self.packet_count: int = 0
        self.bytes_sent: int = 0
        self.already_inferred: bool = False  # 标记是否已推理（防止重复）

    def add_packet(self, packet_length: int, timestamp: float, tcp_flag: Optional[int] = None):
        self.packet_lengths.append(packet_length)
        self.timestamps.append(timestamp)
        if tcp_flag is not None:
            self.tcp_flags.append(tcp_flag)
        self.packet_count += 1
        self.bytes_sent += packet_length

    def compute_features(self) -> Dict[str, float]:
        """计算完整的 18 维特征向量（与训练时一致）"""
        if len(self.timestamps) < 2:
            iats = [0.0]
        else:
            iats = [self.timestamps[i] - self.timestamps[i-1]
                   for i in range(1, len(self.timestamps))]

        duration = self.timestamps[-1] - self.timestamps[0] if len(self.timestamps) > 1 else 0.0

        # 18 维特征（与训练脚本保持一致）
        features = {
            # 基础统计
            "packet_count": self.packet_count,
            "bytes_sent": float(self.bytes_sent),
            "duration": duration,

            # IAT 特征（最重要）
            "iat_mean": float(np.mean(iats)) if iats else 0.0,
            "iat_std": float(np.std(iats)) if iats else 0.0,
            "iat_min": float(np.min(iats)) if iats else 0.0,
            "iat_max": float(np.max(iats)) if iats else 0.0,

            # 包长特征
            "pkt_len_mean": float(np.mean(self.packet_lengths)) if self.packet_lengths else 0.0,
            "pkt_len_std": float(np.std(self.packet_lengths)) if self.packet_lengths else 0.0,
            "pkt_len_min": float(np.min(self.packet_lengths)) if self.packet_lengths else 0.0,
            "pkt_len_max": float(np.max(self.packet_lengths)) if self.packet_lengths else 0.0,

            # TCP 特征
            "tcp_flags_count": len([f for f in self.tcp_flags if f > 0]),
            "syn_count": sum([1 for f in self.tcp_flags if f & 0x02]),
            "ack_count": sum([1 for f in self.tcp_flags if f & 0x10]),
            "fin_count": sum([1 for f in self.tcp_flags if f & 0x01]),
            "rst_count": sum([1 for f in self.tcp_flags if f & 0x04]),

            # 速率特征
            "bytes_per_second": self.bytes_sent / duration if duration > 0 else 0.0,
            "packets_per_second": self.packet_count / duration if duration > 0 else 0.0,
        }
        return features


class DualModelInference:
    """双模型推理引擎：XGBoost + Isolation Forest"""

    def __init__(self, xgb_config: XGBoostConfig, logger):
        self.xgb_config = xgb_config
        self.logger = logger

        # 特征列顺序（必须与训练时一致）
        self.feature_columns = [
            'packet_count', 'bytes_sent', 'duration',
            'iat_mean', 'iat_std', 'iat_min', 'iat_max',
            'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
            'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
            'bytes_per_second', 'packets_per_second'
        ]

        # 加载模型
        self.xgb_model = self._load_xgb_model()
        self.iforest_model = self._load_iforest_model()
        self.iforest_scaler = self._load_iforest_scaler()
        self.anomaly_percentiles = self._load_anomaly_percentiles()

    def _load_xgb_model(self):
        """加载 XGBoost 模型"""
        try:
            import xgboost as xgb
            model_path = Path(self.xgb_config.model_path)

            if model_path.exists():
                model = xgb.Booster()
                model.load_model(str(model_path))
                self.logger.info(f"XGBoost 模型加载成功: {model_path}")
                return model
            else:
                self.logger.warning(f"XGBoost 模型文件不存在: {model_path}，使用启发式模拟")
                return None
        except Exception as e:
            self.logger.error(f"加载 XGBoost 模型失败: {e}")
            return None

    def _load_iforest_model(self):
        """加载 Isolation Forest 模型"""
        try:
            import pickle
            iforest_path = Path(self.xgb_config.model_path).parent / 'iforest_model.pkl'

            if iforest_path.exists():
                with open(iforest_path, 'rb') as f:
                    model = pickle.load(f)
                self.logger.info(f"Isolation Forest 模型加载成功: {iforest_path}")
                return model
            else:
                self.logger.warning(f"Isolation Forest 模型文件不存在: {iforest_path}，使用启发式模拟")
                return None
        except Exception as e:
            self.logger.error(f"加载 Isolation Forest 模型失败: {e}")
            return None

    def _load_iforest_scaler(self):
        """加载 Isolation Forest 特征标准化器"""
        try:
            import pickle
            scaler_path = Path(self.xgb_config.model_path).parent / 'scaler.pkl'

            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    scaler = pickle.load(f)
                self.logger.info(f"Scaler 加载成功: {scaler_path}")
                return scaler
            else:
                self.logger.warning(f"Scaler 文件不存在: {scaler_path}，跳过标准化")
                return None
        except Exception as e:
            self.logger.error(f"加载 Scaler 失败: {e}")
            return None

    def _load_anomaly_percentiles(self):
        """加载训练集异常分数分布（用于运行时归一化）"""
        try:
            import json as _json
            info_path = Path(self.xgb_config.model_path).parent / 'iforest_info.json'

            if info_path.exists():
                with open(info_path, 'r') as f:
                    info = _json.load(f)
                percentiles = info.get('anomaly_score_percentiles')
                if percentiles:
                    self.logger.info(f"异常分数分位数加载成功: {percentiles}")
                    return percentiles
                else:
                    self.logger.warning("iforest_info.json 中无 anomaly_score_percentiles 字段")
            return None
        except Exception as e:
            self.logger.error(f"加载异常分数分位数失败: {e}")
            return None

    def predict(self, features: Dict[str, float]) -> Dict[str, float]:
        """
        双模型推理
        返回: {
            'xgb_score': 0.0-1.0 (已知攻击概率),
            'anomaly_score': 0.0-1.0 (异常程度)
        }
        """
        # 构造特征向量
        feature_vector = [features.get(col, 0.0) for col in self.feature_columns]

        # XGBoost 推理（监督学习）
        xgb_score = self._predict_xgb(feature_vector)

        # Isolation Forest 推理（无监督学习）
        anomaly_score = self._predict_iforest(feature_vector)

        return {
            'xgb_score': xgb_score,
            'anomaly_score': anomaly_score
        }

    def _predict_xgb(self, feature_vector: List[float]) -> float:
        """XGBoost 推理：识别已知攻击模式"""
        if self.xgb_model is None:
            # 启发式模拟（基于特征规则）
            return self._heuristic_xgb(feature_vector)

        try:
            import xgboost as xgb
            dmatrix = xgb.DMatrix([feature_vector], feature_names=self.feature_columns)
            score = float(self.xgb_model.predict(dmatrix)[0])
            return score
        except Exception as e:
            self.logger.error(f"XGBoost 推理失败: {e}")
            return 0.5

    def _predict_iforest(self, feature_vector: List[float]) -> float:
        """Isolation Forest 推理：检测异常行为"""
        if self.iforest_model is None:
            # 启发式模拟（基于统计异常）
            return self._heuristic_iforest(feature_vector)

        try:
            # 标准化特征（训练时用了 StandardScaler，推理必须一致）
            if self.iforest_scaler is not None:
                scaled_vector = self.iforest_scaler.transform([feature_vector])[0]
            else:
                scaled_vector = feature_vector

            # decision_function 返回异常分数（越负越异常）
            anomaly_score_raw = self.iforest_model.decision_function([scaled_vector])[0]

            # 动态归一化到 0-1（基于训练集分布）
            if self.anomaly_percentiles:
                p5 = self.anomaly_percentiles.get('p5', -0.3)
                p95 = self.anomaly_percentiles.get('p95', 0.1)
                # 越负越异常 → 取反后线性映射到 [0, 1]
                inverted = -anomaly_score_raw
                inverted_p5 = -p95   # p95 是最"正常"的一端，取反后变成最小值
                inverted_p95 = -p5   # p5 是最"异常"的一端，取反后变成最大值
                if inverted_p95 > inverted_p5:
                    anomaly_score = (inverted - inverted_p5) / (inverted_p95 - inverted_p5)
                else:
                    anomaly_score = 0.5
                anomaly_score = max(0.0, min(1.0, anomaly_score))
            else:
                # 旧模型兼容：使用固定偏移
                anomaly_score = max(0.0, min(1.0, -anomaly_score_raw + 0.5))

            return anomaly_score
        except Exception as e:
            self.logger.error(f"Isolation Forest 推理失败: {e}")
            return 0.5

    def _heuristic_xgb(self, feature_vector: List[float]) -> float:
        """启发式 XGBoost 模拟（基于已知攻击特征）"""
        features = dict(zip(self.feature_columns, feature_vector))
        score = 0.5

        # 端口扫描特征
        if features['pkt_len_mean'] < 100 and features['iat_mean'] < 0.01:
            score += 0.2

        # DoS 特征
        if features['packet_count'] > 50 and features['iat_mean'] < 0.001:
            score += 0.25

        # 数据外泄特征
        if features['bytes_sent'] > 10000 and features['iat_std'] < 0.01:
            score += 0.15

        # 慢速扫描特征
        if features['iat_mean'] > 5 and features['pkt_len_mean'] < 100:
            score += 0.1

        return max(0.0, min(1.0, score))

    def _heuristic_iforest(self, feature_vector: List[float]) -> float:
        """启发式 Isolation Forest 模拟（基于统计异常）"""
        features = dict(zip(self.feature_columns, feature_vector))
        anomaly_score = 0.0

        # 检测极端值（统计异常）
        # IAT 极端值
        if features['iat_mean'] < 0.0001 or features['iat_mean'] > 100:
            anomaly_score += 0.3

        # 包长极端值
        if features['pkt_len_mean'] < 40 or features['pkt_len_mean'] > 1400:
            anomaly_score += 0.2

        # 速率极端值
        if features['packets_per_second'] > 1000 or features['bytes_per_second'] > 1000000:
            anomaly_score += 0.25

        # 规律性异常（IAT 标准差极小）
        if features['iat_std'] < 0.001 and features['packet_count'] > 10:
            anomaly_score += 0.2

        # 持续时间异常
        if features['duration'] > 300 or (features['duration'] < 0.1 and features['packet_count'] > 5):
            anomaly_score += 0.15

        return max(0.0, min(1.0, anomaly_score))


class EarlyFlowDualModel:
    """早流特征提取与双模型推理模块"""

    def __init__(self, redis_config: RedisConfig, scapy_config: ScapyConfig, xgb_config: XGBoostConfig):
        self.redis_config = redis_config
        self.scapy_config = scapy_config
        self.xgb_config = xgb_config
        self.logger = setup_logger("EarlyFlowDualModel")

        self.redis_client = RedisConnectionFactory.get_client_with_retry(redis_config)

        self.active_flows: OrderedDict[str, FlowStatistics] = OrderedDict()
        self.max_active_flows = 50000  # 内存上限：最多跟踪 50K 个并发流
        self.lock = threading.Lock()  # 保护 active_flows 字典的线程锁
        self.dual_model = DualModelInference(xgb_config, self.logger)
        self.running = False

        # 僵尸流清理配置
        self.flow_timeout = 60.0  # 60 秒超时
        self.last_cleanup_time = time.time()
        self.cleanup_interval = 10.0  # 每 10 秒清理一次

        # Suricata Early Abort 监听（独立 Redis 连接，因为 subscribe 会独占连接）
        self.pubsub_client = RedisConnectionFactory.get_dedicated_client(redis_config)
        self.pubsub = self.pubsub_client.pubsub()
        self.pubsub.subscribe("suricata_alerts_channel")
        self.alert_listener_thread = None

        self.logger.info(f"早流双模型推理模块初始化完成，监听接口: {scapy_config.interface}")
        self.logger.info("已订阅 Suricata 报警频道: suricata_alerts_channel")

    def _extract_five_tuple(self, packet) -> Optional[str]:
        """从数据包提取五元组"""
        try:
            if IP not in packet:
                return None

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto_name = "TCP"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto_name = "UDP"
            else:
                return None

            return generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, proto_name)
        except Exception as e:
            self.logger.debug(f"提取五元组失败: {e}")
            return None

    def _should_trigger(self, flow_key: str, flow_stats: FlowStatistics) -> bool:
        """检查是否触发双重条件"""
        # 如果已经推理过，不再触发
        if flow_stats.already_inferred:
            return False

        # 条件 1: 包数达到阈值
        if flow_stats.packet_count >= self.scapy_config.packet_trigger:
            return True

        # 条件 2: 时间窗口达到阈值 AND
        elapsed = time.time() - flow_stats.flow_start_time
        if elapsed >= self.scapy_config.time_trigger:
            return True

        return False

    def _cleanup_stale_flows(self):
        """清理超时的僵尸流（防止内存泄漏）"""
        current_time = time.time()
        stale_keys = [
            key for key, stats in self.active_flows.items()
            if current_time - stats.flow_start_time > self.flow_timeout
        ]

        for key in stale_keys:
            del self.active_flows[key]

        if stale_keys:
            self.logger.debug(f"清理 {len(stale_keys)} 个超时流（超过 {self.flow_timeout}s）")

    def _listen_for_alerts(self):
        """Suricata 报警监听线程：订阅 Pub/Sub，收到报警后立刻掐断对应流的特征采集"""
        self.logger.info("[Alert Listener] Suricata 报警监听线程已启动")

        try:
            for message in self.pubsub.listen():
                if not self.running:
                    break

                if message["type"] != "message":
                    continue

                flow_key = message["data"]

                # 抢占逻辑：使用锁保护字典访问
                with self.lock:
                    if flow_key in self.active_flows:
                        # 不直接 delete，而是标记为已推理（惰性清理原则）
                        self.active_flows[flow_key].already_inferred = True
                        self.logger.debug(
                            f"[Early Abort] 收到 Suricata 报警，立刻掐断特征采集: {flow_key}"
                        )

        except Exception as e:
            self.logger.error(f"[Alert Listener] 监听线程异常: {e}")
        finally:
            self.logger.info("[Alert Listener] Suricata 报警监听线程已退出")

    def _process_flow(self, flow_key: str, flow_stats: FlowStatistics):
        """处理触发的流：特征提取 + 双模型推理"""
        # 计算特征
        features = flow_stats.compute_features()

        # 双模型推理
        scores = self.dual_model.predict(features)
        xgb_score = scores['xgb_score']
        anomaly_score = scores['anomaly_score']

        # 写入 Redis（使用 Pipeline 保证原子性）
        try:
            # 分配或继承 trace_id
            existing_tid = self.redis_client.hget(flow_key, "trace_id")
            trace_id = existing_tid or generate_trace_id()

            pipe = self.redis_client.pipeline()
            pipe.hset(flow_key, "trace_id", trace_id)
            pipe.hset(flow_key, "xgb_score", str(xgb_score))
            pipe.hset(flow_key, "anomaly_score", str(anomaly_score))
            pipe.hset(flow_key, "packet_count", str(flow_stats.packet_count))
            pipe.hset(flow_key, "flow_start_time", str(flow_stats.flow_start_time))
            pipe.hset(flow_key, "features", json.dumps(features))
            pipe.expire(flow_key, self.redis_config.ttl)
            pipe.execute()

            self.logger.info(
                f"[{trace_id}] [DUAL-MODEL] {flow_key} | "
                f"XGB得分: {xgb_score:.3f} | 异常得分: {anomaly_score:.3f} | "
                f"包数: {flow_stats.packet_count}"
            )

            # 标记已推理（防止重复推理）
            flow_stats.already_inferred = True

        except Exception as e:
            self.logger.error(f"写入 Redis 失败 {flow_key}: {e}")
            # 不删除流，保留以便重试
            raise

    def _packet_handler(self, packet):
        """数据包处理回调"""
        flow_key = self._extract_five_tuple(packet)
        if not flow_key:
            return

        packet_length = len(packet)
        timestamp = time.time()
        tcp_flag = packet[TCP].flags if TCP in packet else None

        with self.lock:
            # 初始化或更新流统计
            if flow_key not in self.active_flows:
                # LRU 淘汰：超过上限时移除最旧的流
                while len(self.active_flows) >= self.max_active_flows:
                    evicted_key, _ = self.active_flows.popitem(last=False)
                    self.logger.debug(f"[LRU] 淘汰最旧流: {evicted_key} (active_flows={len(self.active_flows)})")
                self.active_flows[flow_key] = FlowStatistics()
            else:
                # 访问已有流时移到末尾（LRU 更新）
                self.active_flows.move_to_end(flow_key)

            flow_stats = self.active_flows[flow_key]

            # 如果已推理过（含 Suricata 报警掐断），忽略后续包
            if flow_stats.already_inferred:
                return

            flow_stats.add_packet(packet_length, timestamp, tcp_flag)

            # 检查触发条件
            should_trigger = self._should_trigger(flow_key, flow_stats)

        # 触发推理放在锁外，避免长时间持锁
        if should_trigger:
            try:
                self._process_flow(flow_key, flow_stats)
            except Exception as e:
                self.logger.error(f"处理流失败 {flow_key}: {e}")

        # 定期清理僵尸流
        current_time = time.time()
        if current_time - self.last_cleanup_time >= self.cleanup_interval:
            with self.lock:
                self._cleanup_stale_flows()
            self.last_cleanup_time = current_time

    def start(self):
        """启动抓包与推理"""
        self.running = True

        # 先启动 Suricata 报警监听线程
        self.alert_listener_thread = threading.Thread(
            target=self._listen_for_alerts,
            name="SuricataAlertListener",
            daemon=True
        )
        self.alert_listener_thread.start()
        self.logger.info("Suricata 报警监听线程已启动")

        # 判断是 pcap 回放还是实时捕获
        if self.scapy_config.pcap_file:
            self.logger.info(f"开始回放 pcap 文件: {self.scapy_config.pcap_file}")
            try:
                sniff(
                    offline=self.scapy_config.pcap_file,
                    prn=self._packet_handler,
                    store=False
                )
                # pcap 回放完成后，处理剩余的流
                self.logger.info("pcap 回放完成，处理剩余未触发的流...")
                self._flush_remaining_flows()
            except Exception as e:
                self.logger.error(f"pcap 回放异常: {e}")
            finally:
                self.stop()
        else:
            self.logger.info(f"开始监听网卡: {self.scapy_config.interface}")
            try:
                sniff(
                    iface=self.scapy_config.interface,
                    prn=self._packet_handler,
                    filter=self.scapy_config.bpf_filter if self.scapy_config.bpf_filter else None,
                    store=False
                )
            except KeyboardInterrupt:
                self.logger.info("收到中断信号，停止抓包")
            except Exception as e:
                self.logger.error(f"抓包异常: {e}")
            finally:
                self.stop()

    def _flush_remaining_flows(self):
        """pcap 回放完成后，处理所有剩余未触发的流"""
        with self.lock:
            remaining = [
                (flow_key, flow_stats)
                for flow_key, flow_stats in self.active_flows.items()
                if not flow_stats.already_inferred and flow_stats.packet_count > 0
            ]

        self.logger.info(f"发现 {len(remaining)} 个未处理的流，正在处理...")

        for flow_key, flow_stats in remaining:
            try:
                self._process_flow(flow_key, flow_stats)
            except Exception as e:
                self.logger.error(f"处理剩余流失败 {flow_key}: {e}")

        self.logger.info("所有剩余流处理完成")

    def stop(self):
        """停止模块"""
        self.running = False

        # 关闭 Pub/Sub 监听
        try:
            self.pubsub.unsubscribe()
            self.pubsub.close()
            self.pubsub_client.close()
        except Exception as e:
            self.logger.debug(f"关闭 Pub/Sub 连接时出现异常: {e}")

        # 关闭主 Redis 连接
        try:
            self.redis_client.close()
        except Exception:
            pass

        # 等待监听线程退出
        if self.alert_listener_thread and self.alert_listener_thread.is_alive():
            self.alert_listener_thread.join(timeout=2)

        self.logger.info("早流双模型推理模块停止")


if __name__ == "__main__":
    from pathlib import Path

    redis_cfg = RedisConfig(host="localhost", port=6379)
    scapy_cfg = ScapyConfig(interface="eth0", packet_trigger=10, time_trigger=3.0)
    xgb_cfg = XGBoostConfig(model_path="./src/models/xgb_model.json")

    module = EarlyFlowDualModel(redis_cfg, scapy_cfg, xgb_cfg)

    print("模拟测试：生成 Mock 流量特征")
    test_key = generate_five_tuple_key("192.168.1.200", 12345, "10.0.0.100", 443, "TCP")

    mock_stats = FlowStatistics()
    for i in range(10):
        mock_stats.add_packet(
            packet_length=np.random.randint(40, 1500),
            timestamp=time.time() + i * 0.1,
            tcp_flag=2
        )

    features = mock_stats.compute_features()
    scores = module.dual_model.predict(features)

    print(f"\n流量特征: {json.dumps(features, indent=2)}")
    print(f"\nXGBoost 得分: {scores['xgb_score']:.3f}")
    print(f"异常得分: {scores['anomaly_score']:.3f}")

    # 修复 Redis 3.0 兼容性：使用逐字段 hset
    module.redis_client.hset(test_key, "xgb_score", str(scores['xgb_score']))
    module.redis_client.hset(test_key, "anomaly_score", str(scores['anomaly_score']))
    module.redis_client.hset(test_key, "features", json.dumps(features))
    module.redis_client.expire(test_key, 10)
    print(f"\n已写入测试数据到 Redis: {test_key}")
