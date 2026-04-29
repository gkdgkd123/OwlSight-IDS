"""
Module 3: 智能路由决策模块（双模型协同版）
功能：定时扫描 Redis 中的状态，融合 XGBoost + Isolation Forest 双模型结果，实现三层决策
决策树：
  1. 高危直接拦截：xgb_score > 0.9 → BLOCK
  2. 正常直接放行：xgb_score < 0.5 AND anomaly_score < 0.75 → PASS
  3. 0day 猎杀：xgb_score < 0.5 BUT anomaly_score > 0.75 → LLM 深度研判

改造要点：
  - 移除同步回调，改为向 Redis List 发送消息（生产者模式）
  - 使用 scan() 替代 keys() 避免阻塞
  - 线程安全的统计计数器
  - 时间窗口统计（每分钟重置）+ 全局累计
"""
import time
import json
import redis
import threading
from typing import Dict, Any
from ..utils import setup_logger
from ..config.config import RedisConfig, XGBoostConfig
from ..config.redis_factory import RedisConnectionFactory


class IntelligentRouter:
    """智能路由决策模块 - 双模型协同版（生产者模式）"""

    def __init__(self, redis_config: RedisConfig, xgb_config: XGBoostConfig):
        self.redis_config = redis_config
        self.xgb_config = xgb_config
        self.logger = setup_logger("IntelligentRouter")

        self.redis_client = RedisConnectionFactory.get_client_with_retry(redis_config)

        self.running = False
        self.scan_interval = 1.0
        self.llm_queue_name = "llm_task_queue"  # LLM 任务队列名称

        # 决策阈值
        self.xgb_high_threshold = xgb_config.threshold_high  # 0.9
        self.xgb_low_threshold = xgb_config.threshold_low    # 0.5
        self.anomaly_threshold = xgb_config.anomaly_threshold  # 0.75

        # 线程锁（保护统计计数器）
        self.stats_lock = threading.Lock()

        # 时间窗口统计（每分钟重置）
        self.window_stats = {
            'total_flows': 0,
            'blocked': 0,
            'passed': 0,
            'llm_analyzed': 0,
            'zeroday_detected': 0
        }

        # 全局累计统计
        self.global_stats = {
            'total_flows': 0,
            'blocked': 0,
            'passed': 0,
            'llm_analyzed': 0,
            'zeroday_detected': 0
        }

        # 时间窗口管理
        self.window_start_time = time.time()
        self.window_duration = 60.0  # 60 秒窗口

        self.logger.info("智能路由决策模块初始化完成（双模型协同版 - 生产者模式）")
        self.logger.info(f"决策阈值: XGB_HIGH={self.xgb_high_threshold}, "
                        f"XGB_LOW={self.xgb_low_threshold}, "
                        f"ANOMALY={self.anomaly_threshold}")
        self.logger.info(f"LLM 任务队列: {self.llm_queue_name}")

        # 孤儿任务检测配置
        self.orphan_check_interval = 120.0  # 每 2 分钟检查一次
        self.orphan_timeout = 300.0  # 5 分钟无 LLM 结果视为孤儿

    def _get_flow_state(self, flow_key: str) -> Dict[str, Any]:
        """从 Redis 读取流状态"""
        try:
            state = self.redis_client.hgetall(flow_key)
            if not state:
                return {}

            return {
                "suricata_alert": state.get("suricata_alert", "false").lower() == "true",
                "xgb_score": float(state.get("xgb_score", 0.0)),
                "anomaly_score": float(state.get("anomaly_score", 0.0)),
                "packet_count": int(state.get("packet_count", 0)),
                "features": state.get("features", "{}"),
                "signature": state.get("signature", ""),
                "severity": int(state.get("severity", 0)) if state.get("severity") else 0,
            }
        except Exception as e:
            self.logger.error(f"读取流状态失败 {flow_key}: {e}")
            return {}

    def _make_decision(self, flow_key: str, state: Dict[str, Any]) -> str:
        """
        三层决策树（双模型协同）

        决策逻辑：
        1. 高危直接拦截：Suricata 告警 OR XGB > 0.9
        2. 正常直接放行：XGB < 0.5 AND 异常分数 < 0.75
        3. 0day 猎杀：XGB < 0.5 BUT 异常分数 > 0.75（已知模型认为安全，但行为极度异常）
        """
        suricata_alert = state.get("suricata_alert", False)
        xgb_score = state.get("xgb_score", 0.0)
        anomaly_score = state.get("anomaly_score", 0.0)

        # 决策层 1: 高危直接拦截
        if suricata_alert or xgb_score > self.xgb_high_threshold:
            self.logger.warning(
                f"[BLOCK] 拦截高危流量 {flow_key} | "
                f"Suricata: {suricata_alert} | XGB: {xgb_score:.3f} | Anomaly: {anomaly_score:.3f}"
            )
            if suricata_alert:
                self.logger.warning(f"  └─ 触发规则: {state.get('signature', 'Unknown')}")
            return "BLOCK"

        # 决策层 2: 正常直接放行
        if xgb_score < self.xgb_low_threshold and anomaly_score < self.anomaly_threshold:
            self.logger.debug(
                f"[PASS] 正常流量 {flow_key} | "
                f"XGB: {xgb_score:.3f} | Anomaly: {anomaly_score:.3f}"
            )
            return "PASS"

        # 决策层 3: 0day 猎杀策略
        if xgb_score < self.xgb_low_threshold and anomaly_score >= self.anomaly_threshold:
            self.logger.warning(
                f"[0DAY-HUNT] 检测到疑似未知威胁 {flow_key} | "
                f"XGB: {xgb_score:.3f} (已知模型认为安全) | "
                f"Anomaly: {anomaly_score:.3f} (行为极度异常) | "
                f"→ 转发至 LLM 深度研判"
            )
            return "ZERODAY_HUNT"

        # 决策层 3: 常规疑难流量（XGB 在灰色地带）
        if self.xgb_low_threshold <= xgb_score <= self.xgb_high_threshold:
            self.logger.info(
                f"[SUSPICIOUS] 疑难流量 {flow_key} | "
                f"XGB: {xgb_score:.3f} (灰色地带) | Anomaly: {anomaly_score:.3f} | "
                f"→ 转发至 LLM 深度研判"
            )
            return "LLM_ANALYZE"

        # 兜底：理论上不应该到这里
        self.logger.warning(f"[UNKNOWN] 未匹配决策规则 {flow_key} | XGB: {xgb_score:.3f} | Anomaly: {anomaly_score:.3f}")
        return "LLM_ANALYZE"

    def _send_to_llm_queue(self, flow_key: str, state: Dict[str, Any], decision: str):
        """将疑难流量发送到 LLM 任务队列（生产者）"""
        try:
            message = {
                "flow_key": flow_key,
                "decision": decision,
                "timestamp": time.time(),
                "xgb_score": state.get("xgb_score", 0.0),
                "anomaly_score": state.get("anomaly_score", 0.0),
                "packet_count": state.get("packet_count", 0),
                "features": state.get("features", "{}"),
                "suricata_alert": state.get("suricata_alert", False),
                "signature": state.get("signature", ""),
                "severity": state.get("severity", 0)
            }

            # LPUSH 到队列（Module 4 用 BRPOP 消费）
            self.redis_client.lpush(self.llm_queue_name, json.dumps(message))

            self.logger.debug(
                f"[QUEUE] 发送任务到 LLM 队列 | Flow: {flow_key} | Decision: {decision}"
            )
        except Exception as e:
            self.logger.error(f"发送 LLM 任务失败 {flow_key}: {e}")

    def _scan_redis_keys(self):
        """扫描 Redis 中的所有流状态并做决策（使用 scan 避免阻塞）"""
        try:
            cursor = 0
            processed_count = 0

            while True:
                # 使用 scan 迭代，每次处理 500 个 key
                cursor, keys = self.redis_client.scan(
                    cursor=cursor,
                    match="*:*-*:*-*",
                    count=500
                )

                for flow_key in keys:
                    # 读取流状态
                    state = self._get_flow_state(flow_key)
                    if not state:
                        continue

                    # 检查是否已经决策过（幂等性保护）
                    existing_decision = self.redis_client.hget(flow_key, "decision")
                    if existing_decision:
                        continue  # 已经决策过，跳过

                    # 执行决策
                    decision = self._make_decision(flow_key, state)

                    # 线程安全地更新统计
                    with self.stats_lock:
                        self.window_stats['total_flows'] += 1
                        self.global_stats['total_flows'] += 1

                        # 根据决策执行动作
                        if decision == "BLOCK":
                            self.window_stats['blocked'] += 1
                            self.global_stats['blocked'] += 1
                            pipe = self.redis_client.pipeline()
                            pipe.hset(flow_key, "decision", "BLOCK")
                            pipe.hset(flow_key, "decision_time", str(time.time()))
                            pipe.expire(flow_key, self.redis_config.ttl)  # 刷新 TTL
                            pipe.execute()

                        elif decision == "PASS":
                            self.window_stats['passed'] += 1
                            self.global_stats['passed'] += 1
                            # 正常流量立即释放内存
                            self.redis_client.delete(flow_key)

                        elif decision == "ZERODAY_HUNT":
                            self.window_stats['zeroday_detected'] += 1
                            self.window_stats['llm_analyzed'] += 1
                            self.global_stats['zeroday_detected'] += 1
                            self.global_stats['llm_analyzed'] += 1
                            pipe = self.redis_client.pipeline()
                            pipe.hset(flow_key, "decision", "ZERODAY_HUNT")
                            pipe.expire(flow_key, self.redis_config.ttl)  # 刷新 TTL
                            pipe.execute()
                            self._send_to_llm_queue(flow_key, state, decision)

                        elif decision == "LLM_ANALYZE":
                            self.window_stats['llm_analyzed'] += 1
                            self.global_stats['llm_analyzed'] += 1
                            pipe = self.redis_client.pipeline()
                            pipe.hset(flow_key, "decision", "LLM_ANALYZE")
                            pipe.expire(flow_key, self.redis_config.ttl)  # 刷新 TTL
                            pipe.execute()
                            self._send_to_llm_queue(flow_key, state, decision)

                    processed_count += 1

                # scan 返回 cursor=0 表示遍历完成
                if cursor == 0:
                    break

            if processed_count > 0:
                self.logger.debug(f"本次扫描处理 {processed_count} 个新流量")

        except Exception as e:
            self.logger.error(f"扫描 Redis 键失败: {e}")

    def _print_window_stats(self):
        """打印时间窗口统计（每分钟）"""
        with self.stats_lock:
            elapsed = time.time() - self.window_start_time
            if self.window_stats['total_flows'] > 0:
                self.logger.info(
                    f"[STATS-WINDOW] 过去 {elapsed:.0f}s 处理流量: {self.window_stats['total_flows']} | "
                    f"拦截: {self.window_stats['blocked']} | "
                    f"放行: {self.window_stats['passed']} | "
                    f"送审LLM: {self.window_stats['llm_analyzed']} | "
                    f"0day检测: {self.window_stats['zeroday_detected']}"
                )

            # 重置窗口统计
            self.window_stats = {
                'total_flows': 0,
                'blocked': 0,
                'passed': 0,
                'llm_analyzed': 0,
                'zeroday_detected': 0
            }
            self.window_start_time = time.time()

    def _print_global_stats(self):
        """打印全局累计统计"""
        with self.stats_lock:
            if self.global_stats['total_flows'] > 0:
                self.logger.info(
                    f"[STATS-GLOBAL] 累计处理流量: {self.global_stats['total_flows']} | "
                    f"拦截: {self.global_stats['blocked']} | "
                    f"放行: {self.global_stats['passed']} | "
                    f"送审LLM: {self.global_stats['llm_analyzed']} | "
                    f"0day检测: {self.global_stats['zeroday_detected']}"
                )

    def _check_orphan_tasks(self):
        """检测孤儿任务：已发送到 LLM 队列但长时间无结果的流"""
        try:
            cursor = 0
            orphan_count = 0
            current_time = time.time()

            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor, match="*:*-*:*-*", count=500
                )

                for flow_key in keys:
                    state = self.redis_client.hgetall(flow_key)
                    if not state:
                        continue

                    decision = state.get("decision", "")
                    has_llm_result = "llm_result" in state

                    # 已决策为 LLM 分析但无结果，且超时
                    if decision in ("ZERODAY_HUNT", "LLM_ANALYZE") and not has_llm_result:
                        decision_time = float(state.get("decision_time", current_time))
                        if current_time - decision_time > self.orphan_timeout:
                            orphan_count += 1
                            self.logger.warning(
                                f"[ORPHAN] 检测到孤儿任务: {flow_key} | "
                                f"决策: {decision} | 等待时间: {current_time - decision_time:.0f}s"
                            )
                            # 重新入队
                            requeue_state = self._get_flow_state(flow_key)
                            if requeue_state:
                                self._send_to_llm_queue(flow_key, requeue_state, decision)
                                self.logger.info(f"[ORPHAN] 重新入队: {flow_key}")

                if cursor == 0:
                    break

            if orphan_count > 0:
                self.logger.info(f"[ORPHAN] 本次检查发现 {orphan_count} 个孤儿任务并重新入队")

        except Exception as e:
            self.logger.error(f"孤儿任务检测失败: {e}")

    def start(self):
        """启动路由决策循环"""
        self.running = True
        self.logger.info("智能路由决策模块启动")

        last_window_print = time.time()
        last_orphan_check = time.time()

        try:
            while self.running:
                self._scan_redis_keys()

                current_time = time.time()

                # 检查是否到达窗口边界（60 秒）
                if current_time - last_window_print >= self.window_duration:
                    self._print_window_stats()
                    last_window_print = current_time

                # 定期孤儿任务检测
                if current_time - last_orphan_check >= self.orphan_check_interval:
                    self._check_orphan_tasks()
                    last_orphan_check = current_time

                time.sleep(self.scan_interval)

        except KeyboardInterrupt:
            self.logger.info("收到中断信号，停止路由决策")
        finally:
            self.stop()

    def stop(self):
        """停止路由决策"""
        self.running = False
        self._print_window_stats()  # 打印最后一个窗口统计
        self._print_global_stats()  # 打印全局累计统计
        try:
            self.redis_client.close()
        except Exception:
            pass
        self.logger.info("智能路由决策模块停止")


if __name__ == "__main__":
    from ..utils import generate_five_tuple_key

    redis_cfg = RedisConfig(host="localhost", port=6379)
    xgb_cfg = XGBoostConfig(threshold_high=0.9, threshold_low=0.5)

    router = IntelligentRouter(redis_cfg, xgb_cfg)

    print("=" * 60)
    print("模拟测试：写入不同类型的流量状态到 Redis")
    print("=" * 60)

    test_cases = [
        {
            "name": "高危流量（XGB > 0.9）",
            "key": generate_five_tuple_key("192.168.1.10", 1234, "10.0.0.1", 80, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.95",
                "anomaly_score": "0.6",
                "signature": "Port Scan"
            },
            "expected": "BLOCK"
        },
        {
            "name": "正常流量（XGB < 0.5, Anomaly < 0.75）",
            "key": generate_five_tuple_key("192.168.1.20", 5678, "10.0.0.2", 443, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.3",
                "anomaly_score": "0.4"
            },
            "expected": "PASS"
        },
        {
            "name": "0day 猎杀（XGB < 0.5, Anomaly > 0.75）",
            "key": generate_five_tuple_key("192.168.1.30", 9012, "10.0.0.3", 8080, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.4",
                "anomaly_score": "0.85",
                "features": '{"iat_mean": 0.05, "pkt_len_mean": 1200}'
            },
            "expected": "ZERODAY_HUNT"
        },
        {
            "name": "疑难流量（XGB 在灰色地带）",
            "key": generate_five_tuple_key("192.168.1.40", 3456, "10.0.0.4", 22, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.7",
                "anomaly_score": "0.5"
            },
            "expected": "LLM_ANALYZE"
        },
        {
            "name": "Suricata 告警",
            "key": generate_five_tuple_key("192.168.1.50", 7890, "10.0.0.5", 3389, "TCP"),
            "state": {
                "suricata_alert": "true",
                "xgb_score": "0.6",
                "anomaly_score": "0.5",
                "signature": "ET EXPLOIT RDP Brute Force"
            },
            "expected": "BLOCK"
        }
    ]

    for case in test_cases:
        for field, value in case["state"].items():
            router.redis_client.hset(case["key"], field, value)
        router.redis_client.expire(case["key"], 10)
        print(f"\n写入测试用例: {case['name']}")
        print(f"  Key: {case['key']}")
        print(f"  预期决策: {case['expected']}")

    print("\n" + "=" * 60)
    print("执行一次扫描...")
    print("=" * 60)
    router._scan_redis_keys()

    print("\n" + "=" * 60)
    print("检查决策结果:")
    print("=" * 60)
    for case in test_cases:
        result = router.redis_client.hget(case["key"], "decision")
        exists = router.redis_client.exists(case["key"])
        print(f"\n{case['name']}:")
        print(f"  决策结果: {result}")
        print(f"  Redis存在: {exists}")
        print(f"  预期: {case['expected']}")
        match = result == case['expected'] or (case['expected'] == 'PASS' and not exists)
        print(f"  匹配: {'[OK]' if match else '[FAIL]'}")

    print("\n" + "=" * 60)
    print("检查 LLM 任务队列:")
    print("=" * 60)
    queue_len = router.redis_client.llen(router.llm_queue_name)
    print(f"队列长度: {queue_len}")
    if queue_len > 0:
        print("\n队列内容:")
        for i in range(min(queue_len, 5)):
            msg = router.redis_client.lindex(router.llm_queue_name, i)
            if msg:
                task = json.loads(msg)
                print(f"  [{i+1}] Flow: {task['flow_key']}")
                print(f"      Decision: {task['decision']}")
                print(f"      XGB: {task['xgb_score']:.3f} | Anomaly: {task['anomaly_score']:.3f}")

    print("\n" + "=" * 60)
    print("统计信息:")
    print("=" * 60)
    router._print_window_stats()
    router._print_global_stats()
