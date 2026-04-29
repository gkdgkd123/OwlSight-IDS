"""
E2E 冒烟测试: 使用 data/eve.json 真实告警数据验证完整流水线
覆盖:
  - SuricataMonitor 解析真实 eve.json 告警
  - Router 对 Suricata 告警做出 BLOCK 决策
  - Router 对混合流量做出正确分类
  - 全流水线: eve.json → SuricataMonitor → Redis → Router → LLM Queue → Analyzer
"""
import pytest
import json
import time
import os
from pathlib import Path
from unittest.mock import patch
from tests.conftest import MockRedis
from realtime_ids.config.config import RedisConfig, SuricataConfig, XGBoostConfig, LLMConfig
from realtime_ids.modules.suricata_monitor import SuricataMonitor
from realtime_ids.modules.intelligent_router import IntelligentRouter
from realtime_ids.modules.llm_analyzer import LLMAnalyzer
from realtime_ids.utils import generate_five_tuple_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EVE_JSON_PATH = Path(__file__).parent.parent / "data" / "eve.json"


@pytest.fixture
def shared_redis():
    return MockRedis()


@pytest.fixture
def redis_cfg():
    return RedisConfig(host="localhost", port=6379, ttl=60)


@pytest.fixture
def xgb_cfg():
    return XGBoostConfig(threshold_high=0.9, threshold_low=0.5, anomaly_threshold=0.75)


@pytest.fixture
def llm_cfg():
    return LLMConfig(use_api=True, api_base_url="https://fake.api/v1", api_key="test-key", api_model="test")


@pytest.fixture
def suricata_monitor(shared_redis, redis_cfg):
    """SuricataMonitor with MockRedis"""
    with patch("realtime_ids.modules.suricata_monitor.RedisConnectionFactory") as f:
        f.get_client_with_retry.return_value = shared_redis
        cfg = SuricataConfig(eve_json_path=str(EVE_JSON_PATH))
        m = SuricataMonitor(redis_cfg, cfg)
        m.redis_client = shared_redis
        return m


@pytest.fixture
def router(shared_redis, redis_cfg, xgb_cfg):
    with patch("realtime_ids.modules.intelligent_router.RedisConnectionFactory") as f:
        f.get_client_with_retry.return_value = shared_redis
        r = IntelligentRouter(redis_cfg, xgb_cfg)
        r.redis_client = shared_redis
        return r


@pytest.fixture
def analyzer(shared_redis, redis_cfg, llm_cfg):
    with patch("realtime_ids.modules.llm_analyzer.RedisConnectionFactory") as f:
        f.get_client_with_retry.return_value = shared_redis
        a = LLMAnalyzer(redis_cfg, llm_cfg)
        a.redis_client = shared_redis
        return a


# ---------------------------------------------------------------------------
# 真实 eve.json 解析测试
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not EVE_JSON_PATH.exists(), reason="data/eve.json not found")
class TestSuricataEveJsonParsing:
    """使用真实 eve.json 数据测试 SuricataMonitor"""

    def _load_eve_alerts(self, max_lines=20):
        """加载前 N 条 eve.json 告警"""
        alerts = []
        with open(EVE_JSON_PATH, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                try:
                    event = json.loads(line.strip())
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except json.JSONDecodeError:
                    continue
        return alerts

    def test_parse_real_alerts(self, suricata_monitor):
        """真实告警应能正确解析五元组"""
        alerts = self._load_eve_alerts()
        assert len(alerts) > 0, "eve.json 中应至少有 1 条告警"

        for alert in alerts:
            key = suricata_monitor._parse_five_tuple(alert)
            # IPv4 TCP/UDP 应成功解析
            proto = alert.get("proto", "")
            if proto in ("TCP", "UDP") and alert.get("src_port") and alert.get("dest_port"):
                assert key is not None, f"Failed to parse: {alert.get('src_ip')}:{alert.get('src_port')}"
                assert "-" in key  # 五元组格式: IP:PORT-IP:PORT-PROTO

    def test_process_real_alert_writes_redis(self, suricata_monitor, shared_redis):
        """处理真实告警应写入 Redis"""
        alerts = self._load_eve_alerts(5)
        tcp_alerts = [a for a in alerts if a.get("proto") == "TCP" and a.get("src_port")]

        if not tcp_alerts:
            pytest.skip("No TCP alerts in first 5 lines of eve.json")

        alert = tcp_alerts[0]
        suricata_monitor._process_alert(alert)

        # 验证 Redis 写入
        key = suricata_monitor._parse_five_tuple(alert)
        assert shared_redis.hget(key, "suricata_alert") == "true"
        assert shared_redis.hget(key, "signature") is not None
        assert shared_redis.hget(key, "severity") is not None

    def test_process_multiple_alerts(self, suricata_monitor, shared_redis):
        """批量处理告警不应崩溃"""
        alerts = self._load_eve_alerts(20)
        processed = 0

        for alert in alerts:
            try:
                suricata_monitor._process_alert(alert)
                processed += 1
            except Exception as e:
                pytest.fail(f"Processing alert failed: {e}")

        assert processed == len(alerts)


# ---------------------------------------------------------------------------
# 全流水线 E2E
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not EVE_JSON_PATH.exists(), reason="data/eve.json not found")
class TestFullPipelineE2E:
    """eve.json → SuricataMonitor → Redis → Router → LLM Queue → Analyzer"""

    def test_suricata_alert_to_block(self, suricata_monitor, router, shared_redis):
        """Suricata 告警 → Router BLOCK 决策"""
        # Step 1: 从 eve.json 加载一条 TCP 告警
        with open(EVE_JSON_PATH, "r", encoding="utf-8") as f:
            for line in f:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert" and event.get("proto") == "TCP":
                    break
            else:
                pytest.skip("No TCP alert in eve.json")

        # Step 2: SuricataMonitor 处理告警
        suricata_monitor._process_alert(event)
        flow_key = suricata_monitor._parse_five_tuple(event)
        assert flow_key is not None

        # 验证 Redis 中有 suricata_alert=true
        assert shared_redis.hget(flow_key, "suricata_alert") == "true"

        # 补充 XGB/Anomaly 分数（模拟 Module 2 写入）
        shared_redis.hset(flow_key, "xgb_score", "0.3")
        shared_redis.hset(flow_key, "anomaly_score", "0.2")

        # Step 3: Router 决策
        router._scan_redis_keys()

        # Suricata 告警应导致 BLOCK
        decision = shared_redis.hget(flow_key, "decision")
        assert decision == "BLOCK"

    def test_mixed_traffic_classification(self, suricata_monitor, router, shared_redis):
        """混合流量应被正确分类"""
        # 1. Suricata 告警流量 → BLOCK
        alert_key = "192.168.1.1:1234-10.0.0.1:80-TCP"
        shared_redis.hset(alert_key, "suricata_alert", "true")
        shared_redis.hset(alert_key, "xgb_score", "0.3")
        shared_redis.hset(alert_key, "anomaly_score", "0.2")
        shared_redis.hset(alert_key, "signature", "ET EXPLOIT Test")
        shared_redis.hset(alert_key, "severity", "1")

        # 2. 正常流量 → PASS
        normal_key = "192.168.1.2:2345-10.0.0.2:443-TCP"
        shared_redis.hset(normal_key, "suricata_alert", "false")
        shared_redis.hset(normal_key, "xgb_score", "0.2")
        shared_redis.hset(normal_key, "anomaly_score", "0.3")

        # 3. 0day 嫌疑流量 → ZERODAY_HUNT
        zeroday_key = "192.168.1.3:3456-10.0.0.3:8080-TCP"
        shared_redis.hset(zeroday_key, "suricata_alert", "false")
        shared_redis.hset(zeroday_key, "xgb_score", "0.35")
        shared_redis.hset(zeroday_key, "anomaly_score", "0.88")
        shared_redis.hset(zeroday_key, "features", '{"iat_mean": 0.005}')

        # 4. 灰色地带流量 → LLM_ANALYZE
        gray_key = "192.168.1.4:4567-10.0.0.4:22-TCP"
        shared_redis.hset(gray_key, "suricata_alert", "false")
        shared_redis.hset(gray_key, "xgb_score", "0.7")
        shared_redis.hset(gray_key, "anomaly_score", "0.5")

        # Router 扫描
        router._scan_redis_keys()

        # 验证决策
        assert shared_redis.hget(alert_key, "decision") == "BLOCK"
        assert shared_redis.exists(normal_key) == 0  # PASS → 删除
        assert shared_redis.hget(zeroday_key, "decision") == "ZERODAY_HUNT"
        assert shared_redis.hget(gray_key, "decision") == "LLM_ANALYZE"

        # 验证 LLM 队列
        assert shared_redis.llen("llm_task_queue") == 2  # ZERODAY + LLM_ANALYZE

        # 验证统计
        assert router.global_stats["total_flows"] == 4
        assert router.global_stats["blocked"] == 1
        assert router.global_stats["passed"] == 1

    def test_full_pipeline_with_llm(self, suricata_monitor, router, analyzer, shared_redis):
        """完整流水线: 告警 → 决策 → LLM 消费 → 结果写回"""
        # Step 1: 写入 0day 嫌疑流量
        flow_key = "10.0.0.100:9999-10.0.0.200:80-TCP"
        shared_redis.hset(flow_key, "suricata_alert", "false")
        shared_redis.hset(flow_key, "xgb_score", "0.35")
        shared_redis.hset(flow_key, "anomaly_score", "0.9")
        shared_redis.hset(flow_key, "features", json.dumps({
            "iat_mean": 0.005,
            "iat_std": 0.001,
            "pkt_len_mean": 64,
            "packet_count": 20,
            "syn_count": 20,
            "bytes_sent": 1280,
            "duration": 0.1,
            "packets_per_second": 200,
        }))

        # Step 2: Router 决策 → ZERODAY_HUNT → 入队
        router._scan_redis_keys()
        assert shared_redis.hget(flow_key, "decision") == "ZERODAY_HUNT"
        assert shared_redis.llen("llm_task_queue") == 1

        # Step 3: Analyzer 消费
        mock_result = {
            "is_malicious": True,
            "attack_type": "Port Scanning",
            "confidence": 0.95,
            "reason": "All SYN packets with very short IAT, typical port scan",
            "threat_level": "High",
            "recommended_action": "Block",
        }

        with patch.object(analyzer, "_call_llm_api", return_value=mock_result):
            result = shared_redis.brpop("llm_task_queue", timeout=1)
            assert result is not None
            _, task_json = result
            task_data = json.loads(task_json)
            success = analyzer._process_task(task_data)

        assert success is True

        # Step 4: 验证最终结果
        assert shared_redis.hget(flow_key, "llm_is_malicious") == "True"
        assert shared_redis.hget(flow_key, "llm_attack_type") == "Port Scanning"
        assert shared_redis.hget(flow_key, "llm_confidence") == "0.95"
        assert shared_redis.hget(flow_key, "llm_threat_level") == "High"

        # 队列应为空
        assert shared_redis.llen("llm_task_queue") == 0

        # Analyzer 统计
        assert analyzer.stats["total_processed"] == 1
        assert analyzer.stats["success"] == 1
        assert analyzer.stats["malicious_detected"] == 1

    def test_pubsub_early_abort_signal(self, suricata_monitor, shared_redis):
        """Suricata 告警应通过 Pub/Sub 广播 Early Abort 信号"""
        # 订阅
        pubsub = shared_redis.pubsub()
        pubsub.subscribe("suricata_alerts_channel")

        # 处理一条告警
        event = {
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.50",
            "src_port": 54321,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET EXPLOIT Test Signature",
                "severity": 1,
            },
        }
        suricata_monitor._process_alert(event)

        # 验证 Pub/Sub 消息
        messages = [m for m in pubsub.listen() if m["type"] == "message"]
        assert len(messages) == 1
        assert "192.168.1.100" in messages[0]["data"]
        assert "10.0.0.50" in messages[0]["data"]
