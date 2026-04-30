"""
单元测试: IntelligentRouter 决策树
覆盖: 5 种决策路径 (BLOCK/PASS/ZERODAY_HUNT/LLM_ANALYZE/Suricata)
"""
import pytest
import json
from unittest.mock import patch
from src.modules.intelligent_router import IntelligentRouter
from src.config.config import RedisConfig, XGBoostConfig


@pytest.fixture
def router(mock_redis, redis_config, xgb_config):
    """创建使用 MockRedis 的 IntelligentRouter"""
    with patch(
        "src.modules.intelligent_router.RedisConnectionFactory"
    ) as mock_factory:
        mock_factory.get_client_with_retry.return_value = mock_redis
        r = IntelligentRouter(redis_config, xgb_config)
        r.redis_client = mock_redis
        return r


class TestDecisionTree:
    """决策树完整分支覆盖"""

    def test_block_high_xgb(self, router):
        """XGB > 0.9 → BLOCK"""
        state = {"suricata_alert": False, "xgb_score": 0.95, "anomaly_score": 0.3}
        decision = router._make_decision("test_flow", state)
        assert decision == "BLOCK"

    def test_block_suricata_alert(self, router):
        """Suricata 告警 → BLOCK（无论 XGB 分数）"""
        state = {"suricata_alert": True, "xgb_score": 0.1, "anomaly_score": 0.1}
        decision = router._make_decision("test_flow", state)
        assert decision == "BLOCK"

    def test_pass_low_risk(self, router):
        """XGB < 0.5 AND Anomaly < 0.75 → PASS"""
        state = {"suricata_alert": False, "xgb_score": 0.3, "anomaly_score": 0.4}
        decision = router._make_decision("test_flow", state)
        assert decision == "PASS"

    def test_zeroday_hunt(self, router):
        """XGB < 0.5 BUT Anomaly >= 0.75 → ZERODAY_HUNT"""
        state = {"suricata_alert": False, "xgb_score": 0.35, "anomaly_score": 0.85}
        decision = router._make_decision("test_flow", state)
        assert decision == "ZERODAY_HUNT"

    def test_llm_analyze_gray_zone(self, router):
        """0.5 <= XGB <= 0.9 → LLM_ANALYZE"""
        state = {"suricata_alert": False, "xgb_score": 0.7, "anomaly_score": 0.5}
        decision = router._make_decision("test_flow", state)
        assert decision == "LLM_ANALYZE"

    def test_llm_analyze_boundary_low(self, router):
        """XGB = 0.5 (边界) → LLM_ANALYZE"""
        state = {"suricata_alert": False, "xgb_score": 0.5, "anomaly_score": 0.5}
        decision = router._make_decision("test_flow", state)
        assert decision == "LLM_ANALYZE"

    def test_llm_analyze_boundary_high(self, router):
        """XGB = 0.9 (边界) → LLM_ANALYZE（不是 BLOCK，因为条件是 > 0.9）"""
        state = {"suricata_alert": False, "xgb_score": 0.9, "anomaly_score": 0.5}
        decision = router._make_decision("test_flow", state)
        assert decision == "LLM_ANALYZE"

    def test_zeroday_boundary(self, router):
        """XGB < 0.5 AND Anomaly = 0.75 (边界) → ZERODAY_HUNT"""
        state = {"suricata_alert": False, "xgb_score": 0.4, "anomaly_score": 0.75}
        decision = router._make_decision("test_flow", state)
        assert decision == "ZERODAY_HUNT"


class TestScanAndRoute:
    """扫描 + 路由集成（使用 MockRedis）"""

    def test_scan_processes_new_flows(self, router, mock_redis, sample_flow_key):
        """新流量应被扫描并决策"""
        # 写入一个高危流量
        mock_redis.hset(sample_flow_key, "xgb_score", "0.95")
        mock_redis.hset(sample_flow_key, "anomaly_score", "0.6")
        mock_redis.hset(sample_flow_key, "suricata_alert", "false")

        router._scan_redis_keys()

        # 应该被标记为 BLOCK
        decision = mock_redis.hget(sample_flow_key, "decision")
        assert decision == "BLOCK"

    def test_scan_skips_already_decided(self, router, mock_redis, sample_flow_key):
        """已决策的流量不应重复处理"""
        mock_redis.hset(sample_flow_key, "xgb_score", "0.3")
        mock_redis.hset(sample_flow_key, "anomaly_score", "0.2")
        mock_redis.hset(sample_flow_key, "suricata_alert", "false")
        mock_redis.hset(sample_flow_key, "decision", "PASS")

        router._scan_redis_keys()

        # 决策不应改变
        assert mock_redis.hget(sample_flow_key, "decision") == "PASS"

    def test_llm_queue_populated(self, router, mock_redis):
        """ZERODAY_HUNT 决策应将任务入队"""
        flow_key = "10.0.0.1:1234-10.0.0.2:80-TCP"
        mock_redis.hset(flow_key, "xgb_score", "0.35")
        mock_redis.hset(flow_key, "anomaly_score", "0.88")
        mock_redis.hset(flow_key, "suricata_alert", "false")
        mock_redis.hset(flow_key, "features", '{"iat_mean": 0.01}')

        router._scan_redis_keys()

        # 检查 LLM 队列
        queue_len = mock_redis.llen("llm_task_queue")
        assert queue_len == 1

        task_json = mock_redis.lindex("llm_task_queue", 0)
        task = json.loads(task_json)
        assert task["flow_key"] == flow_key
        assert task["decision"] == "ZERODAY_HUNT"

    def test_pass_deletes_key(self, router, mock_redis):
        """PASS 决策应删除 Redis key（释放内存）"""
        flow_key = "10.0.0.1:5555-10.0.0.2:443-TCP"
        mock_redis.hset(flow_key, "xgb_score", "0.2")
        mock_redis.hset(flow_key, "anomaly_score", "0.3")
        mock_redis.hset(flow_key, "suricata_alert", "false")

        router._scan_redis_keys()

        # key 应该被删除
        assert mock_redis.exists(flow_key) == 0

    def test_stats_updated(self, router, mock_redis):
        """决策后统计应更新"""
        flow_key = "10.0.0.1:8888-10.0.0.2:80-TCP"
        mock_redis.hset(flow_key, "xgb_score", "0.95")
        mock_redis.hset(flow_key, "anomaly_score", "0.5")
        mock_redis.hset(flow_key, "suricata_alert", "false")

        router._scan_redis_keys()

        assert router.global_stats["total_flows"] == 1
        assert router.global_stats["blocked"] == 1
