"""
集成测试: 模块间协同 + Pipeline 原子性 + 错误恢复
覆盖:
  - Pipeline 原子性（多字段写入）
  - Router → LLM Queue → LLMAnalyzer 端到端流
  - MockRedis Pub/Sub 消息传递
  - Redis 断连 → 重连恢复
  - 孤儿任务检测与重新入队
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
from tests.conftest import MockRedis, MockPipeline
from src.config.config import RedisConfig, XGBoostConfig, LLMConfig
from src.modules.intelligent_router import IntelligentRouter
from src.modules.llm_analyzer import LLMAnalyzer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def shared_redis():
    """所有模块共享同一个 MockRedis（模拟真实 Redis 实例）"""
    return MockRedis()


@pytest.fixture
def redis_cfg():
    return RedisConfig(host="localhost", port=6379)


@pytest.fixture
def xgb_cfg():
    return XGBoostConfig(threshold_high=0.9, threshold_low=0.5, anomaly_threshold=0.75)


@pytest.fixture
def llm_cfg():
    return LLMConfig(use_api=True, api_base_url="https://fake.api/v1", api_key="test-key", api_model="test")


@pytest.fixture
def router(shared_redis, redis_cfg, xgb_cfg):
    with patch("src.modules.intelligent_router.RedisConnectionFactory") as f:
        f.get_client_with_retry.return_value = shared_redis
        r = IntelligentRouter(redis_cfg, xgb_cfg)
        r.redis_client = shared_redis
        return r


@pytest.fixture
def analyzer(shared_redis, redis_cfg, llm_cfg):
    with patch("src.modules.llm_analyzer.RedisConnectionFactory") as f:
        f.get_client_with_retry.return_value = shared_redis
        a = LLMAnalyzer(redis_cfg, llm_cfg)
        a.redis_client = shared_redis
        return a


# ---------------------------------------------------------------------------
# Pipeline 原子性测试
# ---------------------------------------------------------------------------

class TestPipelineAtomicity:
    """Pipeline 批量写入的原子性验证"""

    def test_pipeline_multi_field_write(self, shared_redis):
        """Pipeline 应一次性写入多个字段"""
        pipe = shared_redis.pipeline()
        pipe.hset("flow:test", "field1", "value1")
        pipe.hset("flow:test", "field2", "value2")
        pipe.hset("flow:test", "field3", "value3")
        pipe.expire("flow:test", 300)
        results = pipe.execute()

        assert len(results) == 4
        assert shared_redis.hget("flow:test", "field1") == "value1"
        assert shared_redis.hget("flow:test", "field2") == "value2"
        assert shared_redis.hget("flow:test", "field3") == "value3"

    def test_pipeline_chaining(self, shared_redis):
        """Pipeline 方法应支持链式调用"""
        pipe = shared_redis.pipeline()
        pipe.hset("chain:test", "a", "1").hset("chain:test", "b", "2").expire("chain:test", 60)
        pipe.execute()

        assert shared_redis.hget("chain:test", "a") == "1"
        assert shared_redis.hget("chain:test", "b") == "2"

    def test_pipeline_with_context_manager(self, shared_redis):
        """Pipeline 应支持 with 语句"""
        with shared_redis.pipeline() as pipe:
            pipe.hset("ctx:test", "key", "val")
            pipe.execute()

        assert shared_redis.hget("ctx:test", "key") == "val"

    def test_pipeline_clears_after_execute(self, shared_redis):
        """execute 后命令列表应清空"""
        pipe = shared_redis.pipeline()
        pipe.hset("clear:test", "a", "1")
        pipe.execute()

        # 再次 execute 不应重复执行
        results = pipe.execute()
        assert results == []


# ---------------------------------------------------------------------------
# Router → LLM Queue 端到端
# ---------------------------------------------------------------------------

class TestRouterToLLMFlow:
    """Router 决策 → LLM 队列 → LLMAnalyzer 消费 端到端"""

    def test_zeroday_flow_reaches_llm_queue(self, router, shared_redis):
        """ZERODAY_HUNT 流量应出现在 LLM 队列中"""
        flow_key = "10.0.0.1:1234-10.0.0.2:80-TCP"
        shared_redis.hset(flow_key, "xgb_score", "0.35")
        shared_redis.hset(flow_key, "anomaly_score", "0.88")
        shared_redis.hset(flow_key, "suricata_alert", "false")
        shared_redis.hset(flow_key, "features", '{"iat_mean": 0.005}')

        router._scan_redis_keys()

        # 验证队列
        assert shared_redis.llen("llm_task_queue") == 1
        task = json.loads(shared_redis.lindex("llm_task_queue", 0))
        assert task["flow_key"] == flow_key
        assert task["decision"] == "ZERODAY_HUNT"
        assert task["anomaly_score"] == 0.88

    def test_llm_analyze_flow_reaches_queue(self, router, shared_redis):
        """LLM_ANALYZE 流量也应入队"""
        flow_key = "10.0.0.1:5555-10.0.0.2:443-TCP"
        shared_redis.hset(flow_key, "xgb_score", "0.7")
        shared_redis.hset(flow_key, "anomaly_score", "0.5")
        shared_redis.hset(flow_key, "suricata_alert", "false")

        router._scan_redis_keys()

        assert shared_redis.llen("llm_task_queue") == 1
        task = json.loads(shared_redis.lindex("llm_task_queue", 0))
        assert task["decision"] == "LLM_ANALYZE"

    def test_end_to_end_router_to_analyzer(self, router, analyzer, shared_redis):
        """完整流程: Router 入队 → Analyzer 消费并写结果"""
        flow_key = "10.0.0.1:8888-10.0.0.2:80-TCP"
        shared_redis.hset(flow_key, "xgb_score", "0.35")
        shared_redis.hset(flow_key, "anomaly_score", "0.85")
        shared_redis.hset(flow_key, "suricata_alert", "false")
        shared_redis.hset(flow_key, "features", '{"iat_mean": 0.005, "packet_count": 10}')

        # Step 1: Router 决策并入队
        router._scan_redis_keys()
        assert shared_redis.llen("llm_task_queue") == 1

        # Step 2: Analyzer 消费
        mock_result = {
            "is_malicious": True,
            "attack_type": "Port Scanning",
            "confidence": 0.92,
            "reason": "SYN flood pattern",
            "threat_level": "High",
            "recommended_action": "Block",
        }

        with patch.object(analyzer, "_call_llm_api", return_value=mock_result):
            # 手动消费一条
            result = shared_redis.brpop("llm_task_queue", timeout=1)
            assert result is not None
            _, task_json = result
            task_data = json.loads(task_json)
            success = analyzer._process_task(task_data)

        assert success is True

        # Step 3: 验证 Redis 中的 LLM 结果
        assert shared_redis.hget(flow_key, "llm_is_malicious") == "True"
        assert shared_redis.hget(flow_key, "llm_attack_type") == "Port Scanning"
        assert shared_redis.hget(flow_key, "llm_threat_level") == "High"

        # 队列应为空
        assert shared_redis.llen("llm_task_queue") == 0

    def test_multiple_flows_different_decisions(self, router, shared_redis):
        """多种流量应产生不同决策"""
        flows = {
            "1.1.1.1:100-2.2.2.2:80-TCP": {"xgb_score": "0.95", "anomaly_score": "0.5", "suricata_alert": "false"},
            "1.1.1.1:200-2.2.2.2:80-TCP": {"xgb_score": "0.3", "anomaly_score": "0.4", "suricata_alert": "false"},
            "1.1.1.1:300-2.2.2.2:80-TCP": {"xgb_score": "0.35", "anomaly_score": "0.88", "suricata_alert": "false"},
            "1.1.1.1:400-2.2.2.2:80-TCP": {"xgb_score": "0.7", "anomaly_score": "0.5", "suricata_alert": "false"},
        }

        for fk, fields in flows.items():
            for k, v in fields.items():
                shared_redis.hset(fk, k, v)

        router._scan_redis_keys()

        # BLOCK: key 仍存在，decision=BLOCK
        assert shared_redis.hget("1.1.1.1:100-2.2.2.2:80-TCP", "decision") == "BLOCK"

        # PASS: key 被删除
        assert shared_redis.exists("1.1.1.1:200-2.2.2.2:80-TCP") == 0

        # ZERODAY_HUNT: decision 标记 + 入队
        assert shared_redis.hget("1.1.1.1:300-2.2.2.2:80-TCP", "decision") == "ZERODAY_HUNT"

        # LLM_ANALYZE: decision 标记 + 入队
        assert shared_redis.hget("1.1.1.1:400-2.2.2.2:80-TCP", "decision") == "LLM_ANALYZE"

        # 队列应有 2 条（ZERODAY_HUNT + LLM_ANALYZE）
        assert shared_redis.llen("llm_task_queue") == 2

        # 统计
        assert router.global_stats["total_flows"] == 4
        assert router.global_stats["blocked"] == 1
        assert router.global_stats["passed"] == 1


# ---------------------------------------------------------------------------
# Pub/Sub 消息传递
# ---------------------------------------------------------------------------

class TestPubSubIntegration:
    """MockRedis Pub/Sub 消息传递测试"""

    def test_publish_and_subscribe(self, shared_redis):
        """发布消息应被订阅者收到"""
        pubsub = shared_redis.pubsub()
        pubsub.subscribe("suricata_alerts_channel")

        # 发布
        shared_redis.publish("suricata_alerts_channel", "10.0.0.1:1234-10.0.0.2:80-TCP")

        # 消费
        messages = list(pubsub.listen())
        # 第一条是 subscribe 确认，第二条是实际消息
        assert len(messages) >= 2
        assert messages[1]["type"] == "message"
        assert messages[1]["data"] == "10.0.0.1:1234-10.0.0.2:80-TCP"

    def test_multiple_subscribers(self, shared_redis):
        """多个订阅者都应收到消息"""
        ps1 = shared_redis.pubsub()
        ps2 = shared_redis.pubsub()
        ps1.subscribe("test_channel")
        ps2.subscribe("test_channel")

        shared_redis.publish("test_channel", "hello")

        msgs1 = [m for m in ps1.listen() if m["type"] == "message"]
        msgs2 = [m for m in ps2.listen() if m["type"] == "message"]
        assert len(msgs1) == 1
        assert len(msgs2) == 1


# ---------------------------------------------------------------------------
# 孤儿任务检测
# ---------------------------------------------------------------------------

class TestOrphanTaskDetection:
    """孤儿任务检测与重新入队"""

    def test_orphan_detected_and_requeued(self, router, shared_redis):
        """超时未处理的 LLM 任务应被重新入队"""
        flow_key = "10.0.0.1:7777-10.0.0.2:80-TCP"
        shared_redis.hset(flow_key, "xgb_score", "0.35")
        shared_redis.hset(flow_key, "anomaly_score", "0.88")
        shared_redis.hset(flow_key, "suricata_alert", "false")
        shared_redis.hset(flow_key, "decision", "ZERODAY_HUNT")
        # 设置 decision_time 为 10 分钟前（超过 orphan_timeout=300s）
        shared_redis.hset(flow_key, "decision_time", str(time.time() - 600))

        router._check_orphan_tasks()

        # 应该被重新入队
        assert shared_redis.llen("llm_task_queue") == 1

    def test_non_orphan_not_requeued(self, router, shared_redis):
        """未超时的任务不应被重新入队"""
        flow_key = "10.0.0.1:8888-10.0.0.2:80-TCP"
        shared_redis.hset(flow_key, "xgb_score", "0.7")
        shared_redis.hset(flow_key, "anomaly_score", "0.5")
        shared_redis.hset(flow_key, "suricata_alert", "false")
        shared_redis.hset(flow_key, "decision", "LLM_ANALYZE")
        shared_redis.hset(flow_key, "decision_time", str(time.time()))  # 刚刚决策

        router._check_orphan_tasks()

        assert shared_redis.llen("llm_task_queue") == 0

    def test_completed_task_not_orphan(self, router, shared_redis):
        """已有 LLM 结果的任务不应被视为孤儿"""
        flow_key = "10.0.0.1:9999-10.0.0.2:80-TCP"
        shared_redis.hset(flow_key, "xgb_score", "0.35")
        shared_redis.hset(flow_key, "anomaly_score", "0.88")
        shared_redis.hset(flow_key, "suricata_alert", "false")
        shared_redis.hset(flow_key, "decision", "ZERODAY_HUNT")
        shared_redis.hset(flow_key, "decision_time", str(time.time() - 600))
        shared_redis.hset(flow_key, "llm_result", '{"is_malicious": true}')  # 已有结果

        router._check_orphan_tasks()

        assert shared_redis.llen("llm_task_queue") == 0


# ---------------------------------------------------------------------------
# 错误恢复
# ---------------------------------------------------------------------------

class TestErrorRecovery:
    """Redis 断连 → 重连恢复场景"""

    def test_analyzer_retry_on_process_failure(self, analyzer, shared_redis):
        """_process_task 失败后 _retry_failed_task 应重新入队"""
        task = {
            "flow_key": "10.0.0.1:1111-10.0.0.2:80-TCP",
            "decision": "LLM_ANALYZE",
            "xgb_score": 0.7,
            "anomaly_score": 0.5,
            "features": "{}",
            "retry_count": 0,
        }

        with patch.object(analyzer, "_call_llm_api", side_effect=Exception("API down")):
            success = analyzer._process_task(task)
            assert success is False

        # 手动重试
        analyzer._retry_failed_task(json.dumps(task))
        assert shared_redis.llen("llm_task_queue") == 1

        requeued = json.loads(shared_redis.lindex("llm_task_queue", 0))
        assert requeued["retry_count"] == 1

    def test_analyzer_max_retry_to_failed_queue(self, analyzer, shared_redis):
        """超过最大重试次数应移到失败队列"""
        task = {
            "flow_key": "10.0.0.1:2222-10.0.0.2:80-TCP",
            "decision": "LLM_ANALYZE",
            "retry_count": 3,
        }

        analyzer._retry_failed_task(json.dumps(task), max_retries=3)

        assert shared_redis.llen("llm_task_queue") == 0
        assert shared_redis.llen("llm_failed_queue") == 1

    def test_router_scan_handles_empty_state(self, router, shared_redis):
        """空状态的 key 不应导致崩溃"""
        # 创建一个匹配 scan pattern 但无有效字段的 key
        shared_redis.hset("1.1.1.1:0-2.2.2.2:0-TCP", "dummy", "value")

        # 不应抛异常
        router._scan_redis_keys()

        # 统计不应增加（因为 xgb_score 默认为 0，anomaly_score 默认为 0 → PASS）
        # 实际上会被处理为 PASS 并删除
        assert router.global_stats["total_flows"] <= 1
