"""
单元测试: LLMAnalyzer — sanitize_features, build_prompt, process_task, rate_limit, retry
覆盖: 特征清洗、Prompt 构建、任务处理（Mock LLM）、速率控制、重试逻辑
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
from realtime_ids.modules.llm_analyzer import LLMAnalyzer
from realtime_ids.config.config import RedisConfig, LLMConfig


@pytest.fixture
def analyzer(mock_redis, llm_config):
    """创建使用 MockRedis 的 LLMAnalyzer（API 模式）"""
    redis_config = RedisConfig(host="localhost", port=6379)
    with patch(
        "realtime_ids.modules.llm_analyzer.RedisConnectionFactory"
    ) as mock_factory:
        mock_factory.get_client_with_retry.return_value = mock_redis
        a = LLMAnalyzer(redis_config, llm_config)
        a.redis_client = mock_redis
        return a


class TestSanitizeFeatures:
    """_sanitize_features 特征清洗测试"""

    def test_valid_json(self, analyzer):
        """正常 JSON 应正确解析"""
        features_json = json.dumps({
            "iat_mean": 0.005,
            "packet_count": 10,
            "bytes_sent": 640.0,
        })
        result = analyzer._sanitize_features(features_json)
        assert result["iat_mean"] == 0.005
        assert result["packet_count"] == 10
        assert result["bytes_sent"] == 640.0

    def test_string_values_sanitized(self, analyzer):
        """字符串值应被 sanitize_text 处理"""
        features_json = json.dumps({
            "note": "normal text",
            "count": 5,
        })
        result = analyzer._sanitize_features(features_json)
        assert result["note"] == "normal text"
        assert result["count"] == 5

    def test_invalid_json_returns_empty(self, analyzer):
        """无效 JSON 应返回空字典"""
        result = analyzer._sanitize_features("not valid json{{{")
        assert result == {}

    def test_empty_json(self, analyzer):
        """空 JSON 对象"""
        result = analyzer._sanitize_features("{}")
        assert result == {}

    def test_mixed_types_filter(self, analyzer):
        """非 int/float/str 类型应被过滤"""
        features_json = json.dumps({
            "count": 10,
            "name": "test",
            "nested": {"a": 1},  # dict — 应被忽略
            "items": [1, 2, 3],  # list — 应被忽略
        })
        result = analyzer._sanitize_features(features_json)
        assert "count" in result
        assert "name" in result
        assert "nested" not in result
        assert "items" not in result

    def test_long_string_truncated(self, analyzer):
        """超长字符串应被截断到 200 字符"""
        long_str = "x" * 500
        features_json = json.dumps({"payload": long_str})
        result = analyzer._sanitize_features(features_json)
        assert len(result["payload"]) == 200


class TestBuildPrompt:
    """_build_prompt Prompt 构建测试"""

    def test_zeroday_hunt_prompt(self, analyzer):
        """ZERODAY_HUNT 应包含 0day 相关上下文"""
        prompt = analyzer._build_prompt(
            "流量特征正常", xgb_score=0.35, anomaly_score=0.88, decision_type="ZERODAY_HUNT"
        )
        assert "0day" in prompt or "未知变种" in prompt
        assert "0.35" in prompt  # XGB 分数
        assert "0.88" in prompt  # Anomaly 分数
        assert "JSON" in prompt

    def test_llm_analyze_prompt(self, analyzer):
        """LLM_ANALYZE 应包含灰色地带上下文"""
        prompt = analyzer._build_prompt(
            "流量特征正常", xgb_score=0.7, anomaly_score=0.5, decision_type="LLM_ANALYZE"
        )
        assert "灰色地带" in prompt
        assert "0.7" in prompt
        assert "JSON" in prompt

    def test_prompt_includes_features_text(self, analyzer):
        """Prompt 应包含特征文本"""
        features_text = "数据包到达时间间隔极短（平均 5.00ms），疑似快速扫描"
        prompt = analyzer._build_prompt(
            features_text, xgb_score=0.5, anomaly_score=0.5, decision_type="LLM_ANALYZE"
        )
        assert features_text in prompt


class TestFeaturesToNaturalLanguage:
    """_features_to_natural_language 特征转自然语言测试"""

    def test_fast_scan_detection(self, analyzer):
        """IAT 极短应识别为快速扫描"""
        features = {"iat_mean": 0.005, "packet_count": 10}
        text = analyzer._features_to_natural_language(features)
        assert "极短" in text or "快速扫描" in text

    def test_slow_scan_detection(self, analyzer):
        """IAT 很长应识别为慢速扫描"""
        features = {"iat_mean": 10.0}
        text = analyzer._features_to_natural_language(features)
        assert "很长" in text or "慢速" in text

    def test_regular_pattern_detection(self, analyzer):
        """IAT 标准差极小应识别为机器通信"""
        features = {"iat_mean": 0.1, "iat_std": 0.0005, "packet_count": 10}
        text = analyzer._features_to_natural_language(features)
        assert "规律" in text or "机器" in text

    def test_small_packet_detection(self, analyzer):
        """小包应识别为探测流量"""
        features = {"pkt_len_mean": 50}
        text = analyzer._features_to_natural_language(features)
        assert "小" in text or "探测" in text

    def test_large_data_transfer(self, analyzer):
        """大字节数应识别为数据外泄风险"""
        features = {"bytes_sent": 100000}
        text = analyzer._features_to_natural_language(features)
        assert "大" in text or "外泄" in text

    def test_syn_flood_detection(self, analyzer):
        """全 SYN 包应识别为端口扫描"""
        features = {"syn_count": 10, "packet_count": 10}
        text = analyzer._features_to_natural_language(features)
        assert "SYN" in text or "扫描" in text

    def test_high_rate_detection(self, analyzer):
        """高包速率应识别为 DoS"""
        features = {"packets_per_second": 500}
        text = analyzer._features_to_natural_language(features)
        assert "高" in text or "DoS" in text

    def test_normal_traffic(self, analyzer):
        """正常特征应返回正常"""
        features = {"iat_mean": 0.5, "pkt_len_mean": 500, "bytes_sent": 1000, "packet_count": 5}
        text = analyzer._features_to_natural_language(features)
        # 应该有一些描述（至少 packet_count > 0 会触发）
        assert isinstance(text, str)
        assert len(text) > 0


class TestDummyResult:
    """_dummy_result 测试"""

    def test_structure(self, analyzer):
        result = analyzer._dummy_result("test reason")
        assert result["is_malicious"] is False
        assert result["attack_type"] == "Unknown"
        assert result["confidence"] == 0.5
        assert result["reason"] == "test reason"
        assert result["threat_level"] == "Unknown"
        assert result["recommended_action"] == "Monitor"


class TestProcessTask:
    """_process_task 任务处理测试（Mock LLM API）"""

    def test_successful_processing(self, analyzer, mock_redis):
        """成功处理任务应写入 Redis 并更新统计"""
        mock_llm_result = {
            "is_malicious": True,
            "attack_type": "Port Scanning",
            "confidence": 0.92,
            "reason": "SYN flood detected",
            "threat_level": "High",
            "recommended_action": "Block",
        }

        with patch.object(analyzer, "_call_llm_api", return_value=mock_llm_result):
            task = {
                "flow_key": "10.0.0.1:1234-10.0.0.2:80-TCP",
                "decision": "ZERODAY_HUNT",
                "xgb_score": 0.35,
                "anomaly_score": 0.88,
                "features": json.dumps({"iat_mean": 0.005, "packet_count": 10}),
            }
            success = analyzer._process_task(task)

        assert success is True

        # 检查 Redis 写入
        flow_key = "10.0.0.1:1234-10.0.0.2:80-TCP"
        assert mock_redis.hget(flow_key, "llm_is_malicious") == "True"
        assert mock_redis.hget(flow_key, "llm_attack_type") == "Port Scanning"
        assert mock_redis.hget(flow_key, "llm_threat_level") == "High"

        # 检查统计
        assert analyzer.stats["total_processed"] == 1
        assert analyzer.stats["success"] == 1
        assert analyzer.stats["malicious_detected"] == 1

    def test_benign_detection(self, analyzer, mock_redis):
        """正常流量应更新 benign 统计"""
        mock_result = {
            "is_malicious": False,
            "attack_type": "Benign Traffic",
            "confidence": 0.85,
            "reason": "Normal traffic",
            "threat_level": "None",
            "recommended_action": "Allow",
        }

        with patch.object(analyzer, "_call_llm_api", return_value=mock_result):
            task = {
                "flow_key": "10.0.0.1:5555-10.0.0.2:443-TCP",
                "decision": "LLM_ANALYZE",
                "xgb_score": 0.6,
                "anomaly_score": 0.3,
                "features": "{}",
            }
            success = analyzer._process_task(task)

        assert success is True
        assert analyzer.stats["benign_detected"] == 1

    def test_llm_api_failure(self, analyzer, mock_redis):
        """LLM API 失败应返回 False 并更新 failed 统计"""
        with patch.object(analyzer, "_call_llm_api", side_effect=Exception("API timeout")):
            task = {
                "flow_key": "10.0.0.1:9999-10.0.0.2:80-TCP",
                "decision": "LLM_ANALYZE",
                "xgb_score": 0.7,
                "anomaly_score": 0.5,
                "features": "{}",
            }
            success = analyzer._process_task(task)

        assert success is False
        assert analyzer.stats["failed"] == 1


class TestRetryFailedTask:
    """_retry_failed_task 重试逻辑测试"""

    def test_retry_requeues(self, analyzer, mock_redis):
        """未超限的任务应重新入队"""
        task = {"flow_key": "test-flow", "retry_count": 0}
        analyzer._retry_failed_task(json.dumps(task))

        # 应该在主队列中
        assert mock_redis.llen("llm_task_queue") == 1
        requeued = json.loads(mock_redis.lindex("llm_task_queue", 0))
        assert requeued["retry_count"] == 1

    def test_retry_exceeds_max(self, analyzer, mock_redis):
        """超过最大重试次数应移到失败队列"""
        task = {"flow_key": "test-flow", "retry_count": 3}
        analyzer._retry_failed_task(json.dumps(task), max_retries=3)

        # 应该在失败队列中，不在主队列
        assert mock_redis.llen("llm_task_queue") == 0
        assert mock_redis.llen("llm_failed_queue") == 1

    def test_retry_increments_count(self, analyzer, mock_redis):
        """重试应递增 retry_count"""
        task = {"flow_key": "test-flow", "retry_count": 1}
        analyzer._retry_failed_task(json.dumps(task))

        requeued = json.loads(mock_redis.lindex("llm_task_queue", 0))
        assert requeued["retry_count"] == 2
        assert "last_error_time" in requeued


class TestRateLimit:
    """_wait_for_rate_limit 速率控制测试"""

    def test_under_limit_no_wait(self, analyzer):
        """未达限制不应等待"""
        start = time.time()
        analyzer._wait_for_rate_limit()
        elapsed = time.time() - start
        assert elapsed < 0.1

    def test_timestamps_recorded(self, analyzer):
        """每次调用应记录时间戳"""
        analyzer._wait_for_rate_limit()
        assert len(analyzer.request_timestamps) == 1
        analyzer._wait_for_rate_limit()
        assert len(analyzer.request_timestamps) == 2


class TestShutdown:
    """优雅停机测试"""

    def test_request_shutdown(self, analyzer):
        """request_shutdown 应设置 shutdown_event"""
        assert not analyzer.shutdown_event.is_set()
        analyzer.request_shutdown()
        assert analyzer.shutdown_event.is_set()
        assert analyzer.running is False

    def test_stop_closes_redis(self, analyzer, mock_redis):
        """stop 应关闭 Redis 连接"""
        analyzer.running = True
        with patch.object(mock_redis, "close") as mock_close:
            analyzer.stop()
            mock_close.assert_called_once()
        assert analyzer.running is False


class TestQueueHealth:
    """_check_queue_health 队列健康检查测试"""

    def test_empty_queue(self, analyzer, mock_redis):
        """空队列应返回 (0, 0)"""
        queue_len, failed_len = analyzer._check_queue_health()
        assert queue_len == 0
        assert failed_len == 0

    def test_queue_with_items(self, analyzer, mock_redis):
        """有任务的队列应返回正确长度"""
        for i in range(5):
            mock_redis.lpush("llm_task_queue", f"task_{i}")
        queue_len, failed_len = analyzer._check_queue_health()
        assert queue_len == 5
        assert failed_len == 0
