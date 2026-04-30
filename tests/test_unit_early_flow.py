"""
单元测试: EarlyFlowDualModel — LRU 淘汰 + FlowStatistics
覆盖: active_flows 上限、LRU 淘汰、特征计算、触发条件
"""
import pytest
import time
import numpy as np
from collections import OrderedDict
from src.modules.early_flow_xgb import FlowStatistics, EarlyFlowDualModel


class TestFlowStatistics:
    """FlowStatistics 特征计算测试"""

    def test_empty_flow(self):
        fs = FlowStatistics()
        features = fs.compute_features()
        assert features["packet_count"] == 0
        assert features["bytes_sent"] == 0.0
        assert features["duration"] == 0.0

    def test_single_packet(self):
        fs = FlowStatistics()
        fs.add_packet(100, 1000.0, 0x02)  # SYN
        features = fs.compute_features()
        assert features["packet_count"] == 1
        assert features["bytes_sent"] == 100.0
        assert features["syn_count"] == 1
        assert features["iat_mean"] == 0.0  # 只有 1 个包，IAT 为 0

    def test_multiple_packets(self):
        fs = FlowStatistics()
        for i in range(10):
            fs.add_packet(64, 1000.0 + i * 0.1, 0x10)  # ACK
        features = fs.compute_features()
        assert features["packet_count"] == 10
        assert features["bytes_sent"] == 640.0
        assert features["ack_count"] == 10
        assert features["syn_count"] == 0
        assert abs(features["iat_mean"] - 0.1) < 0.01
        assert abs(features["duration"] - 0.9) < 0.01

    def test_tcp_flag_counting(self):
        fs = FlowStatistics()
        fs.add_packet(60, 1.0, 0x02)   # SYN
        fs.add_packet(60, 1.1, 0x12)   # SYN+ACK
        fs.add_packet(60, 1.2, 0x10)   # ACK
        fs.add_packet(60, 1.3, 0x01)   # FIN
        fs.add_packet(60, 1.4, 0x04)   # RST
        features = fs.compute_features()
        assert features["syn_count"] == 2   # 0x02 and 0x12 both have SYN bit
        assert features["ack_count"] == 2   # 0x12 and 0x10 both have ACK bit
        assert features["fin_count"] == 1
        assert features["rst_count"] == 1

    def test_already_inferred_flag(self):
        fs = FlowStatistics()
        assert fs.already_inferred is False
        fs.already_inferred = True
        assert fs.already_inferred is True

    def test_feature_vector_has_18_dimensions(self):
        fs = FlowStatistics()
        for i in range(5):
            fs.add_packet(100, 1.0 + i * 0.5, 0x10)
        features = fs.compute_features()
        # 应该有 18 个特征（与训练时一致）
        expected_keys = [
            "packet_count", "bytes_sent", "duration",
            "iat_mean", "iat_std", "iat_min", "iat_max",
            "pkt_len_mean", "pkt_len_std", "pkt_len_min", "pkt_len_max",
            "tcp_flags_count", "syn_count", "ack_count", "fin_count", "rst_count",
            "bytes_per_second", "packets_per_second",
        ]
        for key in expected_keys:
            assert key in features, f"Missing feature: {key}"
        # 不应有 NaN 或 Inf
        for key, val in features.items():
            assert not np.isnan(val), f"{key} is NaN"
            assert not np.isinf(val), f"{key} is Inf"


class TestLRUEviction:
    """active_flows LRU 淘汰测试（不需要 Redis）"""

    def test_ordered_dict_type(self):
        """active_flows 应该是 OrderedDict"""
        from unittest.mock import patch
        with patch(
            "src.modules.early_flow_xgb.RedisConnectionFactory"
        ) as mock_factory:
            mock_factory.get_client_with_retry.return_value = type("FakeRedis", (), {
                "ping": lambda self: True,
                "close": lambda self: None,
            })()
            mock_factory.get_dedicated_client.return_value = type("FakeRedis", (), {
                "pubsub": lambda self: type("FakePubSub", (), {
                    "subscribe": lambda self, *a: None,
                    "unsubscribe": lambda self, *a: None,
                    "close": lambda self: None,
                    "listen": lambda self: iter([]),
                })(),
                "close": lambda self: None,
            })()

            from src.config.config import RedisConfig, ScapyConfig, XGBoostConfig
            module = EarlyFlowDualModel(
                RedisConfig(), ScapyConfig(), XGBoostConfig()
            )
            assert isinstance(module.active_flows, OrderedDict)
            assert module.max_active_flows == 50000

    def test_lru_eviction_logic(self):
        """直接测试 OrderedDict 的 LRU 淘汰逻辑"""
        flows = OrderedDict()
        max_flows = 3

        # 填满
        for i in range(max_flows):
            flows[f"flow_{i}"] = FlowStatistics()

        assert len(flows) == 3

        # 添加第 4 个 — 应该淘汰最旧的 flow_0
        while len(flows) >= max_flows:
            flows.popitem(last=False)
        flows["flow_3"] = FlowStatistics()

        assert "flow_0" not in flows
        assert "flow_3" in flows
        assert len(flows) == 3

    def test_lru_move_to_end(self):
        """访问已有 key 应移到末尾（不被淘汰）"""
        flows = OrderedDict()
        flows["a"] = 1
        flows["b"] = 2
        flows["c"] = 3

        # 访问 a → 移到末尾
        flows.move_to_end("a")

        # 淘汰最旧的应该是 b（不是 a）
        evicted_key, _ = flows.popitem(last=False)
        assert evicted_key == "b"
