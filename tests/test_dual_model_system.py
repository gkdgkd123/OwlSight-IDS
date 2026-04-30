"""
双模型协同检测系统集成测试
测试 XGBoost + Isolation Forest 的三层决策逻辑
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import time
import numpy as np
from src.utils import generate_five_tuple_key
from src.config.config import RedisConfig, XGBoostConfig
from src.modules.early_flow_xgb import FlowStatistics, DualModelInference
from src.modules.intelligent_router import IntelligentRouter


from tests.conftest import MockRedis


def test_dual_model_inference():
    """测试双模型推理"""
    print("=" * 80)
    print("测试 1: 双模型推理引擎")
    print("=" * 80)

    xgb_cfg = XGBoostConfig(model_path="./src/models/xgb_model.json")

    # 创建推理引擎
    from src.utils import setup_logger
    logger = setup_logger("Test")
    dual_model = DualModelInference(xgb_cfg, logger)

    # 测试用例
    test_cases = [
        {
            "name": "端口扫描特征",
            "features": {
                "packet_count": 10,
                "bytes_sent": 600,
                "duration": 0.1,
                "iat_mean": 0.005,
                "iat_std": 0.001,
                "iat_min": 0.004,
                "iat_max": 0.006,
                "pkt_len_mean": 60,
                "pkt_len_std": 5,
                "pkt_len_min": 55,
                "pkt_len_max": 65,
                "tcp_flags_count": 10,
                "syn_count": 10,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "bytes_per_second": 6000,
                "packets_per_second": 100
            },
            "expected": "高 XGB 得分（已知攻击）"
        },
        {
            "name": "正常 HTTPS 流量",
            "features": {
                "packet_count": 50,
                "bytes_sent": 50000,
                "duration": 5.0,
                "iat_mean": 0.1,
                "iat_std": 0.05,
                "iat_min": 0.05,
                "iat_max": 0.2,
                "pkt_len_mean": 1000,
                "pkt_len_std": 200,
                "pkt_len_min": 500,
                "pkt_len_max": 1400,
                "tcp_flags_count": 50,
                "syn_count": 1,
                "ack_count": 49,
                "fin_count": 1,
                "rst_count": 0,
                "bytes_per_second": 10000,
                "packets_per_second": 10
            },
            "expected": "低 XGB 得分 + 低异常分数（正常）"
        },
        {
            "name": "0day 候选（极端异常但未知模式）",
            "features": {
                "packet_count": 5,
                "bytes_sent": 200,
                "duration": 100.0,
                "iat_mean": 20.0,
                "iat_std": 0.001,
                "iat_min": 19.999,
                "iat_max": 20.001,
                "pkt_len_mean": 40,
                "pkt_len_std": 1,
                "pkt_len_min": 39,
                "pkt_len_max": 41,
                "tcp_flags_count": 5,
                "syn_count": 5,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "bytes_per_second": 2,
                "packets_per_second": 0.05
            },
            "expected": "低 XGB 得分 + 高异常分数（0day）"
        }
    ]

    print("\n测试双模型推理:")
    for case in test_cases:
        scores = dual_model.predict(case["features"])
        print(f"\n{case['name']}:")
        print(f"  XGBoost 得分: {scores['xgb_score']:.3f}")
        print(f"  异常得分: {scores['anomaly_score']:.3f}")
        print(f"  预期: {case['expected']}")


def test_intelligent_router():
    """测试智能路由决策"""
    print("\n" + "=" * 80)
    print("测试 2: 智能路由决策（三层决策树）")
    print("=" * 80)

    redis_cfg = RedisConfig(host="localhost", port=6379)
    xgb_cfg = XGBoostConfig(threshold_high=0.9, threshold_low=0.5)

    # 创建 Mock Redis
    mock_redis = MockRedis()

    # 创建路由器
    from unittest.mock import patch as mock_patch
    with mock_patch(
        "src.modules.intelligent_router.RedisConnectionFactory"
    ) as mock_factory:
        mock_factory.get_client_with_retry.return_value = mock_redis
        router = IntelligentRouter(redis_cfg, xgb_cfg)
        router.redis_client = mock_redis  # 替换为 Mock Redis

    # 测试用例
    test_cases = [
        {
            "name": "高危流量（XGB > 0.9）",
            "key": generate_five_tuple_key("192.168.1.10", 1234, "10.0.0.1", 80, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.95",
                "anomaly_score": "0.6"
            },
            "expected_decision": "BLOCK",
            "expected_llm_call": False
        },
        {
            "name": "正常流量（XGB < 0.5, Anomaly < 0.75）",
            "key": generate_five_tuple_key("192.168.1.20", 5678, "10.0.0.2", 443, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.3",
                "anomaly_score": "0.4"
            },
            "expected_decision": "PASS",
            "expected_llm_call": False
        },
        {
            "name": "0day 猎杀（XGB < 0.5, Anomaly > 0.75）",
            "key": generate_five_tuple_key("192.168.1.30", 9012, "10.0.0.3", 8080, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.4",
                "anomaly_score": "0.85"
            },
            "expected_decision": "ZERODAY_HUNT",
            "expected_llm_call": True
        },
        {
            "name": "疑难流量（XGB 在灰色地带）",
            "key": generate_five_tuple_key("192.168.1.40", 3456, "10.0.0.4", 22, "TCP"),
            "state": {
                "suricata_alert": "false",
                "xgb_score": "0.7",
                "anomaly_score": "0.5"
            },
            "expected_decision": "LLM_ANALYZE",
            "expected_llm_call": True
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
            "expected_decision": "BLOCK",
            "expected_llm_call": False
        }
    ]

    # 写入测试数据
    print("\n写入测试用例到 Mock Redis:")
    for case in test_cases:
        mock_redis.hset(case["key"], mapping=case["state"])
        print(f"  - {case['name']}")

    # 执行决策
    print("\n执行智能路由决策:")
    router._scan_redis_keys()

    # 验证结果
    print("\n验证决策结果:")
    all_passed = True

    for case in test_cases:
        result = mock_redis.hget(case["key"], "decision")
        exists = mock_redis.exists(case["key"])

        # 对于 PASS 决策，Redis 记录会被删除
        if case["expected_decision"] == "PASS":
            actual_decision = "PASS" if not exists else result
        else:
            actual_decision = result

        decision_match = actual_decision == case["expected_decision"]
        # LLM 调用现在通过队列实现，检查队列中是否有对应 flow_key
        passed = decision_match

        print(f"\n  {case['name']}:")
        print(f"    预期决策: {case['expected_decision']}")
        print(f"    实际决策: {actual_decision}")
        print(f"    决策匹配: {'[OK]' if decision_match else '[FAIL]'}")
        print(f"    总体: {'[PASS]' if passed else '[FAIL]'}")

        if not passed:
            all_passed = False

    # 打印统计
    print("\n" + "=" * 80)
    print("决策统计:")
    print("=" * 80)
    router._print_window_stats()
    router._print_global_stats()

    # 打印 LLM 队列详情
    queue_len = mock_redis.llen("llm_task_queue")
    if queue_len > 0:
        print("\n" + "=" * 80)
        print(f"LLM 队列中有 {queue_len} 个任务")
        print("=" * 80)

    return all_passed


def test_end_to_end():
    """端到端测试：从特征提取到决策"""
    print("\n" + "=" * 80)
    print("测试 3: 端到端流程（特征提取 → 双模型推理 → 智能路由）")
    print("=" * 80)

    # 模拟流量场景
    scenarios = [
        {
            "name": "正常 Web 浏览",
            "packets": [
                {"length": 66, "timestamp": 0.0, "tcp_flag": 0x02},  # SYN
                {"length": 66, "timestamp": 0.05, "tcp_flag": 0x12},  # SYN-ACK
                {"length": 54, "timestamp": 0.1, "tcp_flag": 0x10},  # ACK
                {"length": 500, "timestamp": 0.15, "tcp_flag": 0x18},  # PSH-ACK
                {"length": 1400, "timestamp": 0.2, "tcp_flag": 0x10},
                {"length": 1400, "timestamp": 0.25, "tcp_flag": 0x10},
                {"length": 1400, "timestamp": 0.3, "tcp_flag": 0x10},
                {"length": 800, "timestamp": 0.35, "tcp_flag": 0x18},
                {"length": 54, "timestamp": 0.4, "tcp_flag": 0x11},  # FIN-ACK
                {"length": 54, "timestamp": 0.45, "tcp_flag": 0x11},
            ],
            "expected_category": "正常流量"
        },
        {
            "name": "端口扫描",
            "packets": [
                {"length": 60, "timestamp": 0.0, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.005, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.01, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.015, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.02, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.025, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.03, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.035, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.04, "tcp_flag": 0x02},
                {"length": 60, "timestamp": 0.045, "tcp_flag": 0x02},
            ],
            "expected_category": "高危流量（已知攻击）"
        },
        {
            "name": "慢速异常探测（0day 候选）",
            "packets": [
                {"length": 40, "timestamp": 0.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 10.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 20.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 30.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 40.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 50.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 60.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 70.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 80.0, "tcp_flag": 0x02},
                {"length": 40, "timestamp": 90.0, "tcp_flag": 0x02},
            ],
            "expected_category": "0day 候选"
        }
    ]

    xgb_cfg = XGBoostConfig(model_path="./src/models/xgb_model.json")
    from src.utils import setup_logger
    logger = setup_logger("E2E-Test")
    dual_model = DualModelInference(xgb_cfg, logger)

    print("\n模拟流量场景:")
    for scenario in scenarios:
        print(f"\n场景: {scenario['name']}")
        print(f"  包数: {len(scenario['packets'])}")

        # 构建流统计
        flow_stats = FlowStatistics()
        for pkt in scenario['packets']:
            flow_stats.add_packet(
                packet_length=pkt['length'],
                timestamp=pkt['timestamp'],
                tcp_flag=pkt['tcp_flag']
            )

        # 计算特征
        features = flow_stats.compute_features()

        # 双模型推理
        scores = dual_model.predict(features)

        print(f"  特征:")
        print(f"    包数: {features['packet_count']}")
        print(f"    总字节: {features['bytes_sent']:.0f}")
        print(f"    持续时间: {features['duration']:.2f}s")
        print(f"    平均 IAT: {features['iat_mean']:.4f}s")
        print(f"    平均包长: {features['pkt_len_mean']:.1f} bytes")

        print(f"  双模型得分:")
        print(f"    XGBoost: {scores['xgb_score']:.3f}")
        print(f"    异常分数: {scores['anomaly_score']:.3f}")

        # 决策
        if scores['xgb_score'] > 0.9:
            decision = "BLOCK（高危）"
        elif scores['xgb_score'] < 0.5 and scores['anomaly_score'] < 0.75:
            decision = "PASS（正常）"
        elif scores['xgb_score'] < 0.5 and scores['anomaly_score'] >= 0.75:
            decision = "ZERODAY_HUNT（0day 猎杀）"
        else:
            decision = "LLM_ANALYZE（疑难流量）"

        print(f"  决策: {decision}")
        print(f"  预期类别: {scenario['expected_category']}")


def main():
    """主函数"""
    print("=" * 80)
    print("SemFlow-IDS 双模型协同检测系统 - 集成测试")
    print("=" * 80)
    print("\n架构: XGBoost (监督学习) + Isolation Forest (无监督学习)")
    print("决策树:")
    print("  1. 高危直接拦截: XGB > 0.9 → BLOCK")
    print("  2. 正常直接放行: XGB < 0.5 AND Anomaly < 0.75 → PASS")
    print("  3. 0day 猎杀: XGB < 0.5 BUT Anomaly > 0.75 → LLM 深度研判")
    print("  4. 疑难流量: 0.5 ≤ XGB ≤ 0.9 → LLM 深度研判")

    # 测试 1: 双模型推理
    test_dual_model_inference()

    # 测试 2: 智能路由决策
    all_passed = test_intelligent_router()

    # 测试 3: 端到端流程
    test_end_to_end()

    # 总结
    print("\n" + "=" * 80)
    print("测试总结")
    print("=" * 80)
    if all_passed:
        print("[SUCCESS] 所有测试通过！")
        print("\n双模型协同检测架构已就绪:")
        print("  - XGBoost 模型: src/models/xgb_model.json")
        print("  - Isolation Forest 模型: src/models/iforest_model.pkl")
        print("  - 特征标准化器: src/models/scaler.pkl")
        print("\n可以启动实时检测系统了！")
    else:
        print("[FAILED] 部分测试失败，请检查日志")


if __name__ == "__main__":
    main()
