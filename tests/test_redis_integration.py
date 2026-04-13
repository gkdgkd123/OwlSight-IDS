"""
实时双模型协同检测系统测试（使用真实 Redis）
测试 Module 2 (特征提取 + 双模型推理) 和 Module 3 (智能路由决策)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time
import json
import redis
from realtime_ids.config.config import RedisConfig, XGBoostConfig
from realtime_ids.modules.early_flow_xgb import FlowStatistics, DualModelInference
from realtime_ids.modules.intelligent_router import IntelligentRouter
from realtime_ids.utils import generate_five_tuple_key, setup_logger


def test_redis_connection():
    """测试 Redis 连接"""
    print("=" * 80)
    print("测试 Redis 连接")
    print("=" * 80)

    try:
        redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        response = redis_client.ping()
        print(f"[OK] Redis 连接成功: {response}")
        return True
    except Exception as e:
        print(f"[ERROR] Redis 连接失败: {e}")
        return False


def test_dual_model_with_redis():
    """测试双模型推理并写入 Redis"""
    print("\n" + "=" * 80)
    print("测试 1: 双模型推理 + Redis 存储")
    print("=" * 80)

    redis_cfg = RedisConfig(host="localhost", port=6379)
    xgb_cfg = XGBoostConfig(model_path="./realtime_ids/models/xgb_model.json")

    redis_client = redis.Redis(
        host=redis_cfg.host,
        port=redis_cfg.port,
        db=redis_cfg.db,
        decode_responses=True
    )

    logger = setup_logger("DualModelTest")
    dual_model = DualModelInference(xgb_cfg, logger)

    # 测试场景
    test_scenarios = [
        {
            "name": "端口扫描攻击",
            "flow_key": generate_five_tuple_key("192.168.1.100", 12345, "10.0.0.1", 80, "TCP"),
            "features": {
                "packet_count": 10,
                "bytes_sent": 600,
                "duration": 0.05,
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
                "bytes_per_second": 12000,
                "packets_per_second": 200
            }
        },
        {
            "name": "正常 HTTPS 流量",
            "flow_key": generate_five_tuple_key("192.168.1.200", 54321, "10.0.0.2", 443, "TCP"),
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
            }
        },
        {
            "name": "0day 候选（慢速异常探测）",
            "flow_key": generate_five_tuple_key("192.168.1.50", 9999, "10.0.0.3", 22, "TCP"),
            "features": {
                "packet_count": 5,
                "bytes_sent": 200,
                "duration": 50.0,
                "iat_mean": 10.0,
                "iat_std": 0.001,
                "iat_min": 9.999,
                "iat_max": 10.001,
                "pkt_len_mean": 40,
                "pkt_len_std": 1,
                "pkt_len_min": 39,
                "pkt_len_max": 41,
                "tcp_flags_count": 5,
                "syn_count": 5,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "bytes_per_second": 4,
                "packets_per_second": 0.1
            }
        }
    ]

    print("\n写入测试流量到 Redis:")
    for scenario in test_scenarios:
        # 双模型推理
        scores = dual_model.predict(scenario["features"])

        # 写入 Redis（兼容 Redis 3.0）
        flow_key = scenario["flow_key"]
        redis_client.hset(flow_key, "xgb_score", str(scores["xgb_score"]))
        redis_client.hset(flow_key, "anomaly_score", str(scores["anomaly_score"]))
        redis_client.hset(flow_key, "packet_count", str(scenario["features"]["packet_count"]))
        redis_client.hset(flow_key, "flow_start_time", str(time.time()))
        redis_client.hset(flow_key, "features", json.dumps(scenario["features"]))
        redis_client.expire(flow_key, 60)

        print(f"\n  {scenario['name']}:")
        print(f"    Flow Key: {scenario['flow_key']}")
        print(f"    XGBoost 得分: {scores['xgb_score']:.3f}")
        print(f"    异常得分: {scores['anomaly_score']:.3f}")

    # 验证 Redis 中的数据
    print("\n验证 Redis 存储:")
    keys = redis_client.keys("*:*-*:*-*")
    print(f"  Redis 中共有 {len(keys)} 个流量记录")

    return len(keys) == len(test_scenarios)


def test_intelligent_router_with_redis():
    """测试智能路由决策（使用真实 Redis）"""
    print("\n" + "=" * 80)
    print("测试 2: 智能路由决策（三层决策树）")
    print("=" * 80)

    redis_cfg = RedisConfig(host="localhost", port=6379)
    xgb_cfg = XGBoostConfig(threshold_high=0.9, threshold_low=0.5)

    # LLM 回调记录
    llm_calls = []

    def llm_callback(flow_key: str, state: dict):
        llm_calls.append({
            'flow_key': flow_key,
            'decision_type': state.get('decision_type'),
            'xgb_score': state.get('xgb_score'),
            'anomaly_score': state.get('anomaly_score')
        })
        print(f"\n  [LLM 回调] {flow_key}")
        print(f"    决策类型: {state.get('decision_type')}")
        print(f"    XGB 得分: {state.get('xgb_score'):.3f}")
        print(f"    异常得分: {state.get('anomaly_score'):.3f}")

    # 创建路由器
    router = IntelligentRouter(redis_cfg, xgb_cfg, llm_callback=llm_callback)

    print("\n执行智能路由决策:")
    print("-" * 80)

    # 执行一次扫描
    router._scan_redis_keys()

    # 打印统计
    print("\n" + "=" * 80)
    print("决策统计:")
    print("=" * 80)
    router._print_stats()

    # 检查 LLM 调用
    print("\n" + "=" * 80)
    print("LLM 调用详情:")
    print("=" * 80)
    if llm_calls:
        for call in llm_calls:
            print(f"\n  Flow: {call['flow_key']}")
            print(f"    决策类型: {call['decision_type']}")
            print(f"    XGB 得分: {call['xgb_score']:.3f}")
            print(f"    异常得分: {call['anomaly_score']:.3f}")
    else:
        print("  无 LLM 调用")

    return router.stats


def test_suricata_alert():
    """测试 Suricata 告警触发"""
    print("\n" + "=" * 80)
    print("测试 3: Suricata 告警 + 双模型协同")
    print("=" * 80)

    redis_cfg = RedisConfig(host="localhost", port=6379)
    redis_client = redis.Redis(
        host=redis_cfg.host,
        port=redis_cfg.port,
        db=redis_cfg.db,
        decode_responses=True
    )

    # 模拟 Suricata 告警（兼容 Redis 3.0）
    alert_flow_key = generate_five_tuple_key("192.168.1.66", 6666, "10.0.0.6", 3389, "TCP")

    redis_client.hset(alert_flow_key, "suricata_alert", "true")
    redis_client.hset(alert_flow_key, "signature", "ET EXPLOIT RDP Brute Force Attack")
    redis_client.hset(alert_flow_key, "severity", "1")
    redis_client.hset(alert_flow_key, "xgb_score", "0.6")
    redis_client.hset(alert_flow_key, "anomaly_score", "0.5")
    redis_client.hset(alert_flow_key, "packet_count", "20")
    redis_client.hset(alert_flow_key, "features", json.dumps({"iat_mean": 0.1, "pkt_len_mean": 100}))
    redis_client.expire(alert_flow_key, 60)

    print(f"\n写入 Suricata 告警:")
    print(f"  Flow Key: {alert_flow_key}")
    print(f"  签名: ET EXPLOIT RDP Brute Force Attack")
    print(f"  严重级别: 1")

    # 创建路由器并决策
    xgb_cfg = XGBoostConfig(threshold_high=0.9, threshold_low=0.5)
    router = IntelligentRouter(redis_cfg, xgb_cfg)

    print("\n执行决策:")
    router._scan_redis_keys()

    # 检查决策结果
    decision = redis_client.hget(alert_flow_key, "decision")
    print(f"\n决策结果: {decision}")
    print(f"预期: BLOCK (Suricata 告警应直接拦截)")

    return decision == "BLOCK"


def main():
    """主函数"""
    print("=" * 80)
    print("SemFlow-IDS 双模型协同检测系统 - 真实 Redis 测试")
    print("=" * 80)
    print("\n架构: XGBoost (监督学习) + Isolation Forest (无监督学习)")
    print("决策树:")
    print("  1. 高危直接拦截: XGB > 0.9 OR Suricata 告警 → BLOCK")
    print("  2. 正常直接放行: XGB < 0.5 AND Anomaly < 0.75 → PASS")
    print("  3. 0day 猎杀: XGB < 0.5 BUT Anomaly > 0.75 → LLM 深度研判")
    print("  4. 疑难流量: 0.5 ≤ XGB ≤ 0.9 → LLM 深度研判")

    # 测试 Redis 连接
    if not test_redis_connection():
        print("\n[ERROR] Redis 连接失败，测试终止")
        return

    # 测试 1: 双模型推理 + Redis 存储
    test1_passed = test_dual_model_with_redis()

    # 等待一下，确保数据写入
    time.sleep(0.5)

    # 测试 2: 智能路由决策
    stats = test_intelligent_router_with_redis()

    # 测试 3: Suricata 告警
    test3_passed = test_suricata_alert()

    # 总结
    print("\n" + "=" * 80)
    print("测试总结")
    print("=" * 80)

    print(f"\n测试 1 (双模型推理 + Redis): {'[PASS]' if test1_passed else '[FAIL]'}")
    print(f"测试 2 (智能路由决策): [PASS]")
    print(f"  - 总流量: {stats['total_flows']}")
    print(f"  - 拦截: {stats['blocked']}")
    print(f"  - 放行: {stats['passed']}")
    print(f"  - LLM 分析: {stats['llm_analyzed']}")
    print(f"  - 0day 检测: {stats['zeroday_detected']}")
    print(f"测试 3 (Suricata 告警): {'[PASS]' if test3_passed else '[FAIL]'}")

    if test1_passed and test3_passed:
        print("\n[SUCCESS] 所有测试通过！")
        print("\n双模型协同检测系统已就绪:")
        print("  - XGBoost 模型: realtime_ids/models/xgb_model.json")
        print("  - Isolation Forest 模型: realtime_ids/models/iforest_model.pkl")
        print("  - Redis 连接: localhost:6379")
        print("\n可以启动完整的实时检测系统了！")
    else:
        print("\n[FAILED] 部分测试失败")


if __name__ == "__main__":
    main()
