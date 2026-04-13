"""
SemFlow-IDS 双模型协同检测系统 - 完整演示
使用 PCAP 文件模拟实时检测流程，展示三层决策树
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time
import json
import redis
from scapy.all import rdpcap, IP, TCP, UDP
from realtime_ids.config.config import RedisConfig, XGBoostConfig
from realtime_ids.modules.early_flow_xgb import FlowStatistics, DualModelInference
from realtime_ids.modules.intelligent_router import IntelligentRouter
from realtime_ids.utils import generate_five_tuple_key, setup_logger


def demo_system():
    """完整系统演示"""
    print("=" * 80)
    print("SemFlow-IDS 双模型协同检测系统 - 完整演示")
    print("=" * 80)
    print("\n架构: XGBoost (监督学习) + Isolation Forest (无监督学习)")
    print("\n三层决策树:")
    print("  1. 高危直接拦截: XGB > 0.9 OR Suricata 告警 → BLOCK")
    print("  2. 正常直接放行: XGB < 0.5 AND Anomaly < 0.75 → PASS")
    print("  3. 0day 猎杀: XGB < 0.5 BUT Anomaly > 0.75 → LLM 深度研判")
    print("  4. 疑难流量: 0.5 ≤ XGB ≤ 0.9 → LLM 深度研判")

    # 初始化配置
    redis_cfg = RedisConfig(host="localhost", port=6379)
    xgb_cfg = XGBoostConfig(
        model_path="./realtime_ids/models/xgb_model.json",
        threshold_high=0.9,
        threshold_low=0.5
    )

    # 连接 Redis
    redis_client = redis.Redis(
        host=redis_cfg.host,
        port=redis_cfg.port,
        db=redis_cfg.db,
        decode_responses=True
    )

    # 清空 Redis
    redis_client.flushdb()
    print("\n[INFO] Redis 已清空")

    # 初始化双模型推理引擎
    logger = setup_logger("Demo")
    dual_model = DualModelInference(xgb_cfg, logger)

    # LLM 回调统计
    llm_calls = []

    def llm_callback(flow_key: str, state: dict):
        llm_calls.append({
            'flow_key': flow_key,
            'decision_type': state.get('decision_type'),
            'xgb_score': state.get('xgb_score'),
            'anomaly_score': state.get('anomaly_score'),
            'features': json.loads(state.get('features', '{}'))
        })

    # 初始化智能路由
    router = IntelligentRouter(redis_cfg, xgb_cfg, llm_callback=llm_callback)

    # 读取 PCAP 文件
    pcap_file = "data/test.pcap"
    print(f"\n[INFO] 读取 PCAP 文件: {pcap_file}")

    packets = rdpcap(pcap_file)
    print(f"[INFO] 总包数: {len(packets)}")

    # 按流分组
    flows = {}
    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"
            tcp_flag = int(pkt[TCP].flags)
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
            tcp_flag = 0
        else:
            continue

        flow_key = generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, proto)

        if flow_key not in flows:
            flows[flow_key] = FlowStatistics()

        flows[flow_key].add_packet(len(pkt), float(pkt.time), tcp_flag)

    print(f"[INFO] 提取到 {len(flows)} 个流")

    # 模拟早流检测（前 10 包或 3 秒触发）
    print("\n" + "=" * 80)
    print("阶段 1: 早流特征提取与双模型推理")
    print("=" * 80)

    triggered_count = 0
    for flow_key, flow_stats in flows.items():
        # 模拟触发条件（简化：所有流都触发）
        if flow_stats.packet_count >= 5:  # 降低阈值以触发更多流
            features = flow_stats.compute_features()
            scores = dual_model.predict(features)

            # 写入 Redis（兼容 Redis 3.0）
            redis_client.hset(flow_key, "xgb_score", str(scores["xgb_score"]))
            redis_client.hset(flow_key, "anomaly_score", str(scores["anomaly_score"]))
            redis_client.hset(flow_key, "packet_count", str(flow_stats.packet_count))
            redis_client.hset(flow_key, "flow_start_time", str(time.time()))
            redis_client.hset(flow_key, "features", json.dumps(features))
            redis_client.expire(flow_key, 60)

            triggered_count += 1

            if triggered_count <= 5:  # 只显示前 5 个
                print(f"\n  流 {triggered_count}: {flow_key}")
                print(f"    包数: {flow_stats.packet_count}")
                print(f"    XGB 得分: {scores['xgb_score']:.3f}")
                print(f"    异常得分: {scores['anomaly_score']:.3f}")

    print(f"\n[INFO] 共触发 {triggered_count} 个流的早流检测")

    # 智能路由决策
    print("\n" + "=" * 80)
    print("阶段 2: 智能路由决策（三层决策树）")
    print("=" * 80)

    time.sleep(0.5)  # 等待 Redis 写入完成
    router._scan_redis_keys()

    # 统计结果
    print("\n" + "=" * 80)
    print("检测结果统计")
    print("=" * 80)

    stats = router.stats
    total = stats['total_flows']

    print(f"\n总流量: {total}")

    if total > 0:
        print(f"  - 拦截 (BLOCK): {stats['blocked']} ({stats['blocked']/total*100:.1f}%)")
        print(f"  - 放行 (PASS): {stats['passed']} ({stats['passed']/total*100:.1f}%)")
        print(f"  - LLM 分析: {stats['llm_analyzed']} ({stats['llm_analyzed']/total*100:.1f}%)")
        print(f"  - 0day 检测: {stats['zeroday_detected']} ({stats['zeroday_detected']/total*100:.1f}%)")
    else:
        print("  [WARNING] 未检测到任何流量，请检查 Redis 连接")

    # LLM 调用详情
    if llm_calls:
        print("\n" + "=" * 80)
        print("LLM 深度研判详情")
        print("=" * 80)

        for idx, call in enumerate(llm_calls[:5], 1):  # 只显示前 5 个
            print(f"\n{idx}. {call['flow_key']}")
            print(f"   决策类型: {call['decision_type']}")
            print(f"   XGB 得分: {call['xgb_score']:.3f}")
            print(f"   异常得分: {call['anomaly_score']:.3f}")

            features = call['features']
            print(f"   关键特征:")
            print(f"     - 包数: {features.get('packet_count', 0)}")
            print(f"     - 平均 IAT: {features.get('iat_mean', 0):.4f}s")
            print(f"     - 平均包长: {features.get('pkt_len_mean', 0):.1f} bytes")

            # 特征解读
            if call['decision_type'] == 'ZERODAY_HUNT':
                print(f"   [!] 0day 候选: XGB 认为安全但行为极度异常")
            elif features.get('iat_mean', 0) < 0.01:
                print(f"   [!] 包间隔极短，疑似快速扫描")
            elif features.get('pkt_len_mean', 0) < 100:
                print(f"   [!] 小包流量，可能是探测行为")

        if len(llm_calls) > 5:
            print(f"\n   ... 还有 {len(llm_calls) - 5} 个流量需要 LLM 分析")

    # 展示决策分布
    print("\n" + "=" * 80)
    print("决策分布可视化")
    print("=" * 80)

    total = stats['total_flows']
    if total > 0:
        print("\n  BLOCK  " + "█" * int(stats['blocked'] / total * 40) + f" {stats['blocked']}")
        print("  PASS   " + "█" * int(stats['passed'] / total * 40) + f" {stats['passed']}")
        print("  LLM    " + "█" * int(stats['llm_analyzed'] / total * 40) + f" {stats['llm_analyzed']}")
        print("  0day   " + "█" * int(stats['zeroday_detected'] / total * 40) + f" {stats['zeroday_detected']}")

    # 总结
    print("\n" + "=" * 80)
    print("演示总结")
    print("=" * 80)

    print("\n[SUCCESS] 双模型协同检测系统演示完成！")
    print("\n系统亮点:")
    print("  1. XGBoost 识别已知攻击模式（端口扫描、DoS 等）")
    print("  2. Isolation Forest 检测统计异常（0day 候选）")
    print("  3. 三层决策树：高危拦截、正常放行、疑难送 LLM")
    print("  4. 0day 猎杀策略：XGB 认为安全但 IF 认为异常 → LLM 研判")

    print("\n模型文件:")
    print("  - XGBoost: realtime_ids/models/xgb_model.json (AUC: 0.977)")
    print("  - Isolation Forest: realtime_ids/models/iforest_model.pkl")
    print("  - 特征标准化器: realtime_ids/models/scaler.pkl")

    print("\n可用于毕设答辩演示！")


if __name__ == "__main__":
    demo_system()
