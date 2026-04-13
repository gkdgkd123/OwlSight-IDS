"""
SemFlow-IDS 集成测试脚本
使用 test.pcap 文件测试完整的检测流程（不依赖 Redis）
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scapy.all import rdpcap, IP, TCP, UDP
import json
import time
import numpy as np
from collections import defaultdict

# 导入项目模块
from realtime_ids.utils import generate_five_tuple_key
from realtime_ids.modules.early_flow_xgb import FlowStatistics


class MockRedis:
    """模拟 Redis 存储"""
    def __init__(self):
        self.data = {}

    def hset(self, key, mapping=None, **kwargs):
        if key not in self.data:
            self.data[key] = {}
        if mapping:
            self.data[key].update(mapping)
        self.data[key].update(kwargs)

    def hgetall(self, key):
        return self.data.get(key, {})

    def hget(self, key, field):
        return self.data.get(key, {}).get(field)

    def expire(self, key, ttl):
        pass

    def keys(self, pattern):
        return list(self.data.keys())

    def delete(self, key):
        if key in self.data:
            del self.data[key]


def analyze_pcap_with_early_flow(pcap_file, packet_trigger=10, time_trigger=3.0):
    """使用早流检测逻辑分析 PCAP 文件"""

    print("=" * 80)
    print(f"SemFlow-IDS 集成测试 - 分析文件: {pcap_file}")
    print("=" * 80)

    # 读取 PCAP
    packets = rdpcap(pcap_file)
    print(f"\n[INFO] 总包数: {len(packets)}")

    # 模拟存储
    mock_redis = MockRedis()

    # 流统计
    active_flows = {}
    triggered_flows = []

    print(f"\n[INFO] 开始早流特征提取 (触发条件: {packet_trigger}包 或 {time_trigger}秒)")
    print("-" * 80)

    # 处理每个包
    for idx, pkt in enumerate(packets):
        if IP not in pkt:
            continue

        # 提取五元组
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"
            tcp_flag = pkt[TCP].flags
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
            tcp_flag = None
        else:
            continue

        flow_key = generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, proto)

        # 初始化流统计
        if flow_key not in active_flows:
            active_flows[flow_key] = {
                'stats': FlowStatistics(),
                'start_time': float(pkt.time)
            }

        # 添加包统计
        flow_info = active_flows[flow_key]
        flow_info['stats'].add_packet(
            packet_length=len(pkt),
            timestamp=float(pkt.time),
            tcp_flag=tcp_flag
        )

        # 检查触发条件
        packet_count = flow_info['stats'].packet_count
        elapsed = float(pkt.time) - flow_info['start_time']

        should_trigger = (packet_count >= packet_trigger) or (elapsed >= time_trigger)

        if should_trigger and flow_key not in [f['key'] for f in triggered_flows]:
            # 计算特征
            features = flow_info['stats'].compute_features()

            # 模拟 XGBoost 推理
            xgb_score = simulate_xgb_inference(features)

            # 写入模拟 Redis
            mock_redis.hset(
                flow_key,
                mapping={
                    "xgb_score": str(xgb_score),
                    "packet_count": str(packet_count),
                    "flow_start_time": str(flow_info['start_time']),
                    "features": json.dumps(features)
                }
            )

            triggered_flows.append({
                'key': flow_key,
                'features': features,
                'xgb_score': xgb_score,
                'trigger_reason': 'packet_count' if packet_count >= packet_trigger else 'time_window'
            })

            print(f"\n[TRIGGER] 流 #{len(triggered_flows)}: {flow_key}")
            print(f"  触发原因: {'达到{packet_trigger}包'.format(packet_trigger=packet_trigger) if packet_count >= packet_trigger else '超过{time_trigger}秒'.format(time_trigger=time_trigger)}")
            print(f"  包数: {packet_count}, 持续时间: {elapsed:.3f}s")
            print(f"  XGBoost 得分: {xgb_score:.3f}")

    print("\n" + "=" * 80)
    print("智能路由决策")
    print("=" * 80)

    # 模拟智能路由决策
    decisions = {
        'BLOCK': [],
        'PASS': [],
        'LLM_ANALYZE': []
    }

    for flow_info in triggered_flows:
        flow_key = flow_info['key']
        xgb_score = flow_info['xgb_score']

        # 决策逻辑
        if xgb_score > 0.9:
            decision = 'BLOCK'
            decisions['BLOCK'].append(flow_info)
            print(f"\n[BLOCK] 拦截恶意流: {flow_key}")
            print(f"  XGB得分: {xgb_score:.3f} (高危)")
        elif xgb_score < 0.5:
            decision = 'PASS'
            decisions['PASS'].append(flow_info)
            print(f"\n[PASS] 正常流量: {flow_key}")
            print(f"  XGB得分: {xgb_score:.3f} (正常)")
        else:
            decision = 'LLM_ANALYZE'
            decisions['LLM_ANALYZE'].append(flow_info)
            print(f"\n[SUSPICIOUS] 疑难流量: {flow_key}")
            print(f"  XGB得分: {xgb_score:.3f} (需要LLM深度研判)")

            # 模拟 LLM 分析
            llm_result = simulate_llm_analysis(flow_info['features'])
            print(f"  LLM判断: {'恶意' if llm_result['is_malicious'] else '正常'}")
            print(f"  攻击类型: {llm_result['attack_type']}")
            print(f"  置信度: {llm_result['confidence']:.2f}")

    # 统计报告
    print("\n" + "=" * 80)
    print("检测统计报告")
    print("=" * 80)
    print(f"\n总流量数: {len(active_flows)}")
    print(f"触发早流检测: {len(triggered_flows)}")
    print(f"  - 直接拦截 (BLOCK): {len(decisions['BLOCK'])}")
    print(f"  - 直接放行 (PASS): {len(decisions['PASS'])}")
    print(f"  - LLM深度研判 (SUSPICIOUS): {len(decisions['LLM_ANALYZE'])}")

    # 详细流量特征
    print("\n" + "=" * 80)
    print("Top 5 高风险流量详情")
    print("=" * 80)

    sorted_flows = sorted(triggered_flows, key=lambda x: x['xgb_score'], reverse=True)[:5]
    for idx, flow_info in enumerate(sorted_flows, 1):
        features = flow_info['features']
        print(f"\n{idx}. {flow_info['key']}")
        print(f"   XGB得分: {flow_info['xgb_score']:.3f}")
        print(f"   包数: {features['packet_count']}")
        print(f"   总字节: {features['bytes_sent']:.0f}")
        print(f"   平均IAT: {features['iat_mean']:.6f}s")
        print(f"   平均包长: {features['pkt_len_mean']:.2f} bytes")

        # 特征解读
        if features['iat_mean'] < 0.01:
            print(f"   [!] 包间隔极短，疑似自动化攻击")
        if features['pkt_len_mean'] < 100:
            print(f"   [!] 包长较小，可能是探测流量")
        if features['bytes_sent'] > 10000:
            print(f"   [!] 传输量大，可能存在数据外泄")

    print("\n" + "=" * 80)
    print("测试完成")
    print("=" * 80)

    return {
        'total_flows': len(active_flows),
        'triggered_flows': len(triggered_flows),
        'decisions': decisions,
        'mock_redis': mock_redis
    }


def simulate_xgb_inference(features):
    """模拟 XGBoost 推理（基于规则的启发式）"""
    score = 0.5  # 基础分

    # IAT 特征
    if features['iat_mean'] < 0.01:
        score += 0.2  # 包间隔极短
    elif features['iat_mean'] > 1.0:
        score += 0.1  # 慢速扫描

    # 包长特征
    if features['pkt_len_mean'] < 100:
        score += 0.15  # 小包，可能是探测

    # 传输量特征
    if features['bytes_sent'] > 10000:
        score += 0.1  # 大量数据传输

    # IAT 方差
    if features['iat_std'] < 0.01:
        score += 0.1  # 极其规律，疑似机器行为

    # 添加随机扰动
    score += np.random.uniform(-0.1, 0.1)

    return max(0.0, min(1.0, score))


def simulate_llm_analysis(features):
    """模拟 LLM 深度研判"""

    # 基于特征的简单规则判断
    is_malicious = False
    attack_type = "Unknown"
    confidence = 0.5

    if features['iat_mean'] < 0.01 and features['pkt_len_mean'] < 100:
        is_malicious = True
        attack_type = "Port Scanning"
        confidence = 0.85
    elif features['bytes_sent'] > 10000 and features['iat_std'] < 0.01:
        is_malicious = True
        attack_type = "Data Exfiltration"
        confidence = 0.78
    elif features['pkt_len_mean'] > 1000:
        is_malicious = False
        attack_type = "Normal Data Transfer"
        confidence = 0.72
    else:
        is_malicious = False
        attack_type = "Benign Traffic"
        confidence = 0.65

    return {
        "is_malicious": is_malicious,
        "attack_type": attack_type,
        "confidence": confidence,
        "reason": f"基于流量特征分析: IAT={features['iat_mean']:.6f}s, 包长={features['pkt_len_mean']:.2f}bytes"
    }


if __name__ == "__main__":
    pcap_file = "data/test.pcap"

    if not Path(pcap_file).exists():
        print(f"错误: PCAP 文件不存在: {pcap_file}")
        sys.exit(1)

    result = analyze_pcap_with_early_flow(pcap_file)

    print(f"\n[SUCCESS] 测试完成，共分析 {result['total_flows']} 个流量")
