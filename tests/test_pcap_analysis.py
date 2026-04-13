import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scapy.all import rdpcap, IP, TCP, UDP
import json
import time
import numpy as np

class FlowStatistics:
    
    def __init__(self):
        self.packet_lengths = []
        self.timestamps = []
        self.tcp_flags = []
        self.flow_start_time = time.time()
        self.packet_count = 0
        self.bytes_sent = 0
    
    def add_packet(self, packet_length, timestamp, tcp_flag=None):
        self.packet_lengths.append(packet_length)
        self.timestamps.append(timestamp)
        if tcp_flag is not None:
            self.tcp_flags.append(tcp_flag)
        self.packet_count += 1
        self.bytes_sent += packet_length
    
    def compute_features(self):
        if len(self.timestamps) < 2:
            iats = [0.0]
        else:
            iats = [self.timestamps[i] - self.timestamps[i-1] for i in range(1, len(self.timestamps))]
        
        features = {
            "iat_mean": float(np.mean(iats)) if iats else 0.0,
            "iat_std": float(np.std(iats)) if iats else 0.0,
            "pkt_len_mean": float(np.mean(self.packet_lengths)) if self.packet_lengths else 0.0,
            "pkt_len_std": float(np.std(self.packet_lengths)) if self.packet_lengths else 0.0,
            "bytes_sent": float(self.bytes_sent),
            "packet_count": self.packet_count,
            "duration": float(time.time() - self.flow_start_time),
            "tcp_flags_count": len(self.tcp_flags)
        }
        return features

def generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, protocol):
    return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

def analyze_pcap(pcap_file):
    print("=" * 60)
    print(f"分析 PCAP 文件: {pcap_file}")
    print("=" * 60)
    
    packets = rdpcap(pcap_file)
    print(f"\n总包数: {len(packets)}")
    
    print("\n前10个包的详细信息:")
    for i, pkt in enumerate(packets[:10]):
        print(f"  包{i+1}: {pkt.summary()}")
    
    flow_stats = {}
    
    print("\n" + "=" * 60)
    print("按流分组统计")
    print("=" * 60)
    
    for pkt in packets:
        if IP not in pkt:
            continue
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
        else:
            continue
        
        flow_key = generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, proto)
        
        if flow_key not in flow_stats:
            flow_stats[flow_key] = FlowStatistics()
        
        packet_length = len(pkt)
        timestamp = float(pkt.time)
        tcp_flag = pkt[TCP].flags if TCP in pkt else None
        
        flow_stats[flow_key].add_packet(packet_length, timestamp, tcp_flag)
    
    print(f"\n检测到 {len(flow_stats)} 个不同的流\n")
    
    print("=" * 60)
    print("流特征提取与分析")
    print("=" * 60)
    
    for idx, (flow_key, stats) in enumerate(flow_stats.items(), 1):
        features = stats.compute_features()
        
        print(f"\n流 {idx}: {flow_key}")
        print(f"  包数量: {stats.packet_count}")
        print(f"  总字节数: {stats.bytes_sent}")
        print(f"  持续时间: {features['duration']:.3f}s")
        print(f"  平均包间隔: {features['iat_mean']:.6f}s")
        print(f"  包间隔标准差: {features['iat_std']:.6f}s")
        print(f"  平均包长: {features['pkt_len_mean']:.2f} bytes")
        print(f"  包长标准差: {features['pkt_len_std']:.2f} bytes")
        print(f"  TCP标志位数: {features['tcp_flags_count']}")
        
        dummy_score = np.random.uniform(0.3, 0.9)
        print(f"  模拟XGBoost得分: {dummy_score:.3f}")
        
        if dummy_score > 0.7:
            print(f"  [!] 疑似异常流量")
        elif dummy_score > 0.5:
            print(f"  [?] 需要LLM深度研判")
        else:
            print(f"  [OK] 正常流量")
    
    print("\n" + "=" * 60)
    print("早流检测模拟 (前10包触发)")
    print("=" * 60)
    
    early_flow_stats = {}
    packet_count = {}
    
    for pkt in packets:
        if IP not in pkt:
            continue
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
        else:
            continue
        
        flow_key = generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, proto)
        
        if flow_key not in early_flow_stats:
            early_flow_stats[flow_key] = FlowStatistics()
            packet_count[flow_key] = 0
        
        packet_count[flow_key] += 1
        
        packet_length = len(pkt)
        timestamp = float(pkt.time)
        tcp_flag = pkt[TCP].flags if TCP in pkt else None
        
        early_flow_stats[flow_key].add_packet(packet_length, timestamp, tcp_flag)
        
        if packet_count[flow_key] == 10:
            features = early_flow_stats[flow_key].compute_features()
            print(f"\n[OK] 流 {flow_key} 达到10包触发条件")
            print(f"  早流特征: IAT均值={features['iat_mean']:.6f}s, 包长均值={features['pkt_len_mean']:.2f}bytes")
    
    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)

if __name__ == "__main__":
    pcap_file = "data/test.pcap"
    analyze_pcap(pcap_file)
