"""
Isolation Forest 异常分数校准脚本

用 pcap 中的真实正常流量（Suricata 未告警的流）微调 Isolation Forest，
解决异常分数普遍偏高（0.89-1.0）的问题。

用法：
    python scripts/calibrate_iforest.py \
        --pcap data/capture_20260429_155502.pcap \
        --suricata-alerts data/capture_20260429_155502_suricata_alerts.json
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import numpy as np
import pandas as pd
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from scripts.train_xgboost import FlowFeatureExtractor


def load_suricata_malicious_flows(alerts_file: str) -> set:
    """从 Suricata eve.json 提取恶意流的五元组集合"""
    from src.utils import generate_five_tuple_key

    malicious = set()
    with open(alerts_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get('event_type') != 'alert':
                    continue
                src_ip = event.get('src_ip')
                dst_ip = event.get('dest_ip')
                src_port = event.get('src_port', 0)
                dst_port = event.get('dest_port', 0)
                proto = event.get('proto', '')
                if all([src_ip, dst_ip, proto]):
                    key = generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, proto)
                    malicious.add(key)
            except Exception:
                continue
    return malicious


def extract_flows_from_pcap(pcap_file: str) -> pd.DataFrame:
    """从 pcap 提取所有流的 18 维特征"""
    extractor = FlowFeatureExtractor()
    flow_data = extractor.extract_from_pcap(pcap_file)
    features_df = extractor.compute_features(flow_data)
    return features_df


def calibrate(pcap_file: str, alerts_file: str, output_dir: str = 'src/models'):
    """主校准流程"""
    print("=" * 60)
    print("Isolation Forest 异常分数校准")
    print("=" * 60)

    # 1. 提取 pcap 流特征
    print(f"\n[1/5] 从 pcap 提取流特征: {pcap_file}")
    features_df = extract_flows_from_pcap(pcap_file)
    print(f"      总流数: {len(features_df)}")

    # 2. 加载 Suricata 告警，标记恶意流
    print(f"\n[2/5] 加载 Suricata 告警: {alerts_file}")
    malicious_flows = load_suricata_malicious_flows(alerts_file)
    print(f"      恶意流数: {len(malicious_flows)}")

    features_df['is_malicious'] = features_df['flow_key'].isin(malicious_flows)
    normal_df = features_df[~features_df['is_malicious']]
    malicious_df = features_df[features_df['is_malicious']]
    print(f"      正常流数: {len(normal_df)}")
    print(f"      恶意流数: {len(malicious_df)}")

    if len(normal_df) < 10:
        print("[ERROR] 正常流量不足 10 条，无法训练")
        return

    # 3. 特征列
    feature_cols = [
        'packet_count', 'bytes_sent', 'duration',
        'iat_mean', 'iat_std', 'iat_min', 'iat_max',
        'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
        'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
        'bytes_per_second', 'packets_per_second'
    ]

    X_normal = normal_df[feature_cols].fillna(0).values
    X_all = features_df[feature_cols].fillna(0).values

    # 4. 训练新 Scaler + Isolation Forest（仅用正常流量）
    print(f"\n[3/5] 训练新 Scaler + Isolation Forest（{len(X_normal)} 条正常流量）...")

    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)

    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination='auto',
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=42,
        verbose=0
    )
    model.fit(X_normal_scaled)
    print("      训练完成")

    # 5. 评估校准效果
    print(f"\n[4/5] 评估校准效果...")

    # 正常流量的异常分数分布
    normal_scores = model.decision_function(X_normal_scaled)
    print(f"\n      正常流量异常分数（原始 decision_function）:")
    print(f"        mean={normal_scores.mean():.4f}, std={normal_scores.std():.4f}")
    print(f"        min={normal_scores.min():.4f}, max={normal_scores.max():.4f}")
    print(f"        p5={np.percentile(normal_scores, 5):.4f}")
    print(f"        p50={np.percentile(normal_scores, 50):.4f}")
    print(f"        p95={np.percentile(normal_scores, 95):.4f}")

    # 恶意流量的异常分数（如果有）
    if len(malicious_df) > 0:
        X_malicious = malicious_df[feature_cols].fillna(0).values
        X_malicious_scaled = scaler.transform(X_malicious)
        malicious_scores = model.decision_function(X_malicious_scaled)
        print(f"\n      恶意流量异常分数:")
        print(f"        mean={malicious_scores.mean():.4f}, std={malicious_scores.std():.4f}")
        print(f"        min={malicious_scores.min():.4f}, max={malicious_scores.max():.4f}")

    # 归一化后的分数分布（使用新 percentile）
    anomaly_percentiles = {
        'p5': float(np.percentile(normal_scores, 5)),
        'p25': float(np.percentile(normal_scores, 25)),
        'p50': float(np.percentile(normal_scores, 50)),
        'p75': float(np.percentile(normal_scores, 75)),
        'p95': float(np.percentile(normal_scores, 95)),
    }

    # 模拟运行时归一化后的分数
    p5 = anomaly_percentiles['p5']
    p95 = anomaly_percentiles['p95']
    inverted = -normal_scores
    inverted_p5 = -p95
    inverted_p95 = -p5
    if inverted_p95 > inverted_p5:
        normalized = (inverted - inverted_p5) / (inverted_p95 - inverted_p5)
    else:
        normalized = np.full_like(normal_scores, 0.5)
    normalized = np.clip(normalized, 0, 1)

    print(f"\n      校准后正常流量异常分数（归一化到 0-1）:")
    print(f"        mean={normalized.mean():.4f}, std={normalized.std():.4f}")
    print(f"        p50={np.percentile(normalized, 50):.4f}")
    print(f"        p75={np.percentile(normalized, 75):.4f}")
    print(f"        p95={np.percentile(normalized, 95):.4f}")
    print(f"        >0.75 的比例: {(normalized > 0.75).sum() / len(normalized) * 100:.1f}%")

    if len(malicious_df) > 0:
        inv_m = -malicious_scores
        if inverted_p95 > inverted_p5:
            norm_m = (inv_m - inverted_p5) / (inverted_p95 - inverted_p5)
        else:
            norm_m = np.full_like(malicious_scores, 0.5)
        norm_m = np.clip(norm_m, 0, 1)
        print(f"\n      校准后恶意流量异常分数（归一化到 0-1）:")
        print(f"        mean={norm_m.mean():.4f}")
        print(f"        >0.75 的比例: {(norm_m > 0.75).sum() / len(norm_m) * 100:.1f}%")

    # 6. 保存校准后的模型
    print(f"\n[5/5] 保存校准后的模型到 {output_dir}/")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    with open(f'{output_dir}/iforest_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print(f"      iforest_model.pkl")

    with open(f'{output_dir}/scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    print(f"      scaler.pkl")

    model_info = {
        'n_estimators': 100,
        'contamination': 'auto',
        'feature_columns': feature_cols,
        'anomaly_score_percentiles': anomaly_percentiles,
        'anomaly_score_threshold': float(np.percentile(normal_scores, 5)),
        'scaler_path': 'scaler.pkl',
        'calibration_source': pcap_file,
        'calibration_normal_samples': len(X_normal),
        'calibration_malicious_samples': len(malicious_df),
        'total_flows_in_pcap': len(features_df),
    }

    with open(f'{output_dir}/iforest_info.json', 'w') as f:
        json.dump(model_info, f, indent=2)
    print(f"      iforest_info.json")

    print("\n" + "=" * 60)
    print("校准完成！")
    print("=" * 60)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Isolation Forest 异常分数校准')
    parser.add_argument('--pcap', required=True, help='pcap 文件路径')
    parser.add_argument('--suricata-alerts', required=True, help='Suricata eve.json 路径')
    parser.add_argument('--output', default='src/models', help='模型输出目录')
    args = parser.parse_args()

    calibrate(args.pcap, args.suricata_alerts, args.output)
