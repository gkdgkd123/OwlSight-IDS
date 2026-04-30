"""
XGBoost 模型训练脚本
从 PCAP 文件和 Suricata 日志中提取流特征，训练二分类模型
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import pickle

from src.utils import generate_five_tuple_key


class FlowFeatureExtractor:
    """流特征提取器"""

    def __init__(self):
        self.flow_stats = {}

    def extract_from_pcap(self, pcap_file):
        """从 PCAP 文件提取流特征"""
        print(f"[INFO] 读取 PCAP 文件: {pcap_file}")
        packets = rdpcap(pcap_file)
        print(f"[INFO] 总包数: {len(packets)}")

        flow_data = defaultdict(lambda: {
            'packet_lengths': [],
            'timestamps': [],
            'tcp_flags': [],
            'start_time': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'proto': None
        })

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

            flow = flow_data[flow_key]
            if flow['start_time'] is None:
                flow['start_time'] = float(pkt.time)
                flow['src_ip'] = src_ip
                flow['dst_ip'] = dst_ip
                flow['src_port'] = src_port
                flow['dst_port'] = dst_port
                flow['proto'] = proto

            flow['packet_lengths'].append(len(pkt))
            flow['timestamps'].append(float(pkt.time))
            flow['tcp_flags'].append(tcp_flag)

        print(f"[INFO] 提取到 {len(flow_data)} 个流")
        return flow_data

    def compute_features(self, flow_data):
        """计算流统计特征"""
        features_list = []

        for flow_key, flow in flow_data.items():
            if len(flow['timestamps']) < 2:
                iats = [0.0]
            else:
                iats = [flow['timestamps'][i] - flow['timestamps'][i-1]
                       for i in range(1, len(flow['timestamps']))]

            duration = flow['timestamps'][-1] - flow['timestamps'][0] if len(flow['timestamps']) > 1 else 0

            features = {
                'flow_key': flow_key,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'proto': flow['proto'],

                # 统计特征
                'packet_count': len(flow['packet_lengths']),
                'bytes_sent': sum(flow['packet_lengths']),
                'duration': duration,

                # IAT 特征
                'iat_mean': float(np.mean(iats)) if iats else 0.0,
                'iat_std': float(np.std(iats)) if iats else 0.0,
                'iat_min': float(np.min(iats)) if iats else 0.0,
                'iat_max': float(np.max(iats)) if iats else 0.0,

                # 包长特征
                'pkt_len_mean': float(np.mean(flow['packet_lengths'])),
                'pkt_len_std': float(np.std(flow['packet_lengths'])),
                'pkt_len_min': float(np.min(flow['packet_lengths'])),
                'pkt_len_max': float(np.max(flow['packet_lengths'])),

                # TCP 特征
                'tcp_flags_count': len([f for f in flow['tcp_flags'] if f > 0]),
                'syn_count': sum([1 for f in flow['tcp_flags'] if f & 0x02]),
                'ack_count': sum([1 for f in flow['tcp_flags'] if f & 0x10]),
                'fin_count': sum([1 for f in flow['tcp_flags'] if f & 0x01]),
                'rst_count': sum([1 for f in flow['tcp_flags'] if f & 0x04]),

                # 速率特征
                'bytes_per_second': sum(flow['packet_lengths']) / duration if duration > 0 else 0,
                'packets_per_second': len(flow['packet_lengths']) / duration if duration > 0 else 0,
            }

            features_list.append(features)

        return pd.DataFrame(features_list)

    def load_suricata_labels(self, eve_json_file):
        """从 Suricata 日志加载标签"""
        print(f"[INFO] 读取 Suricata 日志: {eve_json_file}")

        malicious_flows = set()

        with open(eve_json_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if event.get('event_type') == 'alert':
                        src_ip = event.get('src_ip')
                        dst_ip = event.get('dest_ip')
                        src_port = event.get('src_port', 0)
                        dst_port = event.get('dest_port', 0)
                        proto = event.get('proto', '')

                        if all([src_ip, dst_ip, proto]):
                            flow_key = generate_five_tuple_key(src_ip, src_port, dst_ip, dst_port, proto)
                            malicious_flows.add(flow_key)
                except:
                    continue

        print(f"[INFO] 检测到 {len(malicious_flows)} 个恶意流")
        return malicious_flows


def prepare_training_data(pcap_file, eve_json_file):
    """准备训练数据"""
    extractor = FlowFeatureExtractor()

    # 从 PCAP 提取特征
    flow_data = extractor.extract_from_pcap(pcap_file)
    features_df = extractor.compute_features(flow_data)

    # 从 Suricata 加载标签
    malicious_flows = extractor.load_suricata_labels(eve_json_file)

    # 添加标签列
    features_df['label'] = features_df['flow_key'].apply(
        lambda x: 1 if x in malicious_flows else 0
    )

    print(f"\n[INFO] 数据集统计:")
    print(f"  总流量数: {len(features_df)}")
    print(f"  恶意流量: {features_df['label'].sum()} ({features_df['label'].sum()/len(features_df)*100:.2f}%)")
    print(f"  正常流量: {(features_df['label']==0).sum()} ({(features_df['label']==0).sum()/len(features_df)*100:.2f}%)")

    # 如果恶意样本太少，生成合成样本
    if features_df['label'].sum() < 10:
        print("\n[WARNING] 恶意样本不足，生成合成恶意样本用于训练")
        features_df = generate_synthetic_malicious_samples(features_df)

    return features_df


def generate_synthetic_malicious_samples(features_df):
    """生成合成的恶意流量样本"""
    normal_samples = features_df[features_df['label'] == 0].copy()

    # 生成恶意样本数量（约30%）
    num_malicious = int(len(normal_samples) * 0.3)

    synthetic_samples = []

    for i in range(num_malicious):
        # 随机选择一个正常样本作为基础
        base_sample = normal_samples.sample(1).iloc[0].copy()

        # 随机选择攻击类型并修改特征
        attack_type = np.random.choice(['port_scan', 'dos', 'data_exfil', 'slow_scan'])

        if attack_type == 'port_scan':
            # 端口扫描：小包、快速、多连接
            base_sample['pkt_len_mean'] = np.random.uniform(40, 80)
            base_sample['pkt_len_std'] = np.random.uniform(5, 15)
            base_sample['iat_mean'] = np.random.uniform(0.001, 0.01)
            base_sample['iat_std'] = np.random.uniform(0.001, 0.005)
            base_sample['packet_count'] = np.random.randint(5, 15)
            base_sample['syn_count'] = base_sample['packet_count']

        elif attack_type == 'dos':
            # DoS 攻击：大量包、快速
            base_sample['packet_count'] = np.random.randint(50, 200)
            base_sample['iat_mean'] = np.random.uniform(0.0001, 0.001)
            base_sample['iat_std'] = np.random.uniform(0.0001, 0.0005)
            base_sample['bytes_per_second'] = np.random.uniform(50000, 200000)
            base_sample['packets_per_second'] = np.random.uniform(100, 500)

        elif attack_type == 'data_exfil':
            # 数据外泄：大量数据传输、规律性强
            base_sample['bytes_sent'] = np.random.uniform(50000, 500000)
            base_sample['pkt_len_mean'] = np.random.uniform(1000, 1400)
            base_sample['iat_mean'] = np.random.uniform(0.01, 0.05)
            base_sample['iat_std'] = np.random.uniform(0.001, 0.01)
            base_sample['duration'] = np.random.uniform(10, 60)

        elif attack_type == 'slow_scan':
            # 慢速扫描：长时间间隔、小包
            base_sample['iat_mean'] = np.random.uniform(5, 30)
            base_sample['iat_std'] = np.random.uniform(1, 5)
            base_sample['pkt_len_mean'] = np.random.uniform(50, 100)
            base_sample['packet_count'] = np.random.randint(3, 10)
            base_sample['duration'] = np.random.uniform(30, 300)

        # 更新派生特征
        if base_sample['duration'] > 0:
            base_sample['bytes_per_second'] = base_sample['bytes_sent'] / base_sample['duration']
            base_sample['packets_per_second'] = base_sample['packet_count'] / base_sample['duration']

        # 标记为恶意
        base_sample['label'] = 1
        base_sample['flow_key'] = f"synthetic_malicious_{i}"

        synthetic_samples.append(base_sample)

    # 合并原始数据和合成数据
    synthetic_df = pd.DataFrame(synthetic_samples)
    combined_df = pd.concat([features_df, synthetic_df], ignore_index=True)

    print(f"[INFO] 生成了 {num_malicious} 个合成恶意样本")
    print(f"[INFO] 新数据集统计:")
    print(f"  总流量数: {len(combined_df)}")
    print(f"  恶意流量: {combined_df['label'].sum()} ({combined_df['label'].sum()/len(combined_df)*100:.2f}%)")
    print(f"  正常流量: {(combined_df['label']==0).sum()} ({(combined_df['label']==0).sum()/len(combined_df)*100:.2f}%)")

    return combined_df


def train_xgboost_model(features_df, output_dir='src/models'):
    """训练 XGBoost 模型"""

    # 选择特征列
    feature_cols = [
        'packet_count', 'bytes_sent', 'duration',
        'iat_mean', 'iat_std', 'iat_min', 'iat_max',
        'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
        'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
        'bytes_per_second', 'packets_per_second'
    ]

    X = features_df[feature_cols].fillna(0)
    y = features_df['label']

    # 检查标签是否包含两个类别
    unique_labels = y.unique()
    if len(unique_labels) < 2:
        print(f"[ERROR] 标签只有 {unique_labels} 一个类别，无法训练二分类模型")
        return None, feature_cols, 0.0

    # 划分训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[INFO] 训练集: {len(X_train)} 样本")
    print(f"[INFO] 测试集: {len(X_test)} 样本")

    # 处理类别不平衡
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
    print(f"[INFO] 类别权重: {scale_pos_weight:.2f}")

    # 训练 XGBoost
    print("\n[INFO] 开始训练 XGBoost 模型...")

    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)

    params = {
        'objective': 'binary:logistic',
        'eval_metric': 'auc',
        'max_depth': 6,
        'eta': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'scale_pos_weight': scale_pos_weight,
        'seed': 42
    }

    evals = [(dtrain, 'train'), (dtest, 'test')]

    model = xgb.train(
        params,
        dtrain,
        num_boost_round=200,
        evals=evals,
        callbacks=[
            xgb.callback.EvaluationMonitor(period=10),
            xgb.callback.EarlyStopping(rounds=10, save_best=True),
        ],
    )

    # 预测
    y_pred_proba = model.predict(dtest)
    y_pred = (y_pred_proba > 0.5).astype(int)

    # 评估
    print("\n" + "="*60)
    print("模型评估结果")
    print("="*60)

    print("\n分类报告:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Malicious'], labels=[0, 1]))

    print("\n混淆矩阵:")
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print(f"  True Negative (TN): {cm[0,0]}, False Positive (FP): {cm[0,1]}")
    print(f"  False Negative (FN): {cm[1,0]}, True Positive (TP): {cm[1,1]}")

    auc_score = roc_auc_score(y_test, y_pred_proba)
    print(f"\nAUC-ROC: {auc_score:.4f}")

    # 特征重要性
    print("\n特征重要性 (Top 10):")
    importance = model.get_score(importance_type='gain')

    # XGBoost 可能使用特征名或索引，需要处理两种情况
    importance_list = []
    for k, v in importance.items():
        if k.startswith('f') and k[1:].isdigit():
            # 索引格式 (f0, f1, ...)
            feat_idx = int(k[1:])
            feat_name = feature_cols[feat_idx]
        else:
            # 直接使用特征名
            feat_name = k
        importance_list.append({'feature': feat_name, 'importance': v})

    importance_df = pd.DataFrame(importance_list).sort_values('importance', ascending=False)

    for idx, row in importance_df.head(10).iterrows():
        print(f"  {row['feature']}: {row['importance']:.2f}")

    # 保存模型
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    model_path = Path(output_dir) / 'xgb_model.json'
    model.save_model(str(model_path))
    print(f"\n[SUCCESS] 模型已保存: {model_path}")

    # 保存特征列表
    feature_info = {
        'feature_columns': feature_cols,
        'model_params': params,
        'auc_score': float(auc_score),
        'num_features': len(feature_cols)
    }

    info_path = Path(output_dir) / 'model_info.json'
    with open(info_path, 'w') as f:
        json.dump(feature_info, f, indent=2)
    print(f"[SUCCESS] 模型信息已保存: {info_path}")

    # 保存完整数据集用于分析
    dataset_path = Path(output_dir) / 'training_dataset.csv'
    features_df.to_csv(dataset_path, index=False)
    print(f"[SUCCESS] 训练数据集已保存: {dataset_path}")

    return model, feature_cols, auc_score


def load_from_csv(csv_file):
    """从预处理好的 CSV 加载训练数据"""
    print(f"[INFO] 从 CSV 加载训练数据: {csv_file}")

    df = pd.read_csv(csv_file)
    print(f"[INFO] 数据集大小: {len(df)} 样本")
    print(f"[INFO] 列: {list(df.columns)}")

    # 检查必要的特征列
    required_features = [
        'packet_count', 'bytes_sent', 'duration',
        'iat_mean', 'iat_std', 'iat_min', 'iat_max',
        'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
        'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
        'bytes_per_second', 'packets_per_second'
    ]

    missing = [col for col in required_features if col not in df.columns]
    if missing:
        print(f"[ERROR] 缺失特征列: {missing}")
        return None

    if 'label' not in df.columns:
        print("[ERROR] 缺失 label 列")
        return None

    # 标签二分类化（如果是字符串 BENIGN/攻击类型）
    if df['label'].dtype == object:
        df['label'] = df['label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

    # 如果没有 flow_key 列，自动生成
    if 'flow_key' not in df.columns:
        df['flow_key'] = [f"flow_{i}" for i in range(len(df))]

    print(f"\n[INFO] 数据集统计:")
    print(f"  总流量数: {len(df)}")
    print(f"  恶意流量: {df['label'].sum()} ({df['label'].sum()/len(df)*100:.2f}%)")
    print(f"  正常流量: {(df['label']==0).sum()} ({(df['label']==0).sum()/len(df)*100:.2f}%)")

    return df


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="XGBoost 模型训练")
    parser.add_argument("--data", help="预处理好的 CSV 文件路径（18维特征 + label）")
    parser.add_argument("--pcap", default="data/test.pcap", help="PCAP 文件路径（与 --eve-json 配合使用）")
    parser.add_argument("--eve-json", default="data/eve.json", help="Suricata eve.json 路径")
    parser.add_argument("--output", default="src/models", help="模型输出目录")
    args = parser.parse_args()

    print("="*60)
    print("OwlSight-IDS XGBoost 模型训练")
    print("="*60)

    if args.data:
        # 从预处理 CSV 加载
        if not Path(args.data).exists():
            print(f"[ERROR] CSV 文件不存在: {args.data}")
            return
        features_df = load_from_csv(args.data)
    else:
        # 从 pcap + eve.json 提取
        if not Path(args.pcap).exists():
            print(f"[ERROR] PCAP 文件不存在: {args.pcap}")
            return
        if not Path(args.eve_json).exists():
            print(f"[ERROR] Suricata 日志不存在: {args.eve_json}")
            return
        features_df = prepare_training_data(args.pcap, args.eve_json)

    if features_df is None:
        return

    # 训练模型
    model, feature_cols, auc_score = train_xgboost_model(features_df, output_dir=args.output)

    print("\n" + "="*60)
    print("训练完成!")
    print("="*60)
    print(f"模型 AUC: {auc_score:.4f}")
    print(f"特征数量: {len(feature_cols)}")
    print(f"模型文件: {args.output}/xgb_model.json")


if __name__ == "__main__":
    main()
