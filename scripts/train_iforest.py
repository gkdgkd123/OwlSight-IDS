"""
训练 Isolation Forest 模型
用于检测异常行为和 0day 攻击
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
from sklearn.metrics import classification_report, confusion_matrix


def load_training_dataset(dataset_path='src/models/training_dataset.csv'):
    """加载 XGBoost 训练时生成的数据集"""
    print(f"[INFO] 加载训练数据集: {dataset_path}")

    if not Path(dataset_path).exists():
        print(f"[ERROR] 数据集不存在: {dataset_path}")
        print("[INFO] 请先运行 scripts/train_xgboost.py 生成训练数据集")
        return None

    df = pd.read_csv(dataset_path)

    # 标签二分类化（兼容字符串标签）
    if df['label'].dtype == object:
        df['label'] = df['label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

    print(f"[INFO] 数据集大小: {len(df)} 样本")
    print(f"[INFO] 恶意样本: {df['label'].sum()} ({df['label'].sum()/len(df)*100:.2f}%)")
    print(f"[INFO] 正常样本: {(df['label']==0).sum()} ({(df['label']==0).sum()/len(df)*100:.2f}%)")

    return df


def train_isolation_forest(df, output_dir='src/models'):
    """
    训练 Isolation Forest 模型

    Isolation Forest 是无监督学习算法，只用正常样本训练，
    让模型学习"正常流量长什么样"，异常流量会被打低分。
    """
    print("\n" + "="*60)
    print("训练 Isolation Forest 模型（无监督异常检测）")
    print("="*60)

    # 特征列（与 XGBoost 一致）
    feature_cols = [
        'packet_count', 'bytes_sent', 'duration',
        'iat_mean', 'iat_std', 'iat_min', 'iat_max',
        'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
        'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
        'bytes_per_second', 'packets_per_second'
    ]

    X = df[feature_cols].fillna(0)
    y = df['label']

    # 分离正常样本用于训练
    X_normal = X[y == 0]
    print(f"\n[INFO] 仅使用正常样本训练: {len(X_normal)} 条（总样本 {len(X)} 条）")

    # 特征标准化（Isolation Forest 对尺度敏感）
    print("[INFO] 特征标准化...")
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)

    # 训练 Isolation Forest
    print("[INFO] 训练 Isolation Forest...")

    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination='auto',  # 自动确定阈值，不受数据集比例影响
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1,
        random_state=42,
        verbose=1
    )

    model.fit(X_normal_scaled)
    print("[INFO] 训练完成！")

    # 在正常样本上计算异常分数分布（用于运行时归一化）
    normal_scores = model.decision_function(X_normal_scaled)
    anomaly_percentiles = {
        'p5': float(np.percentile(normal_scores, 5)),
        'p25': float(np.percentile(normal_scores, 25)),
        'p50': float(np.percentile(normal_scores, 50)),
        'p75': float(np.percentile(normal_scores, 75)),
        'p95': float(np.percentile(normal_scores, 95)),
    }
    print(f"\n[INFO] 正常样本异常分数分布:")
    print(f"  mean={normal_scores.mean():.4f}, std={normal_scores.std():.4f}")
    print(f"  p5={anomaly_percentiles['p5']:.4f}, p50={anomaly_percentiles['p50']:.4f}, p95={anomaly_percentiles['p95']:.4f}")

    # 在全量数据上评估（含恶意样本）
    X_all_scaled = scaler.transform(X)
    all_scores = model.decision_function(X_all_scaled)
    y_pred = model.predict(X_all_scaled)  # 1=正常, -1=异常
    y_pred_binary = (y_pred == -1).astype(int)

    print("\n" + "="*60)
    print("模型评估结果（全量数据）")
    print("="*60)

    print("\n分类报告:")
    print(classification_report(y, y_pred_binary, target_names=['Normal', 'Anomalous'], labels=[0, 1]))

    print("\n混淆矩阵:")
    cm = confusion_matrix(y, y_pred_binary, labels=[0, 1])
    print(f"  True Negative (TN): {cm[0,0]}, False Positive (FP): {cm[0,1]}")
    print(f"  False Negative (FN): {cm[1,0]}, True Positive (TP): {cm[1,1]}")

    print("\n异常分数分布对比:")
    print(f"  正常样本: mean={all_scores[y==0].mean():.4f}, std={all_scores[y==0].std():.4f}")
    print(f"  恶意样本: mean={all_scores[y==1].mean():.4f}, std={all_scores[y==1].std():.4f}")

    # 保存模型
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    model_path = Path(output_dir) / 'iforest_model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"\n[SUCCESS] 模型已保存: {model_path}")

    scaler_path = Path(output_dir) / 'scaler.pkl'
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"[SUCCESS] Scaler 已保存: {scaler_path}")

    model_info = {
        'n_estimators': 100,
        'contamination': 'auto',
        'feature_columns': feature_cols,
        'anomaly_score_percentiles': anomaly_percentiles,
        'anomaly_score_threshold': float(np.percentile(normal_scores, 5)),
        'scaler_path': 'scaler.pkl',
        'training_samples': len(X_normal),
        'normal_samples': int((y == 0).sum()),
        'malicious_samples': int((y == 1).sum()),
        'total_samples': len(X)
    }

    info_path = Path(output_dir) / 'iforest_info.json'
    with open(info_path, 'w') as f:
        json.dump(model_info, f, indent=2)
    print(f"[SUCCESS] 模型信息已保存: {info_path}")

    return model, scaler


def test_0day_detection(model, scaler, df):
    """
    测试 0day 检测能力
    模拟：XGBoost 认为安全，但 Isolation Forest 认为异常
    """
    print("\n" + "="*60)
    print("0day 检测能力测试")
    print("="*60)

    feature_cols = [
        'packet_count', 'bytes_sent', 'duration',
        'iat_mean', 'iat_std', 'iat_min', 'iat_max',
        'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
        'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
        'bytes_per_second', 'packets_per_second'
    ]

    X = df[feature_cols].fillna(0)
    X_scaled = scaler.transform(X)

    # 计算异常分数
    anomaly_scores = model.decision_function(X_scaled)

    # 归一化到 0-1 范围
    anomaly_scores_normalized = -anomaly_scores + 0.5
    anomaly_scores_normalized = np.clip(anomaly_scores_normalized, 0, 1)

    # 模拟 XGBoost 得分（假设恶意样本 XGB 得分较高）
    # 这里我们随机生成一些 XGB 得分用于演示
    np.random.seed(42)
    xgb_scores = np.random.uniform(0.3, 0.7, len(df))

    # 找出 0day 候选：XGB < 0.5 但 Anomaly > 0.75
    zeroday_candidates = (xgb_scores < 0.5) & (anomaly_scores_normalized > 0.75)

    print(f"\n[INFO] 0day 候选数量: {zeroday_candidates.sum()}")

    if zeroday_candidates.sum() > 0:
        print("\n0day 候选样本（前 5 个）:")
        zeroday_df = df[zeroday_candidates].head(5)
        for idx, row in zeroday_df.iterrows():
            print(f"\n  样本 {idx}:")
            print(f"    Flow: {row['flow_key']}")
            print(f"    XGB 得分: {xgb_scores[idx]:.3f} (认为安全)")
            print(f"    异常得分: {anomaly_scores_normalized[idx]:.3f} (极度异常)")
            print(f"    实际标签: {'恶意' if row['label'] == 1 else '正常'}")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="Isolation Forest 模型训练")
    parser.add_argument("--data", help="训练数据 CSV 路径（18维特征 + label）")
    parser.add_argument("--output", default="src/models", help="模型输出目录")
    args = parser.parse_args()

    print("="*60)
    print("Isolation Forest 模型训练（0day 检测）")
    print("="*60)

    if args.data:
        # 从指定 CSV 加载
        print(f"[INFO] 加载训练数据: {args.data}")
        if not Path(args.data).exists():
            print(f"[ERROR] 文件不存在: {args.data}")
            return
        df = pd.read_csv(args.data)

        # 标签二分类化（兼容字符串标签）
        if df['label'].dtype == object:
            df['label'] = df['label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

        print(f"[INFO] 数据集大小: {len(df)} 样本")
        print(f"[INFO] 恶意样本: {df['label'].sum()} ({df['label'].sum()/len(df)*100:.2f}%)")
        print(f"[INFO] 正常样本: {(df['label']==0).sum()} ({(df['label']==0).sum()/len(df)*100:.2f}%)")
    else:
        # 默认加载 xgboost 训练输出的数据集
        df = load_training_dataset()
        if df is None:
            return

    # 训练模型
    model, scaler = train_isolation_forest(df, output_dir=args.output)

    # 测试 0day 检测能力
    test_0day_detection(model, scaler, df)

    print("\n" + "="*60)
    print("训练完成!")
    print("="*60)
    print("模型文件:")
    print(f"  - {args.output}/iforest_model.pkl")
    print(f"  - {args.output}/scaler.pkl")
    print(f"  - {args.output}/iforest_info.json")
    print("\n现在可以在实时检测系统中使用双模型协同检测了！")


if __name__ == "__main__":
    main()
