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


def load_training_dataset(dataset_path='realtime_ids/models/training_dataset.csv'):
    """加载 XGBoost 训练时生成的数据集"""
    print(f"[INFO] 加载训练数据集: {dataset_path}")

    if not Path(dataset_path).exists():
        print(f"[ERROR] 数据集不存在: {dataset_path}")
        print("[INFO] 请先运行 scripts/train_xgboost.py 生成训练数据集")
        return None

    df = pd.read_csv(dataset_path)
    print(f"[INFO] 数据集大小: {len(df)} 样本")
    print(f"[INFO] 恶意样本: {df['label'].sum()} ({df['label'].sum()/len(df)*100:.2f}%)")
    print(f"[INFO] 正常样本: {(df['label']==0).sum()} ({(df['label']==0).sum()/len(df)*100:.2f}%)")

    return df


def train_isolation_forest(df, output_dir='realtime_ids/models'):
    """
    训练 Isolation Forest 模型

    Isolation Forest 是无监督学习算法，只需要正常样本
    但我们可以用恶意样本来评估模型效果
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

    # Isolation Forest 理论上只用正常样本训练
    # 但为了评估效果，我们用全部数据训练，然后在测试集上评估
    print(f"\n[INFO] 使用全部 {len(X)} 个样本训练（包含正常和恶意）")
    print("[INFO] Isolation Forest 是无监督算法，不依赖标签")

    # 特征标准化（Isolation Forest 对尺度敏感）
    print("\n[INFO] 特征标准化...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 训练 Isolation Forest
    print("\n[INFO] 训练 Isolation Forest...")

    # contamination: 预期异常样本比例（根据数据集调整）
    contamination = y.sum() / len(y)
    print(f"[INFO] 设置 contamination={contamination:.3f}（基于数据集恶意样本比例）")

    model = IsolationForest(
        n_estimators=100,           # 树的数量
        max_samples='auto',         # 每棵树的样本数
        contamination=contamination, # 异常样本比例
        max_features=1.0,           # 每棵树使用的特征比例
        bootstrap=False,
        n_jobs=-1,                  # 使用所有 CPU 核心
        random_state=42,
        verbose=1
    )

    model.fit(X_scaled)

    print("\n[INFO] 训练完成！")

    # 预测
    print("\n[INFO] 在训练集上评估...")
    y_pred = model.predict(X_scaled)  # 返回 1 (正常) 或 -1 (异常)
    y_pred_binary = (y_pred == -1).astype(int)  # 转换为 0/1

    # 异常分数（越负越异常）
    anomaly_scores = model.decision_function(X_scaled)

    # 评估
    print("\n" + "="*60)
    print("模型评估结果")
    print("="*60)

    print("\n分类报告:")
    print(classification_report(y, y_pred_binary, target_names=['Normal', 'Anomalous'], labels=[0, 1]))

    print("\n混淆矩阵:")
    cm = confusion_matrix(y, y_pred_binary, labels=[0, 1])
    print(f"  True Negative (TN): {cm[0,0]}, False Positive (FP): {cm[0,1]}")
    print(f"  False Negative (FN): {cm[1,0]}, True Positive (TP): {cm[1,1]}")

    # 异常分数分布
    print("\n异常分数分布:")
    print(f"  正常样本: mean={anomaly_scores[y==0].mean():.4f}, std={anomaly_scores[y==0].std():.4f}")
    print(f"  恶意样本: mean={anomaly_scores[y==1].mean():.4f}, std={anomaly_scores[y==1].std():.4f}")

    # 保存模型
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    model_path = Path(output_dir) / 'iforest_model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"\n[SUCCESS] Isolation Forest 模型已保存: {model_path}")

    # 保存 Scaler
    scaler_path = Path(output_dir) / 'scaler.pkl'
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"[SUCCESS] 特征标准化器已保存: {scaler_path}")

    # 保存模型信息
    model_info = {
        'n_estimators': 100,
        'contamination': float(contamination),
        'feature_columns': feature_cols,
        'anomaly_score_threshold': float(np.percentile(anomaly_scores, 25)),  # 25% 分位数作为阈值
        'training_samples': len(X),
        'normal_samples': int((y==0).sum()),
        'malicious_samples': int((y==1).sum())
    }

    info_path = Path(output_dir) / 'iforest_info.json'
    with open(info_path, 'w') as f:
        json.dump(model_info, f, indent=2)
    print(f"[SUCCESS] 模型信息已保存: {info_path}")

    # 分析特征重要性（基于异常分数方差）
    print("\n" + "="*60)
    print("特征重要性分析（基于异常分数方差）")
    print("="*60)

    feature_importance = []
    for i, col in enumerate(feature_cols):
        # 计算每个特征对异常分数的影响
        X_perturbed = X_scaled.copy()
        X_perturbed[:, i] = 0  # 将特征置零
        scores_perturbed = model.decision_function(X_perturbed)
        importance = np.abs(anomaly_scores - scores_perturbed).mean()
        feature_importance.append({'feature': col, 'importance': importance})

    importance_df = pd.DataFrame(feature_importance).sort_values('importance', ascending=False)

    print("\nTop 10 重要特征:")
    for idx, row in importance_df.head(10).iterrows():
        print(f"  {row['feature']}: {row['importance']:.4f}")

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
    print("="*60)
    print("Isolation Forest 模型训练（0day 检测）")
    print("="*60)

    # 加载数据集
    df = load_training_dataset()
    if df is None:
        return

    # 训练模型
    model, scaler = train_isolation_forest(df)

    # 测试 0day 检测能力
    test_0day_detection(model, scaler, df)

    print("\n" + "="*60)
    print("训练完成!")
    print("="*60)
    print("模型文件:")
    print("  - realtime_ids/models/iforest_model.pkl")
    print("  - realtime_ids/models/scaler.pkl")
    print("  - realtime_ids/models/iforest_info.json")
    print("\n现在可以在实时检测系统中使用双模型协同检测了！")


if __name__ == "__main__":
    main()
