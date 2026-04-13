"""
CICIDS2017 数据集预处理脚本

功能：
1. 加载 CICIDS2017 数据集（8 个 CSV 文件）
2. 特征映射：将 CICIDS2017 的 79 维特征映射到系统的 18 维特征
3. 数据清洗：处理缺失值、异常值、无穷值
4. 标签处理：BENIGN → 0, 其他攻击类型 → 1
5. 数据采样：平衡正负样本，避免类别不平衡
6. 保存处理后的数据集

数据集信息：
- 来源：CICIDS2017 (Canadian Institute for Cybersecurity)
- 总样本数：~283 万条
- 攻击类型：DDoS, PortScan, Infiltration, Web Attack, Brute Force, DoS, Heartbleed, Botnet
- 特征数：79 维（原始）→ 18 维（映射后）
"""
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# 添加项目路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class CICIDS2017Preprocessor:
    """CICIDS2017 数据集预处理器"""

    def __init__(self, data_dir: str = "./data/MachineLearningCVE"):
        self.data_dir = Path(data_dir)
        self.csv_files = list(self.data_dir.glob("*.csv"))

        # 系统使用的 18 维特征
        self.target_features = [
            'packet_count', 'bytes_sent', 'duration',
            'iat_mean', 'iat_std', 'iat_min', 'iat_max',
            'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
            'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
            'bytes_per_second', 'packets_per_second'
        ]

        # CICIDS2017 特征到系统特征的映射
        self.feature_mapping = {
            'packet_count': 'Total Fwd Packets',  # 前向包数作为总包数的近似
            'bytes_sent': 'Total Length of Fwd Packets',
            'duration': 'Flow Duration',
            'iat_mean': 'Flow IAT Mean',
            'iat_std': 'Flow IAT Std',
            'iat_min': 'Flow IAT Min',
            'iat_max': 'Flow IAT Max',
            'pkt_len_mean': 'Fwd Packet Length Mean',
            'pkt_len_std': 'Fwd Packet Length Std',
            'pkt_len_min': 'Fwd Packet Length Min',
            'pkt_len_max': 'Fwd Packet Length Max',
            'tcp_flags_count': None,  # 需要计算
            'syn_count': 'SYN Flag Count',
            'ack_count': 'ACK Flag Count',
            'fin_count': 'FIN Flag Count',
            'rst_count': 'RST Flag Count',
            'bytes_per_second': 'Flow Bytes/s',
            'packets_per_second': 'Flow Packets/s'
        }

        print(f"[INFO] 找到 {len(self.csv_files)} 个 CSV 文件")
        for f in self.csv_files:
            print(f"  - {f.name}")

    def load_single_file(self, csv_path: Path, sample_size: int = None) -> pd.DataFrame:
        """
        加载单个 CSV 文件

        Args:
            csv_path: CSV 文件路径
            sample_size: 采样大小（None 表示加载全部）

        Returns:
            DataFrame
        """
        print(f"\n[LOAD] {csv_path.name}")

        try:
            # 读取 CSV（跳过空格列名）
            df = pd.read_csv(csv_path, skipinitialspace=True)

            # 如果需要采样
            if sample_size and len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)
                print(f"  采样: {len(df)} 条记录")
            else:
                print(f"  加载: {len(df)} 条记录")

            return df

        except Exception as e:
            print(f"  [ERROR] 加载失败: {e}")
            return None

    def map_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        将 CICIDS2017 特征映射到系统的 18 维特征

        Args:
            df: 原始 DataFrame

        Returns:
            映射后的 DataFrame
        """
        print("  [MAP] 特征映射...")

        mapped_data = {}

        for target_feat, source_feat in self.feature_mapping.items():
            if source_feat is None:
                # 需要计算的特征
                if target_feat == 'tcp_flags_count':
                    # TCP 标志总数 = SYN + ACK + FIN + RST + PSH + URG
                    mapped_data[target_feat] = (
                        df.get('SYN Flag Count', 0) +
                        df.get('ACK Flag Count', 0) +
                        df.get('FIN Flag Count', 0) +
                        df.get('RST Flag Count', 0) +
                        df.get('PSH Flag Count', 0) +
                        df.get('URG Flag Count', 0)
                    )
            else:
                # 直接映射
                if source_feat in df.columns:
                    mapped_data[target_feat] = df[source_feat]
                else:
                    print(f"    [WARN] 缺失特征: {source_feat}")
                    mapped_data[target_feat] = 0

        # 创建新 DataFrame
        result_df = pd.DataFrame(mapped_data)

        # 添加标签列
        if 'Label' in df.columns:
            result_df['label'] = df['Label']

        print(f"  [MAP] 完成: {len(result_df)} 条记录, {len(result_df.columns)} 个特征")
        return result_df

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        数据清洗

        Args:
            df: DataFrame

        Returns:
            清洗后的 DataFrame
        """
        print("  [CLEAN] 数据清洗...")

        original_size = len(df)

        # 1. 替换无穷值为 NaN
        df = df.replace([np.inf, -np.inf], np.nan)

        # 2. 删除包含 NaN 的行
        df = df.dropna()

        # 3. 删除 duration = 0 的行（无效流量）
        if 'duration' in df.columns:
            df = df[df['duration'] > 0]

        # 4. 删除 packet_count = 0 的行
        if 'packet_count' in df.columns:
            df = df[df['packet_count'] > 0]

        cleaned_size = len(df)
        removed = original_size - cleaned_size

        print(f"  [CLEAN] 完成: 移除 {removed} 条异常记录 ({removed/original_size*100:.2f}%)")
        return df

    def process_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        处理标签：BENIGN → 0, 其他 → 1

        Args:
            df: DataFrame

        Returns:
            处理后的 DataFrame
        """
        print("  [LABEL] 标签处理...")

        if 'label' not in df.columns:
            print("    [WARN] 没有标签列")
            return df

        # 统计原始标签分布
        label_counts = df['label'].value_counts()
        print("    原始标签分布:")
        for label, count in label_counts.items():
            print(f"      {label}: {count}")

        # 二分类：BENIGN → 0, 其他 → 1
        df['label'] = df['label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

        # 统计处理后的标签分布
        benign_count = (df['label'] == 0).sum()
        malicious_count = (df['label'] == 1).sum()

        print(f"    处理后标签分布:")
        print(f"      正常 (0): {benign_count} ({benign_count/len(df)*100:.2f}%)")
        print(f"      恶意 (1): {malicious_count} ({malicious_count/len(df)*100:.2f}%)")

        return df

    def balance_dataset(self, df: pd.DataFrame, max_samples_per_class: int = 50000) -> pd.DataFrame:
        """
        平衡数据集：对多数类进行下采样

        Args:
            df: DataFrame
            max_samples_per_class: 每个类别的最大样本数

        Returns:
            平衡后的 DataFrame
        """
        print(f"  [BALANCE] 数据平衡（每类最多 {max_samples_per_class} 条）...")

        if 'label' not in df.columns:
            return df

        benign = df[df['label'] == 0]
        malicious = df[df['label'] == 1]

        # 下采样
        if len(benign) > max_samples_per_class:
            benign = benign.sample(n=max_samples_per_class, random_state=42)
            print(f"    正常样本下采样: {len(benign)}")

        if len(malicious) > max_samples_per_class:
            malicious = malicious.sample(n=max_samples_per_class, random_state=42)
            print(f"    恶意样本下采样: {len(malicious)}")

        # 合并
        balanced_df = pd.concat([benign, malicious], ignore_index=True)

        # 打乱顺序
        balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)

        print(f"  [BALANCE] 完成: {len(balanced_df)} 条记录")
        return balanced_df

    def process_all(self, sample_per_file: int = 10000, max_samples_per_class: int = 50000,
                    output_path: str = "./data/processed_cicids2017.csv") -> pd.DataFrame:
        """
        处理所有 CSV 文件

        Args:
            sample_per_file: 每个文件采样数量（None 表示全部加载）
            max_samples_per_class: 每个类别的最大样本数
            output_path: 输出文件路径

        Returns:
            处理后的 DataFrame
        """
        print("=" * 80)
        print("CICIDS2017 数据集预处理")
        print("=" * 80)

        all_data = []

        for csv_file in self.csv_files:
            # 加载
            df = self.load_single_file(csv_file, sample_size=sample_per_file)
            if df is None:
                continue

            # 特征映射
            df = self.map_features(df)

            # 数据清洗
            df = self.clean_data(df)

            # 标签处理
            df = self.process_labels(df)

            all_data.append(df)

        # 合并所有数据
        print("\n" + "=" * 80)
        print("合并所有数据...")
        print("=" * 80)

        combined_df = pd.concat(all_data, ignore_index=True)
        print(f"[MERGE] 合并后: {len(combined_df)} 条记录")

        # 平衡数据集
        balanced_df = self.balance_dataset(combined_df, max_samples_per_class)

        # 保存
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        balanced_df.to_csv(output_path, index=False)
        print(f"\n[SAVE] 保存到: {output_path}")
        print(f"       总样本数: {len(balanced_df)}")
        print(f"       特征数: {len(balanced_df.columns) - 1}")  # 减去 label 列

        return balanced_df


def main():
    """主函数"""
    # 创建预处理器
    preprocessor = CICIDS2017Preprocessor(data_dir="./data/MachineLearningCVE")

    # 处理数据（每个文件采样 10000 条，避免内存溢出）
    df = preprocessor.process_all(
        sample_per_file=10000,  # 每个文件采样 10000 条
        max_samples_per_class=50000,  # 每个类别最多 50000 条
        output_path="./data/processed_cicids2017.csv"
    )

    # 显示统计信息
    print("\n" + "=" * 80)
    print("数据集统计")
    print("=" * 80)
    print(df.describe())

    print("\n" + "=" * 80)
    print("标签分布")
    print("=" * 80)
    print(df['label'].value_counts())

    print("\n[SUCCESS] 数据预处理完成！")


if __name__ == "__main__":
    main()
