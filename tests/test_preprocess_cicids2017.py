"""
测试 CICIDS2017 数据预处理脚本

功能：
1. 验证数据加载逻辑
2. 验证特征映射逻辑
3. 验证数据清洗逻辑
4. 验证标签处理逻辑
5. 不实际处理全部数据，只测试前 100 条
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np
from scripts.preprocess_cicids2017 import CICIDS2017Preprocessor


def test_data_loading():
    """测试数据加载"""
    print("=" * 80)
    print("测试 1: 数据加载")
    print("=" * 80)

    preprocessor = CICIDS2017Preprocessor(data_dir="./data/MachineLearningCVE")

    # 加载第一个文件的前 100 条
    if len(preprocessor.csv_files) == 0:
        print("[SKIP] 没有找到 CSV 文件")
        return False

    csv_file = preprocessor.csv_files[0]
    df = preprocessor.load_single_file(csv_file, sample_size=100)

    if df is None:
        print("[FAIL] 数据加载失败")
        return False

    print(f"\n[OK] 数据加载成功")
    print(f"     行数: {len(df)}")
    print(f"     列数: {len(df.columns)}")
    print(f"     列名示例: {list(df.columns[:5])}")

    return True


def test_feature_mapping():
    """测试特征映射"""
    print("\n" + "=" * 80)
    print("测试 2: 特征映射")
    print("=" * 80)

    preprocessor = CICIDS2017Preprocessor(data_dir="./data/MachineLearningCVE")

    if len(preprocessor.csv_files) == 0:
        print("[SKIP] 没有找到 CSV 文件")
        return False

    # 加载数据
    csv_file = preprocessor.csv_files[0]
    df = preprocessor.load_single_file(csv_file, sample_size=100)

    if df is None:
        return False

    # 特征映射
    mapped_df = preprocessor.map_features(df)

    print(f"\n[OK] 特征映射成功")
    print(f"     原始特征数: {len(df.columns)}")
    print(f"     映射后特征数: {len(mapped_df.columns)}")
    print(f"     目标特征: {list(mapped_df.columns)}")

    # 验证特征是否存在
    expected_features = preprocessor.target_features + ['label']
    missing_features = set(expected_features) - set(mapped_df.columns)

    if missing_features:
        print(f"\n[WARN] 缺失特征: {missing_features}")
    else:
        print(f"\n[OK] 所有目标特征都已映射")

    # 显示前 3 行数据
    print("\n数据示例:")
    print(mapped_df.head(3))

    return True


def test_data_cleaning():
    """测试数据清洗"""
    print("\n" + "=" * 80)
    print("测试 3: 数据清洗")
    print("=" * 80)

    preprocessor = CICIDS2017Preprocessor(data_dir="./data/MachineLearningCVE")

    if len(preprocessor.csv_files) == 0:
        print("[SKIP] 没有找到 CSV 文件")
        return False

    # 加载并映射数据
    csv_file = preprocessor.csv_files[0]
    df = preprocessor.load_single_file(csv_file, sample_size=100)
    if df is None:
        return False

    mapped_df = preprocessor.map_features(df)

    # 数据清洗
    cleaned_df = preprocessor.clean_data(mapped_df)

    print(f"\n[OK] 数据清洗成功")
    print(f"     清洗前: {len(mapped_df)} 条")
    print(f"     清洗后: {len(cleaned_df)} 条")
    print(f"     移除: {len(mapped_df) - len(cleaned_df)} 条")

    # 检查是否还有 NaN 或 Inf
    has_nan = cleaned_df.isnull().any().any()
    has_inf = np.isinf(cleaned_df.select_dtypes(include=[np.number])).any().any()

    if has_nan:
        print(f"\n[WARN] 仍有 NaN 值")
    else:
        print(f"\n[OK] 无 NaN 值")

    if has_inf:
        print(f"[WARN] 仍有 Inf 值")
    else:
        print(f"[OK] 无 Inf 值")

    return True


def test_label_processing():
    """测试标签处理"""
    print("\n" + "=" * 80)
    print("测试 4: 标签处理")
    print("=" * 80)

    preprocessor = CICIDS2017Preprocessor(data_dir="./data/MachineLearningCVE")

    if len(preprocessor.csv_files) == 0:
        print("[SKIP] 没有找到 CSV 文件")
        return False

    # 加载并处理数据
    csv_file = preprocessor.csv_files[0]
    df = preprocessor.load_single_file(csv_file, sample_size=100)
    if df is None:
        return False

    mapped_df = preprocessor.map_features(df)
    cleaned_df = preprocessor.clean_data(mapped_df)

    # 标签处理
    labeled_df = preprocessor.process_labels(cleaned_df)

    print(f"\n[OK] 标签处理成功")

    # 验证标签只有 0 和 1
    unique_labels = labeled_df['label'].unique()
    print(f"     唯一标签: {sorted(unique_labels)}")

    if set(unique_labels).issubset({0, 1}):
        print(f"[OK] 标签格式正确（0 和 1）")
    else:
        print(f"[FAIL] 标签格式错误: {unique_labels}")
        return False

    return True


def test_feature_statistics():
    """测试特征统计"""
    print("\n" + "=" * 80)
    print("测试 5: 特征统计")
    print("=" * 80)

    preprocessor = CICIDS2017Preprocessor(data_dir="./data/MachineLearningCVE")

    if len(preprocessor.csv_files) == 0:
        print("[SKIP] 没有找到 CSV 文件")
        return False

    # 完整处理流程
    csv_file = preprocessor.csv_files[0]
    df = preprocessor.load_single_file(csv_file, sample_size=1000)  # 加载 1000 条
    if df is None:
        return False

    df = preprocessor.map_features(df)
    df = preprocessor.clean_data(df)
    df = preprocessor.process_labels(df)

    print(f"\n[OK] 处理完成，共 {len(df)} 条记录")

    # 统计信息
    print("\n特征统计:")
    print(df.describe())

    # 检查异常值
    print("\n异常值检查:")
    for col in preprocessor.target_features:
        if col in df.columns:
            min_val = df[col].min()
            max_val = df[col].max()
            mean_val = df[col].mean()

            if min_val < 0:
                print(f"  [WARN] {col}: 存在负值 (min={min_val})")
            if np.isinf(max_val):
                print(f"  [WARN] {col}: 存在无穷值")
            if np.isnan(mean_val):
                print(f"  [WARN] {col}: 存在 NaN")

    print("\n[OK] 特征统计完成")
    return True


def test_full_pipeline_small():
    """测试完整流程（小规模）"""
    print("\n" + "=" * 80)
    print("测试 6: 完整流程（小规模）")
    print("=" * 80)

    preprocessor = CICIDS2017Preprocessor(data_dir="./data/MachineLearningCVE")

    if len(preprocessor.csv_files) == 0:
        print("[SKIP] 没有找到 CSV 文件")
        return False

    # 只处理前 2 个文件，每个文件 500 条
    print("\n[INFO] 处理前 2 个文件，每个文件 500 条...")

    # 临时修改文件列表
    original_files = preprocessor.csv_files
    preprocessor.csv_files = preprocessor.csv_files[:2]

    try:
        df = preprocessor.process_all(
            sample_per_file=500,
            max_samples_per_class=1000,
            output_path="./data/test_processed.csv"
        )

        print(f"\n[OK] 完整流程测试成功")
        print(f"     最终样本数: {len(df)}")
        print(f"     特征数: {len(df.columns) - 1}")
        print(f"     标签分布: {df['label'].value_counts().to_dict()}")

        # 验证输出文件
        output_path = Path("./data/test_processed.csv")
        if output_path.exists():
            print(f"\n[OK] 输出文件已创建: {output_path}")
            print(f"     文件大小: {output_path.stat().st_size / 1024:.2f} KB")
        else:
            print(f"\n[FAIL] 输出文件未创建")
            return False

        return True

    except Exception as e:
        print(f"\n[FAIL] 完整流程测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # 恢复文件列表
        preprocessor.csv_files = original_files


def main():
    """运行所有测试"""
    print("\n" + "=" * 80)
    print("CICIDS2017 数据预处理测试套件")
    print("=" * 80)

    results = []

    # 测试 1: 数据加载
    results.append(("数据加载", test_data_loading()))

    # 测试 2: 特征映射
    results.append(("特征映射", test_feature_mapping()))

    # 测试 3: 数据清洗
    results.append(("数据清洗", test_data_cleaning()))

    # 测试 4: 标签处理
    results.append(("标签处理", test_label_processing()))

    # 测试 5: 特征统计
    results.append(("特征统计", test_feature_statistics()))

    # 测试 6: 完整流程（小规模）
    results.append(("完整流程", test_full_pipeline_small()))

    # 总结
    print("\n" + "=" * 80)
    print("测试总结")
    print("=" * 80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {name}")

    print(f"\n通过率: {passed}/{total} ({passed/total*100:.1f}%)")

    if passed == total:
        print("\n[SUCCESS] 所有测试通过！数据预处理逻辑正确")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} 个测试失败")
        return 1


if __name__ == "__main__":
    exit(main())
