"""
测试配置文件加载
验证 config.py 的修复是否正确
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
from src.config.config import (
    RedisConfig, SuricataConfig, ScapyConfig,
    XGBoostConfig, LLMConfig, SystemConfig
)


def test_basic_config():
    """测试基础配置初始化"""
    print("=" * 80)
    print("测试 1: 基础配置初始化")
    print("=" * 80)

    # 测试各个配置类
    redis_cfg = RedisConfig()
    print(f"[OK] RedisConfig: host={redis_cfg.host}, port={redis_cfg.port}, ttl={redis_cfg.ttl}s")

    suricata_cfg = SuricataConfig()
    print(f"[OK] SuricataConfig: eve_json_path={suricata_cfg.eve_json_path}")

    scapy_cfg = ScapyConfig()
    print(f"[OK] ScapyConfig: interface={scapy_cfg.interface}, packet_trigger={scapy_cfg.packet_trigger}")

    xgb_cfg = XGBoostConfig()
    print(f"[OK] XGBoostConfig: threshold_high={xgb_cfg.threshold_high}, anomaly_threshold={xgb_cfg.anomaly_threshold}")

    print("\n测试通过：基础配置初始化正常")


def test_llm_config_without_api_key():
    """测试 LLMConfig 在没有 API Key 时不抛异常（P0 修复验证）"""
    print("\n" + "=" * 80)
    print("测试 2: LLMConfig 延迟验证（P0 修复）")
    print("=" * 80)

    # 清除环境变量
    if "LLM_API_KEY" in os.environ:
        del os.environ["LLM_API_KEY"]

    try:
        llm_cfg = LLMConfig(use_api=True)
        print(f"[OK] LLMConfig 初始化成功（即使没有 API Key）")
        print(f"     api_key={llm_cfg.api_key}")
        print(f"     use_api={llm_cfg.use_api}")
        print("\n测试通过：不再在初始化时抛出异常，改为警告")
    except ValueError as e:
        print(f"[FAIL] LLMConfig 初始化失败: {e}")
        print("P0 修复未生效，仍然在初始化时抛异常")
        return False

    return True


def test_system_config_without_api_key():
    """测试 SystemConfig 在没有 API Key 时能正常初始化"""
    print("\n" + "=" * 80)
    print("测试 3: SystemConfig 初始化（不依赖 LLM API Key）")
    print("=" * 80)

    # 清除环境变量
    if "LLM_API_KEY" in os.environ:
        del os.environ["LLM_API_KEY"]

    try:
        sys_cfg = SystemConfig()
        print(f"[OK] SystemConfig 初始化成功")
        print(f"     Redis TTL: {sys_cfg.redis.ttl}s (应为 60s)")
        print(f"     XGB threshold_high: {sys_cfg.xgboost.threshold_high}")
        print(f"     LLM use_api: {sys_cfg.llm.use_api}")
        print(f"     LLM api_key: {sys_cfg.llm.api_key}")

        # 验证 P1 修复：Redis TTL 应为 60
        if sys_cfg.redis.ttl == 60:
            print("\n[OK] P1 修复验证通过：Redis TTL = 60s")
        else:
            print(f"\n[FAIL] P1 修复未生效：Redis TTL = {sys_cfg.redis.ttl}s (期望 60s)")
            return False

        print("\n测试通过：SystemConfig 可以在没有 LLM API Key 时正常初始化")
    except Exception as e:
        print(f"[FAIL] SystemConfig 初始化失败: {e}")
        return False

    return True


def test_from_env_with_invalid_values():
    """测试 from_env() 对非法环境变量的处理（P2 修复验证）"""
    print("\n" + "=" * 80)
    print("测试 4: from_env() 安全类型转换（P2 修复）")
    print("=" * 80)

    # 设置非法环境变量
    os.environ["REDIS_PORT"] = "abc"
    os.environ["XGB_THRESHOLD_HIGH"] = "not_a_float"

    try:
        sys_cfg = SystemConfig.from_env()
        print(f"[OK] from_env() 成功处理非法环境变量")
        print(f"     REDIS_PORT=abc → {sys_cfg.redis.port} (应为默认值 6379)")
        print(f"     XGB_THRESHOLD_HIGH=not_a_float → {sys_cfg.xgboost.threshold_high} (应为默认值 0.9)")

        # 验证回退到默认值
        if sys_cfg.redis.port == 6379 and sys_cfg.xgboost.threshold_high == 0.9:
            print("\n[OK] P2 修复验证通过：非法值回退到默认值")
        else:
            print(f"\n[FAIL] P2 修复未生效：port={sys_cfg.redis.port}, threshold={sys_cfg.xgboost.threshold_high}")
            return False

        print("\n测试通过：from_env() 能安全处理非法环境变量")
    except Exception as e:
        print(f"[FAIL] from_env() 处理非法环境变量失败: {e}")
        return False
    finally:
        # 清理环境变量
        if "REDIS_PORT" in os.environ:
            del os.environ["REDIS_PORT"]
        if "XGB_THRESHOLD_HIGH" in os.environ:
            del os.environ["XGB_THRESHOLD_HIGH"]

    return True


def test_llm_config_with_api_key():
    """测试 LLMConfig 在有 API Key 时正常工作"""
    print("\n" + "=" * 80)
    print("测试 5: LLMConfig 正常场景（有 API Key）")
    print("=" * 80)

    # 设置环境变量
    os.environ["LLM_API_KEY"] = "test_key_12345"

    try:
        llm_cfg = LLMConfig(use_api=True)
        print(f"[OK] LLMConfig 初始化成功")
        print(f"     api_key={llm_cfg.api_key[:10]}... (从环境变量读取)")
        print(f"     api_base_url={llm_cfg.api_base_url}")
        print(f"     api_model={llm_cfg.api_model}")

        if llm_cfg.api_key == "test_key_12345":
            print("\n[OK] 环境变量 LLM_API_KEY 读取成功")
        else:
            print(f"\n[FAIL] API Key 读取错误: {llm_cfg.api_key}")
            return False

        print("\n测试通过：LLMConfig 在有 API Key 时正常工作")
    except Exception as e:
        print(f"[FAIL] LLMConfig 初始化失败: {e}")
        return False
    finally:
        # 清理环境变量
        if "LLM_API_KEY" in os.environ:
            del os.environ["LLM_API_KEY"]

    return True


def main():
    """运行所有测试"""
    print("\n" + "=" * 80)
    print("config.py 修复验证测试套件")
    print("=" * 80)

    results = []

    # 测试 1: 基础配置
    test_basic_config()

    # 测试 2: P0 修复 - LLMConfig 延迟验证
    results.append(("P0 - LLMConfig 延迟验证", test_llm_config_without_api_key()))

    # 测试 3: SystemConfig 初始化
    results.append(("SystemConfig 初始化", test_system_config_without_api_key()))

    # 测试 4: P2 修复 - 安全类型转换
    results.append(("P2 - 安全类型转换", test_from_env_with_invalid_values()))

    # 测试 5: LLMConfig 正常场景
    results.append(("LLMConfig 正常场景", test_llm_config_with_api_key()))

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
        print("\n[SUCCESS] 所有测试通过！config.py 修复验证成功")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} 个测试失败")
        return 1


if __name__ == "__main__":
    exit(main())
