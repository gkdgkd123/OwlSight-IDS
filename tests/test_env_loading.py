"""
测试 .env 文件加载功能
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
import tempfile
from src.config.config import SystemConfig, load_env_file


def test_env_file_loading():
    """测试 .env 文件加载"""
    print("=" * 80)
    print("测试 .env 文件加载功能")
    print("=" * 80)

    # 创建临时 .env 文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False, encoding='utf-8') as f:
        f.write("""# 测试配置文件
# Redis 配置
REDIS_HOST=test.redis.com
REDIS_PORT=6380
REDIS_DB=1

# LLM 配置
LLM_API_KEY=test_key_from_env_file
LLM_API_MODEL=claude-sonnet-4-6

# XGBoost 配置
XGB_THRESHOLD_HIGH=0.95
""")
        temp_env_path = f.name

    try:
        # 清理环境变量
        for key in ["REDIS_HOST", "REDIS_PORT", "REDIS_DB", "LLM_API_KEY", "LLM_API_MODEL", "XGB_THRESHOLD_HIGH"]:
            if key in os.environ:
                del os.environ[key]

        print(f"\n[1] 创建临时 .env 文件: {temp_env_path}")

        # 加载 .env 文件
        load_env_file(temp_env_path)
        print("[2] 加载 .env 文件完成")

        # 验证环境变量
        print("\n[3] 验证环境变量:")
        print(f"    REDIS_HOST = {os.getenv('REDIS_HOST')}")
        print(f"    REDIS_PORT = {os.getenv('REDIS_PORT')}")
        print(f"    REDIS_DB = {os.getenv('REDIS_DB')}")
        print(f"    LLM_API_KEY = {os.getenv('LLM_API_KEY')[:10]}...")
        print(f"    LLM_API_MODEL = {os.getenv('LLM_API_MODEL')}")
        print(f"    XGB_THRESHOLD_HIGH = {os.getenv('XGB_THRESHOLD_HIGH')}")

        # 使用 from_env() 加载配置
        print("\n[4] 使用 SystemConfig.from_env() 加载配置")
        config = SystemConfig.from_env(temp_env_path)

        print("\n[5] 验证配置对象:")
        print(f"    Redis host: {config.redis.host}")
        print(f"    Redis port: {config.redis.port}")
        print(f"    Redis db: {config.redis.db}")
        print(f"    LLM API key: {config.llm.api_key[:10]}...")
        print(f"    LLM API model: {config.llm.api_model}")
        print(f"    XGB threshold_high: {config.xgboost.threshold_high}")

        # 验证值是否正确
        assert config.redis.host == "test.redis.com", "Redis host 不匹配"
        assert config.redis.port == 6380, "Redis port 不匹配"
        assert config.redis.db == 1, "Redis db 不匹配"
        assert config.llm.api_key == "test_key_from_env_file", "LLM API key 不匹配"
        assert config.llm.api_model == "claude-sonnet-4-6", "LLM API model 不匹配"
        assert config.xgboost.threshold_high == 0.95, "XGB threshold_high 不匹配"

        print("\n[SUCCESS] .env 文件加载测试通过！")
        return True

    except Exception as e:
        print(f"\n[FAIL] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # 清理临时文件
        Path(temp_env_path).unlink(missing_ok=True)


def test_env_priority():
    """测试环境变量优先级（环境变量 > .env 文件）"""
    print("\n" + "=" * 80)
    print("测试环境变量优先级")
    print("=" * 80)

    # 创建临时 .env 文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False, encoding='utf-8') as f:
        f.write("REDIS_HOST=from_env_file\n")
        temp_env_path = f.name

    try:
        # 设置环境变量（优先级更高）
        os.environ["REDIS_HOST"] = "from_environment"

        print(f"\n[1] .env 文件设置: REDIS_HOST=from_env_file")
        print(f"[2] 环境变量设置: REDIS_HOST=from_environment")

        # 加载配置
        config = SystemConfig.from_env(temp_env_path)

        print(f"\n[3] 最终配置: Redis host = {config.redis.host}")

        # 验证环境变量优先级更高
        assert config.redis.host == "from_environment", "环境变量优先级测试失败"

        print("\n[SUCCESS] 环境变量优先级测试通过！")
        print("结论: 环境变量 > .env 文件")
        return True

    except Exception as e:
        print(f"\n[FAIL] 测试失败: {e}")
        return False

    finally:
        # 清理
        Path(temp_env_path).unlink(missing_ok=True)
        if "REDIS_HOST" in os.environ:
            del os.environ["REDIS_HOST"]


def test_missing_env_file():
    """测试 .env 文件不存在时的行为"""
    print("\n" + "=" * 80)
    print("测试 .env 文件不存在的情况")
    print("=" * 80)

    try:
        # 清理所有可能影响的环境变量
        for key in ["REDIS_HOST", "REDIS_PORT", "REDIS_DB", "LLM_API_KEY", "LLM_API_MODEL", "XGB_THRESHOLD_HIGH"]:
            if key in os.environ:
                del os.environ[key]

        # 使用不存在的文件路径
        config = SystemConfig.from_env("nonexistent.env")

        print("\n[1] 使用不存在的 .env 文件")
        print(f"[2] 配置加载成功（使用默认值）")
        print(f"    Redis host: {config.redis.host}")
        print(f"    Redis port: {config.redis.port}")

        # 验证使用了默认值
        assert config.redis.host == "localhost", f"默认值不正确: {config.redis.host}"
        assert config.redis.port == 6379, f"默认值不正确: {config.redis.port}"

        print("\n[SUCCESS] .env 文件不存在时正确使用默认值！")
        return True

    except Exception as e:
        print(f"\n[FAIL] 测试失败: {e}")
        return False


def main():
    """运行所有测试"""
    print("\n" + "=" * 80)
    print(".env 文件加载功能测试套件")
    print("=" * 80)

    results = []

    # 测试 1: .env 文件加载
    results.append(("env 文件加载", test_env_file_loading()))

    # 测试 2: 环境变量优先级
    results.append(("环境变量优先级", test_env_priority()))

    # 测试 3: .env 文件不存在
    results.append(("env 文件不存在", test_missing_env_file()))

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
        print("\n[SUCCESS] 所有测试通过！.env 文件加载功能正常")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} 个测试失败")
        return 1


if __name__ == "__main__":
    exit(main())
