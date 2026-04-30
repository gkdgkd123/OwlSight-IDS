"""
单元测试: config 模块
覆盖: 各 dataclass 默认值、SystemConfig.from_env、load_env_file、_safe_int/_safe_float
"""
import os
import pytest
from unittest.mock import patch
from src.config.config import (
    RedisConfig,
    SuricataConfig,
    ScapyConfig,
    XGBoostConfig,
    LLMConfig,
    SystemConfig,
    load_env_file,
    _safe_int,
    _safe_float,
)


class TestRedisConfig:
    """RedisConfig 默认值测试"""

    def test_defaults(self):
        cfg = RedisConfig()
        assert cfg.host == "localhost"
        assert cfg.port == 6379
        assert cfg.db == 0
        assert cfg.password is None
        assert cfg.ttl == 60

    def test_custom_values(self):
        cfg = RedisConfig(host="redis.local", port=6380, db=2, password="secret", ttl=120)
        assert cfg.host == "redis.local"
        assert cfg.port == 6380
        assert cfg.db == 2
        assert cfg.password == "secret"
        assert cfg.ttl == 120


class TestSuricataConfig:
    def test_defaults(self):
        cfg = SuricataConfig()
        assert cfg.eve_json_path == "/var/log/suricata/eve.json"
        assert cfg.tail_interval == 0.1


class TestScapyConfig:
    def test_defaults(self):
        cfg = ScapyConfig()
        assert cfg.interface == "eth0"
        assert cfg.packet_trigger == 10
        assert cfg.time_trigger == 3.0
        assert cfg.bpf_filter == ""


class TestXGBoostConfig:
    def test_defaults(self):
        cfg = XGBoostConfig()
        assert cfg.threshold_high == 0.9
        assert cfg.threshold_low == 0.5
        assert cfg.anomaly_threshold == 0.75

    def test_custom_thresholds(self):
        cfg = XGBoostConfig(threshold_high=0.95, threshold_low=0.4, anomaly_threshold=0.8)
        assert cfg.threshold_high == 0.95
        assert cfg.threshold_low == 0.4
        assert cfg.anomaly_threshold == 0.8


class TestLLMConfig:
    def test_defaults_api_mode(self):
        """API 模式默认值"""
        with patch.dict(os.environ, {"LLM_API_KEY": "test-key"}, clear=False):
            cfg = LLMConfig(use_api=True)
            assert cfg.use_api is True
            assert cfg.api_key == "test-key"

    def test_api_key_from_env(self):
        """api_key 应从环境变量读取"""
        with patch.dict(os.environ, {"LLM_API_KEY": "env-key-123"}, clear=False):
            cfg = LLMConfig(use_api=True, api_key=None)
            assert cfg.api_key == "env-key-123"

    def test_explicit_api_key_overrides_env(self):
        """显式传入的 api_key 应优先于环境变量"""
        with patch.dict(os.environ, {"LLM_API_KEY": "env-key"}, clear=False):
            cfg = LLMConfig(use_api=True, api_key="explicit-key")
            assert cfg.api_key == "explicit-key"

    def test_local_mode_no_api_key_needed(self):
        """本地模式不需要 API key"""
        cfg = LLMConfig(use_api=False)
        assert cfg.use_api is False


class TestSafeInt:
    def test_valid_int(self):
        with patch.dict(os.environ, {"TEST_INT": "42"}, clear=False):
            assert _safe_int("TEST_INT", 0) == 42

    def test_missing_env_returns_default(self):
        assert _safe_int("NONEXISTENT_VAR_XYZ", 99) == 99

    def test_invalid_value_returns_default(self):
        with patch.dict(os.environ, {"TEST_BAD_INT": "not_a_number"}, clear=False):
            assert _safe_int("TEST_BAD_INT", 10) == 10


class TestSafeFloat:
    def test_valid_float(self):
        with patch.dict(os.environ, {"TEST_FLOAT": "3.14"}, clear=False):
            assert abs(_safe_float("TEST_FLOAT", 0.0) - 3.14) < 0.001

    def test_missing_env_returns_default(self):
        assert _safe_float("NONEXISTENT_VAR_XYZ", 1.5) == 1.5

    def test_invalid_value_returns_default(self):
        with patch.dict(os.environ, {"TEST_BAD_FLOAT": "abc"}, clear=False):
            assert _safe_float("TEST_BAD_FLOAT", 2.0) == 2.0


class TestSystemConfig:
    def test_defaults(self):
        """所有子配置应自动初始化"""
        cfg = SystemConfig()
        assert isinstance(cfg.redis, RedisConfig)
        assert isinstance(cfg.suricata, SuricataConfig)
        assert isinstance(cfg.scapy, ScapyConfig)
        assert isinstance(cfg.xgboost, XGBoostConfig)
        assert isinstance(cfg.llm, LLMConfig)
        assert cfg.log_level == "INFO"

    def test_from_env(self, tmp_path):
        """from_env 应从 .env 文件加载配置"""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "REDIS_HOST=redis.test\n"
            "REDIS_PORT=6380\n"
            "SCAPY_INTERFACE=wlan0\n"
            "LOG_LEVEL=DEBUG\n"
        )

        # 清理可能存在的环境变量
        env_keys = ["REDIS_HOST", "REDIS_PORT", "SCAPY_INTERFACE", "LOG_LEVEL"]
        saved = {k: os.environ.pop(k, None) for k in env_keys}

        try:
            cfg = SystemConfig.from_env(str(env_file))
            assert cfg.redis.host == "redis.test"
            assert cfg.redis.port == 6380
            assert cfg.scapy.interface == "wlan0"
            assert cfg.log_level == "DEBUG"
        finally:
            # 恢复环境变量
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
                elif k in os.environ:
                    del os.environ[k]


class TestLoadEnvFile:
    def test_nonexistent_file(self):
        """不存在的文件不应报错"""
        load_env_file("/nonexistent/path/.env")  # 不应抛异常

    def test_loads_variables(self, tmp_path):
        """应加载变量到 os.environ"""
        env_file = tmp_path / ".env"
        env_file.write_text("TEST_LOAD_VAR=hello_world\n")

        # 确保变量不存在
        os.environ.pop("TEST_LOAD_VAR", None)

        try:
            load_env_file(str(env_file))
            assert os.environ.get("TEST_LOAD_VAR") == "hello_world"
        finally:
            os.environ.pop("TEST_LOAD_VAR", None)

    def test_skips_comments_and_empty_lines(self, tmp_path):
        """应跳过注释和空行"""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# This is a comment\n"
            "\n"
            "TEST_COMMENT_VAR=value\n"
            "# Another comment\n"
        )

        os.environ.pop("TEST_COMMENT_VAR", None)

        try:
            load_env_file(str(env_file))
            assert os.environ.get("TEST_COMMENT_VAR") == "value"
        finally:
            os.environ.pop("TEST_COMMENT_VAR", None)

    def test_env_var_takes_priority(self, tmp_path):
        """已存在的环境变量不应被 .env 覆盖"""
        env_file = tmp_path / ".env"
        env_file.write_text("TEST_PRIORITY_VAR=from_file\n")

        os.environ["TEST_PRIORITY_VAR"] = "from_env"

        try:
            load_env_file(str(env_file))
            assert os.environ["TEST_PRIORITY_VAR"] == "from_env"
        finally:
            os.environ.pop("TEST_PRIORITY_VAR", None)
