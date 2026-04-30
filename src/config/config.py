"""
系统配置文件

支持从环境变量或 .env 文件加载配置
使用方法：
    1. 复制 .env.example 为 .env
    2. 填入实际配置值
    3. 使用 SystemConfig.from_env() 加载配置
"""
import os
import logging
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

# 配置日志
logger = logging.getLogger(__name__)


def load_env_file(env_path: str = ".env"):
    """
    加载 .env 文件到环境变量

    Args:
        env_path: .env 文件路径，默认为项目根目录的 .env
    """
    env_file = Path(env_path)

    if not env_file.exists():
        logger.debug(f".env 文件不存在: {env_file.absolute()}")
        return

    logger.info(f"加载配置文件: {env_file.absolute()}")

    with open(env_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue

            # 解析 KEY=VALUE
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # 只在环境变量未设置时才加载（环境变量优先级更高）
                if key and key not in os.environ:
                    os.environ[key] = value
                    logger.debug(f"加载配置: {key}={value[:20]}..." if len(value) > 20 else f"加载配置: {key}={value}")


def _safe_int(env_var: str, default: int) -> int:
    """安全地从环境变量读取整数"""
    try:
        value = os.getenv(env_var)
        if value is None:
            return default
        return int(value)
    except ValueError:
        logger.warning(f"环境变量 {env_var}={os.getenv(env_var)} 格式错误，使用默认值 {default}")
        return default


def _safe_float(env_var: str, default: float) -> float:
    """安全地从环境变量读取浮点数"""
    try:
        value = os.getenv(env_var)
        if value is None:
            return default
        return float(value)
    except ValueError:
        logger.warning(f"环境变量 {env_var}={os.getenv(env_var)} 格式错误，使用默认值 {default}")
        return default


@dataclass
class RedisConfig:
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    ttl: int = 60  # 60 秒，给 LLM 分析留足时间


@dataclass
class SuricataConfig:
    eve_json_path: str = "/var/log/suricata/eve.json"
    tail_interval: float = 0.1


@dataclass
class ScapyConfig:
    interface: str = "eth0"
    pcap_file: str = ""  # 如果设置，从 pcap 文件回放而不是实时捕获
    packet_trigger: int = 10
    time_trigger: float = 3.0
    bpf_filter: str = ""


@dataclass
class XGBoostConfig:
    model_path: str = "./src/models/xgb_model.json"
    threshold_high: float = 0.9
    threshold_low: float = 0.5
    anomaly_threshold: float = 0.75


@dataclass
class LLMConfig:
    # API 模式配置
    use_api: bool = True  # True: 使用 API, False: 使用本地模型
    api_base_url: str = "https://new.timefiles.online/v1"
    api_key: Optional[str] = None  # 从环境变量 LLM_API_KEY 读取
    api_model: str = "claude-opus-4-6"

    # 本地模型配置（use_api=False 时使用）
    model_path: str = "./models/Qwen-3B"
    vector_db_path: str = "./src/models/vector_db"
    use_rag: bool = False  # API 模式下不使用 RAG
    max_length: int = 512

    def __post_init__(self):
        # 延迟验证：只在使用 API 时从环境变量读取
        if self.use_api and self.api_key is None:
            self.api_key = os.getenv("LLM_API_KEY")
            # 不在初始化时抛异常，延迟到实际使用时检查
            if not self.api_key:
                logger.warning(
                    "使用 API 模式但未设置环境变量 LLM_API_KEY，"
                    "LLM 功能将无法使用。请设置: export LLM_API_KEY=your_key"
                )


@dataclass
class SystemConfig:
    redis: RedisConfig = None
    suricata: SuricataConfig = None
    scapy: ScapyConfig = None
    xgboost: XGBoostConfig = None
    llm: LLMConfig = None
    log_level: str = "INFO"

    def __post_init__(self):
        if self.redis is None:
            self.redis = RedisConfig()
        if self.suricata is None:
            self.suricata = SuricataConfig()
        if self.scapy is None:
            self.scapy = ScapyConfig()
        if self.xgboost is None:
            self.xgboost = XGBoostConfig()
        if self.llm is None:
            self.llm = LLMConfig()

    @classmethod
    def from_env(cls, env_file: str = ".env"):
        """
        从环境变量或 .env 文件加载配置

        Args:
            env_file: .env 文件路径，默认为项目根目录的 .env

        Returns:
            SystemConfig 实例

        使用示例:
            # 从 .env 文件加载
            config = SystemConfig.from_env()

            # 从指定文件加载
            config = SystemConfig.from_env("config/production.env")
        """
        # 加载 .env 文件
        load_env_file(env_file)

        return cls(
            redis=RedisConfig(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=_safe_int("REDIS_PORT", 6379),
                db=_safe_int("REDIS_DB", 0),
                password=os.getenv("REDIS_PASSWORD"),
                ttl=_safe_int("REDIS_TTL", 60),
            ),
            suricata=SuricataConfig(
                eve_json_path=os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"),
                tail_interval=_safe_float("SURICATA_TAIL_INTERVAL", 0.1),
            ),
            scapy=ScapyConfig(
                interface=os.getenv("SCAPY_INTERFACE", "eth0"),
                packet_trigger=_safe_int("SCAPY_PACKET_TRIGGER", 10),
                time_trigger=_safe_float("SCAPY_TIME_TRIGGER", 3.0),
                bpf_filter=os.getenv("SCAPY_BPF_FILTER", ""),
            ),
            xgboost=XGBoostConfig(
                model_path=os.getenv("XGB_MODEL_PATH", "./src/models/xgb_model.json"),
                threshold_high=_safe_float("XGB_THRESHOLD_HIGH", 0.9),
                threshold_low=_safe_float("XGB_THRESHOLD_LOW", 0.5),
                anomaly_threshold=_safe_float("ANOMALY_THRESHOLD", 0.75),
            ),
            llm=LLMConfig(
                use_api=os.getenv("LLM_USE_API", "true").lower() == "true",
                api_base_url=os.getenv("LLM_API_BASE_URL", "https://new.timefiles.online/v1"),
                api_model=os.getenv("LLM_API_MODEL", "claude-opus-4-6"),
                model_path=os.getenv("LLM_MODEL_PATH", "./models/Qwen-3B"),
                vector_db_path=os.getenv("LLM_VECTOR_DB_PATH", "./src/models/vector_db"),
                use_rag=os.getenv("LLM_USE_RAG", "false").lower() == "true",
                max_length=_safe_int("LLM_MAX_LENGTH", 512),
                # api_key 由 LLMConfig.__post_init__ 自动从环境变量读取
            ),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )
