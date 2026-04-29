"""
Redis 连接工厂 — 统一连接池、超时、重试、健康检查

所有模块通过此工厂获取 Redis 客户端，消除 DRY 违规。
"""
import time
import logging
import redis
from redis.connection import ConnectionPool
from typing import Optional

from .config import RedisConfig

logger = logging.getLogger(__name__)


class RedisConnectionFactory:
    """Redis 连接工厂（单例连接池）"""

    _pool: Optional[ConnectionPool] = None
    _config: Optional[RedisConfig] = None

    @classmethod
    def _ensure_pool(cls, config: RedisConfig) -> ConnectionPool:
        """获取或创建连接池（单例）"""
        # 如果配置变了或池不存在，重新创建
        if cls._pool is None or cls._config != config:
            cls._pool = ConnectionPool(
                host=config.host,
                port=config.port,
                db=config.db,
                password=config.password,
                decode_responses=True,
                max_connections=50,
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
                socket_keepalive=True,
                retry_on_timeout=True,
                health_check_interval=30,
            )
            cls._config = config
            logger.info(
                f"Redis 连接池已创建: {config.host}:{config.port}/{config.db} "
                f"(max_connections=50, timeout=5s)"
            )
        return cls._pool

    @classmethod
    def get_client(cls, config: RedisConfig) -> redis.Redis:
        """获取 Redis 客户端（共享连接池）"""
        pool = cls._ensure_pool(config)
        return redis.Redis(connection_pool=pool)

    @classmethod
    def get_client_with_retry(
        cls,
        config: RedisConfig,
        max_retries: int = 3,
        base_backoff: float = 1.0,
    ) -> redis.Redis:
        """获取 Redis 客户端，启动时带重试（指数退避）"""
        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                client = cls.get_client(config)
                client.ping()
                logger.info("Redis 连接成功 (ping OK)")
                return client
            except (redis.ConnectionError, redis.TimeoutError) as exc:
                last_error = exc
                wait = base_backoff * (2 ** (attempt - 1))
                logger.warning(
                    f"Redis 连接失败 (尝试 {attempt}/{max_retries}): {exc}，"
                    f"等待 {wait:.1f}s 后重试"
                )
                time.sleep(wait)

        raise redis.ConnectionError(
            f"Redis 连接在 {max_retries} 次尝试后仍失败: {last_error}"
        )

    @classmethod
    def get_dedicated_client(cls, config: RedisConfig) -> redis.Redis:
        """获取独立 Redis 客户端（不共享连接池，用于 Pub/Sub 等独占场景）"""
        return redis.Redis(
            host=config.host,
            port=config.port,
            db=config.db,
            password=config.password,
            decode_responses=True,
            socket_timeout=5.0,
            socket_connect_timeout=5.0,
            socket_keepalive=True,
            retry_on_timeout=True,
        )

    @classmethod
    def reset_pool(cls):
        """重置连接池（测试用）"""
        if cls._pool is not None:
            cls._pool.disconnect()
            cls._pool = None
            cls._config = None
