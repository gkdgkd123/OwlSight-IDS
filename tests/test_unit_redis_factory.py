"""
单元测试: Redis 连接工厂
覆盖: 连接池创建、重试逻辑、独立连接、池重置
"""
import pytest
import time
from unittest.mock import patch, MagicMock
from realtime_ids.config.config import RedisConfig
from realtime_ids.config.redis_factory import RedisConnectionFactory


@pytest.fixture(autouse=True)
def reset_factory():
    """每个测试前重置连接池单例"""
    RedisConnectionFactory.reset_pool()
    yield
    RedisConnectionFactory.reset_pool()


class TestRedisConnectionFactory:
    """Redis 连接工厂单元测试"""

    def test_get_client_returns_redis_instance(self):
        """get_client 应返回 Redis 实例"""
        config = RedisConfig(host="localhost", port=6379)
        with patch("realtime_ids.config.redis_factory.ConnectionPool") as mock_pool_cls:
            mock_pool = MagicMock()
            mock_pool_cls.return_value = mock_pool
            client = RedisConnectionFactory.get_client(config)
            assert client is not None
            mock_pool_cls.assert_called_once()

    def test_pool_is_singleton(self):
        """相同配置应复用连接池"""
        config = RedisConfig(host="localhost", port=6379)
        with patch("realtime_ids.config.redis_factory.ConnectionPool") as mock_pool_cls:
            mock_pool_cls.return_value = MagicMock()
            RedisConnectionFactory.get_client(config)
            RedisConnectionFactory.get_client(config)
            # 只应创建一次连接池
            assert mock_pool_cls.call_count == 1

    def test_pool_recreated_on_config_change(self):
        """配置变化时应重建连接池"""
        config1 = RedisConfig(host="host1", port=6379)
        config2 = RedisConfig(host="host2", port=6380)
        with patch("realtime_ids.config.redis_factory.ConnectionPool") as mock_pool_cls:
            mock_pool_cls.return_value = MagicMock()
            RedisConnectionFactory.get_client(config1)
            RedisConnectionFactory.get_client(config2)
            assert mock_pool_cls.call_count == 2

    def test_get_client_with_retry_success(self):
        """重试成功场景"""
        config = RedisConfig(host="localhost", port=6379)
        mock_client = MagicMock()
        mock_client.ping.return_value = True

        with patch.object(RedisConnectionFactory, "get_client", return_value=mock_client):
            client = RedisConnectionFactory.get_client_with_retry(config, max_retries=3)
            assert client is mock_client
            mock_client.ping.assert_called_once()

    def test_get_client_with_retry_eventual_success(self):
        """前两次失败，第三次成功"""
        import redis
        config = RedisConfig(host="localhost", port=6379)
        mock_client = MagicMock()
        mock_client.ping.side_effect = [
            redis.ConnectionError("fail 1"),
            redis.ConnectionError("fail 2"),
            True,
        ]

        with patch.object(RedisConnectionFactory, "get_client", return_value=mock_client):
            client = RedisConnectionFactory.get_client_with_retry(
                config, max_retries=3, base_backoff=0.01
            )
            assert client is mock_client
            assert mock_client.ping.call_count == 3

    def test_get_client_with_retry_all_fail(self):
        """所有重试都失败应抛异常"""
        import redis
        config = RedisConfig(host="localhost", port=6379)
        mock_client = MagicMock()
        mock_client.ping.side_effect = redis.ConnectionError("always fail")

        with patch.object(RedisConnectionFactory, "get_client", return_value=mock_client):
            with pytest.raises(redis.ConnectionError, match="仍失败"):
                RedisConnectionFactory.get_client_with_retry(
                    config, max_retries=2, base_backoff=0.01
                )

    def test_get_dedicated_client(self):
        """独立连接不共享连接池"""
        config = RedisConfig(host="localhost", port=6379)
        with patch("realtime_ids.config.redis_factory.redis.Redis") as mock_redis_cls:
            mock_redis_cls.return_value = MagicMock()
            client = RedisConnectionFactory.get_dedicated_client(config)
            assert client is not None
            # 应该直接创建 Redis 实例，不通过连接池
            mock_redis_cls.assert_called_once()
            call_kwargs = mock_redis_cls.call_args[1]
            assert "connection_pool" not in call_kwargs

    def test_reset_pool(self):
        """reset_pool 应清除单例"""
        config = RedisConfig(host="localhost", port=6379)
        with patch("realtime_ids.config.redis_factory.ConnectionPool") as mock_pool_cls:
            mock_pool = MagicMock()
            mock_pool_cls.return_value = mock_pool
            RedisConnectionFactory.get_client(config)
            assert RedisConnectionFactory._pool is not None

            RedisConnectionFactory.reset_pool()
            assert RedisConnectionFactory._pool is None
            assert RedisConnectionFactory._config is None
