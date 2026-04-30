"""
OwlSight-IDS 测试共享 Fixtures

提供 MockRedis、配置工厂、临时 .env 等可复用 fixture。
所有 fixture 自动清理，测试间完全隔离。
"""
import os
import json
import time
import pytest
import threading
from unittest.mock import MagicMock, patch
from typing import Dict, Any, Optional, List
from collections import OrderedDict


# ---------------------------------------------------------------------------
# MockRedis — 完整的内存 Redis 模拟
# ---------------------------------------------------------------------------

class MockRedis:
    """线程安全的内存 Redis 模拟，覆盖 OwlSight 使用的所有操作"""

    def __init__(self, **kwargs):
        self._data: Dict[str, Dict[str, str]] = {}
        self._lists: Dict[str, List[str]] = {}
        self._ttls: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._pubsub_channels: Dict[str, List] = {}

    # --- Connection ---
    def ping(self) -> bool:
        return True

    def close(self):
        pass

    # --- Hash ---
    def hset(self, name: str, key: str = None, value: str = None, mapping: Dict = None) -> int:
        with self._lock:
            if name not in self._data:
                self._data[name] = {}
            if mapping:
                for k, v in mapping.items():
                    self._data[name][str(k)] = str(v)
                return len(mapping)
            if key is not None:
                self._data[name][str(key)] = str(value)
                return 1
            return 0

    def hget(self, name: str, key: str) -> Optional[str]:
        with self._lock:
            return self._data.get(name, {}).get(key)

    def hgetall(self, name: str) -> Dict[str, str]:
        with self._lock:
            return dict(self._data.get(name, {}))

    # --- Key ---
    def delete(self, *names: str) -> int:
        with self._lock:
            count = 0
            for name in names:
                if name in self._data:
                    del self._data[name]
                    count += 1
                if name in self._lists:
                    del self._lists[name]
                    count += 1
            return count

    def exists(self, name: str) -> int:
        with self._lock:
            return 1 if name in self._data or name in self._lists else 0

    def expire(self, name: str, time_seconds: int) -> bool:
        with self._lock:
            self._ttls[name] = time.time() + time_seconds
            return True

    def scan(self, cursor: int = 0, match: str = "*", count: int = 500):
        """简化 SCAN — 一次返回所有匹配 key"""
        import fnmatch
        with self._lock:
            all_keys = list(self._data.keys())
            matched = [k for k in all_keys if fnmatch.fnmatch(k, match)]
            return 0, matched

    # --- List ---
    def lpush(self, name: str, *values: str) -> int:
        with self._lock:
            if name not in self._lists:
                self._lists[name] = []
            for v in values:
                self._lists[name].insert(0, v)
            return len(self._lists[name])

    def rpush(self, name: str, *values: str) -> int:
        with self._lock:
            if name not in self._lists:
                self._lists[name] = []
            self._lists[name].extend(values)
            return len(self._lists[name])

    def brpop(self, keys, timeout: int = 0):
        """非阻塞版本 — 立即返回或 None"""
        if isinstance(keys, str):
            keys = [keys]
        with self._lock:
            for key in keys:
                if key in self._lists and self._lists[key]:
                    val = self._lists[key].pop()
                    return (key, val)
        return None

    def llen(self, name: str) -> int:
        with self._lock:
            return len(self._lists.get(name, []))

    def lindex(self, name: str, index: int) -> Optional[str]:
        with self._lock:
            lst = self._lists.get(name, [])
            if 0 <= index < len(lst):
                return lst[index]
            return None

    # --- Pub/Sub ---
    def publish(self, channel: str, message: str) -> int:
        with self._lock:
            listeners = self._pubsub_channels.get(channel, [])
            for q in listeners:
                q.append({"type": "message", "channel": channel, "data": message})
            return len(listeners)

    def pubsub(self):
        return MockPubSub(self)

    # --- Pipeline ---
    def pipeline(self):
        return MockPipeline(self)


class MockPubSub:
    """MockRedis 的 Pub/Sub 模拟"""

    def __init__(self, redis_instance: MockRedis):
        self._redis = redis_instance
        self._queue: List[Dict] = []
        self._channels: List[str] = []

    def subscribe(self, *channels: str):
        for ch in channels:
            self._channels.append(ch)
            with self._redis._lock:
                if ch not in self._redis._pubsub_channels:
                    self._redis._pubsub_channels[ch] = []
                self._redis._pubsub_channels[ch].append(self._queue)

    def unsubscribe(self, *channels: str):
        pass

    def close(self):
        pass

    def listen(self):
        """生成器 — 在测试中通常不会真正阻塞"""
        yield {"type": "subscribe", "channel": "", "data": 1}
        while True:
            if self._queue:
                yield self._queue.pop(0)
            else:
                break


class MockPipeline:
    """MockRedis 的 Pipeline 模拟 — 收集命令后批量执行"""

    def __init__(self, redis_instance: MockRedis):
        self._redis = redis_instance
        self._commands: List = []

    def hset(self, name, key=None, value=None, mapping=None):
        self._commands.append(("hset", name, key, value, mapping))
        return self

    def expire(self, name, time_seconds):
        self._commands.append(("expire", name, time_seconds))
        return self

    def delete(self, *names):
        self._commands.append(("delete", names))
        return self

    def lpush(self, name, *values):
        self._commands.append(("lpush", name, values))
        return self

    def execute(self):
        results = []
        for cmd in self._commands:
            if cmd[0] == "hset":
                _, name, key, value, mapping = cmd
                results.append(self._redis.hset(name, key, value, mapping=mapping))
            elif cmd[0] == "expire":
                _, name, ts = cmd
                results.append(self._redis.expire(name, ts))
            elif cmd[0] == "delete":
                _, names = cmd
                results.append(self._redis.delete(*names))
            elif cmd[0] == "lpush":
                _, name, values = cmd
                results.append(self._redis.lpush(name, *values))
        self._commands.clear()
        return results

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_redis():
    """提供一个干净的 MockRedis 实例"""
    return MockRedis()


@pytest.fixture
def redis_config():
    """标准 Redis 配置"""
    from src.config.config import RedisConfig
    return RedisConfig(host="localhost", port=6379, db=0, password=None, ttl=60)


@pytest.fixture
def xgb_config():
    """标准 XGBoost 配置"""
    from src.config.config import XGBoostConfig
    return XGBoostConfig(
        model_path="./src/models/xgb_model.json",
        threshold_high=0.9,
        threshold_low=0.5,
        anomaly_threshold=0.75,
    )


@pytest.fixture
def llm_config():
    """标准 LLM 配置（API 模式，使用 fake key）"""
    from src.config.config import LLMConfig
    return LLMConfig(
        use_api=True,
        api_base_url="https://fake.api.test/v1",
        api_key="test-key-fake-12345",
        api_model="test-model",
    )


@pytest.fixture
def suricata_config(tmp_path):
    """Suricata 配置（使用临时 eve.json）"""
    from src.config.config import SuricataConfig
    eve_path = tmp_path / "eve.json"
    eve_path.touch()
    return SuricataConfig(eve_json_path=str(eve_path))


@pytest.fixture
def sample_flow_features():
    """标准测试流量特征"""
    return {
        "packet_count": 10,
        "bytes_sent": 640.0,
        "duration": 0.05,
        "iat_mean": 0.005,
        "iat_std": 0.001,
        "iat_min": 0.003,
        "iat_max": 0.008,
        "pkt_len_mean": 64.0,
        "pkt_len_std": 10.0,
        "pkt_len_min": 40.0,
        "pkt_len_max": 100.0,
        "tcp_flags_count": 10,
        "syn_count": 10,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
        "bytes_per_second": 12800.0,
        "packets_per_second": 200.0,
    }


@pytest.fixture
def sample_flow_key():
    """标准测试五元组 key"""
    return "192.168.1.100:12345-10.0.0.1:80-TCP"
