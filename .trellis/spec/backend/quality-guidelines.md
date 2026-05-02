# Quality Guidelines

> Code quality standards for OwlSight-IDS development.

---

## Overview

OwlSight-IDS is a **real-time security system**. Correctness and reliability outweigh elegance.
Code must be safe-by-default, thread-aware, and resistant to external failures.

---

## Required Patterns

### 1. Thread Safety

All shared state must be protected by locks:

```python
# Real pattern from early_flow_xgb.py
self.lock = threading.Lock()

with self.lock:
    if flow_key not in self.active_flows:
        self.active_flows[flow_key] = FlowStatistics()
    flow_stats = self.active_flows[flow_key]
```

```python
# Real pattern from llm_analyzer.py
self.stats_lock = threading.Lock()

with self.stats_lock:
    self.stats['total_processed'] += 1
```

### 2. Redis Factory

All Redis connections must go through `RedisConnectionFactory`:

```python
from ..config.redis_factory import RedisConnectionFactory

# Shared connection pool (most modules)
self.redis_client = RedisConnectionFactory.get_client_with_retry(redis_config)

# Dedicated connection (Pub/Sub, BRPOP)
self.pubsub_client = RedisConnectionFactory.get_dedicated_client(redis_config)
```

Never create `redis.Redis(host=..., port=...)` directly in module code.

### 3. Graceful Shutdown

Every module must implement `stop()`:

```python
def stop(self):
    self.running = False
    # Close Pub/Sub connections
    try:
        self.pubsub.unsubscribe()
        self.pubsub.close()
        self.pubsub_client.close()
    except Exception:
        pass
    # Close main Redis connection
    try:
        self.redis_client.close()
    except Exception:
        pass
    # Wait for listener threads
    if self.listener_thread and self.listener_thread.is_alive():
        self.listener_thread.join(timeout=2)
```

### 4. Input Sanitization

External input (Suricata events, LLM responses) must be sanitized:

```python
from ..utils import sanitize_text

# Text fields: strip non-ASCII, enforce max length
sanitized = sanitize_text(value, max_length=200)

# Numeric fields: validate type before use
xgb_score = float(state.get("xgb_score", 0.0))
```

### 5. Config via Dataclasses

All configuration uses `@dataclass` with sensible defaults:

```python
@dataclass
class XGBoostConfig:
    model_path: str = "./src/models/xgb_model.json"
    threshold_high: float = 0.9
    threshold_low: float = 0.5
    anomaly_threshold: float = 0.75
```

Loading from environment via `SystemConfig.from_env()`.

---

## Forbidden Patterns

| Pattern | Why | Example of Violation |
|---------|-----|---------------------|
| `redis.Redis(host=...)` directly | Bypasses connection pool, DRY violation | `client = redis.Redis(host="localhost")` |
| `signal.signal()` in non-main thread | Raises `ValueError` in daemon threads | `signal.signal(SIGINT, handler)` inside `start()` |
| `redis.keys("*")` | Blocks Redis on large keyspaces | Use `redis.scan()` instead |
| `pickle.loads()` on untrusted data | Arbitrary code execution | Never pickle user/external input |
| Bare `except:` | Catches SystemExit, KeyboardInterrupt | Always use `except Exception:` minimum |
| `print()` for logging | Bypasses log framework | Use `self.logger.info()` |
| Blocking `time.sleep()` in hot path | Kills throughput | Use event-driven waits or short sleeps |
| Hardcoded model paths | Breaks on different environments | Use config dataclass + env vars |

---

## Thread Architecture Rules

1. **One daemon thread per module** — created in `main_realtime.py`, never self-spawning
2. **`signal.signal()` only in main thread** — use `threading.Event` for daemon thread shutdown
3. **Lock granularity**: lock the smallest possible critical section; never hold a lock during Redis I/O
4. **Inference outside lock**: acquire lock to read flow stats, release lock, then do ML inference

```python
# CORRECT: lock scope is minimal
with self.lock:
    flow_stats = self.active_flows[flow_key]
    should_trigger = self._should_trigger(flow_key, flow_stats)

if should_trigger:  # Outside lock
    self._process_flow(flow_key, flow_stats)
```

---

## Testing Requirements

| Type | Framework | Marker | When to Run |
|------|-----------|--------|-------------|
| Unit tests | pytest | `@pytest.mark.unit` | Every change |
| Integration tests | pytest + Redis | `@pytest.mark.integration` | Before commit |
| E2E smoke | pytest + pcap | `@pytest.mark.slow` | Before release |

Test files follow the naming: `tests/test_unit_<module>.py` for unit, `tests/test_integration*.py` for integration.

---

## Code Review Checklist

- [ ] Thread safety: shared state protected by locks
- [ ] Redis usage: all connections via `RedisConnectionFactory`
- [ ] Error handling: main loops never crash on single-event failures
- [ ] Logging: uses `[TAG]` convention, correct log level
- [ ] Config: no hardcoded paths or thresholds
- [ ] Graceful shutdown: `stop()` closes all connections and joins threads
- [ ] Sanitization: external input is sanitized before use
- [ ] No `signal.signal()` in non-main threads
