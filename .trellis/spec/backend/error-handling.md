# Error Handling

> How errors are caught, logged, and recovered in OwlSight-IDS.

---

## Overview

OwlSight-IDS is a long-running real-time system. The #1 priority is **never crash the detection loop**.
Errors are caught at the module boundary, logged with context, and the system continues.

---

## Core Principle

**Catch wide, log rich, continue running.** A single malformed packet or Redis timeout must never kill a module thread.

---

## Error Handling Patterns

### Pattern 1: Module-level try-except (defense in depth)

Every module's `start()` wraps its main loop in a broad try-except:

```python
# Real pattern from suricata_monitor.py
def start(self):
    self.running = True
    try:
        self._tail_file()
    except KeyboardInterrupt:
        self.logger.info("received interrupt, stopping")
    finally:
        self.stop()
```

### Pattern 2: Per-event try-except (inner loop)

Individual event processing is wrapped so one bad event doesn't kill the loop:

```python
# Real pattern from suricata_monitor.py
while self.running:
    line = f.readline()
    try:
        event = json.loads(line.strip())
        event_type = event.get("event_type", "")
        if event_type == "alert":
            self._process_alert(event)
    except json.JSONDecodeError as e:
        self.logger.warning(f"JSON parse failed: {e}")
    except Exception as e:
        self.logger.error(f"Event processing failed: {e}")
```

### Pattern 3: Redis failure with retry (reconnect)

For Redis connection failures during the main loop, use exponential backoff + auto-reconnect:

```python
# Real pattern from llm_analyzer.py
except (redis.ConnectionError, redis.TimeoutError) as e:
    consecutive_errors += 1
    self.logger.error(f"Redis connection error (attempt {consecutive_errors}): {e}")

    if consecutive_errors >= max_consecutive_errors:
        # Rebuild connection
        self.redis_client = RedisConnectionFactory.get_client_with_retry(self.config)
        consecutive_errors = 0
    else:
        backoff = min(2 ** consecutive_errors, 30)
        time.sleep(backoff)
```

### Pattern 4: Redis Pipeline for atomicity

Multi-field Redis writes use Pipeline to prevent partial writes:

```python
# Real pattern from early_flow_xgb.py
pipe = self.redis_client.pipeline()
pipe.hset(flow_key, "xgb_score", str(xgb_score))
pipe.hset(flow_key, "anomaly_score", str(anomaly_score))
pipe.hset(flow_key, "features", json.dumps(features))
pipe.expire(flow_key, self.redis_config.ttl)
pipe.execute()
```

### Pattern 5: Graceful degradation

When models fail to load, fall back to heuristic mode rather than crash:

```python
# Real pattern from early_flow_xgb.py
def _load_xgb_model(self):
    try:
        model = xgb.Booster()
        model.load_model(str(model_path))
        return model
    except Exception as e:
        self.logger.error(f"XGBoost load failed: {e}")
        return None  # Falls back to _heuristic_xgb()
```

---

## Error Propagation Rules

| Layer | Strategy | Example |
|-------|----------|---------|
| Packet processing | Catch + log + continue | Bad packet → skip, next packet |
| Redis operation | Catch + log + retry | Timeout → backoff + reconnect |
| Model inference | Catch + fallback to heuristic | Model error → return 0.5 |
| LLM API call | Catch + requeue with retry_count | API error → retry up to 3x |
| File I/O (eve.json) | Catch + stop module | Missing file → module stops |

---

## Retry Strategy

| Component | Max Retries | Backoff | Escalation |
|-----------|-------------|---------|------------|
| Redis connection | 3 | Exponential (1s, 2s, 4s) | raise ConnectionError |
| Redis runtime reconnect | 5 consecutive | Exponential (2^n, max 30s) | Rebuild client |
| LLM API call | 3 | No backoff (rate-limited) | Move to `llm_failed_queue` |

---

## What NOT to Do

1. **Never use bare `except:`** — always catch specific exceptions or at minimum `Exception`
2. **Never silently swallow errors** — every catch block must log
3. **Never call `signal.signal()` in non-main threads** — raises `ValueError`; use `threading.Event` instead
4. **Never let Redis Pub/Sub errors kill the main flow** — Pub/Sub is best-effort
5. **Never retry indefinitely** — always have a max retry count and escalation path

---

## Common Mistakes

1. **Forgetting to close Redis connections in `stop()`** — causes connection pool exhaustion on restart
2. **Using `self.running = False` without acquiring a lock** — race condition between the main loop and the stop signal
3. **Logging full exception tracebacks in hot loops** — floods logs; use `self.logger.debug()` for expected errors
