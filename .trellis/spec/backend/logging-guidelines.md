# Logging Guidelines

> How logging is done in OwlSight-IDS.

---

## Overview

OwlSight-IDS uses Python's built-in `logging` module with a custom `setup_logger()` helper.
All modules follow the same format and tagging conventions for consistent, parseable output.

---

## Logger Setup

Every module creates its logger through `src/utils.py`:

```python
from ..utils import setup_logger

class ModuleName:
    def __init__(self, ...):
        self.logger = setup_logger("ModuleName")
```

`setup_logger()` creates a `StreamHandler` with the format:
```
[2026-04-30 22:15:03] [ModuleName] [INFO] message here
```

---

## Log Levels

| Level | When to Use | Example |
|-------|------------|---------|
| `DEBUG` | Per-packet/per-event detail, LRU eviction, scan results | `[LRU] evicting oldest flow` |
| `INFO` | Module lifecycle, per-flow analysis results, periodic stats | `[DUAL-MODEL] flow analysis complete` |
| `WARNING` | Decision outcomes (BLOCK/0DAY-HUNT), queue backlog, rate limiting | `[BLOCK] blocking high-risk flow` |
| `ERROR` | Redis failures, model inference failures, API call failures | `Redis connection failed` |
| `CRITICAL` | Repeated failures requiring reconnect, system-level failures | `Redis consecutive failures, rebuilding` |

---

## Tag Convention

Use `[BRACKET_PREFIX]` tags to categorize log messages by subsystem:

| Tag | Module | Meaning |
|-----|--------|---------|
| `[ALERT]` | Suricata | Suricata rule triggered |
| `[PUB/SUB]` | Suricata | Early Abort broadcast |
| `[DUAL-MODEL]` | ML | Dual-model inference result |
| `[Early Abort]` | ML | Suricata alert killed flow capture |
| `[LRU]` | ML | Memory limit eviction |
| `[BLOCK]` | Router | Decision: block |
| `[PASS]` | Router | Decision: pass |
| `[0DAY-HUNT]` | Router | Decision: zero-day candidate |
| `[SUSPICIOUS]` | Router | Decision: gray-zone |
| `[UNKNOWN]` | Router | Decision: fallback (should not happen) |
| `[QUEUE]` | Router | LLM task enqueued |
| `[ORPHAN]` | Router | Orphan task detected + re-enqueued |
| `[STATS-WINDOW]` | Router | Per-minute window stats |
| `[STATS-GLOBAL]` | Router | Cumulative stats |
| `[QUEUE-ALERT]` | LLM | Queue backlog warning |
| `[WORKER]` | LLM | Task processing start |
| `[LLM]` | LLM | LLM analysis complete |
| `[STATS]` | LLM | LLM consumer stats |

---

## What to Log

**Always log**:
- Module start/stop lifecycle events
- Every detection decision (BLOCK/PASS/ZERODAY_HUNT/LLM_ANALYZE)
- Every LLM verdict (verdict + severity + confidence)
- Redis connection state changes (connect/disconnect/reconnect)
- Queue health: backlog alerts (when queue > 50 or > 100)
- Periodic stats (every 60s window for Router, every 30s health check for LLM)

**Log at DEBUG only**:
- Per-packet processing details
- LRU eviction events
- Redis SCAN iteration counts
- Pub/Sub message receipt

---

## What NOT to Log

- **Raw packet payloads** — privacy and log volume concerns
- **API keys or secrets** — even partially masked
- **Full Redis key scans** — can produce thousands of lines
- **Per-feature JSON dumps** in INFO level — use DEBUG or omit
- **Expected rate-limit waits** — only log actual violations, not routine waits

---

## Anti-Patterns

1. **`print()` instead of `self.logger`** — no timestamps, no level control, no format consistency
2. **Logging in tight loops without level guard** — `self.logger.debug(f"...")` in a per-packet handler can be expensive even when DEBUG is off; guard with `if self.logger.isEnabledFor(logging.DEBUG)`
3. **Inconsistent tag format** — always use `[TAG]` with uppercase inside brackets
4. **Logging the same error repeatedly** — use a counter and log the summary, not each occurrence
