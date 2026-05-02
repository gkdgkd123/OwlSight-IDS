# Backend Development Guidelines

> OwlSight-IDS backend conventions for AI agents and new developers.

---

## Overview

OwlSight-IDS is a real-time network IDS with a **triple-layer cooperative architecture**:
- **L0 (Rule Engine)**: Suricata signature detection
- **L1 (Machine Learning)**: XGBoost + Isolation Forest dual-model inference
- **L2 (Semantic Analysis)**: LLM deep threat analysis

All modules communicate through **Redis** (state hub + message queue).
Each module runs in its own **daemon thread**.

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Module layout, naming conventions, import rules | Filled |
| [Redis Guidelines](./database-guidelines.md) | Key schema, TTL strategy, pipeline patterns, connection factory | Filled |
| [Error Handling](./error-handling.md) | Catch-log-continue pattern, retry strategies, graceful degradation | Filled |
| [Logging Guidelines](./logging-guidelines.md) | Tag convention, log levels, what to log/skip | Filled |
| [Quality Guidelines](./quality-guidelines.md) | Thread safety, required/forbidden patterns, code review checklist | Filled |
| [ML Guidelines](./ml-guidelines.md) | XGBoost/IForest dual-model, feature vector, score normalization | Filled |
| [LLM Guidelines](./llm-guidelines.md) | Prompt template, API calling, result schema, rate limiting | Filled |

---

## Pre-Development Checklist

Before writing or modifying code in this project:

- [ ] Read the relevant spec file(s) for the layer you're working on
- [ ] Check [Directory Structure](./directory-structure.md) for where new files should go
- [ ] Verify your Redis operations follow [Redis Guidelines](./database-guidelines.md)
- [ ] Ensure thread safety per [Quality Guidelines](./quality-guidelines.md)
- [ ] Use `[TAG]` logging per [Logging Guidelines](./logging-guidelines.md)
- [ ] Wrap external calls (Redis, LLM API) per [Error Handling](./error-handling.md)

---

## Quality Check

After implementation, verify:

- [ ] All shared state protected by `threading.Lock`
- [ ] Redis connections via `RedisConnectionFactory` (no direct `redis.Redis()`)
- [ ] No `signal.signal()` in non-main threads
- [ ] Module `stop()` closes all connections
- [ ] External input sanitized before use
- [ ] Log messages use `[TAG]` convention
- [ ] No hardcoded paths or thresholds (use config dataclasses)
