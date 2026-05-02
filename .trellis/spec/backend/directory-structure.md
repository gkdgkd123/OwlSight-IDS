# Directory Structure

> How OwlSight-IDS code is organized.

---

## Overview

OwlSight-IDS is a single-package Python project with a **layered modular architecture**.
Each detection layer (L0/L1/L2) maps to a module under `src/modules/`.
Redis is the shared state hub; configuration is centralized in `src/config/`.

---

## Directory Layout

```
OwlSight-IDS/
├── src/                          # Main package
│   ├── __init__.py               # Version metadata
│   ├── main_realtime.py          # Entry point: thread orchestration, signal handling
│   ├── utils.py                  # Shared utilities (five-tuple key, logger, sanitizer)
│   ├── config/
│   │   ├── __init__.py
│   │   ├── config.py             # Dataclass configs + from_env() loader
│   │   └── redis_factory.py      # Redis connection pool singleton
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── suricata_monitor.py   # Module 1: L0 rule engine (eve.json tailing)
│   │   ├── early_flow_xgb.py     # Module 2: L1 feature extraction + dual-model ML
│   │   ├── intelligent_router.py # Module 3: L1 decision tree (producer)
│   │   └── llm_analyzer.py       # Module 4: L2 LLM semantic analysis (consumer)
│   ├── prompts/
│   │   └── llm_analyst.md        # LLM system prompt template (string.Template)
│   └── models/                   # Pre-trained model artifacts
│       ├── xgb_model.json        # XGBoost model
│       ├── iforest_model.pkl     # Isolation Forest model
│       ├── iforest_info.json     # Anomaly score percentiles
│       ├── scaler.pkl            # StandardScaler for IForest
│       └── training_dataset.csv  # Training reference
├── scripts/                      # Offline tooling (not imported by src/)
│   ├── preprocess_cicids2017.py  # Dataset preprocessing
│   ├── train_xgboost.py          # XGBoost training
│   ├── train_iforest.py          # Isolation Forest training
│   ├── calibrate_iforest.py      # Anomaly score calibration
│   └── generate_finetune_data.py # LLM fine-tune data generation
├── tests/                        # Pytest test suite
│   ├── conftest.py               # Shared fixtures
│   ├── test_unit_*.py            # Unit tests (no external deps)
│   ├── test_integration*.py      # Integration tests (may need Redis)
│   └── test_e2e_smoke.py         # End-to-end smoke test
├── data/                         # Sample data (pcap, eve.json, datasets)
├── docs/                         # Architecture docs, test reports
├── .env.example                  # Environment template (safe to commit)
├── .env                          # Actual secrets (gitignored)
├── run.py                        # One-click startup script
├── redis_server.bat              # Windows Redis startup helper
├── requirements.txt              # Python dependencies
└── pytest.ini                    # Pytest configuration
```

---

## Module Organization

### Naming Convention

- **Module files**: `snake_case.py`, named after their detection layer role
- **Class names**: `PascalCase` (e.g., `SuricataMonitor`, `EarlyFlowDualModel`, `IntelligentRouter`, `LLMAnalyzer`)
- **Config dataclasses**: `PascalCaseConfig` suffix (e.g., `RedisConfig`, `XGBoostConfig`)

### Module Pattern

Every module follows the same structural contract:

```python
class ModuleName:
    def __init__(self, redis_config, ...other_configs):
        # 1. Store configs
        # 2. Initialize logger via setup_logger()
        # 3. Get Redis client via RedisConnectionFactory
        # 4. Initialize module-specific state

    def start(self):
        # Entry point called by main_realtime.py's thread
        self.running = True
        # Main loop or event listener

    def stop(self):
        # Graceful shutdown: close Redis, release resources
        self.running = False
```

### Entry Point Pattern

`main_realtime.py` creates a `SemFlowIDS` class that:
1. Instantiates all 4 modules with config
2. Spawns one `threading.Thread(daemon=True)` per module
3. Registers `signal.signal(SIGINT/SIGTERM)` handlers in the **main thread only**

---

## Naming Conventions

| Scope | Convention | Example |
|-------|-----------|---------|
| Files | `snake_case.py` | `early_flow_xgb.py` |
| Classes | `PascalCase` | `DualModelInference` |
| Functions/methods | `snake_case` | `compute_features()` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_ACTIVE_FLOWS` |
| Private methods | `_leading_underscore` | `_predict_xgb()` |
| Redis keys | `ip:port-ip:port-PROTO` | Five-tuple format |
| Redis Hash fields | `snake_case` | `xgb_score`, `anomaly_score` |
| Log tags | `[BRACKET_PREFIX]` | `[BLOCK]`, `[0DAY-HUNT]`, `[STATS-WINDOW]` |

---

## Key Invariants

1. **No circular imports**: `modules/` never imports from `main_realtime.py`; `config/` never imports from `modules/`
2. **Utils is leaf**: `utils.py` has zero project imports — only stdlib
3. **Models are static artifacts**: `src/models/` contains pickled/JSON model files, never Python code
4. **Scripts are standalone**: `scripts/` may import from `src/` but `src/` never imports from `scripts/`
5. **One module per thread**: Each module's `start()` method runs in its own daemon thread
