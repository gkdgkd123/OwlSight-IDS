# OwlSight-IDS: Real-time Malicious Traffic Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Redis](https://img.shields.io/badge/Redis-6.0%2B-red)
![Suricata](https://img.shields.io/badge/Suricata-6.0%2B-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**🦉 A Triple-Layer Cooperative Detection Architecture for 0day Threat Hunting**

[English](README.md) | [中文](README_CN.md)

</div>

---

### Overview

**OwlSight-IDS** is a real-time network intrusion detection system that combines **rule-based detection**, **machine learning inference**, and **large language model semantic analysis** to identify both known attacks and zero-day threats. The system employs a novel **triple-layer cooperative architecture** with **dual-model machine learning** to achieve high detection accuracy while maintaining low false-positive rates.

### 🌟 Highlighted Features

- **🎯 Triple-Layer Detection Architecture**
  - **L0 (Rule Engine)**: Suricata-based signature detection for rapid filtering
  - **L1 (Machine Learning)**: Dual-model cooperative inference (XGBoost + Isolation Forest)
  - **L2 (Semantic Analysis)**: Claude Opus 4.6 LLM for deep threat analysis

- **🔬 Dual-Model Cooperative Strategy**
  - **XGBoost**: Supervised learning for known attack patterns (AUC: 0.977)
  - **Isolation Forest**: Unsupervised anomaly detection for 0day candidates
  - **Synergistic Decision Tree**: Combines both models for robust classification
  - **Unique 0day Hunting**: Triggers when XGB < 0.5 (safe) AND Anomaly > 0.75 (abnormal)

- **⚡ Early Flow Detection**
  - Dual-trigger mechanism: 10 packets OR 3 seconds
  - 18-dimensional feature vector extraction
  - Sub-second latency for real-time processing
  - Memory leak prevention with automatic cleanup

- **🔄 Asynchronous Decoupled Architecture**
  - Producer-consumer pattern via Redis message queue
  - Non-blocking LLM analysis with rate limiting (10 req/min)
  - Automatic retry mechanism (max 3 retries)
  - Zero traffic detection latency from LLM processing

- **📊 Comprehensive Monitoring & Observability**
  - Time-windowed statistics (per-minute throughput display)
  - Global cumulative metrics tracking
  - Queue health monitoring with automatic alerting
  - Thread-safe statistics with proper locking

### Tech Stack

| Layer | Technology | Purpose | Notes |
|-------|-----------|---------|-------|
| L0 | Suricata 6.0+ | Rule-based detection | Signature matching |
| L1 ML | XGBoost + scikit-learn | Dual-model inference | AUC: 0.977 |
| L1 Decision | Python threading | Decision tree logic | Real-time routing |
| L2 LLM | Claude Opus 4.6 API | Semantic analysis | 0day threat hunting |
| State Hub | Redis 6.0+ | Inter-module communication | Message queue + state store |
| Feature Extraction | Scapy | Packet capture & analysis | 18-dim feature vector |

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Network Traffic                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │   Module 1: Suricata Monitor  │
         │   (L0 Rule Engine Layer)      │
         │   - Eve.json tailing          │
         │   - Alert parsing             │
         └───────────┬───────────────────┘
                     │
                     ▼
         ┌───────────────────────────────┐
         │   Module 2: Early Flow        │
         │   (L1 ML Feature Engineering) │
         │   - Scapy packet capture      │
         │   - 18-dim feature extraction │
         │   - Dual-model inference      │
         └───────────┬───────────────────┘
                     │
                     ▼
              ┌─────────────────┐
              │    Redis Hub    │ ◄─── State Sharing (TTL=60s)
              │    (Message     │      Flow metadata + decisions
              │    Broker)      │
              └──────┬──────────┘
                     │
                     ▼
         ┌───────────────────────────────┐
         │   Module 3: Intelligent       │
         │   Router (L1 Decision Tree)   │
         │   - Three-layer decision      │
         │   - scan() based scanning     │
         │   - Async queue publishing    │
         └───────────┬───────────────────┘
                     │
                     ▼
              ┌─────────────────┐
              │  llm_task_queue │ ◄─── Async Queue
              │   (Redis List)  │      Producer-Consumer
              └──────┬──────────┘
                     │
                     ▼
         ┌───────────────────────────────┐
         │   Module 4: LLM Analyzer      │
         │   (L2 Semantic Analysis)      │
         │   - BRPOP consumption         │
         │   - Rate limiting             │
         │   - Retry mechanism           │
         │   - Claude Opus API calls     │
         └───────────────────────────────┘
```

### Performance Metrics

| Component | Throughput | Latency | Bottleneck | Scalability |
|-----------|-----------|---------|-----------|-------------|
| Module 1 (Suricata) | ~10K pps | <1ms | Disk I/O | Parallel monitors |
| Module 2 (Feature) | ~5K flows/s | <10ms | CPU | GPU acceleration |
| Module 3 (Decision) | ~10K flows/s | <1ms | Redis | Cluster mode |
| Module 4 (LLM) | ~10 req/min | ~3s | API limit | Multiple workers |

### Decision Tree Logic

```
                    ┌─────────────┐
                    │  Read Flow  │
                    └──────┬──────┘
                           │
                           ▼
              ┌──────────────────────┐
              │  Already Decided?    │
              └────┬────────────┬────┘
                   │ Yes        │ No
                   ▼            ▼
                (Skip)      Continue
                           │
                           ▼
        ┌──────────────────────────────┐
        │ Layer 1: High-Risk Block    │
        │ Suricata Alert ∨ XGB > 0.9  │
        └────┬──────────────────────┬──┘
             │ Yes                  │ No
             ▼                      ▼
          BLOCK              ┌────────────────┐
                             │ Layer 2: PASS  │
                             │ XGB < 0.5 ∧    │
                             │ Anomaly < 0.75 │
                             └────┬───────┬───┘
                                  │ Yes   │ No
                                  ▼       ▼
                               PASS    Continue
                             (Delete)     │
                                         ▼
                            ┌──────────────────────┐
                            │ Layer 3: LLM Analysis│
                            │ 0DAY ∨ SUSPICIOUS    │
                            └──────┬───────────────┘
                                   │
                        ┌──────────┴──────────┐
                        ▼                     ▼
                   ZERODAY_HUNT       LLM_ANALYZE
                   (XGB<0.5 ∧          (0.5≤XGB≤0.9)
                    Anomaly>0.75)
                        │                     │
                        └──────────┬──────────┘
                                   ▼
                           ┌───────────────────┐
                           │  Redis Queue →    │
                           │ Module 4 (LLM)    │
                           └───────────────────┘
```

---

## Getting Started

### Prerequisites

- **Python**: 3.8 or higher
- **Redis**: 6.0+ (inter-module state sharing and message queue)
- **Suricata**: 6.0+ (L0 rule-based detection engine)
- **LLM API Key**: Claude Opus 4.6 (or compatible OpenAI-format API)
- **System**: Linux (recommended) / macOS / Windows

### Installation

1. **Install system dependencies**

   Ubuntu/Debian:
   ```bash
   sudo apt update
   sudo apt install -y redis-server suricata
   sudo systemctl enable --now redis-server
   ```

   macOS:
   ```bash
   brew install redis suricata
   brew services start redis
   ```

2. **Clone the repository**
   ```bash
   git clone https://github.com/gkdgkd123/OwlSight-IDS.git
   cd OwlSight-IDS
   ```

3. **Create virtual environment & install Python dependencies**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env — at minimum set your LLM_API_KEY
   ```

### Run the System

All modes are launched via a single entry point `run.py`:

```bash
# Interactive menu (guided setup)
python run.py

# Live capture + auto-launch Suricata (recommended for production)
python run.py --live --with-suricata --iface eth0

# Live capture only (Suricata already running separately)
python run.py --live --iface eth0

# Custom Suricata log directory
python run.py --live --with-suricata --suricata-log-dir /var/log/suricata

# pcap file replay with LLM limit
python run.py --pcap data/test.pcap --llm-limit 20

# pcap replay without LLM (ML-only pipeline)
python run.py --pcap data/test.pcap --llm-limit 0

# Debug logging
python run.py --live --with-suricata --log-level DEBUG
```

| Flag | Description |
|------|-------------|
| `--live` | Real-time capture from network interface |
| `--pcap FILE` | Replay from pcap file |
| `--iface IFACE` | Network interface (default: eth0) |
| `--with-suricata` | Auto-start & manage Suricata subprocess |
| `--suricata-iface IFACE` | Suricata listen interface (defaults to `--iface`) |
| `--suricata-log-dir DIR` | Suricata log directory (default: ./data/suricata_logs) |
| `--llm-limit N` | Max LLM analyses in pcap mode (default: 20, 0=disable) |
| `--log-level LEVEL` | DEBUG, INFO, WARNING, ERROR (default: INFO) |

### Verify Installation

```bash
# Check Redis connectivity
redis-cli ping   # Expected: PONG

# Check Suricata
suricata --build-info | head -3

# Check Python dependencies
python -c "import redis, scapy, xgboost, sklearn; print('OK')"

# Run test suite
python -m pytest tests/ -v
```

### Configuration Details

Create `.env` file (copy from `.env.example`):

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=
REDIS_TTL=60

# Suricata Configuration
SURICATA_EVE_PATH=/var/log/suricata/eve.json
SURICATA_TAIL_INTERVAL=0.1

# Scapy Packet Capture
SCAPY_INTERFACE=eth0
SCAPY_PACKET_TRIGGER=10          # Trigger after 10 packets
SCAPY_TIME_TRIGGER=3.0           # OR after 3 seconds

# XGBoost Model
XGB_MODEL_PATH=./src/models/xgb_model.json
XGB_THRESHOLD_HIGH=0.9           # High-risk threshold
XGB_THRESHOLD_LOW=0.5            # Low-risk threshold
ANOMALY_THRESHOLD=0.75           # Anomaly detection threshold

# LLM Configuration (Claude Opus 4.6)
LLM_USE_API=true
LLM_API_BASE_URL=https://new.timefiles.online/v1
LLM_API_KEY=your_api_key_here    # Set environment variable
LLM_API_MODEL=claude-opus-4-6

# System
LOG_LEVEL=INFO
```

---

## Project Structure

```
OwlSight-IDS/
├── src/                    # Main package
│   ├── config/
│   │   ├── config.py                # Configuration with .env support
│   │   └── redis_factory.py         # Redis connection pool factory
│   ├── modules/
│   │   ├── suricata_monitor.py      # Module 1: Rule engine (eve.json tailing)
│   │   ├── early_flow_xgb.py        # Module 2: Feature extraction & dual-model ML
│   │   ├── intelligent_router.py    # Module 3: Decision tree + LLM task producer
│   │   ├── llm_analyzer.py          # Module 4: LLM semantic analysis consumer
│   │   └── redis_manager.py         # Redis health monitoring & lifecycle mgmt
│   ├── engine.py                    # Engine: 4-module orchestrator
│   ├── suricata_launcher.py         # Suricata subprocess lifecycle manager
│   └── utils.py                     # Trace IDs, colored logging, helpers
├── scripts/
│   ├── preprocess_cicids2017.py     # CICIDS2017 dataset preprocessing
│   ├── train_xgboost.py             # XGBoost model training
│   └── train_iforest.py             # Isolation Forest model training
├── tests/                           # Comprehensive test suite
├── data/                            # Sample data and datasets
│   ├── Suricata/
│   │   ├── suricata.yaml            # Suricata configuration template
│   │   ├── classification.config    # Suricata classification rules
│   │   └── reference.config         # Suricata reference rules
│   └── suricata_logs/               # Suricata runtime logs (eve.json)
├── run.py                           # CLI entry point (live, pcap, interactive)
├── .env.example                     # Environment template (SAFE to commit)
├── .gitignore                       # Git ignore rules (protects .env)
├── requirements.txt                 # Python dependencies
└── README.md                        # This file
```

### Module Responsibilities

| Module | Input | Output | Decision |
|--------|-------|--------|----------|
| M1 Suricata | eve.json | Redis Hash | Alert flag + metadata |
| M2 Feature | Packets | Redis Hash | XGB score + Anomaly score |
| M3 Router | Redis Hash | Redis List | Decision + LLM queue |
| M4 LLM | Redis List | Redis Hash | Semantic verdict |

---

## Key Innovations

### 1. **Dual-Model Cooperative Detection**
- XGBoost identifies known attack patterns (supervised)
- Isolation Forest detects statistical anomalies (unsupervised)
- Synergistic decision tree combines both for robust classification
- **Complementary Strengths**: Handles both known and unknown threats

### 2. **0day Threat Hunting Strategy**
```
Detection Condition:
  XGB_Score < 0.5 (model thinks SAFE)
  AND
  Anomaly_Score > 0.75 (behavior is ABNORMAL)
  
  ⟹ ZERODAY_HUNT triggered
  ⟹ Deep LLM semantic analysis initiated
```

### 3. **Asynchronous Decoupled Architecture**
- **Producer (Module 3)**: Makes fast decisions, enqueues LLM tasks
- **Consumer (Module 4)**: Independently processes with rate limiting
- **Benefit**: LLM API delays (3-5s) don't block real-time detection (<1ms)
- **Scalability**: Multiple LLM workers can process queue independently

### 4. **Early Flow Detection**
- Dual-trigger: 10 packets OR 3 seconds (whichever comes first)
- 18-dimensional feature vector optimized for early detection
- Memory-efficient with automatic cleanup of stale flows

### 5. **Production-Ready Features**
- Thread-safe statistics with proper locking
- Automatic retry mechanism (max 3 retries) for failed tasks
- Queue health monitoring with alerting
- Time-windowed metrics for real-time monitoring

---

## Troubleshooting

### Redis Connection Error
```bash
# Make sure Redis is running
redis-server

# Check Redis connectivity
redis-cli ping  # Should print PONG
```

### Missing LLM API Key
```bash
# Set environment variable (Linux/Mac)
export LLM_API_KEY=your_key_here

# Set environment variable (Windows)
set LLM_API_KEY=your_key_here

# Or configure in .env file
LLM_API_KEY=your_key_here
```

### Suricata Eve.json Not Found
```bash
# Check Suricata log location
cat /var/log/suricata/eve.json

# Or configure custom path in .env
SURICATA_EVE_PATH=/custom/path/eve.json
```

---

## Performance Optimization Tips

1. **Increase Redis Memory** for higher throughput
2. **Enable XGBoost GPU Acceleration** if available
3. **Parallel Module Instances** for distributed detection
4. **Batch LLM Requests** to optimize API usage

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Citation

If you use OwlSight-IDS in your research, please cite:

```bibtex
@software{owlsight-ids-2026,
  title={OwlSight-IDS: Real-time Malicious Traffic Detection with Triple-Layer Cooperative Architecture},
  author={Your Name},
  year={2026},
  url={https://github.com/gkdgkd123/OwlSight-IDS}
}
```

---

## Acknowledgements

- **Suricata**: Open-source network threat detection engine
- **XGBoost**: Gradient boosting framework for machine learning
- **Scikit-learn**: Machine learning library (Isolation Forest)
- **Redis**: In-memory data structure store
- **Scapy**: Packet manipulation library
- **Claude Opus 4.6**: Large language model for semantic analysis
- **CICIDS2017**: Canadian Institute for Cybersecurity dataset

---

<div align="center">

Made with ❤️ for cybersecurity research and education

**OwlSight-IDS** © 2026

</div>

---
