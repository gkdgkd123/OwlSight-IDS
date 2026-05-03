# OwlSight-IDS: Real-time Malicious Traffic Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Redis](https://img.shields.io/badge/Redis-6.0%2B-red)
![Suricata](https://img.shields.io/badge/Suricata-6.0%2B-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**🦉 A Triple-Layer Cooperative Detection Architecture for 0day Threat Hunting**

[English](#overview) | [中文](#项目概述)

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

### 项目概述

**OwlSight-IDS**是一个实时网络入侵检测系统，采用**规则检测**、**机器学习推理**和**大语言模型语义分析**相结合的方式，识别已知攻击和零日威胁。系统采用创新的**三层协同检测架构**和**双模型机器学习**策略，实现高检测准确率和低误报率。

### 🌟 核心特性

- **🎯 三层协同检测架构**
  - **L0（规则引擎）**：基于 Suricata 的签名检测
  - **L1（机器学习）**：双模型协同推理（XGBoost + 孤立森林）
  - **L2（语义分析）**：Claude Opus 4.6 LLM 深度分析

- **🔬 双模型协同策略**
  - **XGBoost**：监督学习识别已知攻击（AUC: 0.977）
  - **孤立森林**：无监督异常检测识别零日候选
  - **协同决策树**：融合两个模型的鲁棒分类
  - **独特的零日猎杀策略**：当 XGB < 0.5（认为安全）且异常 > 0.75（行为异常）时触发

- **⚡ 早流检测**
  - 双重触发机制：10 个包 OR 3 秒
  - 18 维特征向量提取
  - 亚秒级实时处理延迟
  - 自动清理防止内存泄漏

- **🔄 异步解耦架构**
  - 基于 Redis 的生产者-消费者模式
  - 非阻塞 LLM 分析与速率限制（10 req/min）
  - 自动重试机制（最多 3 次）
  - 零因 LLM 处理延迟的流量检测延迟

- **📊 全面监控与可观测性**
  - 时间窗口统计（每分钟吞吐量显示）
  - 全局累计指标追踪
  - 队列健康监控与自动告警
  - 线程安全的统计与适当的锁机制

### 快速开始

#### 前置要求

- **Python**: 3.8+
- **Redis**: 6.0+（模块间状态共享和消息队列）
- **Suricata**: 6.0+（L0 规则检测引擎）
- **LLM API Key**: Claude Opus 4.6（或兼容 OpenAI 格式的 API）
- **系统**: Linux（推荐）/ macOS / Windows

#### 安装步骤

1. **安装系统依赖**

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

2. **克隆仓库**
   ```bash
   git clone https://github.com/gkdgkd123/OwlSight-IDS.git
   cd OwlSight-IDS
   ```

3. **创建虚拟环境并安装 Python 依赖**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. **配置环境变量**
   ```bash
   cp .env.example .env
   # 编辑 .env — 至少需要设置 LLM_API_KEY
   ```

#### 运行系统

所有模式通过统一入口 `run.py` 启动：

```bash
# 交互式菜单（引导式配置）
python run.py

# 实时网卡捕获 + 自动拉起 Suricata（生产推荐）
python run.py --live --with-suricata --iface eth0

# 仅实时捕获（Suricata 已在后台运行）
python run.py --live --iface eth0

# 自定义 Suricata 日志目录
python run.py --live --with-suricata --suricata-log-dir /var/log/suricata

# pcap 回放 + LLM 限制
python run.py --pcap data/test.pcap --llm-limit 20

# pcap 回放不调用 LLM（仅 ML 流水线）
python run.py --pcap data/test.pcap --llm-limit 0

# 调试日志
python run.py --live --with-suricata --log-level DEBUG
```

| 参数 | 说明 |
|------|------|
| `--live` | 从网卡实时捕获流量 |
| `--pcap FILE` | 从 pcap 文件回放 |
| `--iface IFACE` | 网卡接口（默认: eth0） |
| `--with-suricata` | 自动拉起并管理 Suricata 子进程 |
| `--suricata-iface IFACE` | Suricata 监听网卡（默认同 `--iface`） |
| `--suricata-log-dir DIR` | Suricata 日志目录（默认: ./data/suricata_logs） |
| `--llm-limit N` | pcap 模式 LLM 最大分析条数（默认 20，0=禁用） |
| `--log-level LEVEL` | DEBUG, INFO, WARNING, ERROR（默认: INFO） |

#### 验证安装

```bash
# 检查 Redis 连接
redis-cli ping   # 预期: PONG

# 检查 Suricata
suricata --build-info | head -3

# 检查 Python 依赖
python -c "import redis, scapy, xgboost, sklearn; print('OK')"

# 运行测试套件
python -m pytest tests/ -v
```

#### 环境配置说明

复制 `.env.example` 创建 `.env` 文件：

```bash
# Redis 配置
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=
REDIS_TTL=60

# Suricata 配置
SURICATA_EVE_PATH=/var/log/suricata/eve.json
SURICATA_TAIL_INTERVAL=0.1

# Scapy 抓包配置
SCAPY_INTERFACE=eth0
SCAPY_PACKET_TRIGGER=10       # 10 个包后触发
SCAPY_TIME_TRIGGER=3.0        # 或 3 秒后触发

# XGBoost 模型配置
XGB_MODEL_PATH=./src/models/xgb_model.json
XGB_THRESHOLD_HIGH=0.9        # 高危阈值
XGB_THRESHOLD_LOW=0.5         # 低危阈值
ANOMALY_THRESHOLD=0.75        # 异常阈值

# LLM 配置（Claude Opus 4.6）
LLM_USE_API=true
LLM_API_BASE_URL=https://new.timefiles.online/v1
LLM_API_KEY=your_api_key_here # 设置环境变量
LLM_API_MODEL=claude-opus-4-6

# 系统配置
LOG_LEVEL=INFO
```

---

## 项目结构

```
OwlSight-IDS/
├── src/                    # 主包
│   ├── config/
│   │   ├── config.py                # 配置管理（支持 .env）
│   │   └── redis_factory.py         # Redis 连接池工厂
│   ├── modules/
│   │   ├── suricata_monitor.py      # 模块 1: 规则引擎（eve.json 监控）
│   │   ├── early_flow_xgb.py        # 模块 2: 特征提取 & 双模型推理
│   │   ├── intelligent_router.py    # 模块 3: 决策树 + LLM 任务生产
│   │   ├── llm_analyzer.py          # 模块 4: LLM 语义分析消费
│   │   └── redis_manager.py         # Redis 健康监控 & 生命周期管理
│   ├── engine.py                    # 检测引擎：4 模块协同编排
│   ├── suricata_launcher.py         # Suricata 子进程生命周期管理
│   └── utils.py                     # trace_id、着色日志、工具函数
├── scripts/
│   ├── preprocess_cicids2017.py     # CICIDS2017 数据集预处理
│   ├── train_xgboost.py             # XGBoost 模型训练
│   └── train_iforest.py             # 孤立森林模型训练
├── tests/                           # 完整测试套件
├── data/                            # 示例数据
│   ├── Suricata/
│   │   ├── suricata.yaml            # Suricata 配置模板
│   │   ├── classification.config    # Suricata 分类规则
│   │   └── reference.config         # Suricata 引用规则
│   └── suricata_logs/               # Suricata 运行时日志（eve.json）
├── run.py                           # CLI 入口（live / pcap / 交互式）
├── .env.example                     # 环境模板（安全提交）
├── .gitignore                       # Git 忽略规则（保护 .env）
├── requirements.txt                 # Python 依赖
└── README.md                        # 本文件
```

---

## 创新点

### 1. **双模型协同检测**
- XGBoost 识别已知攻击模式（监督学习）
- 孤立森林检测统计异常（无监督学习）
- 互补优势：既能处理已知威胁，又能检测未知威胁

### 2. **零日威胁猎杀策略**
```
触发条件：
  XGB_Score < 0.5（模型认为安全）
  AND
  Anomaly_Score > 0.75（行为极度异常）
  
  ⟹ 触发 ZERODAY_HUNT
  ⟹ 启动 LLM 深度语义分析
```

### 3. **异步解耦架构**
- **生产者（模块 3）**：快速决策，任务入队
- **消费者（模块 4）**：独立处理，速率限制
- **优势**：LLM API 延迟（3-5s）不阻塞实时检测（<1ms）

---

## 故障排查

### Redis 连接错误
```bash
# 确保 Redis 正在运行
redis-server

# 检查 Redis 连接
redis-cli ping  # 应该输出 PONG
```

### 缺少 LLM API 密钥
```bash
# 设置环境变量（Linux/Mac）
export LLM_API_KEY=your_key_here

# 设置环境变量（Windows）
set LLM_API_KEY=your_key_here

# 或在 .env 文件中配置
LLM_API_KEY=your_key_here
```

---

## 许可证

本项目采用 **MIT 许可证** - 详见 [LICENSE](LICENSE) 文件

---

## 致谢

- **Suricata**: 开源网络威胁检测引擎
- **XGBoost**: 梯度提升机器学习框架
- **Scikit-learn**: 机器学习库（孤立森林）
- **Redis**: 内存数据结构存储
- **Scapy**: 数据包操作库
- **Claude Opus 4.6**: 大语言模型
- **CICIDS2017**: 加拿大网络安全研究所数据集

---

<div align="center">

用 ❤️ 为网络安全研究和教育而开发

**OwlSight-IDS** © 2026

</div>

