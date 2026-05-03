# OwlSight-IDS: 实时恶意流量入侵检测系统

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Redis](https://img.shields.io/badge/Redis-6.0%2B-red)
![Suricata](https://img.shields.io/badge/Suricata-6.0%2B-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**🦉 面向 0day 威胁猎杀的三层协同检测架构**

[English](README.md) | [中文](README_CN.md)

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
├── README.md                        # 英文文档
└── README_CN.md                     # 本文件
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
