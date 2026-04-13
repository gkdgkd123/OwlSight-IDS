# SemFlow-IDS 项目结构

```
SemFlow-IDS2/
├── .gitignore              # Git 忽略配置
├── LICENSE                 # MIT 许可证
├── README.md               # 项目说明文档
├── requirements.txt        # Python 依赖列表
│
├── realtime_ids/           # 核心代码模块
│   ├── __init__.py
│   ├── utils.py            # 工具函数（五元组生成、日志等）
│   ├── main_realtime.py    # 主程序入口
│   ├── config/             # 配置模块
│   │   ├── __init__.py
│   │   └── config.py       # 系统配置类
│   └── modules/            # 四大核心模块
│       ├── __init__.py
│       ├── suricata_monitor.py      # Module 1: Suricata 日志监控
│       ├── early_flow_xgb.py        # Module 2: 早流特征提取与 XGBoost
│       ├── intelligent_router.py    # Module 3: 智能路由决策
│       └── llm_analyzer.py          # Module 4: LLM 深度研判
│
├── tests/                  # 测试脚本
│   ├── test_integrated_system.py    # 集成测试（推荐）
│   ├── test_pcap_analysis.py        # PCAP 分析测试
│   ├── test_suricata_monitor.py     # Suricata 监控测试
│   └── test_suricata_log_parser.py  # 日志解析测试
│
├── docs/                   # 文档目录
│   ├── requirements.md     # 需求描述文档（中文）
│   ├── TEST_REPORT.md      # 测试报告（英文）
│   └── test_results.txt    # 测试输出日志
│
├── examples/               # 示例数据
│   ├── eve_sample_real.jsonl       # 真实 Suricata 日志样本
│   ├── sample_eve.json             # 单条日志示例
│   ├── samples.jsonl               # 多条日志样本
│   ├── test_sample.jsonl           # 测试样本
│   ├── results.jsonl               # 检测结果示例
│   └── results_real.jsonl          # 真实检测结果
│
└── data/                   # 数据目录
    ├── eve.json            # Suricata 日志文件（151KB）
    └── test.pcap           # 测试抓包文件（665KB）
```

## 目录说明

### 核心代码 (`realtime_ids/`)
- **config/**: 系统配置（Redis、Suricata、Scapy、XGBoost、LLM）
- **modules/**: 四大检测模块的实现
- **main_realtime.py**: 多线程协同运行的主程序

### 测试 (`tests/`)
- **test_integrated_system.py**: 完整的集成测试，模拟三层检测流程
- 其他测试脚本用于单独测试各个模块

### 文档 (`docs/`)
- **requirements.md**: 详细的需求文档和技术规范
- **TEST_REPORT.md**: 测试报告，包含检测结果和性能指标

### 示例数据 (`examples/`)
- Suricata 日志样本和检测结果示例
- 用于演示和答辩展示

### 数据 (`data/`)
- 真实的 PCAP 文件和 Suricata 日志
- 用于测试和开发

## 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 运行测试
```bash
# 集成测试（推荐）
python tests/test_integrated_system.py

# PCAP 分析测试
python tests/test_pcap_analysis.py
```

### 3. 启动系统
```bash
# 启动 Redis
redis-server --port 6379

# 运行主程序
python realtime_ids/main_realtime.py \
    --eve-json data/eve.json \
    --interface eth0 \
    --redis-host localhost
```

## 依赖项

核心依赖：
- **redis**: 状态共享
- **scapy**: 流量捕获
- **xgboost**: 机器学习推理
- **transformers**: Qwen-3B 模型
- **langchain**: RAG 框架
- **chromadb**: 向量数据库

详见 `requirements.txt`

## 待完成

- [ ] 训练 XGBoost 模型
- [ ] 下载 Qwen-3B 模型权重
- [ ] 构建威胁情报向量库
- [ ] 配置 Suricata 规则集

## 许可证

MIT License - 详见 LICENSE 文件
