# SemFlow-IDS 实时恶意流量协同检测系统

## 项目概述

SemFlow-IDS 是一个基于三层异构协同检测架构的实时网络安全检测系统，采用"规则匹配 + 机器学习 + 大语言模型"的创新方案，解决传统检测器无法识别未知威胁以及大模型直接处理流量导致高延迟的问题。

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    SemFlow-IDS 系统架构                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │ Suricata     │         │ Scapy        │                 │
│  │ 日志监控     │         │ 流量抓包     │                 │
│  │ (Module 1)   │         │ (Module 2)   │                 │
│  └──────┬───────┘         └──────┬───────┘                 │
│         │                        │                          │
│         │  规则告警              │  早流特征 + XGBoost      │
│         │                        │                          │
│         └────────┬───────────────┘                          │
│                  ▼                                           │
│         ┌─────────────────┐                                 │
│         │  Redis 状态池   │                                 │
│         │  (五元组索引)   │                                 │
│         └────────┬────────┘                                 │
│                  ▼                                           │
│         ┌─────────────────┐                                 │
│         │ 智能路由决策    │                                 │
│         │ (Module 3)      │                                 │
│         └────────┬────────┘                                 │
│                  │                                           │
│         ┌────────┼────────┐                                 │
│         ▼        ▼        ▼                                 │
│      [BLOCK]  [PASS]  [疑难流量]                            │
│                           │                                  │
│                           ▼                                  │
│                  ┌─────────────────┐                        │
│                  │ RAG + Qwen LLM  │                        │
│                  │ 深度研判        │                        │
│                  │ (Module 4)      │                        │
│                  └─────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块

### Module 1: Suricata 日志监控模块
- 实时 tail Suricata 的 eve.json 文件
- 解析安全报警事件
- 提取五元组并写入 Redis

### Module 2: 早流特征提取与 XGBoost 推理模块
- 使用 Scapy 旁路监听网卡
- 双重触发机制：包数(N=10) 或 时间(T=3s)
- 提取流统计特征（IAT、包长、字节数等）
- XGBoost 模型推理异常得分

### Module 3: 智能路由决策模块
- 定时扫描 Redis 状态池
- 融合 Suricata 告警 + XGBoost 得分
- 决策树：
  - `suricata_alert=True` 或 `xgb_score>0.9` → **拦截**
  - `suricata_alert=False` 且 `xgb_score<0.5` → **放行**
  - `0.5 ≤ xgb_score ≤ 0.9` → **转发 LLM**

### Module 4: RAG + Qwen LLM 深度研判模块
- 数据净化（防提示词注入）
- 特征降维转述为自然语言
- RAG 检索本地威胁情报
- Qwen-3B 模型推理
- 输出结构化 JSON 结果

## 技术栈

- **编程语言**: Python 3.10+
- **抓包**: Scapy
- **规则引擎**: Suricata (eve.json)
- **机器学习**: XGBoost, scikit-learn, pandas, numpy
- **状态管理**: Redis
- **大模型**: Transformers (Qwen-3B)
- **RAG**: LangChain, ChromaDB/FAISS

## 安装依赖

```bash
pip install -r src/requirements.txt
```

## 配置说明

### 环境变量配置

```bash
export REDIS_HOST=localhost
export REDIS_PORT=6379
export SURICATA_EVE_PATH=/var/log/suricata/eve.json
export SCAPY_INTERFACE=eth0
export XGB_MODEL_PATH=./src/models/xgb_model.json
export LLM_MODEL_PATH=./models/Qwen-3B
```

### 命令行参数

```bash
python src/main_realtime.py \
  --redis-host localhost \
  --redis-port 6379 \
  --eve-json ./data/eve.json \
  --interface eth0 \
  --xgb-model ./src/models/xgb_model.json \
  --llm-model ./models/Qwen-3B \
  --log-level INFO
```

## 使用方法

### 1. 启动 Redis

```bash
redis-server
```

### 2. 启动 Suricata

```bash
suricata -c /etc/suricata/suricata.yaml -i eth0
```

### 3. 运行 SemFlow-IDS

```bash
python src/main_realtime.py --interface eth0
```

## 模块独立测试

每个模块都包含 `if __name__ == "__main__"` 测试入口，可独立运行：

```bash
# 测试 Suricata 监控模块
python -m src.modules.suricata_monitor

# 测试早流特征提取模块
python -m src.modules.early_flow_xgb

# 测试智能路由决策模块
python -m src.modules.intelligent_router

# 测试 LLM 分析模块
python -m src.modules.llm_analyzer
```

## 数据结构

### Redis 五元组键格式

```
{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}
```

### Redis Hash 字段

```
suricata_alert: Boolean
xgb_score: Float (0.0~1.0)
packet_count: Int
flow_start_time: Float
features: JSON String
signature: String
severity: Int
decision: String (BLOCK/PASS/LLM_ANALYZE)
llm_result: JSON String
```

## 项目结构

```
src/
├── __init__.py
├── main_realtime.py          # 主程序入口
├── utils.py                   # 工具函数
├── requirements.txt           # 依赖列表
├── config/
│   ├── __init__.py
│   └── config.py              # 配置类
├── modules/
│   ├── __init__.py
│   ├── suricata_monitor.py    # Module 1
│   ├── early_flow_xgb.py      # Module 2
│   ├── intelligent_router.py  # Module 3
│   └── llm_analyzer.py        # Module 4
├── models/
│   ├── xgb_model.json         # XGBoost 模型
│   └── vector_db/             # 向量数据库
└── tests/
    └── ...
```

## 性能优化

- **双重触发机制**: 避免长流量阻塞，确保早期检测
- **Redis TTL**: 自动清理过期流状态，防止内存泄漏
- **异步处理**: 多线程并行运行各模块
- **分层过滤**: 规则引擎 + ML 快速过滤，仅疑难流量进入 LLM

## 注意事项

1. **权限要求**: Scapy 抓包需要 root 权限或 CAP_NET_RAW 能力
2. **网卡选择**: 确保 `--interface` 参数指定正确的网卡名称
3. **模型路径**: 首次运行需下载 Qwen-3B 模型到指定路径
4. **Redis 连接**: 确保 Redis 服务正常运行

## 毕设答辩演示

系统包含详细的日志输出，适合答辩演示：

```
[2026-04-13 00:07:15] [SuricataMonitor] [INFO] [ALERT] 检测到高危流量 192.168.1.10:1234-10.0.0.1:80-TCP | 规则: SQL Injection | 严重级别: 1
[2026-04-13 00:07:16] [EarlyFlowXGBoost] [INFO] [XGB] 流量分析完成 192.168.1.20:5678-10.0.0.2:443-TCP | 异常得分: 0.723 | 包数: 10
[2026-04-13 00:07:17] [IntelligentRouter] [WARNING] [BLOCK] 拦截恶意流 192.168.1.10:1234-10.0.0.1:80-TCP | Suricata告警: True | XGB得分: 0.950
[2026-04-13 00:07:18] [LLMAnalyzer] [INFO] [LLM] 深度研判完成 192.168.1.30:9012-10.0.0.3:8080-TCP | 恶意: True | 类型: Port Scanning | 置信度: 0.85
```

## 许可证

MIT License
