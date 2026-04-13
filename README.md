# SemFlow-IDS

基于语义流的入侵检测系统 (Semantic Flow IDS)

## 功能概述

SemFlow-IDS 是一个多层检测系统，结合传统规则匹配（L0）和语义分析（L1/L2）进行入侵检测。

## 架构

```
输入 (eve.json) → L0 (规则匹配) → L1 (语义分析) → L2 (攻击链关联)
```

### 检测阶段

| 阶段 | 说明 | 技术 |
|------|------|------|
| L0 | 规则匹配 | Suricata 告警规则 |
| L1 | 语义特征提取 | LLM API (语义分析) |
| L2 | 攻击链关联 | LLM API (多流量关联) |

## 支持的事件类型

- `alert` - Suricata 告警
- `http` - HTTP 流量
- `flow` - 流信息
- `anomaly` - 异常事件
- `fileinfo` - 文件信息

## 使用方法

```bash
# 只做 L0 检测
python main.py --input eve.json --output results.jsonl

# L0 + L1 语义分析
python main.py --input eve.json --output results.jsonl --enable-l1

# L0 + L1 + L2 攻击链分析
python main.py --input eve.json --output results.jsonl --enable-l1 --enable-l2
```

## 输出格式

### L0 结果
```json
{
  "stage": "L0",
  "final_label": "malicious",
  "risk_score": 8,
  "suricata_alert": {...}
}
```

### L1 结果
```json
{
  "stage": "L1",
  "risk_score": 8,
  "confidence": 0.85,
  "is_suspicious": true,
  "attack_result": "failed",
  "attack_result_reason": "状态码 404",
  "semantic_features": ["XSS攻击特征", "可疑路径"],
  "payload": "alert(document.domain)",
  "indicators": {
    "xss_indicator": true,
    "scanning_behavior": false
  }
}
```

### L2 结果
```json
{
  "stage": "L2",
  "risk_score": 9,
  "confidence": 0.9,
  "attack_chain": ["reconnaissance", "exploitation"],
  "attack_chain_confidence": 0.85,
  "risk_adjusted": "up",
  "attack_summary": "同一 IP 发起多次扫描并尝试漏洞利用",
  "key_findings": ["发现 XSS 攻击", "发现目录扫描"],
  "related_samples": [...]
}
```

## 配置

API 配置通过环境变量：

- `OPENAI_BASEURL` - API 基础 URL (默认: https://api.qnaigc.com/v1)
- `OPENAI_API_KEY` - API Key (必填)
- `OPENAI_MODEL` - 模型名称 (默认: doubao-seed-2.0-lite)

## 项目结构

```
SemFlow-IDS/
├── main.py                 # 入口程序
├── src/semflow_ids/
│   ├── models.py           # 数据结构
│   ├── l0_filter.py        # L0 规则检测
│   ├── eve_parser.py       # EVE JSON 解析
│   ├── ollama_client.py    # LLM API 客户端
│   └── output_writer.py    # 结果输出
└── README.md
```

## 进展

- [x] L0 规则匹配
- [x] L1 语义特征提取
- [x] L2 攻击链关联
- [x] 多事件类型支持 (alert/http/flow/anomaly/fileinfo)
- [x] 攻击结果判断 (success/failed/unknown)
- [x] 风险分数 1-10 分制
- [x] 置信度输出
- [x] 攻击载荷提取
- [x] API 错误处理完善
- [x] L1 结果 O(1) 查找优化
