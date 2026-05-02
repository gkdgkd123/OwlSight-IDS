# OwlSight-IDS 系统架构详细文档

## 1. 系统概述

OwlSight-IDS 是一个基于三层协同检测架构的实时恶意流量检测系统，采用"规则引擎 + 双模型机器学习 + 大语言模型语义分析"的创新架构，专注于 0day 威胁检测。

### 1.1 核心设计理念

**三层协同检测架构**：
- **L0 层（规则引擎）**：Suricata 基于签名的快速过滤
- **L1 层（双模型 ML）**：XGBoost（监督学习）+ Isolation Forest（无监督学习）
- **L2 层（语义分析）**：Claude Opus 4.6 LLM 深度研判

**双模型协同策略**：
- **XGBoost**：识别已知攻击模式（训练集覆盖的攻击类型）
- **Isolation Forest**：检测统计异常行为（0day 候选）
- **协同决策**：当 XGBoost 认为安全但 Isolation Forest 检测到极度异常时，触发 0day 猎杀流程

### 1.2 系统拓扑

```
┌─────────────────────────────────────────────────────────────────┐
│                        网络流量入口                              │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │   Module 1: Suricata 监听     │
         │   (L0 规则引擎层)              │
         │   - 读取 eve.json              │
         │   - 提取告警事件                │
         │   - 写入 Redis                 │
         └───────────┬───────────────────┘
                     │
                     ▼
         ┌───────────────────────────────┐
         │   Module 2: 早流特征提取       │
         │   (L1 机器学习层 - 特征工程)   │
         │   - Scapy 旁路抓包             │
         │   - 双重触发：10包 OR 3秒      │
         │   - 18维特征向量提取            │
         │   - 双模型推理                 │
         │   - 写入 Redis                 │
         └───────────┬───────────────────┘
                     │
                     ▼
              ┌─────────────┐
              │    Redis     │ ◄─── 状态共享中心
              │  (消息总线)  │      TTL = 60s
              └──────┬───────┘
                     │
                     ▼
         ┌───────────────────────────────┐
         │   Module 3: 智能路由决策       │
         │   (L1 机器学习层 - 决策树)     │
         │   - scan() 扫描 Redis          │
         │   - 三层决策树                 │
         │   - LPUSH 到 LLM 队列          │
         │   - 时间窗口统计               │
         └───────────┬───────────────────┘
                     │
                     ▼
              ┌─────────────┐
              │ llm_task_queue│ ◄─── 异步消息队列
              │  (Redis List) │
              └──────┬────────┘
                     │
                     ▼
         ┌───────────────────────────────┐
         │   Module 4: LLM 深度研判       │
         │   (L2 语义分析层)              │
         │   - BRPOP 消费队列             │
         │   - 速率控制 (10次/分钟)       │
         │   - Claude Opus 4.6 API        │
         │   - 失败重试机制               │
         │   - 写回 Redis                 │
         └───────────────────────────────┘
```

---

## 2. 数据流详解

### 2.1 五元组流标识

系统使用五元组作为流的唯一标识：

```
flow_key = "{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
示例: "192.168.1.100:12345-10.0.0.1:80-TCP"
```

### 2.2 Redis 数据结构

**Hash 结构（每个流一个 Hash）**：

```redis
Key: 192.168.1.100:12345-10.0.0.1:80-TCP
Fields:
  - suricata_alert: "true"/"false"
  - signature: "ET EXPLOIT Port Scan"
  - severity: "1"
  - xgb_score: "0.85"
  - anomaly_score: "0.92"
  - packet_count: "10"
  - flow_start_time: "1234567890.123"
  - features: '{"iat_mean": 0.005, "pkt_len_mean": 64, ...}'
  - decision: "BLOCK"/"PASS"/"LLM_ANALYZE"/"ZERODAY_HUNT"
  - decision_time: "1234567890.456"
  - llm_result: '{"is_malicious": true, "attack_type": "Port Scan", ...}'
  - llm_is_malicious: "true"
  - llm_confidence: "0.95"
  - llm_attack_type: "Port Scanning"
  - llm_threat_level: "High"
TTL: 60 秒
```

**List 结构（LLM 任务队列）**：

```redis
Key: llm_task_queue
Type: List
Content: JSON 消息
  {
    "flow_key": "192.168.1.100:12345-10.0.0.1:80-TCP",
    "decision": "ZERODAY_HUNT",
    "timestamp": 1234567890.123,
    "xgb_score": 0.35,
    "anomaly_score": 0.88,
    "packet_count": 10,
    "features": "{...}",
    "suricata_alert": false,
    "signature": "",
    "severity": 0,
    "retry_count": 0  // 重试次数
  }
```

---

## 3. 三层决策树逻辑

### 3.1 决策阈值

```python
XGB_HIGH = 0.9      # XGBoost 高危阈值
XGB_LOW = 0.5       # XGBoost 低危阈值
ANOMALY = 0.75      # Isolation Forest 异常阈值
```

### 3.2 决策流程图

```
                    ┌─────────────┐
                    │  读取流状态  │
                    └──────┬──────┘
                           │
                           ▼
                  ┌────────────────┐
                  │ 已决策过？      │
                  └────┬───────┬───┘
                       │ Yes   │ No
                       ▼       ▼
                    跳过    继续决策
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │ 决策层 1: 高危直接拦截                │
        │ Suricata Alert OR XGB > 0.9          │
        └────┬─────────────────────────────┬───┘
             │ Yes                         │ No
             ▼                             ▼
        ┌─────────┐              ┌──────────────────┐
        │  BLOCK  │              │ 决策层 2: 正常放行│
        └─────────┘              │ XGB < 0.5 AND     │
                                 │ Anomaly < 0.75    │
                                 └────┬──────────┬───┘
                                      │ Yes      │ No
                                      ▼          ▼
                                 ┌─────────┐  ┌──────────────────┐
                                 │  PASS   │  │ 决策层 3: 疑难流量│
                                 │ (删除)  │  └────┬──────────┬──┘
                                 └─────────┘       │          │
                                                   ▼          ▼
                                        ┌──────────────┐  ┌──────────────┐
                                        │ 0day 猎杀     │  │ 常规疑难      │
                                        │ XGB < 0.5 AND │  │ 0.5 ≤ XGB ≤ 0.9│
                                        │ Anomaly > 0.75│  └──────┬───────┘
                                        └──────┬───────┘         │
                                               │                 │
                                               ▼                 ▼
                                        ┌──────────────┐  ┌──────────────┐
                                        │ZERODAY_HUNT  │  │ LLM_ANALYZE  │
                                        │→ LLM 队列    │  │→ LLM 队列    │
                                        └──────────────┘  └──────────────┘
```

### 3.3 决策逻辑伪代码

```python
def make_decision(flow_key, state):
    suricata_alert = state["suricata_alert"]
    xgb_score = state["xgb_score"]
    anomaly_score = state["anomaly_score"]
    
    # 层 1: 高危拦截
    if suricata_alert or xgb_score > 0.9:
        return "BLOCK"
    
    # 层 2: 正常放行
    if xgb_score < 0.5 and anomaly_score < 0.75:
        return "PASS"  # 立即删除 Redis 记录
    
    # 层 3: 0day 猎杀
    if xgb_score < 0.5 and anomaly_score >= 0.75:
        return "ZERODAY_HUNT"  # 发送到 LLM 队列
    
    # 层 3: 常规疑难
    if 0.5 <= xgb_score <= 0.9:
        return "LLM_ANALYZE"  # 发送到 LLM 队列
    
    # 兜底
    return "LLM_ANALYZE"
```

---

## 4. 关键设计决策

### 4.1 为什么使用双模型？

**单一 XGBoost 的局限性**：
- 只能识别训练集中见过的攻击模式
- 对未知变种和 0day 攻击无能为力
- 依赖标注数据，标注成本高

**Isolation Forest 的优势**：
- 无监督学习，不需要标注数据
- 基于统计异常检测，能发现"不正常"的行为
- 对 0day 攻击敏感

**协同策略的威力**：
```
场景 1: 已知攻击
  XGB: 0.95 (高危) → 直接拦截
  Anomaly: 0.6 (中等异常)
  
场景 2: 正常流量
  XGB: 0.3 (安全) → 直接放行
  Anomaly: 0.4 (正常)
  
场景 3: 0day 攻击 ⭐
  XGB: 0.35 (认为安全，因为训练集没见过)
  Anomaly: 0.88 (极度异常，统计特征偏离)
  → 触发 0day 猎杀！
```

### 4.2 为什么使用 Redis 作为消息总线？

**优势**：
- 高性能：内存数据库，读写速度快
- TTL 机制：自动清理过期数据，无需手动管理
- 原子操作：HSET/HGET/LPUSH/BRPOP 保证并发安全
- 简单部署：单机即可，无需复杂的消息队列

**替代方案对比**：
- RabbitMQ/Kafka：过于重量级，部署复杂
- 共享内存：跨进程困难，无持久化
- 数据库：性能不足，无 TTL 机制

### 4.3 为什么 Module 3 和 Module 4 解耦？

**同步回调的问题**（修复前）：
```python
# Module 3 直接调用 LLM
def process_flow(flow_key):
    decision = make_decision(flow_key)
    if decision == "LLM_ANALYZE":
        llm_result = llm_analyzer.analyze(flow_key)  # 阻塞 30 秒！
        # 在这 30 秒内，Module 3 无法处理其他流量
```

**异步队列的优势**（修复后）：
```python
# Module 3 只负责决策和入队
def process_flow(flow_key):
    decision = make_decision(flow_key)
    if decision == "LLM_ANALYZE":
        redis.lpush("llm_task_queue", task)  # 立即返回
        # Module 3 继续处理下一个流量

# Module 4 独立消费
while True:
    task = redis.brpop("llm_task_queue", timeout=1)
    if task:
        llm_result = call_llm_api(task)  # 慢速操作不影响 Module 3
```

**解耦带来的好处**：
- Module 3 吞吐量不受 LLM API 速度影响
- Module 4 可以独立扩展（多个 Worker）
- LLM API 限流不会阻塞整个系统
- 失败重试逻辑独立管理

---

## 5. 性能与可扩展性

### 5.1 性能指标（单机）

| 模块 | 吞吐量 | 延迟 | 瓶颈 |
|------|--------|------|------|
| Module 1 (Suricata) | ~10K pps | <1ms | 磁盘 I/O |
| Module 2 (特征提取) | ~5K flows/s | <10ms | CPU (特征计算) |
| Module 3 (决策) | ~10K flows/s | <1ms | Redis 网络 |
| Module 4 (LLM) | ~10 req/min | ~3s | API 限流 |

### 5.2 扩展方案

**水平扩展**：
- Module 2: 多网卡并行抓包
- Module 3: 多实例扫描 Redis（使用 scan 避免冲突）
- Module 4: 多 Worker 消费队列（BRPOP 天然支持多消费者）

**垂直扩展**：
- Redis: 增加内存，提高 TTL
- XGBoost: GPU 加速推理
- LLM: 切换到本地模型（Qwen）

---

## 6. 容错与可靠性

### 6.1 故障场景与应对

| 故障场景 | 影响 | 应对措施 |
|---------|------|---------|
| Redis 宕机 | 系统停止工作 | Redis 持久化 (AOF) + 主从复制 |
| Module 2 崩溃 | 新流量无法检测 | 进程守护 (systemd/supervisor) |
| Module 3 崩溃 | 决策停止 | 进程守护 + Redis 数据不丢失 |
| Module 4 崩溃 | LLM 分析停止 | 队列保留，重启后继续消费 |
| LLM API 限流 | 队列积压 | 速率控制 + 队列长度监控 |
| LLM API 失败 | 单个流量分析失败 | 重试 3 次 + 失败队列 |

### 6.2 数据一致性保证

**幂等性设计**：
```python
# Module 3 检查是否已决策
existing_decision = redis.hget(flow_key, "decision")
if existing_decision:
    return  # 跳过，避免重复决策
```

**原子操作**：
```python
# Redis HSET 是原子操作，不会出现部分写入
redis.hset(flow_key, "decision", "BLOCK")
redis.hset(flow_key, "decision_time", str(time.time()))
```

**TTL 自动清理**：
```python
# 60 秒后自动删除，无需手动清理
redis.expire(flow_key, 60)
```

---

## 7. 安全性考虑

### 7.1 敏感信息保护

- API Key 存储在 `.env` 文件，不提交到 Git
- Redis 密码保护（可选）
- 日志脱敏（不记录完整 API Key）

### 7.2 注入攻击防护

- 特征清洗：`sanitize_text()` 过滤特殊字符
- JSON 解析：使用 `json.loads()` 而非 `eval()`
- Redis 命令：使用参数化查询，避免拼接

---

## 8. 监控与可观测性

### 8.1 统计指标

**Module 3 (智能路由)**：
- 时间窗口统计（每 60 秒）：
  - 处理流量数
  - 拦截数
  - 放行数
  - 送审 LLM 数
  - 0day 检测数
- 全局累计统计

**Module 4 (LLM 分析)**：
- 累计处理数
- 成功率
- 失败数
- 检出恶意数
- 检出正常数

### 8.2 健康检查

**队列积压监控**：
```python
queue_len = redis.llen("llm_task_queue")
if queue_len > 100:
    logger.warning("队列积压严重")
```

**失败队列监控**：
```python
failed_len = redis.llen("llm_failed_queue")
if failed_len > 10:
    logger.error("失败任务过多，需要人工介入")
```

---

## 9. 部署架构

### 9.1 单机部署（开发/演示）

```
┌─────────────────────────────────────┐
│         单台服务器                   │
│  ┌──────────────────────────────┐  │
│  │  Redis (localhost:6379)      │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Module 1 (Suricata)         │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Module 2 (特征提取)          │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Module 3 (决策)              │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Module 4 (LLM Worker)       │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

### 9.2 分布式部署（生产）

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  抓包节点 1  │     │  抓包节点 2  │     │  抓包节点 N  │
│  Module 2   │     │  Module 2   │     │  Module 2   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           ▼
                  ┌─────────────────┐
                  │  Redis Cluster  │
                  │  (主从 + 哨兵)   │
                  └────────┬─────────┘
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  决策节点 1  │     │  决策节点 2  │     │  决策节点 N  │
│  Module 3   │     │  Module 3   │     │  Module 3   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  LLM 任务队列    │
                  └────────┬─────────┘
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ LLM Worker 1│     │ LLM Worker 2│     │ LLM Worker N│
│  Module 4   │     │  Module 4   │     │  Module 4   │
└─────────────┘     └─────────────┘     └─────────────┘
```

---

## 10. 未来优化方向

### 10.1 短期优化（1-3 个月）

1. **特征工程优化**
   - 增加 DNS 查询特征
   - 增加 TLS 握手特征
   - 增加应用层协议特征

2. **模型优化**
   - 在线学习：定期重训练 XGBoost
   - 模型集成：增加 Random Forest
   - 超参数调优：网格搜索最优参数

3. **性能优化**
   - Redis Pipeline 批量操作
   - XGBoost GPU 加速
   - 特征缓存

### 10.2 中期优化（3-6 个月）

1. **流量回放与测试**
   - PCAP 回放工具
   - 自动化测试框架
   - 性能基准测试

2. **可视化界面**
   - 实时流量监控大屏
   - 告警事件列表
   - 统计图表

3. **告警联动**
   - 邮件通知
   - Webhook 集成
   - SIEM 对接

### 10.3 长期优化（6-12 个月）

1. **深度学习模型**
   - CNN 提取流量时序特征
   - RNN/LSTM 建模流量序列
   - Transformer 注意力机制

2. **联邦学习**
   - 多节点协同训练
   - 隐私保护
   - 模型聚合

3. **自适应防御**
   - 根据攻击类型动态调整阈值
   - 自动生成 Suricata 规则
   - 攻击溯源与取证

---

## 11. 总结

OwlSight-IDS 通过三层协同检测架构，实现了从规则引擎到机器学习再到语义分析的完整检测链路。双模型协同策略有效弥补了单一模型的局限性，特别是在 0day 检测方面具有独特优势。

系统采用模块化设计，各模块通过 Redis 解耦，保证了高性能和可扩展性。完善的容错机制和监控体系确保了系统的可靠性。

**核心创新点**：
1. 双模型协同检测（XGBoost + Isolation Forest）
2. 0day 猎杀策略（统计异常 + 语义分析）
3. 异步队列架构（生产者-消费者解耦）
4. 早流检测（10 包或 3 秒触发）

**适用场景**：
- 企业网络边界防护
- 数据中心流量监控
- 云环境安全防护
- 0day 威胁研究

---

**文档版本**: v1.0  
**最后更新**: 2026-04-13  
**作者**: OwlSight-IDS 开发团队
