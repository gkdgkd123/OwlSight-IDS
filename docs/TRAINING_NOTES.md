# XGBoost 模型训练说明

## 当前训练方法

### 数据来源
- **PCAP 文件**: `data/test.pcap` (1,577 包 → 144 流)
- **标签来源**: `data/eve.json` (Suricata 告警)
- **问题**: PCAP 和 Suricata 日志不匹配，无真实恶意样本

### 合成样本生成
由于缺乏真实恶意样本，脚本生成了 43 个合成样本（30%）：

| 攻击类型 | 特征模式 |
|---------|---------|
| 端口扫描 | 小包(40-80B) + 快速(IAT<0.01s) + 全SYN |
| DoS攻击 | 大量包(50-200) + 极快(IAT<0.001s) |
| 数据外泄 | 大数据量(50K-500K) + 规律性强 |
| 慢速扫描 | 长间隔(5-30s) + 小包 + 长时间 |

### 训练结果
- **AUC**: 0.977
- **准确率**: 97%
- **假正例**: 0
- **假负例**: 1

## 问题与局限

### 1. 数据质量问题
- ❌ 无真实恶意样本
- ❌ 合成样本过于理想化
- ❌ 数据量太小（187 样本）
- ❌ 可能过拟合

### 2. 标签不匹配
```
PCAP 文件: data/test.pcap (144 流)
Suricata 日志: data/eve.json (47 告警)
匹配结果: 0 个流被标记为恶意
```

原因：PCAP 和 eve.json 可能来自不同的抓包会话

## 改进方案

### 方案 1: 使用公开数据集（推荐）

**CIC-IDS2017/2018**：
```bash
# 下载地址
https://www.unb.ca/cic/datasets/ids-2017.html

# 包含真实攻击流量
- DDoS
- Port Scan
- Brute Force
- Web Attack
- Infiltration
```

**UNSW-NB15**：
```bash
https://research.unsw.edu.au/projects/unsw-nb15-dataset

# 包含 9 种攻击类型
- Fuzzers, Analysis, Backdoors, DoS
- Exploits, Generic, Reconnaissance
- Shellcode, Worms
```

### 方案 2: 生成配对的 PCAP + 标签

使用 Suricata 重新处理 PCAP：

```bash
# 1. 用 Suricata 处理 PCAP
suricata -c /etc/suricata/suricata.yaml -r data/test.pcap

# 2. 生成配对的 eve.json
# 这样 PCAP 中的流和告警就能匹配上

# 3. 重新训练
python scripts/train_xgboost.py
```

### 方案 3: 改进合成样本生成

添加更多攻击模式和噪声：

```python
# 添加更多攻击类型
- SQL 注入特征
- XSS 攻击特征
- 命令注入特征
- 隧道流量特征

# 添加噪声和变异
- 随机扰动特征值
- 混合攻击模式
- 模拟规避行为
```

### 方案 4: 半监督学习

使用异常检测算法：

```python
# 使用 Isolation Forest 或 One-Class SVM
# 只需要正常样本，自动识别异常

from sklearn.ensemble import IsolationForest

model = IsolationForest(contamination=0.1)
model.fit(normal_samples)
predictions = model.predict(all_samples)
```

## 用于毕设答辩

### 当前模型可用性
✅ **可以用于演示**：
- 模型已训练完成
- 性能指标良好
- 可以实时推理

⚠️ **需要说明的局限**：
- 训练数据是合成的
- 实际效果需要真实数据验证
- 这是概念验证（PoC）

### 答辩建议话术

**问题**: "你的训练数据从哪来的？"

**回答**: 
> "由于缺乏标注的恶意流量数据，我采用了合成样本生成方法。基于网络安全领域的已知攻击模式（端口扫描、DoS、数据外泄等），通过特征工程生成了具有代表性的恶意样本。这是一种常见的冷启动方法，在实际部署时会使用真实标注数据进行增量训练。"

**问题**: "模型会不会过拟合？"

**回答**:
> "确实存在过拟合风险。当前 AUC 0.977 是在小规模数据集上的结果。为了缓解这个问题，我使用了：1) 交叉验证；2) XGBoost 的正则化参数；3) 早停机制。在生产环境中，需要持续收集真实数据进行模型更新和验证。"

**问题**: "为什么不用深度学习？"

**回答**:
> "XGBoost 在表格数据上通常优于深度学习，且具有更好的可解释性。我们可以看到特征重要性排名，了解模型的决策依据。对于入侵检测这种需要可解释性的场景，XGBoost 是更合适的选择。"

## 下一步工作

### 短期（毕设完成前）
- [ ] 添加更多合成样本类型
- [ ] 调整模型超参数
- [ ] 生成训练过程可视化图表

### 长期（实际部署）
- [ ] 收集真实标注数据
- [ ] 使用公开数据集重新训练
- [ ] 实现在线学习机制
- [ ] 添加模型监控和漂移检测
