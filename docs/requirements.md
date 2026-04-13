实时恶意流量协同检测系统 - 开发需求文档 (PRD for Code Generation)
1. 项目概述
本项目是一个针对本科毕业设计的网络安全检测系统，采用“规则匹配 + 机器学习 + 大语言模型”的三层异构协同检测架构。系统需对网络流量进行实时分析，解决传统检测器无法识别未知威胁、以及大模型直接处理流量导致高延迟的问题。

2. 技术栈约束
请严格使用以下技术栈生成代码：

编程语言：Python 3.12

抓包与流量解析：scapy (用于旁路流量捕获与早期流特征提取)

规则引擎集成：监控 Suricata 的标准输出文件 eve.json

机器学习：xgboost, pandas, numpy, scikit-learn

状态共享内存：redis (使用 redis-py 库)

大模型与RAG框架：transformers (加载 Qwen-3B), langchain (用于 RAG 检索), chromadb 或 faiss (本地向量库)

3. 全局数据结构定义
3.1 五元组定义 (5-Tuple Key)
所有的 Redis Key 和内部字典均以五元组哈希字符串作为唯一标识：
"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}" (单向流)

3.2 Redis 状态存储结构
在 Redis 中为每个五元组维护一个 Hash 结构：

suricata_alert: Boolean (是否命中高危规则)

xgb_score: Float (XGBoost 异常概率得分，0.0~1.0)

packet_count: Int (已捕获包数)

flow_start_time: Float (流起始时间戳)

features: JSON String (提取到的早期流统计特征)

4. 模块详细设计与编码需求
Module 1: Suricata 日志监控模块 (Suricata Monitor)
功能描述：实时监控（Tail）Suricata 产生的 eve.json 文件，解析安全报警并写入 Redis。
执行逻辑：

异步读取 eve.json 的新增行。

如果 event_type == "alert"，解析出五元组。

连接 Redis，将该五元组的 suricata_alert 字段设为 True，设置 TTL 为 10 秒。

Module 2: 早流特征提取与 XGBoost 推理模块 (Early-Flow & XGB)
功能描述：旁路监听网卡，基于“包数(N=10) 或 时间(T=3s)”进行双重触发，提取流特征并进行 XGBoost 推理。
执行逻辑：

使用 scapy 的 sniff 函数异步捕获数据包（不阻塞）。

在内存中维护活动流状态字典 active_flows。

当捕获一个包时，更新五元组的统计信息：

包长列表 (Packet Lengths)

到达时间间隔列表 (Inter-Arrival Times, IAT)

TCP Flags 统计

触发条件检测：如果该流包数达到 10 个，或当前时间距离首包超过 3 秒：

计算统计特征：IAT均值、IAT方差、包长均值、包长方差、上行字节数。

调用预先加载的 xgboost 模型 xgb.Booster 进行推理（需提供一个加载 dummy 模型的占位函数）。

将生成的 xgb_score 和计算出的特征 JSON 写入 Redis，设置 TTL 10 秒。

从 active_flows 中删除该流，停止对该流后续包的统计。

Module 3: 智能路由决策模块 (Intelligent Router)
功能描述：定时扫描 Redis 中的状态，融合双轨引擎结果，决定是直接阻断还是转发给 LLM。
执行逻辑：

每秒轮询（或通过 Redis Keyspace Notifications 订阅）五元组状态。

决策树：

拦截条件：suricata_alert == True 或 xgb_score > 0.9。直接打印拦截日志 [BLOCK] 拦截恶意流 {5-tuple}。

正常条件：suricata_alert == False 且 xgb_score < 0.5。忽略并清理记录。

模糊/疑难流量：suricata_alert == False 且 0.5 <= xgb_score <= 0.9。触发 Module 4 进行深度研判。

Module 4: 数据净化与 LLM 深度研判模块 (RAG + Qwen LLM)
功能描述：接收疑难流量的特征，经过清洗后组装 Prompt，结合本地知识库向 Qwen-3B 提问，输出结构化 JSON 结果。
执行逻辑：

数据净化：对传入的 JSON 特征进行校验，过滤掉所有非 ASCII 字符或过长的无意义字符串（防提示词注入）。

特征降维转述：将数值特征转换为自然语言。例如：if IAT方差 < 0.1: text = "发现该流数据包到达时间间隔极其固定，疑似机器定时心跳通信。"

RAG 检索 (模拟)：编写一个基于 langchain 的假定检索函数 query_threat_intelligence(text)，返回一段相关的本地威胁情报（Dummy string 即可）。

Prompt 组装：

Plaintext
你是一个专业的网络安全分析专家。请根据以下流量特征和威胁情报，判断该网络流是否为恶意攻击。
【流量特征】：{转述后的自然语言特征}
【威胁情报】：{RAG检索结果}
请以严格的 JSON 格式输出，包含字段：{"is_malicious": true/false, "attack_type": "类型", "confidence": 0.0-1.0, "reason": "分析过程"}
模型调用：使用 transformers 库加载本地模型（代码中可配置 model_path），并执行推理。

5. 对大模型生成代码的强制要求 (Instructions for AI)
当让你编写具体模块时，请遵守以下规范：

必须使用面向对象编程 (OOP) 范式，每个模块为一个独立的 Class。

代码必须包含详细的中文注释，解释核心业务逻辑（特别是五元组解析和双重触发逻辑）。

所有外部依赖（如 Redis, 数据库路径, 模型路径）必须通过类的 __init__ 参数或配置文件传入，不能硬编码。

考虑到这是本科毕设，请保留适当的 logger.info() 打印日志，以便于在答辩演示时能在终端展示系统的实时分析过程。

针对缺乏真实数据的环境，请在每个模块末尾提供一个 if __name__ == "__main__": 的测试入口（Mock 数据），以确保模块可独立运行测试。