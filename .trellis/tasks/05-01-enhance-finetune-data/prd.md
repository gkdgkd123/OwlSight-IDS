# 增强微调数据质量：引入 Suricata HTTP/Payload 语义证据

## Goal

当前 `generate_finetune_data.py` 生成的 LLM 微调数据中，`is_successful_attack` 判断质量很差——仅依赖流量行为特征（字节数、SYN/ACK 标志、签名关键词匹配），没有分析实际的 HTTP 请求/响应内容和 payload 语义。真实场景中，判断攻击是否成功的核心证据在于：请求包是否包含恶意 payload、服务端是否返回了有意义的响应（如 SQL 查询结果、WebShell 内容、命令执行输出）。

**目标**：将 Suricata 告警中的 HTTP 语义数据（method, url, status, request headers, response body）和 payload 数据引入微调数据的 prompt context 和标注引擎，让 LLM 学会基于**包内容语义**而非仅行为特征来判断攻击结果。

## What I already know

- **数据源**：`data/capture_20260429_155502_suricata_alerts.json`（236 条告警）
  - 216 条有 `http` 字段（91.5%）
  - 82 条有 `http_response_body_printable`（34.7%）
  - 236 条全部有 `payload_printable`
  - 主要攻击类型：XSS（136 条）、SQL注入（16 条）、信息泄露（16 条）、WebShell（6 条）、RCE（8 条）等

- **当前问题**：`load_suricata_alerts()` 仅提取 `signature/category/severity/action/signature_id/pkts_toserver/pkts_toclient/bytes_toserver/bytes_toclient`，**完全丢弃了 `http` 和 `payload_printable` 字段**

- **影响范围**：`scripts/generate_finetune_data.py`（标注引擎 + prompt 构建）和 `src/prompts/llm_analyst.md`（prompt 模板）

- **关键文件**：
  - `scripts/generate_finetune_data.py` — 核心改动文件
  - `src/prompts/llm_analyst.md` — prompt 模板需同步更新
  - `src/modules/llm_analyzer.py` — 运行时也需要同步提取 HTTP 数据（影响 `_build_context`）
  - `src/modules/suricata_monitor.py` — M1 写入 Redis 时也需要存储 HTTP 语义字段

## Requirements

1. `load_suricata_alerts()` 必须提取 Suricata 告警中的 HTTP 语义字段：
   - `http.hostname`, `http.url`, `http.http_method`, `http.protocol`, `http.status`, `http.length`
   - `http.http_user_agent`, `http.http_content_type`
   - `http.http_response_body_printable`（截断到合理长度，如 2000 字符）
   - `payload_printable`（截断到合理长度，如 1000 字符）

2. `_build_context()` 必须将 HTTP 请求/响应内容作为 **"HTTP Evidence"** 和 **"Payload Evidence"** 段落注入 prompt context

3. `annotate()` 标注引擎必须利用 HTTP 语义来改进 `is_successful_attack` 判断：
   - SQL注入：检查 response body 是否包含 SQL 错误信息或数据（如 `mysql_`, `ORA-`, `syntax error`, 表名/列名泄漏）
   - XSS：检查 response body 是否包含未转义的 `<script>` 标签
   - WebShell 上传：检查 status 200 + POST + 可执行文件路径
   - 命令执行：检查 response body 是否包含 shell 输出特征（如 `root:`, `/bin/bash`, `uid=`）
   - 信息泄露（/etc/passwd）：检查 response body 是否包含 `/etc/passwd` 内容

4. prompt 模板 `llm_analyst.md` 需新增指引，教 LLM 如何分析 HTTP request/response 语义

5. 样本质量：重新生成后，SQL注入/XSS/RCE 类攻击的 `is_successful_attack` 标注应显著更准确

## Acceptance Criteria

- [x] `load_suricata_alerts()` 提取 `http` 和 `payload_printable` 字段 + `alert.rule` + 完整 flow 数据
- [x] prompt context 中包含完整的 HTTP 请求行 + 响应状态码 + 响应体（截断到 2000 字符）
- [x] prompt context 中包含 payload 内容（截断到 1000 字符）+ alert.rule 原文
- [x] 标注引擎基于 HTTP 语义判断 `is_successful_attack`（`_check_http_success_indicators()` 函数覆盖 SQLi/XSS/RCE/WebShell/IoT/信息泄露/C2/恶意下载）
- [x] `llm_analyst.md` prompt 模板新增 HTTP Semantic Analysis + Payload Semantic Analysis 分析指引
- [x] 重新生成 `finetune_llm.jsonl`，对比前后同一条告警的标注质量差异
- [x] 运行时模块（`suricata_monitor.py`、`llm_analyzer.py`）同步支持 HTTP 语义提取与 prompt 注入

## Definition of Done

- 重新生成的微调数据中，SQL注入响应包含实际查询结果的样本应标记为 `is_successful_attack: "yes"`
- 仅有告警但响应为错误页面（如 403 Forbidden）的样本应标记为 `"no"`
- prompt 模板能引导 LLM 关注 HTTP 语义证据
- 代码通过 lint + 基本测试

## Out of Scope

- 重新训练 ML 模型（XGBoost/IForest）
- 修改 LLM API 调用逻辑本身
- 新增 Prometheus 指标
- 全面的集成测试覆盖

## Technical Notes

- Suricata HTTP 字段结构（来自真实数据）：
  ```json
  {
    "http": {
      "hostname": "169.254.169.254",
      "url": "/opc/v2/instance/",
      "http_user_agent": "Go-http-client/1.1",
      "http_content_type": "application/json",
      "http_method": "GET",
      "protocol": "HTTP/1.1",
      "status": 200,
      "length": 2512,
      "http_response_body_printable": "{\"agentConfig\": ...}"
    }
  }
  ```
- payload 字段是原始抓包内容（可能含二进制），需 sanitize
- response body 可能很长（>10KB），需要截断并标注 `(truncated)`
- 需要与 `src/modules/suricata_monitor.py` 同步——运行时也需要把这些字段写入 Redis Hash
