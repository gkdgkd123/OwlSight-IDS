# LLM Layer Guidelines

> LLM deep analysis patterns: prompt engineering, API calling, result schema for OwlSight-IDS.

---

## Overview

Module 4 (`llm_analyzer.py`) implements the L2 (Semantic Analysis) layer.
It consumes tasks from `llm_task_queue` (Redis List), calls an LLM API, and writes structured verdicts back to Redis.

---

## Dual-Mode Architecture

| Mode | Config | Backend | When to Use |
|------|--------|---------|-------------|
| API mode | `LLM_USE_API=true` | Claude Opus 4.6 via OpenAI-compatible API | Production (recommended) |
| Local mode | `LLM_USE_API=false` | Qwen-3B via HuggingFace Transformers | Air-gapped environments |

---

## Prompt Template System

### Template Location

`src/prompts/llm_analyst.md` — uses Python `string.Template` syntax (`$variable`).

**Why `string.Template` instead of f-string/format**: The prompt contains JSON examples with `{}` braces.
`string.Template` uses `$variable` which avoids conflicts with JSON syntax.

### Template Variables

| Variable | Source | Description |
|----------|--------|-------------|
| `$context` | Built by `_build_prompt()` | Detection context (scores, decision type) |
| `$features_text` | Built by `_features_to_natural_language()` | Natural language flow analysis |

### Context Building

Two context templates based on decision type:

```python
if decision_type == "ZERODAY_HUNT":
    context = (
        "**Detection Source**: ML Alert Only (no Suricata)\n"
        "- XGBoost score: {xgb_score:.3f} (< 0.5, model considers SAFE)\n"
        "- Isolation Forest anomaly score: {anomaly_score:.3f} (> 0.75, EXTREMELY anomalous)\n\n"
        "**Key Finding**: XGBoost considers this flow safe, but Isolation Forest detected "
        "an extremely anomalous behavioral pattern..."
    )
else:  # LLM_ANALYZE
    context = (
        "**Detection Source**: ML Alert Only (no Suricata)\n"
        "- XGBoost score: {xgb_score:.3f} (0.5-0.9 gray zone, needs deep analysis)\n"
        "- Isolation Forest anomaly score: {anomaly_score:.3f}\n\n"
        "**Key Finding**: This flow is in the gray zone..."
    )
```

### Fallback Prompt

If template file is missing, use a minimal built-in prompt:

```python
if self.prompt_template is None:
    prompt = f"""你是一个专业的网络安全分析专家...
    【检测背景】{context}
    【流量特征分析】{features_text}
    请以严格的 JSON 格式输出分析结果。"""
```

---

## Feature-to-Language Conversion

Raw features are converted to Chinese natural language before being sent to the LLM:

```python
def _features_to_natural_language(self, features):
    descriptions = []

    if iat_mean < 0.01:
        descriptions.append(f"数据包到达时间间隔极短（平均 {iat_mean*1000:.2f}ms），疑似快速扫描或自动化攻击")

    if syn_count > 5 and syn_count == packet_count:
        descriptions.append(f"全部为 SYN 包（{syn_count} 个），典型的端口扫描特征")

    return "；".join(descriptions) if descriptions else "流量特征正常"
```

**Key analysis dimensions**:
- IAT (Inter-Arrival Time) patterns
- Packet length distribution
- TCP flag analysis (SYN/ACK/FIN/RST)
- Traffic volume and rate
- Early flow detection (no FIN/RST, low packet count)

---

## LLM Result Schema

The LLM MUST return a JSON object with these fields:

```json
{
  "reasoning": "Detailed step-by-step analysis (Chinese)",
  "verdict": "benign | suspicious | malicious | unknown",
  "severity": "Critical | High | Medium | Low | Info",
  "threat_type": "Brief type (e.g., Reconnaissance, Successful_RCE, Suspected_C2)",
  "is_successful_attack": "yes | no | unknown",
  "success_evidence": "One-sentence objective evidence",
  "confidence": 0.0,
  "key_indicators": ["indicator1", "indicator2"],
  "recommended_action": "Monitor | Block_IP | Investigate_Further | ...",
  "mitre_techniques": ["T1234"],
  "explanation_for_non_expert": "Plain-language explanation (Chinese)"
}
```

### Verdict Logic

| Verdict | Meaning | Action |
|---------|---------|--------|
| `malicious` | Confirmed attack | Block_IP / Immediate_Isolation |
| `suspicious` | Likely attack, needs verification | Investigate_Further |
| `benign` | Normal traffic (false positive) | Monitor |
| `unknown` | Insufficient data (early flow, encrypted, blind exploit) | Investigate_OOB_Logs |

### `is_successful_attack` Logic

This is the **most critical** field. The LLM prompt emphasizes:
- `"yes"` only when there's evidence of actual compromise (data returned, C2 established)
- `"no"` when attack failed (no response, handshake failed, connection reset)
- `"unknown"` for early flows, blind exploits, encrypted traffic

---

## API Calling Pattern

```python
def _call_llm_api(self, prompt):
    # 1. Rate limiting (wait if needed)
    self._wait_for_rate_limit()

    # 2. Build OpenAI-compatible request
    payload = {
        "model": self.llm_config.api_model,
        "messages": [
            {"role": "system", "content": "You are OwlSight-L2..."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 4096
    }

    # 3. Call with 60s timeout
    response = requests.post(url, headers=headers, json=payload, timeout=60)

    # 4. Parse response (handle both content and reasoning_content)
    content = message.get("content", "") or ""
    reasoning = message.get("reasoning_content", "") or ""
    if not content and reasoning:
        content = reasoning  # Reasoning models put output here

    # 5. Extract JSON from response
    json_start = content.find("{")
    json_end = content.rfind("}") + 1
    result = json.loads(content[json_start:json_end])
```

### Rate Limiting

```python
rate_limit_requests = 10  # per minute
rate_limit_window = 60.0  # seconds

# Sliding window: track timestamps, sleep if at limit
```

### Reasoning Model Compatibility

Some models (e.g., DeepSeek-R1) put their output in `reasoning_content` instead of `content`.
The code handles both cases.

---

## Result Storage in Redis

After LLM analysis, results are written to the flow's Redis Hash:

```python
pipe = self.redis_client.pipeline()
pipe.hset(flow_key, "llm_result", json.dumps(result, ensure_ascii=False))
pipe.hset(flow_key, "llm_verdict", result["verdict"])
pipe.hset(flow_key, "llm_severity", result["severity"])
# ... additional fields
pipe.expire(flow_key, 300)  # 5 minutes
pipe.execute()
```

---

## Retry and Failure Handling

| Scenario | Action |
|----------|--------|
| API call fails | Re-enqueue with `retry_count += 1` |
| `retry_count >= 3` | Move to `llm_failed_queue` |
| Redis connection lost | Exponential backoff + auto-reconnect |
| JSON parse failure | Return `_dummy_result()` with "unknown" verdict |

### Dummy Result

When LLM is unavailable, return a safe default:

```python
{
    "verdict": "unknown",
    "severity": "Info",
    "is_successful_attack": "unknown",
    "recommended_action": "Monitor"
}
```

---

## Prompt Engineering Principles

1. **Explicit JSON schema** in the prompt — don't rely on the model guessing
2. **Edge case rules** — early flow, blind exploit, encrypted traffic → mark as "unknown"
3. **Success matrix** — distinguish "attack happened" vs "attack succeeded"
4. **Chinese explanations** — `explanation_for_non_expert` is for front-line engineers
5. **Low temperature (0.3)** — deterministic analysis, reduce hallucination

---

## Anti-Patterns

| Pattern | Why It's Wrong |
|---------|---------------|
| Using f-string for prompt template | JSON `{}` in prompt causes format errors |
| Not sanitizing features before LLM | Potential prompt injection via Suricata signatures |
| Assuming `content` is always populated | Reasoning models use `reasoning_content` |
| Hardcoding API URL/key | Must come from config |
| Infinite retry loop | Always cap at `max_retries` |
