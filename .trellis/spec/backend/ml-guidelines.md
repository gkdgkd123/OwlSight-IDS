# ML Layer Guidelines

> XGBoost + Isolation Forest dual-model inference patterns for OwlSight-IDS.

---

## Overview

Module 2 (`early_flow_xgb.py`) implements the L1 (Machine Learning) layer.
It performs **early flow detection** with a dual-trigger mechanism (10 packets OR 3 seconds),
extracts an **18-dimensional feature vector**, and runs **dual-model inference** (XGBoost + Isolation Forest).

---

## Dual-Model Architecture

| Model | Type | Purpose | Score Range | Threshold |
|-------|------|---------|-------------|-----------|
| XGBoost | Supervised | Known attack detection | 0-1 | >0.9 = BLOCK, <0.5 = safe |
| Isolation Forest | Unsupervised | Anomaly / 0day detection | 0-1 | >0.75 = highly anomalous |

**Key insight**: XGBoost alone misses novel attacks. Isolation Forest alone has high false positives.
The dual-model approach uses both scores in a synergistic decision tree (handled by Module 3).

---

## Feature Vector (18 Dimensions)

Must be **identical** between training and inference:

```python
feature_columns = [
    # Basic stats
    'packet_count', 'bytes_sent', 'duration',
    # IAT features (most important for attack detection)
    'iat_mean', 'iat_std', 'iat_min', 'iat_max',
    # Packet length features
    'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
    # TCP flag features
    'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
    # Rate features
    'bytes_per_second', 'packets_per_second'
]
```

**Rule**: The order of `feature_columns` MUST match the training pipeline exactly.
Adding/removing/reordering features requires retraining all models.

---

## Model Loading

Models are loaded at module init via pickle/JSON:

| Model | Format | Path | Loader |
|-------|--------|------|--------|
| XGBoost | JSON (`xgb_model.json`) | `XGBoostConfig.model_path` | `xgb.Booster().load_model()` |
| Isolation Forest | Pickle (`iforest_model.pkl`) | `{model_dir}/iforest_model.pkl` | `pickle.load()` |
| StandardScaler | Pickle (`scaler.pkl`) | `{model_dir}/scaler.pkl` | `pickle.load()` |
| Percentiles | JSON (`iforest_info.json`) | `{model_dir}/iforest_info.json` | `json.load()` |

**Fallback**: If any model file is missing, fall back to heuristic mode (rule-based scoring).
Never crash on missing models — the system degrades gracefully.

---

## Isolation Forest Score Normalization

Raw `decision_function()` scores are negative (more negative = more anomalous).
Must normalize to 0-1 using training set percentiles:

```python
# Load percentiles from iforest_info.json
p5 = percentiles['p5']   # Most anomalous end
p95 = percentiles['p95'] # Most normal end

# Invert (raw is negative), then linear map to [0,1]
inverted = -anomaly_score_raw
inverted_p5 = -p95   # Normal → small
inverted_p95 = -p5   # Anomalous → large
anomaly_score = (inverted - inverted_p5) / (inverted_p95 - inverted_p5)
anomaly_score = max(0.0, min(1.0, anomaly_score))
```

If percentiles are unavailable, use legacy fallback: `max(0, min(1, -raw + 0.5))`.

---

## Early Flow Detection

### Dual-Trigger Mechanism

A flow triggers inference when **either** condition is met:

| Condition | Threshold | Config Key |
|-----------|-----------|------------|
| Packet count | 10 packets | `ScapyConfig.packet_trigger` |
| Time elapsed | 3 seconds | `ScapyConfig.time_trigger` |

### Deduplication

Mark `flow_stats.already_inferred = True` after inference to prevent re-processing.
This flag is also set by Suricata Early Abort (Pub/Sub signal).

---

## Early Abort (Suricata Integration)

Module 2 subscribes to `suricata_alerts_channel` on a **dedicated Redis connection** (Pub/Sub requires exclusive connection).
When a Suricata alert arrives for a flow being captured:

```python
# Mark flow as already inferred (stops feature collection)
if flow_key in self.active_flows:
    self.active_flows[flow_key].already_inferred = True
```

**Thread safety**: Access to `active_flows` inside the listener is protected by `self.lock`.

---

## Memory Management

### LRU Eviction

`active_flows` uses `OrderedDict` with `MAX_ACTIVE_FLOWS = 50000`:

```python
# On new flow creation, evict oldest if at capacity
while len(self.active_flows) >= self.max_active_flows:
    evicted_key, _ = self.active_flows.popitem(last=False)

# On existing flow access, move to end (most recent)
self.active_flows.move_to_end(flow_key)
```

### Stale Flow Cleanup

Every 10 seconds, remove flows older than 60 seconds:

```python
stale_keys = [
    key for key, stats in self.active_flows.items()
    if current_time - stats.flow_start_time > self.flow_timeout  # 60s
]
for key in stale_keys:
    del self.active_flows[key]
```

---

## Heuristic Fallback

When model files are unavailable, use rule-based heuristics:

```python
def _heuristic_xgb(self, feature_vector):
    score = 0.5
    # Port scan: small packets + fast intervals
    if pkt_len_mean < 100 and iat_mean < 0.01:
        score += 0.2
    # DoS: many packets + extremely fast
    if packet_count > 50 and iat_mean < 0.001:
        score += 0.25
    return max(0.0, min(1.0, score))
```

**Purpose**: Keeps the detection pipeline functional even without trained models.

---

## Anti-Patterns

| Pattern | Why It's Wrong |
|---------|---------------|
| Changing `feature_columns` order silently | Models trained with different order produce garbage |
| Using `pickle.loads()` on external data | Arbitrary code execution risk |
| Not normalizing IForest scores | Raw scores are unbounded negatives, unusable for thresholding |
| Running inference inside the lock | Blocks packet capture; inference can be slow |
| Not marking `already_inferred` | Same flow gets analyzed multiple times, wasting resources |
