"""
LLM 微调数据生成脚本

从 pcap 流特征 + Suricata 告警 + ML 推理结果，生成 fine-tune 格式的训练数据。
输出格式兼容 OpenAI / Qwen fine-tune（messages 数组）。

用法：
    python scripts/generate_finetune_data.py \
        --pcap data/capture_20260429_155502.pcap \
        --suricata-alerts data/capture_20260429_155502_suricata_alerts.json \
        --output data/finetune_llm.jsonl
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import random
import numpy as np
import pandas as pd
import pickle
from collections import defaultdict
from string import Template

from scripts.train_xgboost import FlowFeatureExtractor
from src.utils import generate_five_tuple_key


# ─── Prompt 模板 ─────────────────────────────────────

PROMPT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "src" / "prompts" / "llm_analyst.md"


def load_prompt_template() -> Template:
    return Template(PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8"))


# ─── 特征提取 ────────────────────────────────────────

FEATURE_COLS = [
    'packet_count', 'bytes_sent', 'duration',
    'iat_mean', 'iat_std', 'iat_min', 'iat_max',
    'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
    'tcp_flags_count', 'syn_count', 'ack_count', 'fin_count', 'rst_count',
    'bytes_per_second', 'packets_per_second'
]


def extract_flows(pcap_file: str) -> pd.DataFrame:
    extractor = FlowFeatureExtractor()
    flow_data = extractor.extract_from_pcap(pcap_file)
    return extractor.compute_features(flow_data)


def load_suricata_alerts(alerts_file: str) -> dict:
    """加载 Suricata 告警，按五元组 key 聚合（含 flow 双向流量数据）"""
    alerts = defaultdict(list)
    with open(alerts_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get('event_type') != 'alert':
                    continue
                key = generate_five_tuple_key(
                    event['src_ip'], event.get('src_port', 0),
                    event['dest_ip'], event.get('dest_port', 0),
                    event.get('proto', '')
                )
                alert_info = event.get('alert', {})
                flow_info = event.get('flow', {})
                alerts[key].append({
                    'signature': alert_info.get('signature', ''),
                    'category': alert_info.get('category', ''),
                    'severity': alert_info.get('severity', 3),
                    'action': alert_info.get('action', ''),
                    'signature_id': alert_info.get('signature_id', 0),
                    'pkts_toserver': flow_info.get('pkts_toserver', 0),
                    'pkts_toclient': flow_info.get('pkts_toclient', 0),
                    'bytes_toserver': flow_info.get('bytes_toserver', 0),
                    'bytes_toclient': flow_info.get('bytes_toclient', 0),
                })
            except Exception:
                continue
    return dict(alerts)


def load_models():
    """加载校准后的 ML 模型"""
    models_dir = Path("src/models")

    with open(models_dir / "xgb_model.json", "rb") as f:
        import xgboost as xgb
        xgb_model = xgb.Booster()
        xgb_model.load_model(str(models_dir / "xgb_model.json"))

    with open(models_dir / "iforest_model.pkl", "rb") as f:
        iforest_model = pickle.load(f)

    with open(models_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)

    with open(models_dir / "iforest_info.json", "r") as f:
        iforest_info = json.load(f)

    return xgb_model, iforest_model, scaler, iforest_info


def ml_predict(xgb_model, iforest_model, scaler, iforest_info, feature_vector):
    """运行双模型推理，返回 xgb_score 和 anomaly_score"""
    import xgboost as xgb

    # XGBoost
    dmat = xgb.DMatrix([feature_vector], feature_names=FEATURE_COLS)
    xgb_score = float(xgb_model.predict(dmat)[0])

    # Isolation Forest（带 scaler 和 percentile 归一化）
    scaled = scaler.transform([feature_vector])[0]
    raw_score = iforest_model.decision_function([scaled])[0]

    percentiles = iforest_info.get('anomaly_score_percentiles', {})
    p5 = percentiles.get('p5', -0.3)
    p95 = percentiles.get('p95', 0.1)
    inverted = -raw_score
    inverted_p5 = -p95
    inverted_p95 = -p5
    if inverted_p95 > inverted_p5:
        anomaly_score = (inverted - inverted_p5) / (inverted_p95 - inverted_p5)
    else:
        anomaly_score = 0.5
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    return xgb_score, anomaly_score


# ─── 特征转自然语言 ─────────────────────────────────

def features_to_nl(features: dict) -> str:
    """将 18 维流特征转换为自然语言描述"""
    desc = []

    iat_mean = features.get("iat_mean", 0)
    iat_std = features.get("iat_std", 0)
    pkt_count = features.get("packet_count", 0)
    pkt_len_mean = features.get("pkt_len_mean", 0)
    pkt_len_std = features.get("pkt_len_std", 0)
    bytes_sent = features.get("bytes_sent", 0)
    duration = features.get("duration", 0)
    bps = features.get("bytes_per_second", 0)
    pps = features.get("packets_per_second", 0)
    flags_count = features.get("tcp_flags_count", 0)
    syn = features.get("syn_count", 0)
    ack = features.get("ack_count", 0)
    fin = features.get("fin_count", 0)
    rst = features.get("rst_count", 0)

    # ── 包间隔 (IAT) ──
    if iat_mean < 0.001:
        desc.append(f"数据包到达间隔极短（均值 {iat_mean*1000:.2f}ms），疑似高速自动化攻击")
    elif iat_mean < 0.01:
        desc.append(f"数据包到达间隔很短（均值 {iat_mean*1000:.1f}ms），疑似快速扫描或自动化工具")
    elif iat_mean > 10.0:
        desc.append(f"数据包到达间隔很长（均值 {iat_mean:.1f}s），可能是慢速扫描或Beacon心跳")
    elif iat_mean > 5.0:
        desc.append(f"数据包到达间隔较长（均值 {iat_mean:.2f}s），疑似慢速探测或低频通信")

    if iat_std < 0.001 and pkt_count > 5:
        desc.append(f"包间隔标准差极小（{iat_std*1000:.3f}ms），行为极度规律，疑似机器定时通信")
    elif iat_std < 0.01 and pkt_count > 10 and iat_mean > 1.0:
        desc.append(f"包间隔变异系数低（std={iat_std:.3f}s/mean={iat_mean:.2f}s），定期通信模式")

    # ── 包长 ──
    if pkt_len_mean < 60:
        desc.append(f"平均包长极小（{pkt_len_mean:.0f}B），典型的纯控制/探测流量")
    elif pkt_len_mean < 100:
        desc.append(f"平均包长很小（{pkt_len_mean:.1f}B），可能是探测流量或控制流量")
    elif pkt_len_mean > 1200:
        desc.append(f"平均包长接近MTU（{pkt_len_mean:.0f}B），大量数据填充传输")
    elif pkt_len_mean > 1000:
        desc.append(f"平均包长较大（{pkt_len_mean:.1f}B），可能包含大量数据传输")

    if pkt_len_std < 10 and pkt_count > 5:
        desc.append(f"包长标准差极小（{pkt_len_std:.1f}B），包大小高度一致，疑似固定格式协议或Beacon")
    elif pkt_len_std > pkt_len_mean * 0.8 and pkt_count > 5:
        desc.append(f"包长波动大（std={pkt_len_std:.0f}B/mean={pkt_len_mean:.0f}B），混合了控制包和数据包")

    # ── 传输量 ──
    if bytes_sent > 10000000:
        desc.append(f"总传输量巨大（{bytes_sent/1024/1024:.1f}MB），疑似批量数据传输或外泄")
    elif bytes_sent > 100000:
        desc.append(f"总传输量较大（{bytes_sent/1024:.1f}KB），可能存在数据外泄风险")
    elif bytes_sent < 100 and pkt_count > 0:
        desc.append(f"总传输量极小（{bytes_sent}B），仅传输了控制信息")

    # ── 吞吐量 ──
    if bps > 500000:
        desc.append(f"传输速率极高（{bps/1024:.0f}KB/s），疑似大文件传输或数据外泄")
    elif bps > 100000:
        desc.append(f"传输速率较高（{bps/1024:.0f}KB/s），数据密集型通信")

    # ── 包速率 ──
    if pps > 1000:
        desc.append(f"包速率极高（{pps:.0f}pkt/s），典型的DDoS攻击特征")
    elif pps > 100:
        desc.append(f"包速率很高（{pps:.1f}pkt/s），可能是DoS攻击或高速扫描")

    # ── 包数与时长 ──
    if pkt_count > 0:
        if duration < 0.01:
            desc.append(f"捕获到 {pkt_count} 个数据包，持续时间极短（{duration*1000:.0f}ms）")
        elif duration > 300:
            desc.append(f"长连接：{pkt_count} 个数据包，持续 {duration:.0f}s")
        else:
            desc.append(f"捕获到 {pkt_count} 个数据包，持续 {duration:.2f}s")

    # ── TCP 标志 ──
    if flags_count >= 5:
        desc.append(f"TCP标志种类多（{flags_count}种），连接经历了多种状态转换")

    if syn > 5 and syn == pkt_count:
        desc.append(f"全部为SYN包（{syn}个），典型的端口扫描/DoS特征")
    elif syn > 0 and ack == 0:
        desc.append(f"有{syn}个SYN包但无ACK响应，TCP三次握手未完成")
    elif syn > 0 and ack > 0:
        desc.append(f"完整的TCP握手（SYN={syn}, ACK={ack}），连接已建立")

    if rst > 0 and ack > 0:
        desc.append(f"存在{rst}个RST包（连接已建立后被重置），可能为攻击后清理或异常终止")
    elif rst > 0:
        desc.append(f"存在{rst}个RST包，连接被重置")

    if fin > 0:
        desc.append(f"存在{fin}个FIN包，连接正常关闭")
    if fin == 0 and rst == 0 and pkt_count < 10:
        desc.append("连接尚未关闭（无FIN/RST）且包数较少，属于早期流，结果可能不完整")

    return "；".join(desc) if desc else "流量特征正常"


# ─── 标注引擎 ────────────────────────────────────────

def _compute_confidence(xgb_score, anomaly_score, has_suricata, min_severity, is_successful, verdict):
    """分层计算置信度：Suricata 告警 > ML 分数 > 基线"""
    # Suricata 高置信度告警（severity 1-2）→ 保底 0.6
    if has_suricata and min_severity <= 1:
        base = 0.55
        c = round(min(0.95, max(0.6, base + anomaly_score * 0.2 + (0.15 if is_successful == "yes" else 0))), 2)
    # Suricata 中置信度告警（severity 2）→ 保底 0.5
    elif has_suricata and min_severity <= 2:
        base = 0.45
        c = round(min(0.95, max(0.5, base + xgb_score * 0.2 + anomaly_score * 0.15 + (0.1 if is_successful == "yes" else 0))), 2)
    # Suricata 低置信度或仅 ML
    else:
        base = 0.10
        c = round(min(0.95, max(0.30, base + xgb_score * 0.35 + anomaly_score * 0.25 + (0.1 if is_successful == "yes" else 0))), 2)
    return c


def annotate(flow: dict, suricata_alerts: list) -> dict:
    """根据 Suricata 告警 + 流特征生成专家标注 JSON"""
    xgb_score = flow['xgb_score']
    anomaly_score = flow['anomaly_score']
    features = flow['features']
    has_suricata = len(suricata_alerts) > 0

    syn = features.get('syn_count', 0)
    ack = features.get('ack_count', 0)
    fin = features.get('fin_count', 0)
    rst = features.get('rst_count', 0)
    pkt_count = features.get('packet_count', 0)
    duration = features.get('duration', 0)
    bytes_sent = features.get('bytes_sent', 0)
    pps = features.get('packets_per_second', 0)
    iat_mean = features.get('iat_mean', 0)
    iat_std = features.get('iat_std', 0)
    pkt_len_mean = features.get('pkt_len_mean', 0)
    is_early = (fin == 0 and rst == 0 and pkt_count < 10)

    # 收集 Suricata 签名信息
    signatures = [a['signature'] for a in suricata_alerts]
    categories = list(set(a['category'] for a in suricata_alerts))
    min_severity = min((a['severity'] for a in suricata_alerts), default=3)

    # ── 判定逻辑 ──

    # 1. verdict
    if has_suricata and min_severity <= 2:
        verdict = "malicious"
    elif has_suricata and min_severity == 3:
        verdict = "suspicious"
    elif xgb_score >= 0.8:
        verdict = "malicious"
    elif xgb_score >= 0.5 or anomaly_score >= 0.75:
        verdict = "suspicious"
    else:
        verdict = "benign"

    # 2. severity
    if has_suricata and min_severity <= 1:
        severity = "Critical"
    elif has_suricata and min_severity == 2:
        severity = "High"
    elif has_suricata or xgb_score >= 0.7:
        severity = "Medium"
    elif anomaly_score >= 0.5:
        severity = "Low"
    else:
        severity = "Info"

    # 3. is_successful_attack
    if verdict == "benign":
        is_successful = "no"
    elif is_early:
        is_successful = "unknown"
    elif syn > 0 and ack == 0 and pkt_count <= syn + 5:
        is_successful = "no"  # 纯 SYN，握手未完成
    elif rst > 0 and bytes_sent < 1000:
        is_successful = "no"  # 连接立即被重置
    elif has_suricata and ack > 0 and bytes_sent > 5000:
        is_successful = "yes"  # Suricata + 完整握手 + 数据
    elif has_suricata and rst > 0 and ack > 0 and bytes_sent >= 1000:
        is_successful = "yes"  # Suricata + 握手后 RST
    elif has_suricata and xgb_score >= 0.5 and ack > 0 and bytes_sent > 2000:
        is_successful = "yes"  # Suricata + ML 高分 + 数据
    elif not has_suricata and xgb_score >= 0.7 and ack > 0 and bytes_sent > 10000:
        is_successful = "yes"  # 仅 ML 高确信 + 大量数据
    else:
        is_successful = "unknown"

    # 4. threat_type
    sig_text = " ".join(signatures).lower()
    if verdict == "benign":
        threat_type = "Benign_Traffic"
    elif "drop" in sig_text or "spamhaus" in sig_text:
        threat_type = "Known_Malicious_IP"
    elif "scan" in sig_text or (syn == pkt_count and syn > 3):
        threat_type = "Reconnaissance"
    elif "dos" in sig_text or (pps > 100 and syn > 0 and ack == 0):
        threat_type = "DoS_Attempt"
    elif "exploit" in sig_text or "rce" in sig_text:
        threat_type = "Exploit_Attempt"
    elif "c2" in sig_text or "botnet" in sig_text:
        threat_type = "Suspected_C2"
    elif "sql" in sig_text:
        threat_type = "Exploit_Attempt"
    elif anomaly_score >= 0.75 and xgb_score < 0.5:
        threat_type = "Unknown_Anomaly"
    else:
        threat_type = "Suspicious_Traffic"

    # 5. success_evidence（基于实际流状态细化）
    bps = features.get('bytes_per_second', 0)
    if is_successful == "no":
        if verdict == "benign":
            if fin > 0 and ack > 0 and bytes_sent > 50000:
                success_evidence = f"正常数据传输（{bytes_sent/1024:.0f}KB/{pkt_count}个包），TCP正常关闭（FIN={fin}），无异常行为"
            elif fin > 0 and ack > 0 and duration > 60:
                success_evidence = f"长连接通信（{duration:.0f}s/{pkt_count}个包），TCP正常关闭，属正常持续通信"
            elif fin > 0:
                success_evidence = f"短连接（{pkt_count}个包/{bytes_sent}字节），TCP正常关闭（FIN={fin}），行为正常"
            elif ack > 0:
                success_evidence = f"活跃TCP通信（{pkt_count}个包/{bytes_sent}字节），连接状态正常，无恶意指标"
            else:
                success_evidence = f"低频短连接（{pkt_count}个包/{duration:.2f}s），无已知攻击指标"
        elif syn > 0 and ack == 0:
            success_evidence = f"SYN={syn}但无ACK响应，TCP握手未完成（{pkt_count}个包/{duration:.2f}s）"
        elif rst > 0:
            success_evidence = f"连接被RST重置（{rst}个RST包），仅传输{bytes_sent}字节，数据交换未完成"
        elif is_early:
            success_evidence = f"早期流（{pkt_count}个包/{duration:.2f}s），连接尚未关闭，攻击尚在进行"
        else:
            success_evidence = f"触发告警但无数据交换证据（{pkt_count}个包/{bytes_sent}字节）"
    elif is_successful == "yes":
        if bps > 50000:
            success_evidence = f"高带宽数据传输（{bytes_sent/1024:.0f}KB/{duration:.1f}s，{bps/1024:.0f}KB/s），连接正常完成"
        elif rst > 0 and bytes_sent > 1000:
            success_evidence = f"连接已建立并交换{bytes_sent}字节数据后被RST终止，数据可能已被篡改/窃取"
        elif has_suricata:
            success_evidence = f"Suricata签名'{signatures[0][:60]}'匹配，完整TCP通信（{pkt_count}个包/{bytes_sent}字节）"
        else:
            success_evidence = f"完整TCP握手（SYN+ACK），双向传输{bytes_sent}字节/{pkt_count}个包，连接正常完成"
    else:  # unknown
        if is_early:
            success_evidence = f"早期流（仅{pkt_count}个包/{duration:.2f}s），连接仍开放，结果待定"
        elif has_suricata and ack == 0:
            success_evidence = f"Suricata匹配签名'{signatures[0][:50]}'但握手未完成，可能为探测阶段"
        elif anomaly_score >= 0.75 and xgb_score < 0.3:
            success_evidence = f"ML异常分数极高（{anomaly_score:.3f}）但无签名匹配，疑似0day利用，需OOB验证"
        elif ack > 0:
            success_evidence = f"TCP已握手（{pkt_count}个包/{bytes_sent}字节）但数据量不足以确认攻击结果"
        else:
            success_evidence = f"流量特征介于攻击与正常之间（XGB={xgb_score:.3f}，异常={anomaly_score:.3f}），需进一步分析"

    # 6. key_indicators（基于实际特征细化）
    indicators = []
    if has_suricata:
        indicators.append(f"Suricata: {signatures[0][:70]}")
    if xgb_score >= 0.8:
        indicators.append(f"XGBoost={xgb_score:.3f}（高确信恶意）")
    elif xgb_score >= 0.5:
        indicators.append(f"XGBoost={xgb_score:.3f}（疑似恶意）")
    if anomaly_score >= 0.9:
        indicators.append(f"异常分数={anomaly_score:.3f}（极度异常）")
    elif anomaly_score >= 0.75:
        indicators.append(f"异常分数={anomaly_score:.3f}（高度异常）")
    if syn == pkt_count and syn > 3:
        indicators.append(f"纯SYN包（{syn}个），端口扫描/DoS特征")
    if pps > 500:
        indicators.append(f"极高包速率={pps:.0f}pkt/s（DDoS级）")
    elif pps > 100:
        indicators.append(f"高包速率={pps:.0f}pkt/s")
    if bytes_sent > 1000000:
        indicators.append(f"大数据传输={bytes_sent/1024/1024:.1f}MB")
    elif bytes_sent > 50000:
        indicators.append(f"中等数据量={bytes_sent/1024:.0f}KB")
    if rst > 0 and ack > 0:
        indicators.append(f"连接建立后被RST终止（RST={rst}）")
    if is_early:
        indicators.append(f"早期流（{pkt_count}个包/{duration:.1f}s），连接未结束")
    if not indicators:
        if fin > 0:
            indicators.append(f"正常关闭流（FIN={fin}，{pkt_count}个包）")
        else:
            indicators.append(f"常规TCP通信（{pkt_count}个包/{bytes_sent}字节）")

    # 7. recommended_action
    if verdict == "benign":
        action = "Monitor"
    elif is_successful == "yes":
        action = "Block_IP"
    elif is_successful == "unknown" and anomaly_score >= 0.75:
        action = "Investigate_Further"
    elif has_suricata and is_successful == "unknown":
        action = "Investigate_Further"
    elif has_suricata:
        action = "Monitor"
    else:
        action = "Investigate_Further"

    # 8. mitre_techniques（仅 malicious/suspicious 才关联 ATT&CK）
    mitre = []
    if verdict != "benign":
        if "drop" in sig_text or "spamhaus" in sig_text:
            mitre.append("T1071")
        if syn == pkt_count and syn > 3:
            mitre.append("T1046")
        if pps > 100 and syn > 0:
            mitre.append("T1498")
        if "exploit" in sig_text or "rce" in sig_text:
            mitre.append("T1190")
        if "sql" in sig_text:
            mitre.append("T1190")

    # 9. reasoning（更详细，包含实际特征分析）
    source_type = "双源（Suricata + ML）" if has_suricata else "仅ML"
    tcp_state = "早期流（连接未关闭）" if is_early else (
        "TCP握手完成" if (syn > 0 and ack > 0) else (
        "握手失败（无ACK）" if (syn > 0 and ack == 0) else "无TCP握手信息"
    ))
    bidirectional = "双向通信" if (ack > 0 and bytes_sent > 0) else "单向或无数据"

    # 附加特征分析
    extra = []
    if iat_mean < 0.01 and pkt_count > 5:
        extra.append(f"IAT极短（{iat_mean*1000:.1f}ms），疑似自动化")
    elif iat_mean > 10:
        extra.append(f"IAT很长（{iat_mean:.1f}s），疑似慢速扫描")
    if iat_std < 0.001 and pkt_count > 5:
        extra.append(f"包间隔极规律（std={iat_std*1000:.2f}ms）")
    if pkt_len_mean < 60 and pkt_count > 5:
        extra.append(f"包长极小（均值{pkt_len_mean:.0f}B），控制流量特征")
    if pkt_len_mean > 1200:
        extra.append(f"大包（均值{pkt_len_mean:.0f}B），数据密集型")
    if syn > 0 and ack > 0 and rst > 0:
        extra.append(f"混合标志：SYN={syn},ACK={ack},RST={rst}")
    if bps > 100000:
        extra.append(f"高吞吐（{bps/1024:.0f}KB/s）")

    reasoning = (
        f"1. 数据源：{source_type}。"
        f"{'Suricata签名: ' + signatures[0] + '。' if has_suricata else ''}"
        f"XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。"
        f"2. TCP状态：{tcp_state}。包数={pkt_count}，持续{duration:.2f}s，"
        f"IAT均值={iat_mean:.4f}s（std={iat_std:.4f}s）。"
        f"3. {bidirectional}。总字节={bytes_sent}，"
        f"包长均值={pkt_len_mean:.1f}B。"
        f"{'RST=' + str(rst) + '，连接被重置。' if rst > 0 else ''}"
        f"{'4. 附加特征：' + '；'.join(extra) + '。' if extra else ''}"
        f"{'5' if extra else '4'}. 综合判断：{verdict}（{severity}）。{success_evidence}。"
    )

    # 10. explanation_for_non_expert（更丰富，早期流有独立描述）
    if verdict == "benign":
        if has_suricata and min_severity == 3:
            explanation = f"虽然Suricata触发了低危告警（{signatures[0][:50]}），但从流量行为看是正常通信。建议关注但无需处置。"
        elif bytes_sent > 5000000:
            explanation = f"大流量传输（{bytes_sent/1024/1024:.1f}MB），但属于正常的批量数据传输（如视频流、软件更新）。"
        elif bytes_sent > 100000:
            explanation = f"数据量较大（{bytes_sent/1024:.0f}KB），但连接行为正常，是合法的应用数据传输。"
        elif duration > 300:
            explanation = f"长时间连接（{duration:.0f}s），属于正常的持续通信（如WebSocket、SSH会话）。"
        elif duration > 30:
            explanation = f"中等时长连接（{duration:.0f}s），{pkt_count}个数据包，行为模式正常。"
        elif is_early and ack == 0:
            explanation = f"极早期流（{pkt_count}个包/{duration:.2f}s），仅捕获到SYN握手阶段，属于正常的连接建立过程。"
        elif is_early and ack > 0:
            explanation = f"早期流（{pkt_count}个包），TCP刚开始数据交换，流量过少无法判断意图，但无恶意特征。"
        elif pkt_count <= 5:
            explanation = f"短连接（{pkt_count}个包/{bytes_sent}字节），可能是单次HTTP请求或DNS查询，无异常。"
        elif fin > 0:
            explanation = f"正常的应用通信（{pkt_count}个包/{bytes_sent}字节），TCP已正常关闭，无恶意行为。"
        else:
            explanation = "正常的应用流量，TCP连接行为正常，无任何恶意特征。"
    elif is_successful == "yes":
        if has_suricata:
            explanation = f"真实攻击已成功（签名: {signatures[0][:50]}）。传输了{bytes_sent/1024:.0f}KB数据。建议立即封禁来源IP并检查目标系统。"
        else:
            explanation = f"ML检测到的攻击行为已成功建立连接并传输{bytes_sent/1024:.0f}KB数据。建议检查服务端日志确认影响。"
    elif is_successful == "no":
        if syn > 0 and ack == 0:
            explanation = f"攻击尝试但未成功：TCP握手失败（SYN={syn}，无ACK响应）。攻击者未能建立连接。建议持续监控该IP。"
        elif rst > 0:
            explanation = f"连接被目标服务器主动重置（RST={rst}），攻击未能完成数据交换。可能有防护设备在起作用。"
        else:
            explanation = f"虽然触发了告警，但未观察到攻击成功的证据。建议持续监控。"
    else:
        parts = ["这条流量需要进一步排查。"]
        if is_early:
            parts.append("连接仍在进行中，建议等待结束后重新分析。")
        if has_suricata:
            parts.append(f"有Suricata告警（{signatures[0][:40]}）但无法确认结果，建议检查服务端日志。")
        if not has_suricata and anomaly_score >= 0.75:
            parts.append("ML检测到高度异常但无已知签名匹配，可能是0day攻击，建议抓包深入分析。")
        if not has_suricata and anomaly_score < 0.75:
            parts.append(f"ML分数在灰色地带（XGB={xgb_score:.3f}），建议结合业务上下文判断。")
        explanation = "".join(parts)

    return {
        "reasoning": reasoning,
        "verdict": verdict,
        "severity": severity,
        "threat_type": threat_type,
        "is_successful_attack": is_successful,
        "success_evidence": success_evidence,
        "confidence": _compute_confidence(xgb_score, anomaly_score, has_suricata, min_severity, is_successful, verdict),
        "key_indicators": indicators,
        "recommended_action": action,
        "mitre_techniques": mitre if mitre else [],
        "explanation_for_non_expert": explanation,
    }


# ─── 合成数据引擎 ────────────────────────────────────

def _rand_ip(internal=False):
    if internal:
        return f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _flow_key(src, sp, dst, dp, proto="TCP"):
    return f"{src}:{sp}-{dst}:{dp}-{proto}"


def _build_context(features, xgb_score, anomaly_score, suricata_alerts=None):
    """构建 prompt context（与 generate_finetune_data 中的逻辑一致）"""
    if suricata_alerts:
        a = suricata_alerts[0]
        alert_count = len(suricata_alerts)
        action = a.get('action', 'unknown')
        sid = a.get('signature_id', 0)
        multi = f" (total {alert_count} alerts on this flow)" if alert_count > 1 else ""
        pts = a.get('pkts_toserver', 0)
        ptc = a.get('pkts_toclient', 0)
        bts = a.get('bytes_toserver', 0)
        btc = a.get('bytes_toclient', 0)
        flow_detail = ""
        if pts > 0 or ptc > 0:
            flow_detail = f"\n- Flow: pkts_toserver={pts}, pkts_toclient={ptc}, bytes_toserver={bts}, bytes_toclient={btc}"
            if btc > 1000:
                flow_detail += " (server returned significant data)"
            elif ptc == 0:
                flow_detail += " (unidirectional - no server response)"
        return (
            f"**Detection Source**: Dual (Suricata + ML)\n"
            f"- Suricata Alert: {a['signature']} (category: {a['category']}, severity: {a['severity']}, action: {action}, sid: {sid}){multi}{flow_detail}\n"
            f"- XGBoost score: {xgb_score:.3f}\n"
            f"- Isolation Forest anomaly score: {anomaly_score:.3f}\n\n"
            f"**Key Finding**: Suricata rule matched known attack signature. "
            f"{'Traffic was dropped by firewall. ' if action == 'drop' else 'Traffic was allowed through. '}"
            f"{'Server returned ' + str(btc) + ' bytes of data. ' if btc > 1000 else ''}"
            f"ML models provide behavioral context."
        )
    if anomaly_score >= 0.75 and xgb_score < 0.5:
        return (
            f"**Detection Source**: ML Alert Only (no Suricata)\n"
            f"- XGBoost score: {xgb_score:.3f} (< 0.5, model considers SAFE)\n"
            f"- Isolation Forest anomaly score: {anomaly_score:.3f} (> 0.75, EXTREMELY anomalous)\n\n"
            f"**Key Finding**: XGBoost considers this flow safe, but Isolation Forest detected "
            f"an extremely anomalous behavioral pattern. Possible 0day threat."
        )
    return (
        f"**Detection Source**: ML Alert Only (no Suricata)\n"
        f"- XGBoost score: {xgb_score:.3f}\n"
        f"- Isolation Forest anomaly score: {anomaly_score:.3f}\n\n"
        f"**Key Finding**: ML models flagged this flow for review."
    )


def _record(system_prompt, prompt_template, context, features, annotation):
    """构建一条 JSONL 训练记录"""
    features_text = features_to_nl(features)
    user_prompt = prompt_template.substitute(context=context, features_text=features_text)
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": json.dumps(annotation, ensure_ascii=False, indent=2)}
        ]
    }


def generate_synthetic_scenarios(prompt_template, system_prompt, rng_seed=42):
    """生成 8 类合成场景，覆盖真实 pcap 中缺失的模式"""
    rng = random.Random(rng_seed)
    records = []

    # ── 1. 成功的 SQL 注入（双源，高频变体）──────────────
    for i in range(20):
        src = _rand_ip()
        dst = _rand_ip()
        sp = rng.randint(1024, 65535)
        dp = rng.choice([80, 443, 8080, 8443])
        fk = _flow_key(src, sp, dst, dp)

        pkt_count = rng.randint(30, 200)
        dur = rng.uniform(2.0, 30.0)
        bytes_sent = rng.randint(8000, 150000)
        pps = pkt_count / max(dur, 0.01)

        sqli_patterns = [
            ("ET SQL Injection Possible SELECT...UNION", "Web Application Attack", 1),
            ("ET SQL Injection MySQL Comment-Based", "Web Application Attack", 1),
            ("ET SQL Injection ORDER BY Clause Detected", "Web Application Attack", 2),
            ("ET SQL Injection Possible 1=1", "Web Application Attack", 1),
        ]
        sig, cat, sev = rng.choice(sqli_patterns)
        payload = rng.choice([
            "' UNION SELECT username,password FROM users--",
            "1' OR '1'='1' UNION SELECT null,table_name FROM information_schema.tables--",
            "'; DROP TABLE sessions; --",
            "1 UNION SELECT LOAD_FILE('/etc/passwd')--",
        ])

        features = {
            'flow_key': fk, 'packet_count': pkt_count, 'bytes_sent': bytes_sent,
            'duration': dur, 'iat_mean': rng.uniform(0.05, 0.5), 'iat_std': rng.uniform(0.02, 0.3),
            'iat_min': rng.uniform(0.001, 0.01), 'iat_max': rng.uniform(0.5, 3.0),
            'pkt_len_mean': rng.uniform(200, 800), 'pkt_len_std': rng.uniform(100, 400),
            'pkt_len_min': rng.randint(40, 100), 'pkt_len_max': rng.randint(800, 1500),
            'tcp_flags_count': rng.randint(3, 6), 'syn_count': rng.randint(1, 3),
            'ack_count': rng.randint(int(pkt_count*0.4), int(pkt_count*0.6)),
            'fin_count': rng.randint(0, 2), 'rst_count': 0,
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pps,
        }
        suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        xgb_score = rng.uniform(0.85, 0.98)
        anomaly_score = rng.uniform(0.5, 0.9)

        annotation = {
            "reasoning": f"1. 数据源类型：双源（Suricata + ML）。Suricata签名: {sig}。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：TCP握手完成。包数={pkt_count}，持续{dur:.2f}s。3. 双向通信。总字节={bytes_sent}。4. 综合判断：malicious（Critical）。Suricata匹配SQL注入payload，服务端有大量响应数据，攻击成功。",
            "verdict": "malicious",
            "severity": "Critical",
            "threat_type": "Exploit_Attempt",
            "is_successful_attack": "yes",
            "success_evidence": f"Suricata匹配SQL注入签名'{sig}'，服务端返回{bytes_sent}字节数据，表明数据库查询被执行并返回结果",
            "confidence": round(min(0.95, xgb_score * 0.5 + anomaly_score * 0.3 + 0.2), 2),
            "key_indicators": [f"Suricata告警: {sig}", f"XGBoost得分 {xgb_score:.3f}", f"大量服务端响应数据 {bytes_sent} bytes", "SQL注入payload匹配"],
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1190", "T1059.007"],
            "explanation_for_non_expert": f"攻击者通过SQL注入成功访问了数据库（签名: {sig}），服务端返回了大量数据。建议立即封禁来源IP，检查数据库是否被篡改。",
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 2. C2 Beacon 心跳通信（双源）────────────────────
    for i in range(15):
        src = _rand_ip(internal=True)
        dst = _rand_ip()
        sp = rng.randint(49152, 65535)
        dp = rng.choice([443, 8443, 53, 8080, 4444])

        beacon_interval = rng.uniform(30.0, 300.0)
        pkt_count = rng.randint(50, 500)
        dur = rng.uniform(beacon_interval * 5, beacon_interval * 20)
        bytes_sent = rng.randint(5000, 50000)

        c2_patterns = [
            ("ET TROJAN Cobalt Strike Beacon Activity", "Malware Command and Control", 1),
            ("ET TROJAN Meterpreter or Reverse Shell", "Malware Command and Control", 1),
            ("ET C2 Domain Observed in Malleable C2 Profile", "Malware Command and Control", 1),
            ("ET TROJAN Possible C2 Beacon", "Malware Command and Control", 2),
        ]
        sig, cat, sev = rng.choice(c2_patterns)

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': beacon_interval, 'iat_std': rng.uniform(1.0, beacon_interval * 0.1),
            'iat_min': rng.uniform(beacon_interval * 0.8, beacon_interval * 0.95),
            'iat_max': rng.uniform(beacon_interval * 1.05, beacon_interval * 1.3),
            'pkt_len_mean': rng.uniform(50, 200), 'pkt_len_std': rng.uniform(10, 80),
            'pkt_len_min': rng.randint(40, 80), 'pkt_len_max': rng.randint(100, 500),
            'tcp_flags_count': rng.randint(2, 4), 'syn_count': rng.randint(1, 2),
            'ack_count': rng.randint(int(pkt_count*0.45), int(pkt_count*0.55)),
            'fin_count': 0, 'rst_count': 0,
            'bytes_per_second': bytes_sent / max(dur, 1), 'packets_per_second': pkt_count / max(dur, 1),
        }
        suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        xgb_score = rng.uniform(0.7, 0.95)
        anomaly_score = rng.uniform(0.6, 0.95)

        annotation = {
            "reasoning": f"1. 数据源类型：双源（Suricata + ML）。Suricata签名: {sig}。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：TCP握手完成，连接长期存在。包数={pkt_count}，持续{dur:.1f}s。3. 双向通信。总字节={bytes_sent}。平均包间隔{beacon_interval:.1f}s，高度规律。4. 综合判断：malicious（Critical）。C2心跳通信特征明显。",
            "verdict": "malicious",
            "severity": "Critical",
            "threat_type": "Suspected_C2",
            "is_successful_attack": "yes",
            "success_evidence": f"长期双向C2通信已建立（持续{dur:.0f}s），定期心跳间隔约{beacon_interval:.0f}s，表明受控主机与C2服务器通信正常",
            "confidence": round(min(0.95, xgb_score * 0.5 + anomaly_score * 0.3 + 0.2), 2),
            "key_indicators": [f"Suricata告警: {sig}", f"C2心跳特征：间隔{beacon_interval:.0f}s±{features['iat_std']:.0f}s", "长期双向通信", f"连接持续{dur:.0f}s"],
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1071", "T1573", "T1041"],
            "explanation_for_non_expert": f"主机 {src} 疑似已被植入恶意软件，正与C2服务器定期通信（签名: {sig}）。建议立即隔离该主机，封禁C2服务器IP。",
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 3. 成功的远程代码执行 RCE（双源）────────────────
    for i in range(15):
        src = _rand_ip()
        dst = _rand_ip()
        sp = rng.randint(1024, 65535)
        dp = rng.choice([80, 443, 8080, 9200, 2379])

        pkt_count = rng.randint(15, 80)
        dur = rng.uniform(1.0, 15.0)
        bytes_sent = rng.randint(5000, 80000)

        rce_patterns = [
            ("ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)", "Attempted Administrator Privilege Gain", 1),
            ("ET EXPLOIT Spring4Shell RCE Attempt (CVE-2022-22965)", "Attempted Administrator Privilege Gain", 1),
            ("ET EXPLOIT Apache Struts2 RCE (CVE-2017-5638)", "Attempted Administrator Privilege Gain", 1),
            ("ET EXPLOIT Possible Confluence RCE (CVE-2022-26134)", "Attempted Administrator Privilege Gain", 1),
            ("ET EXPLOIT ThinkPHP RCE Attempt", "Attempted Administrator Privilege Gain", 2),
        ]
        sig, cat, sev = rng.choice(rce_patterns)

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.05, 0.5), 'iat_std': rng.uniform(0.02, 0.3),
            'iat_min': rng.uniform(0.001, 0.01), 'iat_max': rng.uniform(0.3, 2.0),
            'pkt_len_mean': rng.uniform(300, 900), 'pkt_len_std': rng.uniform(100, 400),
            'pkt_len_min': rng.randint(40, 100), 'pkt_len_max': rng.randint(800, 1500),
            'tcp_flags_count': rng.randint(3, 5), 'syn_count': rng.randint(1, 2),
            'ack_count': rng.randint(int(pkt_count*0.4), int(pkt_count*0.6)),
            'fin_count': rng.randint(0, 1), 'rst_count': rng.randint(0, 1),
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        xgb_score = rng.uniform(0.8, 0.98)
        anomaly_score = rng.uniform(0.5, 0.9)

        # Log4j 类可能是盲打（无响应），其余有响应
        is_blind = "Log4j" in sig or "JNDI" in sig
        if is_blind:
            success = "unknown"
            success_evidence = "盲打型漏洞利用（Log4j/JNDI），服务端响应不明显，需检查DNS/OOB日志确认"
            explanation = f"检测到{sig}攻击尝试，属于盲打型漏洞利用，无法仅从网络流量判断是否成功。建议检查DNS查询日志和目标服务器安全日志。"
        else:
            success = "yes"
            success_evidence = f"完整TCP握手，服务端返回{bytes_sent}字节响应，RCE利用可能已成功执行"
            explanation = f"检测到RCE漏洞利用（{sig}），服务端有大量响应数据，攻击可能已成功。建议立即检查目标服务器。"

        annotation = {
            "reasoning": f"1. 数据源类型：双源（Suricata + ML）。Suricata签名: {sig}。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：TCP握手完成。包数={pkt_count}，持续{dur:.2f}s。3. {'双向' if not is_blind else '单向'}通信。总字节={bytes_sent}。4. 综合判断：malicious（Critical）。RCE漏洞利用检测。",
            "verdict": "malicious",
            "severity": "Critical",
            "threat_type": "Exploit_Attempt",
            "is_successful_attack": success,
            "success_evidence": success_evidence,
            "confidence": round(min(0.95, xgb_score * 0.5 + anomaly_score * 0.3 + 0.2), 2),
            "key_indicators": [f"Suricata告警: {sig}", "RCE漏洞利用签名", f"XGBoost得分 {xgb_score:.3f}"] + (["盲打型利用，需OOB确认"] if is_blind else [f"服务端响应 {bytes_sent} bytes"]),
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1190", "T1059"],
            "explanation_for_non_expert": explanation,
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 4. 数据外泄 Exfiltration（双源/ML-only）────────
    for i in range(20):
        src = _rand_ip(internal=True)
        dst = _rand_ip()
        sp = rng.randint(49152, 65535)
        dp = rng.choice([443, 8443, 22, 21, 53, 8080, 4444])

        pkt_count = rng.randint(200, 5000)
        dur = rng.uniform(30.0, 600.0)
        bytes_sent = rng.randint(100000, 50000000)  # 100KB to 50MB
        pps = pkt_count / max(dur, 1)

        has_suricata = rng.random() < 0.4
        if has_suricata:
            exfil_patterns = [
                ("ET POLICY Possible Data Exfiltration", "Potential Corporate Privacy Violation", 2),
                ("ET TROJAN Possible Backdoor Transfer", "Malware Command and Control", 1),
                ("ET POLICY Large Outbound Data Transfer", "Potential Corporate Privacy Violation", 3),
            ]
            sig, cat, sev = rng.choice(exfil_patterns)
            suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        else:
            suricata = None

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.001, 0.1), 'iat_std': rng.uniform(0.001, 0.05),
            'iat_min': rng.uniform(0.0001, 0.005), 'iat_max': rng.uniform(0.05, 1.0),
            'pkt_len_mean': rng.uniform(800, 1400), 'pkt_len_std': rng.uniform(100, 400),
            'pkt_len_min': rng.randint(40, 200), 'pkt_len_max': rng.randint(1200, 1500),
            'tcp_flags_count': rng.randint(3, 6), 'syn_count': rng.randint(1, 3),
            'ack_count': rng.randint(int(pkt_count*0.45), int(pkt_count*0.55)),
            'fin_count': rng.randint(0, 2), 'rst_count': 0,
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pps,
        }
        xgb_score = rng.uniform(0.4, 0.8)
        anomaly_score = rng.uniform(0.8, 0.99)

        verdict = "malicious" if has_suricata else "suspicious"
        sev_label = "High" if verdict == "malicious" else "Medium"
        source_desc = "双源（Suricata + ML）" if has_suricata else "仅ML"

        annotation = {
            "reasoning": f"1. 数据源类型：{source_desc}。{'Suricata签名: ' + suricata[0]['signature'] + '。' if suricata else ''}XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：TCP握手完成。包数={pkt_count}，持续{dur:.1f}s。3. 双向通信，大量数据传输。总字节={bytes_sent}（{bytes_sent/1024/1024:.1f}MB）。4. 综合判断：{verdict}（{sev_label}）。内网主机向外部传输大量数据，疑似数据外泄。",
            "verdict": verdict,
            "severity": sev_label,
            "threat_type": "Data_Exfiltration",
            "is_successful_attack": "yes",
            "success_evidence": f"大量数据（{bytes_sent/1024/1024:.1f}MB）已通过网络传输完成，连接正常关闭",
            "confidence": round(min(0.9, xgb_score * 0.5 + anomaly_score * 0.3 + (0.2 if has_suricata else 0)), 2),
            "key_indicators": [f"异常大数据传输 {bytes_sent/1024/1024:.1f}MB", f"异常分数 {anomaly_score:.3f}（极高）", f"传输速率 {features['bytes_per_second']/1024:.1f} KB/s"] + ([f"Suricata告警: {suricata[0]['signature']}"] if suricata else []),
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1041", "T1048"],
            "explanation_for_non_expert": f"主机 {src} 向外部IP {dst} 传输了 {bytes_sent/1024/1024:.1f}MB 数据，远超正常通信量。高度疑似数据外泄。建议立即封禁该连接，检查主机是否被入侵。",
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 5. 横向移动（双源）──────────────────────────────
    for i in range(15):
        src = _rand_ip(internal=True)
        dst = _rand_ip(internal=True)
        sp = rng.randint(49152, 65535)
        dp = rng.choice([445, 3389, 5985, 5986, 22, 135, 139])

        pkt_count = rng.randint(20, 500)
        dur = rng.uniform(1.0, 120.0)
        bytes_sent = rng.randint(2000, 200000)
        svc = {445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS", 22: "SSH", 135: "RPC", 139: "NetBIOS"}[dp]

        lat_patterns = [
            (f"ET POLICY {svc} Internal Traffic - Possible Lateral Movement", "Attempted Administrator Privilege Gain", 2),
            (f"ET TROJAN Possible {svc} Lateral Movement", "Malware Command and Control", 1),
            (f"ET POLICY Outbound {svc} Connection to Non-Standard Port", "Potentially Bad Traffic", 3),
        ]
        sig, cat, sev = rng.choice(lat_patterns)

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.01, 0.5), 'iat_std': rng.uniform(0.01, 0.3),
            'iat_min': rng.uniform(0.001, 0.01), 'iat_max': rng.uniform(0.3, 5.0),
            'pkt_len_mean': rng.uniform(200, 800), 'pkt_len_std': rng.uniform(50, 300),
            'pkt_len_min': rng.randint(40, 100), 'pkt_len_max': rng.randint(500, 1500),
            'tcp_flags_count': rng.randint(3, 5), 'syn_count': rng.randint(1, 3),
            'ack_count': rng.randint(int(pkt_count*0.4), int(pkt_count*0.6)),
            'fin_count': rng.randint(0, 1), 'rst_count': rng.randint(0, 1),
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        xgb_score = rng.uniform(0.6, 0.9)
        anomaly_score = rng.uniform(0.5, 0.9)

        annotation = {
            "reasoning": f"1. 数据源类型：双源（Suricata + ML）。Suricata签名: {sig}。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：TCP握手完成。包数={pkt_count}，持续{dur:.1f}s。3. 双向通信。总字节={bytes_sent}。4. 内网→内网通信（{src} → {dst}:{dp}/{svc}）。5. 综合判断：malicious（High）。{svc}横向移动特征明显。",
            "verdict": "malicious",
            "severity": "High",
            "threat_type": "Lateral_Movement",
            "is_successful_attack": "yes",
            "success_evidence": f"内网主机间{svc}通信已建立（{src} → {dst}:{dp}），传输{bytes_sent}字节数据，表明横向移动已完成",
            "confidence": round(min(0.9, xgb_score * 0.5 + anomaly_score * 0.3 + 0.2), 2),
            "key_indicators": [f"Suricata告警: {sig}", f"内网→内网 {svc} 流量", f"源 {src} → 目标 {dst}:{dp}", f"传输数据 {bytes_sent} bytes"],
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1021", "T1570"],
            "explanation_for_non_expert": f"检测到内网横向移动：主机 {src} 通过{svc}协议连接到另一台内网主机 {dst}。这表明攻击者已经入侵了一台主机并试图扩展控制范围。建议立即隔离相关主机。",
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 6. SYN Flood / DDoS 攻击（双源/ML-only）────────
    for i in range(15):
        src = _rand_ip()
        dst = _rand_ip()
        sp = rng.randint(1024, 65535)
        dp = rng.choice([80, 443, 53])

        pkt_count = rng.randint(1000, 50000)
        dur = rng.uniform(1.0, 60.0)
        bytes_sent = pkt_count * rng.randint(40, 80)
        pps = pkt_count / max(dur, 1)

        has_suricata = rng.random() < 0.5
        if has_suricata:
            ddos_patterns = [
                ("ET DOS Possible SYN Flood", "Attempted Denial of Service", 2),
                ("ET DOS Potential NTP DDoS Amplification", "Attempted Denial of Service", 2),
                ("ET DOS Possible DNS Amplification Attack", "Attempted Denial of Service", 2),
                ("ET DOS Outbound DOS Attack Detected", "Attempted Denial of Service", 1),
            ]
            sig, cat, sev = rng.choice(ddos_patterns)
            suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'drop', 'signature_id': rng.randint(2000000, 2999999)}]
        else:
            suricata = None

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.0001, 0.01), 'iat_std': rng.uniform(0.0001, 0.005),
            'iat_min': rng.uniform(0.00001, 0.001), 'iat_max': rng.uniform(0.005, 0.05),
            'pkt_len_mean': rng.uniform(40, 80), 'pkt_len_std': rng.uniform(0, 20),
            'pkt_len_min': rng.randint(40, 60), 'pkt_len_max': rng.randint(60, 100),
            'tcp_flags_count': 1, 'syn_count': pkt_count,
            'ack_count': 0, 'fin_count': 0, 'rst_count': rng.randint(0, int(pkt_count*0.01)),
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pps,
        }
        xgb_score = rng.uniform(0.85, 0.99)
        anomaly_score = rng.uniform(0.9, 1.0)

        verdict = "malicious"
        source_desc = "双源（Suricata + ML）" if has_suricata else "仅ML"

        annotation = {
            "reasoning": f"1. 数据源类型：{source_desc}。{'Suricata签名: ' + sig + '。' if has_suricata else ''}XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. 全部为SYN包（{pkt_count}个），无ACK响应。3. 包速率极高：{pps:.0f} 包/秒。4. 综合判断：malicious（Critical）。SYN Flood DDoS攻击。",
            "verdict": "malicious",
            "severity": "Critical",
            "threat_type": "DoS_Attempt",
            "is_successful_attack": "yes",
            "success_evidence": f"极高包速率（{pps:.0f} pkt/s）的SYN Flood持续{dur:.1f}s，目标服务可能已被淹没",
            "confidence": round(min(0.98, xgb_score * 0.5 + anomaly_score * 0.3 + (0.2 if has_suricata else 0)), 2),
            "key_indicators": [f"极高包速率 {pps:.0f} pkt/s", f"SYN Flood：{pkt_count}个SYN包", f"异常分数 {anomaly_score:.3f}（极高）"] + ([f"Suricata告警: {sig}"] if has_suricata else []),
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1498", "T1499"],
            "explanation_for_non_expert": f"检测到大规模SYN Flood攻击：{pps:.0f}个/秒的SYN包涌向 {dst}:{dp}。目标服务极可能已无法正常响应。建议启用上游DDoS防护。",
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 7. 暴力破解成功（双源）──────────────────────────
    for i in range(15):
        src = _rand_ip()
        dst = _rand_ip()
        sp = rng.randint(1024, 65535)
        dp = rng.choice([22, 3389, 21, 3306, 5432])
        svc = {22: "SSH", 3389: "RDP", 21: "FTP", 3306: "MySQL", 5432: "PostgreSQL"}[dp]

        pkt_count = rng.randint(500, 5000)
        dur = rng.uniform(60.0, 1800.0)
        bytes_sent = rng.randint(20000, 500000)

        brute_patterns = [
            (f"ET POLICY {svc} Brute Force Attempt", "Attempted User Privilege Gain", 2),
            (f"ET SCAN Potential {svc} Brute Force", "Attempted User Privilege Gain", 2),
            (f"ET TROJAN Successful {svc} Login After Brute Force", "Successful Administrator Privilege Gain", 1),
        ]
        sig, cat, sev = rng.choice(brute_patterns)

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.05, 2.0), 'iat_std': rng.uniform(0.1, 3.0),
            'iat_min': rng.uniform(0.001, 0.01), 'iat_max': rng.uniform(5.0, 60.0),
            'pkt_len_mean': rng.uniform(50, 300), 'pkt_len_std': rng.uniform(20, 150),
            'pkt_len_min': rng.randint(40, 60), 'pkt_len_max': rng.randint(200, 800),
            'tcp_flags_count': rng.randint(3, 5), 'syn_count': rng.randint(5, 50),
            'ack_count': rng.randint(int(pkt_count*0.3), int(pkt_count*0.5)),
            'fin_count': rng.randint(0, int(pkt_count*0.01)), 'rst_count': rng.randint(5, int(pkt_count*0.1)),
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        xgb_score = rng.uniform(0.7, 0.95)
        anomaly_score = rng.uniform(0.5, 0.85)

        is_success = "Successful" in sig
        if is_success:
            success = "yes"
            success_evidence = f"暴力破解成功：大量失败尝试后有一条成功的{svc}登录会话"
            explanation = f"检测到针对{svc}服务的暴力破解攻击且已成功登录（签名: {sig}）。建议立即重置被攻击账户密码，检查是否有后门。"
            sev_label = "Critical"
        else:
            success = "yes"
            success_evidence = f"持续{dur:.0f}s的暴力破解尝试，RST包表明大量失败尝试，但攻击仍在进行"
            explanation = f"检测到针对{svc}服务的暴力破解攻击（{pkt_count}个数据包，持续{dur:.0f}s）。建议启用账户锁定策略，限制来源IP。"
            sev_label = "High"

        annotation = {
            "reasoning": f"1. 数据源类型：双源（Suricata + ML）。Suricata签名: {sig}。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：多次握手尝试，大量RST（{features['rst_count']}个）。包数={pkt_count}，持续{dur:.1f}s。3. 针对{svc}(端口{dp})服务。4. 综合判断：malicious（{sev_label}）。暴力破解攻击。",
            "verdict": "malicious",
            "severity": sev_label,
            "threat_type": "Brute_Force",
            "is_successful_attack": success,
            "success_evidence": success_evidence,
            "confidence": round(min(0.95, xgb_score * 0.5 + anomaly_score * 0.3 + 0.2), 2),
            "key_indicators": [f"Suricata告警: {sig}", f"暴力破解 {svc}(端口{dp})", f"持续 {dur:.0f}s，{pkt_count} 个数据包", f"大量RST（{features['rst_count']}个）表示失败尝试"],
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1110", "T1021"],
            "explanation_for_non_expert": explanation,
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 8. 端口扫描（各种类型）──────────────────────────
    for i in range(15):
        src = _rand_ip()
        dst = _rand_ip()
        sp = rng.randint(1024, 65535)

        scan_type = rng.choice(["syn_scan", "fin_scan", "xmas_scan", "udp_scan", "service_scan"])
        if scan_type == "syn_scan":
            pkt_count = rng.randint(20, 200)
            syn, ack, fin, rst = pkt_count, 0, 0, rng.randint(0, int(pkt_count*0.3))
            proto = "TCP"
            dp = 0  # multiple ports
            sig = rng.choice(["ET SCAN Potential VNC Scan", "ET SCAN NMAP -sS", "ET SCAN Multiple SYN Packets"])
        elif scan_type == "fin_scan":
            pkt_count = rng.randint(20, 150)
            syn, ack, fin, rst = 0, 0, pkt_count, rng.randint(0, int(pkt_count*0.2))
            proto = "TCP"
            sig = rng.choice(["ET SCAN NMAP -sF FIN Scan", "ET SCAN FIN Scan Detected"])
        elif scan_type == "xmas_scan":
            pkt_count = rng.randint(10, 100)
            syn, ack, fin, rst = 0, 0, pkt_count, rng.randint(0, int(pkt_count*0.5))
            proto = "TCP"
            sig = "ET SCAN NMAP XMAS Tree Scan"
        elif scan_type == "udp_scan":
            pkt_count = rng.randint(10, 100)
            syn, ack, fin, rst = 0, 0, 0, 0
            proto = "UDP"
            sig = "ET SCAN NMAP UDP Scan"
        else:
            pkt_count = rng.randint(50, 500)
            syn, ack, fin, rst = rng.randint(1, 5), rng.randint(0, 3), 0, rng.randint(0, 10)
            proto = "TCP"
            sig = "ET SCAN Suspicious Service Enumeration"

        dur = rng.uniform(1.0, 60.0)
        bytes_sent = pkt_count * rng.randint(40, 120)

        features = {
            'flow_key': _flow_key(src, sp, dst, rng.randint(1, 1024), proto), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.001, 0.1), 'iat_std': rng.uniform(0.001, 0.05),
            'iat_min': rng.uniform(0.0001, 0.01), 'iat_max': rng.uniform(0.05, 1.0),
            'pkt_len_mean': rng.uniform(40, 80), 'pkt_len_std': rng.uniform(0, 20),
            'pkt_len_min': rng.randint(40, 60), 'pkt_len_max': rng.randint(60, 120),
            'tcp_flags_count': rng.randint(1, 4), 'syn_count': syn, 'ack_count': ack,
            'fin_count': fin, 'rst_count': rst,
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        suricata = [{'signature': sig, 'category': 'Attempted Information Leak', 'severity': 2, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        xgb_score = rng.uniform(0.7, 0.95)
        anomaly_score = rng.uniform(0.6, 0.9)

        annotation = {
            "reasoning": f"1. 数据源类型：双源（Suricata + ML）。Suricata签名: {sig}。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. 扫描类型：{scan_type}。包数={pkt_count}，持续{dur:.1f}s。SYN={syn}, RST={rst}。3. 综合判断：malicious（Medium）。端口扫描/服务枚举。",
            "verdict": "malicious",
            "severity": "Medium",
            "threat_type": "Reconnaissance",
            "is_successful_attack": "no",
            "success_evidence": f"扫描行为已发生但未建立有效连接，属于侦察阶段",
            "confidence": round(min(0.9, xgb_score * 0.5 + anomaly_score * 0.3 + 0.2), 2),
            "key_indicators": [f"Suricata告警: {sig}", f"扫描类型: {scan_type}", f"包数: {pkt_count}，持续: {dur:.1f}s"],
            "recommended_action": "Monitor",
            "mitre_techniques": ["T1046", "T1595"],
            "explanation_for_non_expert": f"检测到来自 {src} 的端口扫描活动（{scan_type}）。扫描本身不造成直接损害，但通常是攻击的前奏。建议关注该来源IP后续行为。",
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 9. 恶意软件下载（双源）──────────────────────────
    for i in range(10):
        src = _rand_ip(internal=True)
        dst = _rand_ip()
        sp = rng.randint(49152, 65535)
        dp = rng.choice([80, 443, 8080])

        pkt_count = rng.randint(30, 300)
        dur = rng.uniform(2.0, 60.0)
        bytes_sent = rng.randint(500000, 50000000)  # 500KB - 50MB executable

        dl_patterns = [
            ("ET TROJAN Possible Malware Download via HTTP", "A Network Trojan was Detected", 1),
            ("ET POLICY PE EXE or DLL Windows Download", "Potential Corporate Privacy Violation", 3),
            ("ET MALWARE Suspicious Executable Download", "A Network Trojan was Detected", 2),
            ("ET TROJAN Possible Win32/Trojan Download", "A Network Trojan was Detected", 1),
        ]
        sig, cat, sev = rng.choice(dl_patterns)

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.005, 0.1), 'iat_std': rng.uniform(0.002, 0.05),
            'iat_min': rng.uniform(0.001, 0.01), 'iat_max': rng.uniform(0.1, 2.0),
            'pkt_len_mean': rng.uniform(800, 1400), 'pkt_len_std': rng.uniform(200, 500),
            'pkt_len_min': rng.randint(40, 200), 'pkt_len_max': rng.randint(1200, 1500),
            'tcp_flags_count': rng.randint(3, 5), 'syn_count': rng.randint(1, 2),
            'ack_count': rng.randint(int(pkt_count*0.45), int(pkt_count*0.55)),
            'fin_count': rng.randint(0, 2), 'rst_count': 0,
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        suricata = [{'signature': sig, 'category': cat, 'severity': sev, 'action': 'allowed', 'signature_id': rng.randint(2000000, 2999999)}]
        xgb_score = rng.uniform(0.75, 0.95)
        anomaly_score = rng.uniform(0.6, 0.9)

        annotation = {
            "reasoning": f"1. 数据源类型：双源（Suricata + ML）。Suricata签名: {sig}。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：TCP握手完成。包数={pkt_count}，持续{dur:.1f}s。3. 双向通信。总字节={bytes_sent}（{bytes_sent/1024/1024:.1f}MB），大量数据下载。4. 综合判断：malicious（High）。恶意软件下载。",
            "verdict": "malicious",
            "severity": "High",
            "threat_type": "Malware_Download",
            "is_successful_attack": "yes",
            "success_evidence": f"下载了{bytes_sent/1024/1024:.1f}MB的可疑可执行文件，连接正常完成",
            "confidence": round(min(0.95, xgb_score * 0.5 + anomaly_score * 0.3 + 0.2), 2),
            "key_indicators": [f"Suricata告警: {sig}", f"下载大小 {bytes_sent/1024/1024:.1f}MB", "可执行文件下载"],
            "recommended_action": "Block_IP",
            "mitre_techniques": ["T1105", "T1204"],
            "explanation_for_non_expert": f"主机 {src} 从 {dst} 下载了 {bytes_sent/1024/1024:.1f}MB 的可疑文件（签名: {sig}），极可能是恶意软件。建议立即隔离该主机，扫描已下载文件。",
        }
        context = _build_context(features, xgb_score, anomaly_score, suricata)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 10. 多样化正常流量场景（纯ML）───────────────────
    benign_scenarios = [
        # (场景名, 端口, 包数范围, 时长范围, 字节范围, IAT均值范围, 包长均值范围, 额外参数)
        ("HTTPS浏览", (443,), (5, 80), (0.5, 10.0), (2000, 50000), (0.05, 0.5), (200, 900)),
        ("DNS查询", (53,), (2, 8), (0.01, 0.5), (100, 500), (0.01, 0.1), (40, 100)),
        ("视频流媒体", (443, 80), (500, 8000), (60.0, 600.0), (500000, 50000000), (0.005, 0.05), (800, 1400)),
        ("软件更新下载", (443, 80, 8080), (100, 3000), (10.0, 120.0), (100000, 50000000), (0.01, 0.1), (600, 1400)),
        ("SSH远程管理", (22,), (20, 500), (5.0, 300.0), (5000, 200000), (0.05, 2.0), (60, 300)),
        ("SMTP邮件", (25, 465, 587), (10, 200), (2.0, 30.0), (5000, 500000), (0.05, 0.5), (200, 800)),
        ("数据库查询", (3306, 5432, 1433), (5, 100), (0.1, 5.0), (500, 50000), (0.01, 0.2), (100, 500)),
        ("WebSocket长连接", (443, 8080), (100, 5000), (60.0, 1800.0), (10000, 1000000), (0.05, 1.0), (50, 200)),
        ("HTTP API调用", (80, 8080, 443), (5, 50), (0.2, 5.0), (1000, 100000), (0.05, 0.5), (200, 800)),
        ("NTP时间同步", (123,), (2, 6), (0.01, 0.5), (100, 400), (0.05, 0.5), (48, 80)),
    ]
    for scenario_name, ports, pkt_range, dur_range, bytes_range, iat_range, pktlen_range in benign_scenarios:
        for i in range(rng.randint(3, 8)):
            src = _rand_ip(internal=True)
            dst = _rand_ip()
            sp = rng.randint(49152, 65535)
            dp = rng.choice(ports)

            pkt_count = rng.randint(*pkt_range)
            dur = rng.uniform(*dur_range)
            bytes_sent = rng.randint(*bytes_range)
            iat_mean = rng.uniform(*iat_range)
            pkt_len_mean = rng.uniform(*pktlen_range)

            features = {
                'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
                'bytes_sent': bytes_sent, 'duration': dur,
                'iat_mean': iat_mean, 'iat_std': iat_mean * rng.uniform(0.3, 0.8),
                'iat_min': iat_mean * rng.uniform(0.1, 0.5), 'iat_max': iat_mean * rng.uniform(1.5, 3.0),
                'pkt_len_mean': pkt_len_mean, 'pkt_len_std': pkt_len_mean * rng.uniform(0.1, 0.5),
                'pkt_len_min': int(pkt_len_mean * rng.uniform(0.3, 0.7)),
                'pkt_len_max': int(pkt_len_mean * rng.uniform(1.2, 2.0)),
                'tcp_flags_count': rng.randint(3, 5) if dp != 53 else 1,
                'syn_count': rng.randint(1, 2),
                'ack_count': rng.randint(int(pkt_count*0.45), int(pkt_count*0.55)),
                'fin_count': rng.randint(1, 3), 'rst_count': 0,
                'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
            }
            xgb_score = rng.uniform(0.05, 0.35)
            anomaly_score = rng.uniform(0.1, 0.45)

            annotation = {
                "reasoning": f"1. 数据源：仅ML。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：握手完成+正常关闭。包数={pkt_count}，持续{dur:.1f}s，IAT均值={iat_mean:.3f}s。3. 双向通信。总字节={bytes_sent}，包长均值={pkt_len_mean:.0f}B。4. 综合判断：benign（Info）。{scenario_name}流量，行为模式与正常应用一致。",
                "verdict": "benign",
                "severity": "Info",
                "threat_type": "Benign_Traffic",
                "is_successful_attack": "no",
                "success_evidence": f"正常{scenario_name}流量（{pkt_count}个包/{bytes_sent/1024:.0f}KB），TCP正常关闭",
                "confidence": round(rng.uniform(0.55, 0.85), 2),
                "key_indicators": [f"正常{scenario_name}模式", f"XGBoost={xgb_score:.3f}（低风险）", f"TCP正常关闭（FIN={features['fin_count']}）"],
                "recommended_action": "Monitor",
                "mitre_techniques": [],
                "explanation_for_non_expert": f"这是正常的{scenario_name}流量。连接正常建立和关闭，无任何恶意特征。",
            }
            context = _build_context(features, xgb_score, anomaly_score, None)
            records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 10b. 灰色地带正常流量（ML分数偏高但实际正常）───
    for i in range(12):
        src = _rand_ip(internal=True)
        dst = _rand_ip()
        sp = rng.randint(49152, 65535)
        dp = rng.choice([443, 80, 8080])

        pkt_count = rng.randint(50, 2000)
        dur = rng.uniform(5.0, 300.0)
        bytes_sent = rng.randint(50000, 5000000)

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.01, 0.5), 'iat_std': rng.uniform(0.01, 0.3),
            'iat_min': rng.uniform(0.001, 0.01), 'iat_max': rng.uniform(0.5, 5.0),
            'pkt_len_mean': rng.uniform(200, 1200), 'pkt_len_std': rng.uniform(50, 500),
            'pkt_len_min': rng.randint(40, 200), 'pkt_len_max': rng.randint(800, 1500),
            'tcp_flags_count': rng.randint(3, 5), 'syn_count': rng.randint(1, 3),
            'ack_count': rng.randint(int(pkt_count*0.45), int(pkt_count*0.55)),
            'fin_count': rng.randint(1, 3), 'rst_count': 0,
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        xgb_score = rng.uniform(0.35, 0.55)
        anomaly_score = rng.uniform(0.3, 0.55)

        annotation = {
            "reasoning": f"1. 数据源：仅ML。XGBoost={xgb_score:.3f}（灰色地带），异常分数={anomaly_score:.3f}。2. TCP状态：握手完成+正常关闭。包数={pkt_count}，持续{dur:.1f}s。3. 双向通信。总字节={bytes_sent}。4. 综合判断：benign（Info）。ML分数偏高但TCP行为正常，无Suricata告警，属于正常应用流量。",
            "verdict": "benign",
            "severity": "Info",
            "threat_type": "Benign_Traffic",
            "is_successful_attack": "no",
            "success_evidence": f"TCP正常关闭（FIN={features['fin_count']}），{pkt_count}个包/{bytes_sent/1024:.0f}KB，无异常行为",
            "confidence": round(rng.uniform(0.45, 0.65), 2),
            "key_indicators": [f"XGBoost={xgb_score:.3f}（灰色地带）", f"数据量={bytes_sent/1024:.0f}KB", "TCP正常关闭"],
            "recommended_action": "Monitor",
            "mitre_techniques": [],
            "explanation_for_non_expert": "这是合法的网络通信。虽然ML分数偏高，但连接行为正常，属于正常的大数据量应用流量。",
        }
        context = _build_context(features, xgb_score, anomaly_score, None)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 11. 0day 异常流量（ML-only，无签名）────────────
    for i in range(12):
        src = _rand_ip(internal=True)
        dst = _rand_ip()
        sp = rng.randint(49152, 65535)
        dp = rng.choice([443, 8443, 53, 8080, 12345])

        pkt_count = rng.randint(10, 500)
        dur = rng.uniform(1.0, 60.0)
        bytes_sent = rng.randint(500, 100000)

        # 异常模式：极规律的包间隔、不寻常的包长分布
        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.5, 5.0), 'iat_std': rng.uniform(0.001, 0.05),  # 极规律
            'iat_min': rng.uniform(0.4, 0.8), 'iat_max': rng.uniform(0.6, 5.5),
            'pkt_len_mean': rng.uniform(50, 150), 'pkt_len_std': rng.uniform(0, 10),  # 极一致
            'pkt_len_min': rng.randint(45, 60), 'pkt_len_max': rng.randint(55, 160),
            'tcp_flags_count': rng.randint(2, 4), 'syn_count': rng.randint(1, 3),
            'ack_count': rng.randint(int(pkt_count*0.4), int(pkt_count*0.6)),
            'fin_count': 0, 'rst_count': 0,  # 连接未关闭
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        xgb_score = rng.uniform(0.1, 0.4)  # XGBoost 认为正常
        anomaly_score = rng.uniform(0.8, 0.99)  # 但异常分数极高

        annotation = {
            "reasoning": f"1. 数据源类型：仅ML。XGBoost={xgb_score:.3f}（低，模型认为正常），异常分数={anomaly_score:.3f}（极高，统计异常）。2. TCP状态：早期流（连接未关闭）。包数={pkt_count}，持续{dur:.1f}s。3. 包间隔极规律（std={features['iat_std']:.4f}s），包长极一致（std={features['pkt_len_std']:.1f}bytes）。4. 综合判断：suspicious（Medium）。可能是0day或新型隐蔽通信。",
            "verdict": "suspicious",
            "severity": "Medium",
            "threat_type": "Unknown_Anomaly",
            "is_successful_attack": "unknown",
            "success_evidence": "流量模式异常但无已知攻击签名，可能是0day利用或新型隐蔽通信，需进一步调查",
            "confidence": round(rng.uniform(0.4, 0.6), 2),
            "key_indicators": [f"异常分数 {anomaly_score:.3f}（极高）", f"XGBoost得分 {xgb_score:.3f}（正常范围）", f"包间隔极规律（std={features['iat_std']*1000:.2f}ms）", "ML检测到未知异常模式"],
            "recommended_action": "Investigate_Further",
            "mitre_techniques": [],
            "explanation_for_non_expert": "ML层检测到一种非常异常的流量模式，但无法匹配任何已知攻击签名。这可能是0day漏洞利用或新型攻击。建议抓取完整数据包进行深入分析。",
        }
        context = _build_context(features, xgb_score, anomaly_score, None)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    # ── 12. 隧道/代理流量（可疑但不一定是恶意）─────────
    for i in range(10):
        src = _rand_ip(internal=True)
        dst = _rand_ip()
        sp = rng.randint(49152, 65535)
        dp = rng.choice([443, 8443, 8080, 1080, 3128])

        pkt_count = rng.randint(100, 3000)
        dur = rng.uniform(30.0, 600.0)
        bytes_sent = rng.randint(50000, 5000000)

        features = {
            'flow_key': _flow_key(src, sp, dst, dp), 'packet_count': pkt_count,
            'bytes_sent': bytes_sent, 'duration': dur,
            'iat_mean': rng.uniform(0.01, 0.5), 'iat_std': rng.uniform(0.005, 0.2),
            'iat_min': rng.uniform(0.001, 0.01), 'iat_max': rng.uniform(0.5, 5.0),
            'pkt_len_mean': rng.uniform(500, 1200), 'pkt_len_std': rng.uniform(100, 300),
            'pkt_len_min': rng.randint(40, 100), 'pkt_len_max': rng.randint(1000, 1500),
            'tcp_flags_count': rng.randint(3, 5), 'syn_count': rng.randint(1, 2),
            'ack_count': rng.randint(int(pkt_count*0.45), int(pkt_count*0.55)),
            'fin_count': 0, 'rst_count': 0,
            'bytes_per_second': bytes_sent / max(dur, 0.01), 'packets_per_second': pkt_count / max(dur, 0.01),
        }
        xgb_score = rng.uniform(0.3, 0.6)
        anomaly_score = rng.uniform(0.6, 0.85)

        annotation = {
            "reasoning": f"1. 数据源类型：仅ML。XGBoost={xgb_score:.3f}，异常分数={anomaly_score:.3f}。2. TCP状态：TCP握手完成，连接长期存在。包数={pkt_count}，持续{dur:.1f}s。3. 双向通信。总字节={bytes_sent}。4. 目标端口{dp}，可能是代理/隧道服务。5. 综合判断：suspicious（Low）。可能是用户自建VPN/代理，也可能是C2隧道。",
            "verdict": "suspicious",
            "severity": "Low",
            "threat_type": "Suspicious_Traffic",
            "is_successful_attack": "unknown",
            "success_evidence": "无法确定是否为恶意隧道通信，需结合上下文（用户行为基线、目的IP信誉）判断",
            "confidence": round(rng.uniform(0.35, 0.55), 2),
            "key_indicators": [f"异常分数 {anomaly_score:.3f}（较高）", f"长连接 {dur:.0f}s", f"目标端口 {dp}（可能代理）", f"传输数据 {bytes_sent/1024:.0f}KB"],
            "recommended_action": "Investigate_Further",
            "mitre_techniques": ["T1572", "T1090"],
            "explanation_for_non_expert": f"主机 {src} 与 {dst}:{dp} 建立了长时间连接，可能是用户自建代理/VPN，也可能是恶意隧道。建议确认该连接是否属于已知业务。",
        }
        context = _build_context(features, xgb_score, anomaly_score, None)
        records.append(_record(system_prompt, prompt_template, context, features, annotation))

    rng.shuffle(records)
    return records


# ─── 生成训练数据 ────────────────────────────────────

def generate_finetune_data(pcap_file, alerts_file, output_file):
    print("=" * 60)
    print("LLM 微调数据生成")
    print("=" * 60)

    # 1. 提取流特征
    print(f"\n[1/4] 从 pcap 提取流特征: {pcap_file}")
    features_df = extract_flows(pcap_file)
    print(f"      总流数: {len(features_df)}")

    # 2. 加载 Suricata 告警
    print(f"\n[2/4] 加载 Suricata 告警: {alerts_file}")
    suricata_alerts = load_suricata_alerts(alerts_file)
    flows_with_alerts = sum(1 for k in features_df['flow_key'] if k in suricata_alerts)
    print(f"      告警流数: {flows_with_alerts}")

    # 3. 加载 ML 模型并推理
    print(f"\n[3/4] 加载 ML 模型并推理...")
    xgb_model, iforest_model, scaler, iforest_info = load_models()

    # 4. 构建 prompt 并生成标注
    print(f"\n[4/5] 从 pcap 构建训练数据...")
    prompt_template = load_prompt_template()
    system_prompt = "You are OwlSight-L2, an expert cybersecurity analyst. Always respond with valid JSON only."

    # 统计
    stats = {"total": 0, "by_verdict": defaultdict(int), "by_source": defaultdict(int),
             "by_success": defaultdict(int), "by_threat": defaultdict(int)}

    # 写入 JSONL
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as out_f:
        # --- 真实 pcap 数据 ---
        for _, row in features_df.iterrows():
            flow_key = row['flow_key']
            feature_vector = [row[col] for col in FEATURE_COLS]
            features_dict = {col: row[col] for col in FEATURE_COLS}
            features_dict['flow_key'] = flow_key

            # ML 推理
            xgb_score, anomaly_score = ml_predict(
                xgb_model, iforest_model, scaler, iforest_info, feature_vector
            )

            # Suricata 告警
            flow_alerts = suricata_alerts.get(flow_key, [])

            # 构建 context
            has_suricata = len(flow_alerts) > 0
            if has_suricata:
                sig = flow_alerts[0]['signature']
                cat = flow_alerts[0]['category']
                sev = flow_alerts[0]['severity']
                action = flow_alerts[0].get('action', 'unknown')
                sid = flow_alerts[0].get('signature_id', 0)
                pts = flow_alerts[0].get('pkts_toserver', 0)
                ptc = flow_alerts[0].get('pkts_toclient', 0)
                bts = flow_alerts[0].get('bytes_toserver', 0)
                btc = flow_alerts[0].get('bytes_toclient', 0)
                multi = f" (total {len(flow_alerts)} alerts on this flow)" if len(flow_alerts) > 1 else ""
                flow_detail = ""
                if pts > 0 or ptc > 0:
                    flow_detail = f"\n- Flow: pkts_toserver={pts}, pkts_toclient={ptc}, bytes_toserver={bts}, bytes_toclient={btc}"
                    if btc > 1000:
                        flow_detail += " (server returned significant data)"
                    elif ptc == 0:
                        flow_detail += " (unidirectional - no server response)"
                context = (
                    f"**Detection Source**: Dual (Suricata + ML)\n"
                    f"- Suricata Alert: {sig} (category: {cat}, severity: {sev}, action: {action}, sid: {sid}){multi}{flow_detail}\n"
                    f"- XGBoost score: {xgb_score:.3f}\n"
                    f"- Isolation Forest anomaly score: {anomaly_score:.3f}\n\n"
                    f"**Key Finding**: Suricata rule matched known attack signature. "
                    f"{'Traffic was dropped by firewall. ' if action == 'drop' else 'Traffic was allowed through. '}"
                    f"{'Server returned ' + str(btc) + ' bytes of data. ' if btc > 1000 else ''}"
                    f"ML models provide behavioral context."
                )
            else:
                if anomaly_score >= 0.75 and xgb_score < 0.5:
                    context = (
                        f"**Detection Source**: ML Alert Only (no Suricata)\n"
                        f"- XGBoost score: {xgb_score:.3f} (< 0.5, model considers SAFE)\n"
                        f"- Isolation Forest anomaly score: {anomaly_score:.3f} (> 0.75, EXTREMELY anomalous)\n\n"
                        f"**Key Finding**: XGBoost considers this flow safe, but Isolation Forest detected "
                        f"an extremely anomalous behavioral pattern. Possible 0day threat."
                    )
                else:
                    context = (
                        f"**Detection Source**: ML Alert Only (no Suricata)\n"
                        f"- XGBoost score: {xgb_score:.3f}\n"
                        f"- Isolation Forest anomaly score: {anomaly_score:.3f}\n\n"
                        f"**Key Finding**: ML models flagged this flow for review."
                    )

            features_text = features_to_nl(features_dict)
            user_prompt = prompt_template.substitute(context=context, features_text=features_text)

            # 标注输出
            flow_data = {
                'flow_key': flow_key,
                'xgb_score': xgb_score,
                'anomaly_score': anomaly_score,
                'features': features_dict,
            }
            annotation = annotate(flow_data, flow_alerts)

            # 写入 JSONL
            record = {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                    {"role": "assistant", "content": json.dumps(annotation, ensure_ascii=False, indent=2)}
                ]
            }
            out_f.write(json.dumps(record, ensure_ascii=False) + "\n")

            # 统计
            stats["total"] += 1
            stats["by_verdict"][annotation["verdict"]] += 1
            stats["by_source"]["dual" if has_suricata else "ml_only"] += 1
            stats["by_success"][annotation["is_successful_attack"]] += 1
            stats["by_threat"][annotation["threat_type"]] += 1

        # --- 合成数据 ---
        print(f"\n[5/5] 生成合成场景数据...")
        synthetic_records = generate_synthetic_scenarios(prompt_template, system_prompt)
        for rec in synthetic_records:
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            annotation = json.loads(rec["messages"][2]["content"])
            stats["total"] += 1
            stats["by_verdict"][annotation["verdict"]] += 1
            stats["by_source"]["synthetic"] += 1
            stats["by_success"][annotation["is_successful_attack"]] += 1
            stats["by_threat"][annotation["threat_type"]] += 1

    # 打印统计
    print("\n" + "=" * 60)
    print("生成完成！")
    print("=" * 60)
    print(f"\n输出文件: {output_file}")
    print(f"总样本数: {stats['total']}")
    print(f"\n按 verdict 分布:")
    for v, c in sorted(stats['by_verdict'].items()):
        print(f"  {v}: {c} ({c/stats['total']*100:.1f}%)")
    print(f"\n按 is_successful_attack 分布:")
    for s, c in sorted(stats['by_success'].items()):
        print(f"  {s}: {c} ({c/stats['total']*100:.1f}%)")
    print(f"\n按 threat_type 分布:")
    for t, c in sorted(stats['by_threat'].items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}")
    print(f"\n按数据源分布:")
    for s, c in sorted(stats['by_source'].items()):
        print(f"  {s}: {c} ({c/stats['total']*100:.1f}%)")

    # 文件大小
    size_mb = Path(output_file).stat().st_size / 1024 / 1024
    print(f"\n文件大小: {size_mb:.1f} MB")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='LLM 微调数据生成')
    parser.add_argument('--pcap', required=True, help='pcap 文件路径')
    parser.add_argument('--suricata-alerts', required=True, help='Suricata eve.json 路径')
    parser.add_argument('--output', default='data/finetune_llm.jsonl', help='输出 JSONL 路径')
    args = parser.parse_args()

    generate_finetune_data(args.pcap, args.suricata_alerts, args.output)
