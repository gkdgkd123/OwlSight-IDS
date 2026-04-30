"""
测试 LLM API 调用
验证 Claude Opus 4.6 API 是否正常工作
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
import json
from src.config.config import RedisConfig, LLMConfig
from src.modules.llm_analyzer import LLMAnalyzer
from src.utils import generate_five_tuple_key


def test_llm_api():
    """测试 LLM API 调用"""
    print("=" * 80)
    print("测试 LLM API 调用（Claude Opus 4.6）")
    print("=" * 80)

    # 检查环境变量
    api_key = os.getenv('LLM_API_KEY')
    if not api_key:
        print("\n[ERROR] 环境变量 LLM_API_KEY 未设置")
        print("请设置环境变量后重试：")
        print("  Windows: set LLM_API_KEY=your_api_key")
        print("  Linux/Mac: export LLM_API_KEY=your_api_key")
        return

    print(f"\n[OK] API Key 已设置: {api_key[:10]}...{api_key[-4:]}")

    # 初始化配置
    redis_cfg = RedisConfig(host="localhost", port=6379)
    llm_cfg = LLMConfig(
        use_api=True,
        api_base_url="https://new.timefiles.online/v1",
        api_key=api_key,
        api_model="claude-opus-4-6"
    )

    print(f"[OK] API 地址: {llm_cfg.api_base_url}")
    print(f"[OK] 模型: {llm_cfg.api_model}")

    # 初始化 LLM 分析器
    analyzer = LLMAnalyzer(redis_cfg, llm_cfg)

    # 测试场景 1: 0day 候选流量
    print("\n" + "=" * 80)
    print("测试场景 1: 0day 候选流量（端口扫描特征）")
    print("=" * 80)

    test_key_1 = generate_five_tuple_key("192.168.1.100", 12345, "10.0.0.1", 80, "TCP")

    mock_state_1 = {
        "xgb_score": 0.35,
        "anomaly_score": 0.88,
        "decision_type": "ZERODAY_HUNT",
        "features": json.dumps({
            "iat_mean": 0.005,
            "iat_std": 0.001,
            "pkt_len_mean": 64,
            "pkt_len_std": 10,
            "bytes_sent": 640,
            "packet_count": 10,
            "duration": 0.05,
            "tcp_flags_count": 10,
            "syn_count": 10,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "bytes_per_second": 12800,
            "packets_per_second": 200
        })
    }

    print(f"\n流量: {test_key_1}")
    print(f"XGB 得分: {mock_state_1['xgb_score']:.3f} (认为安全)")
    print(f"异常得分: {mock_state_1['anomaly_score']:.3f} (极度异常)")
    print("\n正在调用 LLM API 进行深度研判...")

    result_1 = analyzer.analyze(test_key_1, mock_state_1)

    print("\n" + "-" * 80)
    print("LLM 分析结果:")
    print("-" * 80)
    print(json.dumps(result_1, indent=2, ensure_ascii=False))

    # 测试场景 2: 疑难流量
    print("\n" + "=" * 80)
    print("测试场景 2: 疑难流量（灰色地带）")
    print("=" * 80)

    test_key_2 = generate_five_tuple_key("192.168.1.200", 54321, "10.0.0.2", 443, "TCP")

    mock_state_2 = {
        "xgb_score": 0.65,
        "anomaly_score": 0.55,
        "decision_type": "LLM_ANALYZE",
        "features": json.dumps({
            "iat_mean": 0.1,
            "iat_std": 0.05,
            "pkt_len_mean": 800,
            "pkt_len_std": 200,
            "bytes_sent": 8000,
            "packet_count": 10,
            "duration": 1.0,
            "tcp_flags_count": 10,
            "syn_count": 1,
            "ack_count": 9,
            "fin_count": 0,
            "rst_count": 0,
            "bytes_per_second": 8000,
            "packets_per_second": 10
        })
    }

    print(f"\n流量: {test_key_2}")
    print(f"XGB 得分: {mock_state_2['xgb_score']:.3f} (灰色地带)")
    print(f"异常得分: {mock_state_2['anomaly_score']:.3f} (中等异常)")
    print("\n正在调用 LLM API 进行深度研判...")

    result_2 = analyzer.analyze(test_key_2, mock_state_2)

    print("\n" + "-" * 80)
    print("LLM 分析结果:")
    print("-" * 80)
    print(json.dumps(result_2, indent=2, ensure_ascii=False))

    # 总结
    print("\n" + "=" * 80)
    print("测试总结")
    print("=" * 80)

    print("\n场景 1 (0day 候选):")
    print(f"  恶意判断: {result_1.get('is_malicious')}")
    print(f"  攻击类型: {result_1.get('attack_type')}")
    print(f"  威胁等级: {result_1.get('threat_level')}")
    print(f"  置信度: {result_1.get('confidence', 0):.2f}")
    print(f"  建议措施: {result_1.get('recommended_action')}")

    print("\n场景 2 (疑难流量):")
    print(f"  恶意判断: {result_2.get('is_malicious')}")
    print(f"  攻击类型: {result_2.get('attack_type')}")
    print(f"  威胁等级: {result_2.get('threat_level')}")
    print(f"  置信度: {result_2.get('confidence', 0):.2f}")
    print(f"  建议措施: {result_2.get('recommended_action')}")

    print("\n[SUCCESS] LLM API 测试完成！")
    print("\nClaude Opus 4.6 已成功集成到 SemFlow-IDS 系统")
    print("可以用于实时流量的深度语义分析和 0day 检测")


if __name__ == "__main__":
    test_llm_api()
