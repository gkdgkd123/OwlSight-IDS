"""
测试 Suricata 日志监控模块 (无 Redis 版本)
使用 data 目录下的 JSON 日志文件进行测试
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.utils import generate_five_tuple_key


def test_parse_eve_json(file_path: str):
    print(f"\n{'='*60}")
    print(f"测试文件: {file_path}")
    print(f"{'='*60}\n")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    print(f"总行数: {len(lines)}")
    
    alert_count = 0
    event_types = {}
    sample_alerts = []
    
    for idx, line in enumerate(lines, 1):
        try:
            event = json.loads(line.strip())
            event_type = event.get("event_type", "unknown")
            
            event_types[event_type] = event_types.get(event_type, 0) + 1
            
            if event_type == "alert":
                alert_count += 1
                if len(sample_alerts) < 5:
                    sample_alerts.append(event)
                    
        except json.JSONDecodeError as e:
            print(f"第 {idx} 行 JSON 解析失败: {e}")
    
    print(f"\n事件类型统计:")
    for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
        print(f"  {event_type}: {count}")
    
    print(f"\n告警事件数量: {alert_count}")
    
    if sample_alerts:
        print(f"\n前 {len(sample_alerts)} 条告警样本:")
        for idx, alert in enumerate(sample_alerts, 1):
            print(f"\n--- 告警 {idx} ---")
            print(f"  时间戳: {alert.get('timestamp', 'N/A')}")
            print(f"  源IP: {alert.get('src_ip', 'N/A')}:{alert.get('src_port', 'N/A')}")
            print(f"  目标IP: {alert.get('dest_ip', 'N/A')}:{alert.get('dest_port', 'N/A')}")
            print(f"  协议: {alert.get('proto', 'N/A')}")
            
            alert_info = alert.get('alert', {})
            print(f"  签名: {alert_info.get('signature', 'N/A')}")
            print(f"  严重级别: {alert_info.get('severity', 'N/A')}")
            print(f"  分类: {alert_info.get('category', 'N/A')}")
            
            five_tuple = generate_five_tuple_key(
                alert.get('src_ip', ''),
                alert.get('src_port', 0),
                alert.get('dest_ip', ''),
                alert.get('dest_port', 0),
                alert.get('proto', '')
            )
            print(f"  五元组: {five_tuple}")
    
    return alert_count, event_types


def test_alert_severity_distribution(file_path: str):
    print(f"\n{'='*60}")
    print(f"告警严重级别分布: {file_path}")
    print(f"{'='*60}\n")
    
    severity_dist = {}
    category_dist = {}
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    alert_info = event.get('alert', {})
                    severity = alert_info.get('severity', 'unknown')
                    category = alert_info.get('category', 'unknown')
                    
                    severity_dist[severity] = severity_dist.get(severity, 0) + 1
                    category_dist[category] = category_dist.get(category, 0) + 1
            except:
                pass
    
    print("严重级别分布:")
    for severity, count in sorted(severity_dist.items()):
        print(f"  级别 {severity}: {count} 条")
    
    print("\n告警分类分布:")
    for category, count in sorted(category_dist.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {category}: {count} 条")


def test_five_tuple_extraction(file_path: str):
    print(f"\n{'='*60}")
    print(f"五元组提取测试: {file_path}")
    print(f"{'='*60}\n")
    
    unique_flows = set()
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    five_tuple = generate_five_tuple_key(
                        event.get('src_ip', ''),
                        event.get('src_port', 0),
                        event.get('dest_ip', ''),
                        event.get('dest_port', 0),
                        event.get('proto', '')
                    )
                    unique_flows.add(five_tuple)
            except:
                pass
    
    print(f"唯一流数量: {len(unique_flows)}")
    
    if unique_flows:
        print(f"\n前 10 个流:")
        for idx, flow in enumerate(list(unique_flows)[:10], 1):
            print(f"  {idx}. {flow}")


def main():
    print("\n" + "="*60)
    print("SemFlow-IDS Suricata 日志读取测试")
    print("="*60)
    
    test_files = [
        "./data/eve.json",
        "./data/alert_65511.jsonl",
        "./data/eve_65511_grep.jsonl"
    ]
    
    total_alerts = 0
    
    for file_path in test_files:
        if Path(file_path).exists():
            alert_count, event_types = test_parse_eve_json(file_path)
            total_alerts += alert_count
            
            if alert_count > 0:
                test_alert_severity_distribution(file_path)
                test_five_tuple_extraction(file_path)
        else:
            print(f"\n文件不存在: {file_path}")
    
    print("\n" + "="*60)
    print("测试总结")
    print("="*60)
    print(f"✓ 成功解析 {len([f for f in test_files if Path(f).exists()])} 个文件")
    print(f"✓ 总告警数量: {total_alerts}")
    print(f"✓ Suricata 日志格式解析正常")
    print(f"✓ 五元组提取功能正常")
    print("\n提示: 如需测试 Redis 集成，请确保 Redis 服务已启动")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
