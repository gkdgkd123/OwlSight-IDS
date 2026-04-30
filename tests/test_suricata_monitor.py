"""
测试 Suricata 日志监控模块
使用 data 目录下的 JSON 日志文件进行测试
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.modules.suricata_monitor import SuricataMonitor
from src.config.config import RedisConfig, SuricataConfig
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
                if len(sample_alerts) < 3:
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


def test_suricata_monitor_with_redis():
    print(f"\n{'='*60}")
    print("测试 Suricata 监控模块 (Redis 集成)")
    print(f"{'='*60}\n")
    
    redis_cfg = RedisConfig(host="localhost", port=6379, db=0)
    suricata_cfg = SuricataConfig(
        eve_json_path="./data/eve.json",
        tail_interval=0.1
    )
    
    try:
        monitor = SuricataMonitor(redis_cfg, suricata_cfg)
        print("✓ Suricata 监控模块初始化成功")
        print(f"✓ Redis 连接: {redis_cfg.host}:{redis_cfg.port}")
        
        monitor.redis_client.ping()
        print("✓ Redis 连接测试成功")
        
        test_key = generate_five_tuple_key("192.168.1.100", 54321, "10.0.0.50", 80, "TCP")
        monitor.redis_client.hset(
            test_key,
            mapping={
                "suricata_alert": "true",
                "signature": "TEST: Mock Alert",
                "severity": "1",
                "test": "true"
            }
        )
        monitor.redis_client.expire(test_key, 60)
        
        result = monitor.redis_client.hgetall(test_key)
        print(f"✓ Redis 写入测试成功: {test_key}")
        print(f"  数据: {result}")
        
        monitor.redis_client.delete(test_key)
        print("✓ 测试数据已清理")
        
        return True
        
    except Exception as e:
        print(f"✗ 测试失败: {e}")
        print("\n提示: 请确保 Redis 服务已启动")
        print("  Windows: 启动 redis-server.exe")
        print("  Linux: sudo systemctl start redis")
        return False


def test_batch_process_alerts():
    print(f"\n{'='*60}")
    print("测试批量处理告警 (模拟写入 Redis)")
    print(f"{'='*60}\n")
    
    redis_cfg = RedisConfig(host="localhost", port=6379, db=0)
    suricata_cfg = SuricataConfig(eve_json_path="./data/eve.json")
    
    try:
        monitor = SuricataMonitor(redis_cfg, suricata_cfg)
        
        with open("./data/eve.json", 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        processed = 0
        for line in lines:
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    monitor._process_alert(event)
                    processed += 1
            except Exception as e:
                print(f"处理失败: {e}")
        
        print(f"\n✓ 成功处理 {processed} 条告警")
        
        keys = monitor.redis_client.keys("*")
        print(f"✓ Redis 中共有 {len(keys)} 个流状态")
        
        if keys:
            print(f"\n前 5 个流状态:")
            for key in keys[:5]:
                data = monitor.redis_client.hgetall(key)
                print(f"  {key}")
                print(f"    签名: {data.get('signature', 'N/A')}")
                print(f"    严重级别: {data.get('severity', 'N/A')}")
        
        monitor.redis_client.flushdb()
        print(f"\n✓ 测试数据已清理")
        
        return True
        
    except Exception as e:
        print(f"✗ 测试失败: {e}")
        return False


def main():
    print("\n" + "="*60)
    print("SemFlow-IDS Suricata 日志读取测试")
    print("="*60)
    
    test_files = [
        "./data/eve.json",
        "./data/alert_65511.jsonl",
        "./data/eve_65511_grep.jsonl"
    ]
    
    for file_path in test_files:
        if Path(file_path).exists():
            test_parse_eve_json(file_path)
        else:
            print(f"\n文件不存在: {file_path}")
    
    redis_ok = test_suricata_monitor_with_redis()
    
    if redis_ok:
        test_batch_process_alerts()
    
    print("\n" + "="*60)
    print("测试完成")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
