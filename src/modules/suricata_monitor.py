"""
Module 1: Suricata 日志监控模块
功能：实时监控 Suricata 的 eve.json 文件，解析安全报警并写入 Redis
"""
import json
import time
import redis
from typing import Optional, Dict, Any
from pathlib import Path
from ..utils import generate_five_tuple_key, generate_trace_id, setup_logger
from ..config.config import RedisConfig, SuricataConfig
from ..config.redis_factory import RedisConnectionFactory


class SuricataMonitor:

    def __init__(self, redis_config: RedisConfig, suricata_config: SuricataConfig):
        self.redis_config = redis_config
        self.suricata_config = suricata_config
        self.logger = setup_logger("SuricataMonitor")

        self.redis_client = RedisConnectionFactory.get_client_with_retry(redis_config)
        
        self.eve_path = Path(suricata_config.eve_json_path)
        self.running = False
        
        self.logger.info(f"Suricata 监控模块初始化完成，监控文件: {self.eve_path}")
    
    def _parse_five_tuple(self, event: Dict[str, Any]) -> Optional[str]:
        try:
            src_ip = event.get("src_ip", "")
            dst_ip = event.get("dest_ip", "")
            src_port = event.get("src_port", 0)
            dst_port = event.get("dest_port", 0)
            proto = event.get("proto", "")
            
            if not all([src_ip, dst_ip, proto]):
                return None
            
            five_tuple_key = generate_five_tuple_key(
                src_ip, src_port, dst_ip, dst_port, proto
            )
            return five_tuple_key
        except Exception as e:
            self.logger.error(f"解析五元组失败: {e}")
            return None
    
    def _process_alert(self, event: Dict[str, Any]) -> None:
        five_tuple_key = self._parse_five_tuple(event)
        if not five_tuple_key:
            return

        alert_info = event.get("alert", {})
        signature = alert_info.get("signature", "Unknown")
        severity = alert_info.get("severity", 0)

        # 分配或继承 trace_id
        existing_tid = self.redis_client.hget(five_tuple_key, "trace_id")
        trace_id = existing_tid or generate_trace_id()

        # 构建 Redis Hash 字段（保留完整告警证据）
        fields = {
            "trace_id": trace_id,
            "suricata_alert": "true",
            "signature": signature,
            "severity": str(severity),
            "timestamp": str(time.time()),
        }

        # 完整规则文本
        rule = alert_info.get("rule", "")
        if rule:
            fields["suricata_rule"] = rule[:3000]

        # Payload 原文（截断到 1000 字符）
        payload = event.get("payload_printable", "") or ""
        if payload:
            fields["payload_printable"] = payload[:1000]

        # HTTP 语义字段（仅 HTTP 协议告警有值）
        http_info = event.get("http", {})
        if http_info:
            http_fields = {
                "http_method": http_info.get("http_method", ""),
                "http_url": http_info.get("url", "")[:500],
                "http_hostname": http_info.get("hostname", ""),
                "http_status": str(http_info.get("status", 0)),
                "http_user_agent": http_info.get("http_user_agent", "")[:200],
                "http_content_type": http_info.get("http_content_type", ""),
                "http_protocol": http_info.get("protocol", ""),
            }
            # 响应体（截断到 2000 字符）
            resp_body = http_info.get("http_response_body_printable", "") or ""
            if resp_body:
                http_fields["http_response_body_printable"] = resp_body[:2000]
            fields.update(http_fields)

        # Flow 双向流量
        flow_info = event.get("flow", {})
        if flow_info:
            fields["pkts_toserver"] = str(flow_info.get("pkts_toserver", 0))
            fields["pkts_toclient"] = str(flow_info.get("pkts_toclient", 0))
            fields["bytes_toserver"] = str(flow_info.get("bytes_toserver", 0))
            fields["bytes_toclient"] = str(flow_info.get("bytes_toclient", 0))

        try:
            self.redis_client.hset(five_tuple_key, mapping=fields)
            self.redis_client.expire(five_tuple_key, self.redis_config.ttl)

            # 通过 Pub/Sub 广播高危流提前终止信号
            try:
                self.redis_client.publish("suricata_alerts_channel", five_tuple_key)
            except redis.RedisError as pub_err:
                self.logger.error(
                    f"[PUB/SUB] 发布 Early Abort 信号失败: {five_tuple_key}, 错误: {pub_err}"
                )
                # Early Abort 失效不影响主流程，继续

            self.logger.info(
                f"[{trace_id}] [ALERT] {five_tuple_key} | "
                f"规则: {signature} | 严重级别: {severity} | 已广播提前终止信号"
            )
        except Exception as e:
            self.logger.error(f"写入 Redis 失败: {e}")
    
    def _tail_file(self):
        if not self.eve_path.exists():
            self.logger.error(f"文件不存在: {self.eve_path}")
            return
        
        with open(self.eve_path, 'r', encoding='utf-8') as f:
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(self.suricata_config.tail_interval)
                    continue
                
                try:
                    event = json.loads(line.strip())
                    event_type = event.get("event_type", "")
                    
                    if event_type == "alert":
                        self._process_alert(event)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"JSON 解析失败: {e}")
                except Exception as e:
                    self.logger.error(f"处理事件失败: {e}")
    
    def start(self):
        self.running = True
        self.logger.info("Suricata 监控模块启动")
        try:
            self._tail_file()
        except KeyboardInterrupt:
            self.logger.info("收到中断信号，停止监控")
        finally:
            self.stop()
    
    def stop(self):
        self.running = False
        try:
            self.redis_client.close()
        except Exception:
            pass
        self.logger.info("Suricata 监控模块停止")


if __name__ == "__main__":
    redis_cfg = RedisConfig(host="localhost", port=6379)
    suricata_cfg = SuricataConfig(eve_json_path="./data/eve.json")
    
    monitor = SuricataMonitor(redis_cfg, suricata_cfg)
    
    print("模拟测试：写入一条 Mock 告警到 Redis")
    test_key = generate_five_tuple_key("192.168.1.100", 54321, "10.0.0.50", 80, "TCP")
    monitor.redis_client.hset(
        test_key,
        mapping={
            "suricata_alert": "true",
            "signature": "ET EXPLOIT SQL Injection Attempt",
            "severity": "1"
        }
    )
    monitor.redis_client.expire(test_key, 10)
    print(f"已写入测试数据到 Redis: {test_key}")
    
    result = monitor.redis_client.hgetall(test_key)
    print(f"读取结果: {result}")
