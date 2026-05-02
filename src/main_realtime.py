"""
OwlSight-IDS 实时恶意流量协同检测系统 - 主程序入口
三层异构协同检测架构：规则匹配 + 机器学习 + 大语言模型
"""
import argparse
import threading
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config.config import SystemConfig
from src.modules.suricata_monitor import SuricataMonitor
from src.modules.early_flow_xgb import EarlyFlowDualModel
from src.modules.intelligent_router import IntelligentRouter
from src.modules.llm_analyzer import LLMAnalyzer
from src.utils import setup_logger


class SemFlowIDS:
    
    def __init__(self, config: SystemConfig):
        self.config = config
        self.logger = setup_logger("SemFlowIDS", config.log_level)
        
        self.suricata_monitor = SuricataMonitor(
            config.redis,
            config.suricata
        )
        
        self.early_flow_xgb = EarlyFlowDualModel(
            config.redis,
            config.scapy,
            config.xgboost
        )
        
        self.llm_analyzer = LLMAnalyzer(
            config.redis,
            config.llm
        )
        
        self.intelligent_router = IntelligentRouter(
            config.redis,
            config.xgboost
        )

        self.threads = []
        self.running = False

        self.logger.info("OwlSight-IDS 系统初始化完成")
    
    def start(self):
        self.running = True
        self.logger.info("=" * 60)
        self.logger.info("OwlSight-IDS 实时恶意流量协同检测系统启动")
        self.logger.info("=" * 60)

        suricata_thread = threading.Thread(
            target=self.suricata_monitor.start,
            name="SuricataMonitor",
            daemon=True
        )

        xgb_thread = threading.Thread(
            target=self.early_flow_xgb.start,
            name="EarlyFlowXGBoost",
            daemon=True
        )

        router_thread = threading.Thread(
            target=self.intelligent_router.start,
            name="IntelligentRouter",
            daemon=True
        )

        llm_thread = threading.Thread(
            target=self.llm_analyzer.start,
            name="LLMAnalyzer",
            daemon=True
        )

        self.threads = [suricata_thread, xgb_thread, router_thread, llm_thread]

        for thread in self.threads:
            thread.start()
            self.logger.info(f"启动线程: {thread.name}")

        self.logger.info("=" * 60)
        self.logger.info("  [READY] 系统就绪 — 4 模块已启动，等待流量...")
        self.logger.info("=" * 60)

        import time
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.logger.info("收到中断信号，正在停止系统...")
            self.stop()
    
    def stop(self):
        self.running = False

        self.suricata_monitor.stop()
        self.early_flow_xgb.stop()
        self.intelligent_router.stop()
        self.llm_analyzer.request_shutdown()

        self.logger.info("=" * 60)
        self.logger.info("OwlSight-IDS 系统已停止")
        self.logger.info("=" * 60)


def parse_args():
    parser = argparse.ArgumentParser(
        description="OwlSight-IDS 实时恶意流量协同检测系统"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="配置文件路径（可选，默认使用环境变量）"
    )
    
    parser.add_argument(
        "--redis-host",
        type=str,
        default="localhost",
        help="Redis 主机地址"
    )
    
    parser.add_argument(
        "--redis-port",
        type=int,
        default=6379,
        help="Redis 端口"
    )
    
    parser.add_argument(
        "--eve-json",
        type=str,
        default="./data/eve.json",
        help="Suricata eve.json 文件路径"
    )
    
    parser.add_argument(
        "--interface",
        type=str,
        default="eth0",
        help="网卡接口名称"
    )
    
    parser.add_argument(
        "--xgb-model",
        type=str,
        default="./src/models/xgb_model.json",
        help="XGBoost 模型路径"
    )
    
    parser.add_argument(
        "--llm-model",
        type=str,
        default="./models/Qwen-3B",
        help="Qwen LLM 模型路径"
    )
    
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="日志级别"
    )
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    config = SystemConfig.from_env()
    
    config.redis.host = args.redis_host
    config.redis.port = args.redis_port
    config.suricata.eve_json_path = args.eve_json
    config.scapy.interface = args.interface
    config.xgboost.model_path = args.xgb_model
    config.llm.model_path = args.llm_model
    config.log_level = args.log_level
    
    ids_system = SemFlowIDS(config)
    
    def signal_handler(sig, frame):
        print("\n收到终止信号，正在关闭系统...")
        ids_system.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    ids_system.start()


if __name__ == "__main__":
    main()
