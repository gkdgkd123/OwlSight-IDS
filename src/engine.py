"""
OwlSight-IDS 检测引擎 — 4 模块协同编排器

三层异构检测架构：Suricata 规则 + ML 双模型 + LLM 深度研判
"""
import threading
import time

from .config.config import SystemConfig
from .modules.suricata_monitor import SuricataMonitor
from .modules.early_flow_xgb import EarlyFlowDualModel
from .modules.intelligent_router import IntelligentRouter
from .modules.llm_analyzer import LLMAnalyzer
from .modules.redis_manager import RedisManager
from .utils import setup_logger


class Engine:
    """4 模块实时协同检测引擎"""

    def __init__(self, config: SystemConfig):
        self.config = config
        self.logger = setup_logger("Engine", config.log_level)

        self.suricata_monitor = SuricataMonitor(config.redis, config.suricata)
        self.early_flow_xgb = EarlyFlowDualModel(config.redis, config.scapy, config.xgboost)
        self.llm_analyzer = LLMAnalyzer(config.redis, config.llm)
        self.intelligent_router = IntelligentRouter(config.redis, config.xgboost)
        self.redis_manager = RedisManager(config.redis, startup_scan=True, cleanup_on_shutdown=True)

        self.threads = []
        self.running = False
        self.logger.info("OwlSight-IDS 系统初始化完成")

    def start(self):
        self.running = True
        self.logger.info("=" * 60)
        self.logger.info("OwlSight-IDS 实时恶意流量协同检测系统启动")
        self.logger.info("=" * 60)

        suricata_thread = threading.Thread(
            target=self.suricata_monitor.start, name="SuricataMonitor", daemon=True)
        xgb_thread = threading.Thread(
            target=self.early_flow_xgb.start, name="EarlyFlowXGBoost", daemon=True)
        router_thread = threading.Thread(
            target=self.intelligent_router.start, name="IntelligentRouter", daemon=True)
        llm_thread = threading.Thread(
            target=self.llm_analyzer.start, name="LLMAnalyzer", daemon=True)

        self.threads = [suricata_thread, xgb_thread, router_thread, llm_thread]

        for thread in self.threads:
            thread.start()
            self.logger.info(f"启动线程: {thread.name}")

        self.logger.info("=" * 60)
        self.logger.info("  [READY] 系统就绪 — 4 模块已启动，等待流量...")
        self.logger.info("=" * 60)

        self.redis_manager.start()
        self.logger.info("启动线程: RedisManager")

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
        self.redis_manager.stop()
        self.logger.info("=" * 60)
        self.logger.info("OwlSight-IDS 系统已停止")
        self.logger.info("=" * 60)
