"""
OwlSight-IDS 真实代码端到端测试
使用项目实际代码验证完整流程能跑通
"""
import os
import sys
import time
import json
import signal
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config.config import SystemConfig, load_env_file
from src.modules.early_flow_xgb import EarlyFlowDualModel
from src.modules.intelligent_router import IntelligentRouter
from src.modules.llm_analyzer import LLMAnalyzer
from src.utils import setup_logger

# 加载 .env
load_env_file(".env")


class TestRunner:
    """测试运行器 - 使用项目实际代码"""

    def __init__(self, pcap_file: str, max_llm_tasks: int = 10):
        self.pcap_file = pcap_file
        self.max_llm_tasks = max_llm_tasks
        self.logger = setup_logger("TestRunner", "INFO")

        # 创建配置
        self.config = SystemConfig.from_env()
        self.config.scapy.pcap_file = pcap_file
        self.config.scapy.packet_trigger = 5
        self.config.scapy.time_trigger = 1.0

        # 模块实例
        self.early_flow = None
        self.router = None
        self.llm_analyzer = None

        # 控制标志
        self.llm_task_count = 0
        self.llm_done = threading.Event()
        self.running = False

    def start(self):
        """启动测试"""
        self.running = True
        self.logger.info("=" * 60)
        self.logger.info("OwlSight-IDS 真实代码端到端测试")
        self.logger.info("=" * 60)
        self.logger.info(f"pcap 文件: {self.pcap_file}")
        self.logger.info(f"LLM 限制: {self.max_llm_tasks} 条")
        self.logger.info(f"LLM API: {self.config.llm.api_base_url} | Model: {self.config.llm.api_model} | Key: {'set' if self.config.llm.api_key else 'MISSING'}")

        # 初始化模块（使用项目实际代码）
        self.logger.info("\n[1/3] 初始化 EarlyFlowDualModel...")
        self.early_flow = EarlyFlowDualModel(
            self.config.redis,
            self.config.scapy,
            self.config.xgboost
        )

        self.logger.info("\n[2/3] 初始化 IntelligentRouter...")
        self.router = IntelligentRouter(
            self.config.redis,
            self.config.xgboost
        )

        self.logger.info("\n[3/3] 初始化 LLMAnalyzer...")
        self.llm_analyzer = LLMAnalyzer(
            self.config.redis,
            self.config.llm
        )

        # 启动各模块
        self.logger.info("\n[START] 启动各模块...")

        # 1. 启动 EarlyFlow（pcap 回放）
        flow_thread = threading.Thread(
            target=self._run_early_flow,
            name="EarlyFlow",
            daemon=True
        )
        flow_thread.start()

        # 2. 启动 Router
        router_thread = threading.Thread(
            target=self._run_router,
            name="Router",
            daemon=True
        )
        router_thread.start()

        # 3. 启动 LLM（限制处理数量）
        llm_thread = threading.Thread(
            target=self._run_llm_limited,
            name="LLM",
            daemon=True
        )
        llm_thread.start()

        # 等待 pcap 回放完成
        self.logger.info("\n[WAIT] 等待 pcap 回放...")
        flow_thread.join(timeout=60)

        # 等待 Router 处理完成
        self.logger.info("[WAIT] 等待 Router 处理...")
        time.sleep(5)

        # 等待 LLM 处理完成（每条约 15-20s，留足余量）
        llm_timeout = max(60, self.max_llm_tasks * 25)
        self.logger.info(f"[WAIT] 等待 LLM 处理（最多 {self.max_llm_tasks} 条，超时 {llm_timeout}s）...")
        self.llm_done.wait(timeout=llm_timeout)

        # 打印结果
        self._print_results()

        # 停止
        self.stop()

    def _run_early_flow(self):
        """运行 EarlyFlow 模块"""
        try:
            self.early_flow.start()
        except Exception as e:
            self.logger.error(f"EarlyFlow 异常: {e}")

    def _run_router(self):
        """运行 Router 模块"""
        try:
            self.router.start()
        except Exception as e:
            self.logger.error(f"Router 异常: {e}")

    def _run_llm_limited(self):
        """运行 LLM 模块（限制处理数量）"""
        try:
            self.logger.info("[LLM] 启动 LLM 消费者（限制模式）...")

            # 手动消费循环，限制数量
            while self.running and self.llm_task_count < self.max_llm_tasks:
                try:
                    # BRPOP 获取任务
                    result = self.llm_analyzer.redis_client.brpop(
                        self.llm_analyzer.llm_queue_name,
                        timeout=1
                    )

                    if result is None:
                        continue

                    _, task_json = result
                    task_data = json.loads(task_json)

                    self.llm_task_count += 1
                    self.logger.info(
                        f"[LLM] 处理任务 {self.llm_task_count}/{self.max_llm_tasks}: "
                        f"{task_data.get('flow_key', 'unknown')}"
                    )

                    # 调用项目实际的处理方法
                    success = self.llm_analyzer._process_task(task_data)

                    if success:
                        self.logger.info(f"[LLM] 任务 {self.llm_task_count} 处理成功")
                    else:
                        self.logger.warning(f"[LLM] 任务 {self.llm_task_count} 处理失败")

                except Exception as e:
                    self.logger.error(f"[LLM] 处理异常: {e}")
                    time.sleep(0.1)

            self.logger.info(f"[LLM] 已处理 {self.llm_task_count} 条任务，停止")
            self.llm_done.set()

        except Exception as e:
            self.logger.error(f"[LLM] 模块异常: {e}")
            self.llm_done.set()

    def _print_results(self):
        """打印检测结果"""
        from src.config.redis_factory import RedisConnectionFactory
        redis_client = RedisConnectionFactory.get_client_with_retry(self.config.redis)

        print("\n" + "=" * 80)
        print("检测结果汇总")
        print("=" * 80)

        # 统计决策
        cursor = 0
        decisions = {"BLOCK": 0, "PASS": 0, "ZERODAY_HUNT": 0, "LLM_ANALYZE": 0}
        total_flows = 0

        while True:
            cursor, keys = redis_client.scan(cursor=cursor, match="*:*-*:*-*", count=100)
            for key in keys:
                total_flows += 1
                decision = redis_client.hget(key, "decision")
                if decision in decisions:
                    decisions[decision] += 1
            if cursor == 0:
                break

        print(f"\n总流量数: {total_flows}")
        print("\n决策统计:")
        for decision, count in decisions.items():
            print(f"  {decision}: {count}")

        # 打印 BLOCK 的流
        if decisions["BLOCK"] > 0:
            print("\n[BLOCK] 高危流量示例:")
            cursor = 0
            shown = 0
            while shown < 3:
                cursor, keys = redis_client.scan(cursor=cursor, match="*:*-*:*-*", count=100)
                for key in keys:
                    if redis_client.hget(key, "decision") == "BLOCK":
                        state = redis_client.hgetall(key)
                        print(f"  - {key}")
                        print(f"    XGB: {state.get('xgb_score', 'N/A')} | "
                              f"Anomaly: {state.get('anomaly_score', 'N/A')}")
                        shown += 1
                        if shown >= 3:
                            break
                if cursor == 0:
                    break

        # 打印 LLM 分析结果
        print(f"\n[LLM] 已分析: {self.llm_task_count} 条")
        cursor = 0
        llm_results = []
        while True:
            cursor, keys = redis_client.scan(cursor=cursor, match="*:*-*:*-*", count=100)
            for key in keys:
                llm_result = redis_client.hget(key, "llm_result")
                if llm_result:
                    llm_results.append((key, json.loads(llm_result)))
            if cursor == 0:
                break
            if len(llm_results) >= 5:
                break

        if llm_results:
            print("\n[LLM] 分析结果示例:")
            for key, result in llm_results[:5]:
                print(f"  - {key}")
                print(f"    判定: {'恶意' if result.get('is_malicious') else '正常'}")
                print(f"    类型: {result.get('attack_type', 'Unknown')}")
                print(f"    置信度: {result.get('confidence', 0):.2f}")
                print(f"    威胁等级: {result.get('threat_level', 'Unknown')}")

        print("\n" + "=" * 80)

    def stop(self):
        """停止所有模块"""
        self.running = False

        if self.early_flow:
            self.early_flow.stop()
        if self.router:
            self.router.stop()
        if self.llm_analyzer:
            self.llm_analyzer.stop()

        self.logger.info("[STOP] 所有模块已停止")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="OwlSight-IDS 真实代码测试")
    parser.add_argument(
        "--pcap",
        default="data/capture_20260429_155502.pcap",
        help="pcap 文件路径"
    )
    parser.add_argument(
        "--llm-limit",
        type=int,
        default=10,
        help="LLM 最大处理任务数"
    )

    args = parser.parse_args()

    # 检查文件
    if not Path(args.pcap).exists():
        print(f"[ERROR] pcap 文件不存在: {args.pcap}")
        sys.exit(1)

    # 运行测试
    runner = TestRunner(args.pcap, args.llm_limit)

    try:
        runner.start()
    except KeyboardInterrupt:
        print("\n[INTERRUPT] 用户中断")
        runner.stop()


if __name__ == "__main__":
    main()
