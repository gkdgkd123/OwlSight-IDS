#!/usr/bin/env python3
"""
OwlSight-IDS 一键启动脚本

用法：
    python run.py                          # 交互式菜单
    python run.py --live                   # 从网卡实时捕获
    python run.py --live --iface eth0      # 指定网卡
    python run.py --pcap data/xxx.pcap     # 从 pcap 文件回放
    python run.py --pcap data/xxx.pcap --llm-limit 20
"""
import sys
import os
import signal
import threading
import time
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.config.config import SystemConfig, load_env_file
from src.modules.early_flow_xgb import EarlyFlowDualModel
from src.modules.intelligent_router import IntelligentRouter
from src.modules.llm_analyzer import LLMAnalyzer
from src.utils import setup_logger


# ─── 预检 ──────────────────────────────────────────────

def check_redis(config):
    import redis
    try:
        r = redis.Redis(
            host=config.redis.host,
            port=config.redis.port,
            db=config.redis.db,
            socket_connect_timeout=3,
        )
        r.ping()
        print("[OK] Redis 连接正常")
        return True
    except Exception as e:
        print(f"[FAIL] Redis 连接失败: {e}")
        print("       请先启动 Redis 服务")
        return False


def check_models():
    models_dir = Path("src/models")
    required = ["xgb_model.json", "iforest_model.pkl", "scaler.pkl"]
    missing = [f for f in required if not (models_dir / f).exists()]
    if missing:
        print(f"[FAIL] 模型文件缺失: {missing}")
        print("       请先运行训练脚本: scripts/train_xgboost.py / scripts/train_iforest.py")
        return False
    print("[OK] 模型文件就绪")
    return True


def list_pcap_files():
    data_dir = Path("data")
    return sorted(data_dir.glob("*.pcap")) + sorted(data_dir.glob("*.pcapng"))


def list_interfaces():
    try:
        from scapy.arch import get_if_list
        return get_if_list()
    except Exception:
        return []


# ─── 实时模式 (网卡捕获) ───────────────────────────────

def run_live(config, iface=None):
    from src.main_realtime import SemFlowIDS

    if iface:
        config.scapy.interface = iface

    print(f"  流量来源 : 网卡 [{config.scapy.interface}]")
    print(f"  BPF 过滤 : {config.scapy.bpf_filter or '(无)'}")
    print(f"  Suricata : {config.suricata.eve_json_path}")

    ids = SemFlowIDS(config)

    def shutdown(signum, frame):
        print("\n[STOP] 正在停止...")
        ids.stop()
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("\n按 Ctrl+C 停止\n")
    ids.start()


# ─── pcap 回放模式 ─────────────────────────────────────

class PcapRunner:
    """pcap 回放模式 —— 3 个模块并行运行（无 Suricata）"""

    def __init__(self, config, pcap_file, llm_limit):
        self.config = config
        self.pcap_file = pcap_file
        self.llm_limit = llm_limit
        self.logger = setup_logger("PcapRunner", "INFO")
        self.running = False
        self.llm_task_count = 0
        self.llm_done = threading.Event()
        self.early_flow = None
        self.router = None
        self.llm_analyzer = None

    def start(self):
        self.running = True
        self.config.scapy.pcap_file = self.pcap_file
        # pcap 回放用更小的触发阈值
        self.config.scapy.packet_trigger = 5
        self.config.scapy.time_trigger = 1.0

        print(f"  pcap 文件: {self.pcap_file}")
        print(f"  LLM 限制 : {self.llm_limit} 条")

        # 初始化模块
        self.early_flow = EarlyFlowDualModel(
            self.config.redis, self.config.scapy, self.config.xgboost
        )
        self.router = IntelligentRouter(
            self.config.redis, self.config.xgboost
        )
        self.llm_analyzer = LLMAnalyzer(
            self.config.redis, self.config.llm
        )

        # 启动 3 个线程
        threads = [
            threading.Thread(target=self._run_early_flow, name="EarlyFlow", daemon=True),
            threading.Thread(target=self._run_router, name="Router", daemon=True),
        ]

        if self.llm_limit > 0:
            threads.append(
                threading.Thread(target=self._run_llm_limited, name="LLM", daemon=True)
            )

        for t in threads:
            t.start()

        # 等待 pcap 回放完成
        print("\n[...] pcap 回放中...")
        threads[0].join(timeout=120)

        # 给 Router 留时间处理
        time.sleep(5)

        # 等 LLM 完成
        if self.llm_limit > 0:
            timeout = max(60, self.llm_limit * 25)
            print(f"[...] 等待 LLM 分析（最多 {self.llm_limit} 条，超时 {timeout}s）...")
            self.llm_done.wait(timeout=timeout)

        self._print_results()
        self.stop()

    def _run_early_flow(self):
        try:
            self.early_flow.start()
        except Exception as e:
            self.logger.error(f"EarlyFlow 异常: {e}")

    def _run_router(self):
        try:
            self.router.start()
        except Exception as e:
            self.logger.error(f"Router 异常: {e}")

    def _run_llm_limited(self):
        try:
            while self.running and self.llm_task_count < self.llm_limit:
                try:
                    result = self.llm_analyzer.redis_client.brpop(
                        self.llm_analyzer.llm_queue_name, timeout=1
                    )
                    if result is None:
                        continue
                    _, task_json = result
                    task_data = json.loads(task_json)
                    self.llm_task_count += 1
                    self.logger.info(
                        f"[LLM] 任务 {self.llm_task_count}/{self.llm_limit}: "
                        f"{task_data.get('flow_key', '?')}"
                    )
                    self.llm_analyzer._process_task(task_data)
                except Exception as e:
                    self.logger.error(f"[LLM] 异常: {e}")
                    time.sleep(0.1)
            self.logger.info(f"[LLM] 完成 {self.llm_task_count} 条")
        except Exception as e:
            self.logger.error(f"[LLM] 模块异常: {e}")
        finally:
            self.llm_done.set()

    def _print_results(self):
        from src.config.redis_factory import RedisConnectionFactory
        redis_client = RedisConnectionFactory.get_client_with_retry(self.config.redis)

        print("\n" + "=" * 70)
        print("  检测结果汇总")
        print("=" * 70)

        decisions = {"BLOCK": 0, "PASS": 0, "ZERODAY_HUNT": 0, "LLM_ANALYZE": 0}
        total = 0
        cursor = 0
        while True:
            cursor, keys = redis_client.scan(cursor=cursor, match="*:*-*:*-*", count=100)
            for key in keys:
                total += 1
                d = redis_client.hget(key, "decision")
                if d in decisions:
                    decisions[d] += 1
            if cursor == 0:
                break

        print(f"\n  总流量数 : {total}")
        for d, c in decisions.items():
            bar = "#" * min(c, 40)
            print(f"  {d:<15} {c:>5}  {bar}")

        # LLM 分析结果
        if self.llm_task_count > 0:
            print(f"\n  LLM 已分析: {self.llm_task_count} 条")
            cursor = 0
            shown = 0
            while shown < 3:
                cursor, keys = redis_client.scan(cursor=cursor, match="*:*-*:*-*", count=100)
                for key in keys:
                    lr = redis_client.hget(key, "llm_result")
                    if lr:
                        r = json.loads(lr)
                        print(f"\n  [{key}]")
                        print(f"    判定   : {'恶意' if r.get('is_malicious') else '正常'}")
                        print(f"    类型   : {r.get('attack_type', '?')}")
                        print(f"    置信度 : {r.get('confidence', 0):.2f}")
                        shown += 1
                        if shown >= 3:
                            break
                if cursor == 0:
                    break

        print("\n" + "=" * 70)

    def stop(self):
        self.running = False
        if self.early_flow:
            self.early_flow.stop()
        if self.router:
            self.router.stop()
        if self.llm_analyzer:
            self.llm_analyzer.stop()
        self.logger.info("[STOP] 已停止")


def run_pcap(config, pcap_file, llm_limit):
    runner = PcapRunner(config, pcap_file, llm_limit)

    def shutdown(signum, frame):
        print("\n[STOP] 正在停止...")
        runner.stop()
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    runner.start()


# ─── 交互式菜单 ────────────────────────────────────────

def interactive_menu():
    print("""
  选择流量输入方式:

    [1] 网卡实时捕获
    [2] pcap 文件回放
    [q] 退出
""")
    choice = input("  请输入选项: ").strip()

    if choice == "1":
        ifaces = list_interfaces()
        if ifaces:
            print("\n  可用网卡:")
            for i, iface in enumerate(ifaces):
                print(f"    [{i}] {iface}")
            sel = input("\n  选择网卡编号（回车使用默认）: ").strip()
            iface = ifaces[int(sel)] if sel.isdigit() and int(sel) < len(ifaces) else None
        else:
            iface = None
        return "live", {"iface": iface}

    elif choice == "2":
        pcaps = list_pcap_files()
        if pcaps:
            print("\n  data/ 目录下的 pcap 文件:")
            for i, p in enumerate(pcaps):
                size_mb = p.stat().st_size / 1024 / 1024
                print(f"    [{i}] {p.name} ({size_mb:.1f} MB)")
            sel = input("\n  选择文件编号: ").strip()
            if sel.isdigit() and int(sel) < len(pcaps):
                pcap_file = str(pcaps[int(sel)])
            else:
                pcap_file = input("  或输入完整路径: ").strip()
        else:
            pcap_file = input("  data/ 下无 pcap 文件，请输入完整路径: ").strip()

        limit_str = input("  LLM 分析上限（回车默认 20，0 表示不调用 LLM）: ").strip()
        llm_limit = int(limit_str) if limit_str.isdigit() else 20

        return "pcap", {"pcap_file": pcap_file, "llm_limit": llm_limit}

    elif choice == "q":
        sys.exit(0)
    else:
        print("  无效选项")
        sys.exit(1)


# ─── 主入口 ────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OwlSight-IDS 一键启动",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="从网卡实时捕获")
    mode.add_argument("--pcap", metavar="FILE", help="从 pcap 文件回放")
    parser.add_argument("--iface", metavar="IFACE", help="指定网卡（仅实时模式）")
    parser.add_argument("--llm-limit", type=int, default=20, help="LLM 最大分析条数（默认 20，0=不调用）")
    parser.add_argument("--log-level", default="INFO", help="日志级别（默认 INFO）")
    args = parser.parse_args()

    # 加载 .env
    load_env_file(".env")

    # 打印 Banner
    if args.live:
        mode_name = "网卡实时捕获"
    elif args.pcap:
        mode_name = f"pcap 回放: {args.pcap}"
    else:
        mode_name = "交互式选择"

    print(f"""
{'=' * 60}
  OwlSight-IDS — 三层异构协同入侵检测系统
{'=' * 60}
  模式     : {mode_name}
  日志级别 : {args.log_level}
{'=' * 60}

  [1/2] 加载配置...""")

    config = SystemConfig.from_env()

    print("  [2/2] 预检...")
    if not check_redis(config):
        sys.exit(1)
    if not check_models():
        sys.exit(1)

    # 如果没指定参数，进交互菜单
    if not args.live and not args.pcap:
        mode, kwargs = interactive_menu()
    elif args.live:
        mode = "live"
        kwargs = {"iface": args.iface}
    else:
        mode = "pcap"
        kwargs = {"pcap_file": args.pcap, "llm_limit": args.llm_limit}

    print(f"\n{'=' * 60}")
    if mode == "live":
        run_live(config, **kwargs)
    else:
        run_pcap(config, **kwargs)


if __name__ == "__main__":
    main()
