"""
Redis 运行时健康监控与生命周期管理

作为独立守护线程运行，提供：
- 定时健康 ping（断连自动重连）
- 内存使用率监控（超 80% 告警）
- 键统计（DBSIZE + 队列长度）
- 启动残留 key 扫描
- 优雅停机清理（清队列 + 可选清流量 key）
"""
import time
import threading
from typing import Dict, Any, Optional

import redis

from ..utils import setup_logger
from ..config.config import RedisConfig
from ..config.redis_factory import RedisConnectionFactory


class RedisManager:
    """Redis 运行时监控与生命周期管理"""

    FLOW_KEY_PATTERN = "*:*-*:*-*"
    LLM_TASK_QUEUE = "llm_task_queue"
    LLM_FAILED_QUEUE = "llm_failed_queue"

    def __init__(
        self,
        redis_config: RedisConfig,
        startup_scan: bool = True,
        health_interval: float = 15.0,
        stats_interval: float = 60.0,
        memory_check_interval: float = 30.0,
        cleanup_on_shutdown: bool = True,
        flush_flow_keys_on_shutdown: bool = False,
    ):
        self.redis_config = redis_config
        self.startup_scan = startup_scan
        self.health_interval = health_interval
        self.stats_interval = stats_interval
        self.memory_check_interval = memory_check_interval
        self.cleanup_on_shutdown = cleanup_on_shutdown
        self.flush_flow_keys_on_shutdown = flush_flow_keys_on_shutdown

        self.logger = setup_logger("RedisManager")
        self.redis_client = RedisConnectionFactory.get_client(redis_config)

        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._last_memory: Dict[str, Any] = {}
        self._healthy = True
        self._start_time: float = 0.0

        # 启动残留扫描
        if self.startup_scan:
            self._scan_stale_keys()

        self.logger.info(
            "Redis 管理器初始化完成 "
            f"(health={self.health_interval}s, stats={self.stats_interval}s, "
            f"memory={self.memory_check_interval}s, "
            f"cleanup={self.cleanup_on_shutdown}, flush={self.flush_flow_keys_on_shutdown})"
        )

    # ─── 生命周期 ───────────────────────────────────────

    def start(self):
        """启动监控守护线程"""
        self.running = True
        self._start_time = time.time()
        self._thread = threading.Thread(
            target=self._monitor_loop, name="RedisManager", daemon=True
        )
        self._thread.start()
        self.logger.info("Redis 监控线程已启动")

    def stop(self):
        """停止监控线程并执行清理"""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

        if self.cleanup_on_shutdown:
            self._cleanup_queues()
            if self.flush_flow_keys_on_shutdown:
                self._flush_flow_keys()

        try:
            self.redis_client.close()
        except Exception:
            pass
        self.logger.info("Redis 管理器已停止")

    # ─── 监控主循环 ────────────────────────────────────

    def _monitor_loop(self):
        last_health = 0.0
        last_stats = 0.0
        last_memory = 0.0
        consecutive_failures = 0

        while self.running:
            now = time.time()

            # 1. 健康 ping
            if now - last_health >= self.health_interval:
                ok = self._health_ping()
                if not ok:
                    consecutive_failures += 1
                    self._healthy = False
                    if consecutive_failures >= 3:
                        self._reconnect()
                        consecutive_failures = 0
                else:
                    consecutive_failures = 0
                    self._healthy = True
                last_health = now

            # 2. 内存检查
            if now - last_memory >= self.memory_check_interval:
                self._last_memory = self._get_memory_info()
                usage = self._last_memory.get("usage_percent", 0)
                if usage > 80:
                    self.logger.warning(
                        f"[REDIS-OOM] 内存使用率 {usage:.1f}%! "
                        f"(used={self._last_memory.get('used_memory_human', '?')} "
                        f"/ max={self._last_memory.get('maxmemory_human', '?')}) "
                        f"建议检查积压或扩容"
                    )
                last_memory = now

            # 3. 全量统计输出
            if now - last_stats >= self.stats_interval:
                key_stats = self._get_key_stats()
                self._log_stats(self._last_memory, key_stats)
                last_stats = now

            time.sleep(1.0)

        self.logger.info("Redis 监控线程退出")

    # ─── 健康检查 ──────────────────────────────────────

    def _health_ping(self) -> bool:
        try:
            self.redis_client.ping()
            return True
        except (redis.ConnectionError, redis.TimeoutError) as e:
            self.logger.error(f"[REDIS-UNHEALTHY] Ping 失败: {e}")
            return False

    def _reconnect(self):
        """尝试重建 Redis 连接"""
        self.logger.warning("[REDIS-UNHEALTHY] 尝试重建 Redis 连接...")
        try:
            self.redis_client.close()
        except Exception:
            pass
        try:
            self.redis_client = RedisConnectionFactory.get_client_with_retry(
                self.redis_config, max_retries=2, base_backoff=1.0
            )
            self.logger.info("[REDIS-HEALTHY] Redis 重连成功")
        except redis.ConnectionError as e:
            self.logger.error(f"[REDIS-UNHEALTHY] Redis 重连失败: {e}")

    # ─── 内存信息 ──────────────────────────────────────

    def _get_memory_info(self) -> Dict[str, Any]:
        try:
            info = self.redis_client.info("memory")
            used = info.get("used_memory", 0)
            maxmem = info.get("maxmemory", 0)
            usage_pct = (used / maxmem * 100) if maxmem > 0 else 0.0
            return {
                "used_memory_human": info.get("used_memory_human", "?"),
                "used_memory_rss_human": info.get("used_memory_rss_human", "?"),
                "mem_fragmentation_ratio": info.get("mem_fragmentation_ratio", 0),
                "maxmemory_human": info.get("maxmemory_human", "unlimited"),
                "maxmemory": maxmem,
                "usage_percent": usage_pct,
            }
        except Exception as e:
            self.logger.debug(f"获取 Redis 内存信息失败: {e}")
            return {}

    # ─── 键统计 ────────────────────────────────────────

    def _get_key_stats(self) -> Dict[str, Any]:
        try:
            dbsize = self.redis_client.dbsize()
            task_q = self.redis_client.llen(self.LLM_TASK_QUEUE)
            failed_q = self.redis_client.llen(self.LLM_FAILED_QUEUE)

            # SCAN 估算流量 key 数（上限 2000 避免长阻塞）
            flow_count = 0
            cursor = 0
            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor, match=self.FLOW_KEY_PATTERN, count=500
                )
                flow_count += len(keys)
                if cursor == 0 or flow_count >= 2000:
                    break

            return {
                "dbsize": dbsize,
                "flow_keys": flow_count,
                "llm_task_queue": task_q,
                "llm_failed_queue": failed_q,
            }
        except Exception as e:
            self.logger.debug(f"获取 Redis 键统计失败: {e}")
            return {}

    # ─── 统计日志 ──────────────────────────────────────

    def _log_stats(self, memory_info: Dict[str, Any], key_stats: Dict[str, Any]):
        if not key_stats:
            return

        uptime = int(time.time() - self._start_time)
        health_tag = "[REDIS-HEALTHY]" if self._healthy else "[REDIS-UNHEALTHY]"
        health_msg = "连接正常" if self._healthy else "连接异常"

        self.logger.info(
            f"[REDIS-STATS] 状态报告 (每 {self.stats_interval:.0f}s) | "
            f"{health_tag} {health_msg} | 运行: {uptime}s"
        )

        mem = memory_info
        if mem:
            self.logger.info(
                f"[REDIS-STATS] 内存: used={mem.get('used_memory_human')} "
                f"rss={mem.get('used_memory_rss_human')} "
                f"frag={mem.get('mem_fragmentation_ratio')} "
                f"usage={mem.get('usage_percent', 0):.1f}%"
            )

        self.logger.info(
            f"[REDIS-STATS] 键: DBSIZE={key_stats.get('dbsize')} | "
            f"流量keys≈{key_stats.get('flow_keys')} | "
            f"llm_task={key_stats.get('llm_task_queue')} | "
            f"llm_failed={key_stats.get('llm_failed_queue')}"
        )

    # ─── 启动残留扫描 ──────────────────────────────────

    def _scan_stale_keys(self):
        """扫描上次运行残留的流 key（只报告，不删除）"""
        try:
            stale_keys = []
            cursor = 0
            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor, match=self.FLOW_KEY_PATTERN, count=100
                )
                stale_keys.extend(keys)
                if cursor == 0 or len(stale_keys) >= 500:
                    break

            if stale_keys:
                self.logger.warning(
                    f"[REDIS-STALE] 发现 {len(stale_keys)} 个残留流量 key（上次运行可能异常退出）"
                )
                # 展示前 10 个
                preview = stale_keys[:10]
                for k in preview:
                    ttl = self.redis_client.ttl(k)
                    self.logger.warning(f"[REDIS-STALE]   {k} (TTL={ttl}s)")
                if len(stale_keys) > 10:
                    self.logger.warning(f"[REDIS-STALE]   ... 还有 {len(stale_keys) - 10} 个")
            else:
                self.logger.info("[REDIS-HEALTHY] 无残留流量 key，Redis 干净")
        except Exception as e:
            self.logger.debug(f"残留 key 扫描失败: {e}")

    # ─── 停机清理 ──────────────────────────────────────

    def _cleanup_queues(self):
        """清空 LLM 任务队列和失败队列"""
        try:
            task_len = self.redis_client.llen(self.LLM_TASK_QUEUE)
            failed_len = self.redis_client.llen(self.LLM_FAILED_QUEUE)

            if task_len > 0 or failed_len > 0:
                self.logger.info(
                    f"[REDIS-CLEANUP] 清理队列: llm_task={task_len}, llm_failed={failed_len}"
                )
                pipe = self.redis_client.pipeline()
                pipe.delete(self.LLM_TASK_QUEUE)
                pipe.delete(self.LLM_FAILED_QUEUE)
                pipe.execute()
            else:
                self.logger.info("[REDIS-CLEANUP] 队列已空，无需清理")
        except Exception as e:
            self.logger.error(f"队列清理失败: {e}")

    def _flush_flow_keys(self):
        """SCAN + 批量 DEL 所有流量 key"""
        try:
            pipe = self.redis_client.pipeline()
            cursor = 0
            deleted = 0
            batch = 0

            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor, match=self.FLOW_KEY_PATTERN, count=500
                )
                for key in keys:
                    pipe.delete(key)
                    deleted += 1
                    batch += 1
                    if batch >= 100:
                        pipe.execute()
                        pipe = self.redis_client.pipeline()
                        batch = 0

                if cursor == 0:
                    break

            if batch > 0:
                pipe.execute()

            self.logger.info(f"[REDIS-CLEANUP] 已清理 {deleted} 个流量 key")
        except Exception as e:
            self.logger.error(f"流量 key 清理失败: {e}")


if __name__ == "__main__":
    import sys

    cfg = RedisConfig()
    rm = RedisManager(cfg, startup_scan=True, stats_interval=20.0, memory_check_interval=10.0)

    print("=" * 60)
    print("RedisManager 功能测试 — 启动监控 30s 后自动退出")
    print("=" * 60)

    rm.start()
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n手动中断")
    rm.stop()

    print("\n测试完成")
