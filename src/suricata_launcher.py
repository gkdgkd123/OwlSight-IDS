"""
Suricata 进程启动器 —— subprocess 管理 Suricata 生命周期

用法：
    launcher = SuricataLauncher(
        config_template="data/Suricata/suricata.yaml",
        interface="eth0",
        log_dir="./data/suricata_logs",
    )
    launcher.start()   # 启动 Suricata，等待 eve.json 就绪
    launcher.stop()    # 优雅终止
"""
import subprocess
import time
import signal
import os
from pathlib import Path
from typing import Optional

from .utils import setup_logger


class SuricataLauncher:
    """管理 Suricata 进程的完整生命周期"""

    def __init__(
        self,
        config_template: str = "data/Suricata/suricata.yaml",
        interface: str = "eth0",
        log_dir: str = "./data/suricata_logs",
        extra_args: Optional[list] = None,
    ):
        self.config_template = Path(config_template)
        self.interface = interface
        self.log_dir = Path(log_dir)
        self.extra_args = extra_args or []
        self.logger = setup_logger("SuricataLauncher")
        self.process: Optional[subprocess.Popen] = None
        self._eve_json_path: Optional[Path] = None

        if not self.config_template.exists():
            raise FileNotFoundError(f"Suricata 配置模板不存在: {self.config_template}")

    @property
    def eve_json_path(self) -> Path:
        if self._eve_json_path is None:
            self._eve_json_path = self.log_dir / "eve.json"
        return self._eve_json_path

    def start(self):
        """启动 Suricata 进程并等待 eve.json 就绪"""
        if self.process is not None:
            self.logger.warning("Suricata 已在运行中")
            return

        self.log_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "suricata",
            "-c", str(self.config_template),
            "-i", self.interface,
            "-l", str(self.log_dir),
        ]
        cmd.extend(self.extra_args)

        self.logger.info(f"启动 Suricata: {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
            )
        except FileNotFoundError:
            raise RuntimeError("找不到 suricata 命令，请确认 Suricata 已安装并在 PATH 中")
        except Exception as e:
            raise RuntimeError(f"启动 Suricata 失败: {e}")

        self._wait_for_eve_json()

    def _wait_for_eve_json(self, timeout: float = 15.0):
        """等待 Suricata 进程启动并就绪（eve.json 文件已创建即可）"""
        start = time.time()
        while time.time() - start < timeout:
            # 进程已退出 → 诊断原因
            if self.process is None or self.process.poll() is not None:
                exit_code = self.process.returncode if self.process else -1
                stderr_tail = ""
                try:
                    stderr_tail = self.process.stderr.read().decode(errors="replace")[-800:]
                except Exception:
                    pass
                raise RuntimeError(
                    f"Suricata 进程意外退出 (exitcode={exit_code})\n"
                    f"--- stderr (tail) ---\n{stderr_tail or '(空)'}"
                )

            # eve.json 已创建即视为就绪（低流量环境下可能为空）
            if self.eve_json_path.exists():
                elapsed = time.time() - start
                size = self.eve_json_path.stat().st_size
                self.logger.info(
                    f"Suricata 已就绪 (eve.json={size}bytes, 耗时 {elapsed:.1f}s)"
                )
                return

            time.sleep(0.3)

        # 超时诊断：进程还在但 eve.json 没创建
        raise TimeoutError(
            f"等待 eve.json 超时 ({timeout}s)。进程存活但 eve.json 未创建。\n"
            f"  预期路径: {self.eve_json_path}\n"
            f"  日志目录内容: {list(self.log_dir.glob('*')) if self.log_dir.exists() else '目录不存在'}"
        )

    def health_check(self) -> bool:
        """检查 Suricata 进程是否健康"""
        if self.process is None:
            return False

        poll = self.process.poll()
        if poll is not None:
            self.logger.error(f"Suricata 进程已退出, exitcode={poll}")
            return False

        if not self.eve_json_path.exists():
            self.logger.warning(f"eve.json 不存在: {self.eve_json_path}")
            return False

        return True

    def stop(self, graceful_timeout: float = 10.0):
        """优雅终止 Suricata 进程"""
        if self.process is None:
            return

        pid = self.process.pid
        self.logger.info(f"正在停止 Suricata (PID={pid})...")

        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass

        try:
            self.process.wait(timeout=graceful_timeout)
            self.logger.info(f"Suricata 已优雅退出 (exitcode={self.process.returncode})")
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Suricata 未在 {graceful_timeout}s 内退出，发送 SIGKILL")
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                self.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.logger.error("SIGKILL 后 Suricata 仍未退出")

        self.process = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
