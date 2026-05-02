"""
工具函数和辅助类
"""
import hashlib
import logging
import re
import threading
from typing import Dict, Any, Optional

# ─── 全局流计数器（跨模块共享 trace_id） ─────────────────
_trace_counter = 0
_trace_lock = threading.Lock()


def generate_trace_id() -> str:
    """生成唯一短 ID：T-0001, T-0002, ..."""
    global _trace_counter
    with _trace_lock:
        _trace_counter += 1
        return f"T-{_trace_counter:04d}"


def reset_trace_counter():
    """重置计数器（仅测试用）"""
    global _trace_counter
    with _trace_lock:
        _trace_counter = 0


def generate_five_tuple_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> str:
    return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"


def parse_five_tuple_key(key: str) -> Dict[str, Any]:
    try:
        src, dst, protocol = key.split("-")
        src_ip, src_port = src.split(":")
        dst_ip, dst_port = dst.split(":")
        return {
            "src_ip": src_ip,
            "src_port": int(src_port),
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),
            "protocol": protocol,
        }
    except Exception as e:
        logging.error(f"解析五元组失败: {key}, 错误: {e}")
        return {}


# ─── ANSI 终端颜色码 ─────────────────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"
_BRIGHT_RED = "\033[91m"
_BRIGHT_GREEN = "\033[92m"
_BRIGHT_YELLOW = "\033[93m"
_BRIGHT_CYAN = "\033[96m"
_BRIGHT_MAGENTA = "\033[95m"


class _ColoredFormatter(logging.Formatter):
    """按日志级别和关键标签着色"""

    _LEVEL_COLORS = {
        "ERROR": _BRIGHT_RED + _BOLD,
        "CRITICAL": _BRIGHT_RED + _BOLD,
        "WARNING": _YELLOW,
        "INFO": _RESET,
        "DEBUG": _DIM,
    }

    # 按长度降序排列，确保长模式优先匹配（避免 [LLM] 误匹配 [LLM-OUT] 等子串问题）
    _TAG_COLORS = [
        ("[LLM-RESPONSE]", _BRIGHT_CYAN),
        ("[0DAY-HUNT]", _BRIGHT_YELLOW + _BOLD),
        ("[DUAL-MODEL]", _CYAN),
        ("[SUSPICIOUS]", _YELLOW),
        ("[LLM-OUT]", _BRIGHT_MAGENTA),
        ("[WORKER]", _BLUE),
        ("[READY]", _BRIGHT_GREEN + _BOLD),
        ("[ALERT]", _BRIGHT_RED + _BOLD),
        ("[BLOCK]", _RED + _BOLD),
        ("[LLM]", _MAGENTA),
        ("[PASS]", _GREEN),
        ("判定: MALICIOUS", _RED + _BOLD),
        ("判定: SUSPICIOUS", _YELLOW),
        ("判定: BENIGN", _GREEN),
        ("攻击成功: UNKNOWN", _YELLOW),
        ("攻击成功: YES", _RED + _BOLD),
        ("攻击成功: NO", _GREEN),
        ("严重性: CRITICAL", _BRIGHT_RED + _BOLD),
        ("严重性: HIGH", _RED),
        ("严重性: MEDIUM", _YELLOW),
        ("严重性: LOW", _RESET),
    ]

    # 编译为单次扫描正则（长模式在交替中优先）
    _TAG_RE = re.compile('|'.join(re.escape(p) for p, _ in _TAG_COLORS))
    _TAG_MAP = {p: c for p, c in _TAG_COLORS}

    def format(self, record: logging.LogRecord) -> str:
        level_color = self._LEVEL_COLORS.get(record.levelname, _RESET)
        record.levelname = f"{level_color}{record.levelname}{_RESET}"

        def _apply_color(m: re.Match) -> str:
            matched = m.group(0)
            return f"{self._TAG_MAP[matched]}{matched}{_RESET}"

        record.msg = self._TAG_RE.sub(_apply_color, record.msg)
        return super().format(record)


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = _ColoredFormatter(
            '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def sanitize_text(text: str, max_length: int = 1000) -> str:
    if not text:
        return ""
    
    text = ''.join(char for char in text if ord(char) < 128)
    
    if len(text) > max_length:
        text = text[:max_length]
    
    return text
