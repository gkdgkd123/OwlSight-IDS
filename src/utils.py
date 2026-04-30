"""
工具函数和辅助类
"""
import hashlib
import logging
from typing import Dict, Any, Optional


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


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
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
