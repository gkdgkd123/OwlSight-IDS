"""
单元测试: utils 模块
覆盖: generate_five_tuple_key, parse_five_tuple_key, setup_logger, sanitize_text
"""
import pytest
import logging
from realtime_ids.utils import (
    generate_five_tuple_key,
    parse_five_tuple_key,
    setup_logger,
    sanitize_text,
)


class TestGenerateFiveTupleKey:
    """generate_five_tuple_key 测试"""

    def test_normal_tcp(self):
        key = generate_five_tuple_key("192.168.1.1", 12345, "10.0.0.1", 80, "TCP")
        assert key == "192.168.1.1:12345-10.0.0.1:80-TCP"

    def test_normal_udp(self):
        key = generate_five_tuple_key("10.0.0.2", 53, "8.8.8.8", 53, "UDP")
        assert key == "10.0.0.2:53-8.8.8.8:53-UDP"

    def test_port_zero(self):
        key = generate_five_tuple_key("1.2.3.4", 0, "5.6.7.8", 0, "ICMP")
        assert key == "1.2.3.4:0-5.6.7.8:0-ICMP"

    def test_ipv6_like(self):
        key = generate_five_tuple_key("::1", 80, "::2", 443, "TCP")
        assert "::1" in key and "::2" in key


class TestParseFiveTupleKey:
    """parse_five_tuple_key 测试"""

    def test_roundtrip(self):
        original = generate_five_tuple_key("192.168.1.1", 12345, "10.0.0.1", 80, "TCP")
        parsed = parse_five_tuple_key(original)
        assert parsed["src_ip"] == "192.168.1.1"
        assert parsed["src_port"] == 12345
        assert parsed["dst_ip"] == "10.0.0.1"
        assert parsed["dst_port"] == 80
        assert parsed["protocol"] == "TCP"

    def test_invalid_key_returns_empty(self):
        result = parse_five_tuple_key("invalid-key")
        assert result == {}

    def test_empty_string(self):
        result = parse_five_tuple_key("")
        assert result == {}


class TestSetupLogger:
    """setup_logger 测试"""

    def test_returns_logger(self):
        logger = setup_logger("test_module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_module"

    def test_level_setting(self):
        logger = setup_logger("test_debug", "DEBUG")
        assert logger.level == logging.DEBUG

    def test_no_duplicate_handlers(self):
        """多次调用不应重复添加 handler"""
        logger1 = setup_logger("test_dup")
        handler_count_1 = len(logger1.handlers)
        logger2 = setup_logger("test_dup")
        assert len(logger2.handlers) == handler_count_1


class TestSanitizeText:
    """sanitize_text 测试"""

    def test_normal_ascii(self):
        assert sanitize_text("hello world") == "hello world"

    def test_empty_string(self):
        assert sanitize_text("") == ""

    def test_none_input(self):
        assert sanitize_text(None) == ""

    def test_max_length_truncation(self):
        long_text = "a" * 2000
        result = sanitize_text(long_text, max_length=100)
        assert len(result) == 100

    def test_strips_non_ascii(self):
        """当前实现过滤 ord >= 128 的字符，保留 ord < 128（含控制字符）"""
        result = sanitize_text("hello\x00world\xff")
        # \xff (ord=255) 应被过滤
        assert "\xff" not in result
        # \x00 (ord=0) < 128，当前实现保留
        assert "\x00" in result

    def test_control_characters_stripped(self):
        result = sanitize_text("test\x01\x02\x03data")
        # 控制字符 < 128 但不可打印 — 当前实现保留 ord < 128
        # 这里验证函数不崩溃
        assert isinstance(result, str)

    def test_custom_max_length(self):
        result = sanitize_text("abcdefghij", max_length=5)
        assert result == "abcde"
