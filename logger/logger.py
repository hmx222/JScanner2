import hashlib
import logging
import os
import sys
import threading
import time
from logging.handlers import RotatingFileHandler

from config.config import (
    FEISHU_WEBHOOK,
    FEISHU_ALERT_LEVELS,
    FEISHU_RATE_LIMIT_SECONDS
)
from infra.feishu import send_feishu_notify
# ==================== 日志配置 ====================
LOG_DIR = "logs"
LOG_FILENAME = "scanner.log"
LOG_ERROR_FILENAME = "scanner_error.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

_console_level_str = "INFO"
CONSOLE_LOG_LEVEL = getattr(logging, _console_level_str) if isinstance(_console_level_str, str) else _console_level_str

# ==================== 全局状态 ====================
_initialized = False
_feishu_sent_time: dict = {}  # {hash: timestamp}
_feishu_lock = threading.Lock()


# ==================== 飞书告警处理 ====================

def _should_send_feishu(content: str) -> bool:
    """检查是否应该发送飞书告警（频率限制）"""
    if not FEISHU_WEBHOOK:
        return False

    content_hash = hashlib.md5(content.encode()).hexdigest()
    current_time = time.time()

    with _feishu_lock:
        # 检查频率限制
        if content_hash in _feishu_sent_time:
            last_sent = _feishu_sent_time[content_hash]
            if current_time - last_sent < FEISHU_RATE_LIMIT_SECONDS:
                return False

        # 记录发送时间
        _feishu_sent_time[content_hash] = current_time

        # ✅ 清理过期记录（避免重新赋值，不需要 global）
        cutoff = current_time - 3600
        expired_keys = [k for k, v in _feishu_sent_time.items() if v <= cutoff]
        for key in expired_keys:
            del _feishu_sent_time[key]

    return True


def _send_feishu_alert(level: str, message: str, logger_name: str):
    """发送飞书告警（异步）"""
    title = f"🚨【JScanner 告警】{level}"
    content = (
        f"• 级别：{level}\n"
        f"• 模块：{logger_name}\n"
        f"• 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"{message}"
    )

    def send_async():
        try:
            send_feishu_notify(title, content)
        except Exception:
            pass

    thread = threading.Thread(target=send_async, daemon=True)
    thread.start()


# ==================== 自定义 Handler ====================

class FeishuAlertHandler(logging.Handler):
    """拦截指定级别的日志并发送飞书告警"""

    def __init__(self, levels: list = None):
        super().__init__()
        level_names = levels or FEISHU_ALERT_LEVELS
        self.alert_levels = set()
        for level in level_names:
            if isinstance(level, str):
                self.alert_levels.add(getattr(logging, level))
            else:
                self.alert_levels.add(level)

    def emit(self, record: logging.LogRecord):
        if record.levelno not in self.alert_levels:
            return
        message = record.getMessage()
        if not _should_send_feishu(message):
            return
        _send_feishu_alert(
            level=record.levelname,
            message=message,
            logger_name=record.name
        )


# ==================== 辅助函数 ====================

def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def _create_console_handler() -> logging.Handler:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(CONSOLE_LOG_LEVEL)
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    handler.setFormatter(formatter)
    return handler


def _create_file_handler(filename: str, level: int) -> logging.Handler:
    filepath = os.path.join(LOG_DIR, filename)
    handler = RotatingFileHandler(
        filepath,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    handler.setLevel(level)
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    handler.setFormatter(formatter)
    return handler


def _configure_logger(logger: logging.Logger):
    logger.setLevel(logging.DEBUG)
    logger.addHandler(_create_console_handler())
    logger.addHandler(_create_file_handler(LOG_FILENAME, logging.DEBUG))
    logger.addHandler(_create_file_handler(LOG_ERROR_FILENAME, logging.ERROR))
    logger.addHandler(FeishuAlertHandler())


# ==================== 核心函数 ====================

def get_logger(name: str = "JScanner") -> logging.Logger:
    """获取 logger 对象"""
    global _initialized
    logger = logging.getLogger(name)
    if _initialized:
        return logger
    _ensure_log_dir()
    _configure_logger(logger)
    _initialized = True
    return logger


def shutdown_logger():
    """关闭日志系统"""
    logging.shutdown()