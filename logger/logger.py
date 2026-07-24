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
from infra.utils import send_feishu_notify

LOG_DIR = "logs"
LOG_FILENAME = "scanner.log"
LOG_ERROR_FILENAME = "scanner_error.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

CONSOLE_LOG_LEVEL = logging.INFO

_initialized = False
_feishu_sent_time: dict = {}
_feishu_lock = threading.Lock()


def _should_send_feishu(content: str) -> bool:
    """
    检查是否应该发送飞书通知（频率限制）

    同一内容的通知在 FEISHU_RATE_LIMIT_SECONDS 秒内不会重复发送。

    Args:
        content: 通知内容

    Returns:
        bool: 是否允许发送
    """
    # Webhook 未配置则跳过
    if not FEISHU_WEBHOOK:
        return False

    # 计算内容哈希用于去重
    content_hash = hashlib.md5(content.encode()).hexdigest()
    current_time = time.time()

    # 检查频率限制
    with _feishu_lock:
        if content_hash in _feishu_sent_time:
            last_sent = _feishu_sent_time[content_hash]
            # 距上次发送不足限制时间，跳过
            if current_time - last_sent < FEISHU_RATE_LIMIT_SECONDS:
                return False

        # 更新发送时间
        _feishu_sent_time[content_hash] = current_time
        # 清理过期记录（超过1小时）
        cutoff = current_time - 3600
        expired_keys = [k for k, v in _feishu_sent_time.items() if v <= cutoff]
        for key in expired_keys:
            del _feishu_sent_time[key]

    return True


def _send_feishu_alert(level: str, message: str, logger_name: str):
    """
    异步发送飞书告警通知

    在后台线程中发送告警，不阻塞主流程。

    Args:
        level: 日志级别（如 ERROR, CRITICAL）
        message: 告警消息内容
        logger_name: 产生告警的模块名
    """
    title = f"🚨【JScanner 告警】{level}"
    content = (
        f"• 级别：{level}\n"
        f"• 模块：{logger_name}\n"
        f"• 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"{message}"
    )

    def send_async():
        """后台线程执行飞书通知发送"""
        try:
            send_feishu_notify(title, content)
        except Exception:
            pass

    # 启动后台线程发送通知
    thread = threading.Thread(target=send_async, daemon=True)
    thread.start()


class FeishuAlertHandler(logging.Handler):
    """
    飞书告警处理器

    当日志级别匹配告警级别时，自动发送飞书通知。
    """

    def __init__(self, levels: list = None):
        """
        初始化飞书告警处理器

        Args:
            levels: 需要触发告警的日志级别列表（如 ["ERROR", "CRITICAL"]）
        """
        super().__init__()
        level_names = levels or FEISHU_ALERT_LEVELS
        self.alert_levels = set()
        for level in level_names:
            if isinstance(level, str):
                # 将级别名称转换为 logging 级别常量
                self.alert_levels.add(getattr(logging, level))
            else:
                self.alert_levels.add(level)

    def emit(self, record: logging.LogRecord):
        """
        处理日志记录：匹配告警级别时发送飞书通知

        Args:
            record: 日志记录对象
        """
        # 检查级别是否匹配告警条件
        if record.levelno not in self.alert_levels:
            return
        message = record.getMessage()
        # 检查频率限制
        if not _should_send_feishu(message):
            return
        # 发送飞书告警
        _send_feishu_alert(
            level=record.levelname,
            message=message,
            logger_name=record.name
        )


def _ensure_log_dir():
    """确保日志目录存在"""
    os.makedirs(LOG_DIR, exist_ok=True)


def _create_console_handler() -> logging.Handler:
    """
    创建控制台日志处理器

    Returns:
        logging.Handler: 配置好的控制台处理器
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(CONSOLE_LOG_LEVEL)
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)
    handler.setFormatter(formatter)
    return handler


def _create_file_handler(filename: str, level: int) -> logging.Handler:
    """
    创建文件日志处理器（带自动轮转）

    Args:
        filename: 日志文件名
        level: 日志级别

    Returns:
        logging.Handler: 配置好的文件处理器
    """
    filepath = os.path.join(LOG_DIR, filename)
    # 使用 RotatingFileHandler 实现日志轮转
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


def _init_global_logging():
    """
    全局日志初始化（仅执行一次）

    配置根日志记录器，添加控制台、文件和飞书告警三种处理器。
    所有通过 get_logger 获取的日志器自动继承此配置。
    """
    global _initialized
    if _initialized:
        return
    _ensure_log_dir()

    # 配置根日志器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # 清空默认 handler，避免重复打印
    root_logger.handlers.clear()

    # 添加控制台、文件和飞书告警处理器
    root_logger.addHandler(_create_console_handler())
    root_logger.addHandler(_create_file_handler(LOG_FILENAME, logging.DEBUG))
    root_logger.addHandler(_create_file_handler(LOG_ERROR_FILENAME, logging.ERROR))
    root_logger.addHandler(FeishuAlertHandler())

    _initialized = True


def get_logger(name: str = "JScanner") -> logging.Logger:
    """
    获取日志记录器（全局统一配置）

    第一次调用时自动初始化全局日志系统，后续调用直接返回对应名称的日志器。

    Args:
        name: 日志器名称，通常使用 __name__

    Returns:
        logging.Logger: 配置好的日志记录器
    """
    _init_global_logging()
    return logging.getLogger(name)

