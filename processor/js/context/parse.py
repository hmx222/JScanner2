from typing import Optional

import tree_sitter_javascript
from tree_sitter import Language, Parser

from logger import get_logger

# 全局单例解析器（延迟初始化）
_PARSER: Optional[Parser] = None
logger = get_logger(__name__)

try:
    # 初始化 JavaScript 语言和 Tree-sitter 解析器
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
    _PARSER = Parser(JS_LANGUAGE)
except Exception as e:
    logger.error(f"❌ Tree-sitter Init Error: {e}")


def get_parser():
    """
    获取全局 Tree-sitter 解析器实例（单例模式）

    Returns:
        Optional[Parser]: Tree-sitter Parser 实例，初始化失败返回 None
    """
    return _PARSER