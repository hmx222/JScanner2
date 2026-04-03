from typing import Optional

import tree_sitter_javascript
from tree_sitter import Language, Parser

from logger import get_logger

_PARSER: Optional[Parser] = None
logger = get_logger(__name__)
try:
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
    _PARSER = Parser(JS_LANGUAGE)
except Exception as e:
    logger.error(f"❌ Tree-sitter Init Error: {e}")

def get_parser():
    return _PARSER
