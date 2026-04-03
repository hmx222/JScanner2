from typing import Any, Dict, Optional, List

from tree_sitter import Node

from processor.js.context.context_extractor import _extract_heuristic_slice, _find_enclosing_function, \
    _get_function_name, _find_callers_of_function
from processor.js.context.parse import get_parser, get_logger


class SenInfoContextExtractor:
    """
    敏感字符串上下文溯源提取器
    复用现有的 _extract_heuristic_slice, _find_enclosing_function 等函数
    """

    def __init__(self, js_code: str):
        self.js_code = js_code
        self.code_bytes = js_code.encode('utf-8', errors='replace')
        self.tree = None
        self.parser = get_parser()
        self.logger = get_logger()
        self._parse()

    def _parse(self):
        """解析 AST (复用全局 Parser)"""
        if self.parser is None:
            return
        try:
            self.tree = self.parser.parse(self.code_bytes)
        except Exception as e:
            self.logger.error(f"AST Parse Error: {e}")

    def find_string_node(self, target_value: str) -> Optional[Node]:
        """在 AST 中定位目标字符串节点"""
        if not self.tree:
            return None

        target_bytes = target_value.encode('utf-8', errors='replace')
        # 加引号匹配 (因为 AST 中 string 节点包含引号)
        target_with_quotes = [
            f'"{target_value}"'.encode(),
            f"'{target_value}'".encode(),
            f'`{target_value}`'.encode(),
        ]

        found_node = None

        def traverse(node):
            nonlocal found_node
            if found_node:
                return
            if node.type == 'string':
                node_bytes = self.code_bytes[node.start_byte:node.end_byte]
                for tq in target_with_quotes:
                    if tq == node_bytes or target_bytes in node_bytes:
                        found_node = node
                        return
            for child in node.children:
                traverse(child)

        traverse(self.tree.root_node)
        return found_node

    def get_full_context(self, target_value: str) -> Dict[str, Any]:
        """
        获取敏感字符串的完整上下文
        复用现有的 _extract_heuristic_slice, _find_enclosing_function 等
        """
        result = {
            "value": target_value,
            "found": False,
            "declaration": "",
            "wrapper_func": "",
            "callers": []
        }

        node = self.find_string_node(target_value)
        if not node:
            return result

        result["found"] = True

        # 复用现有切片函数
        result["declaration"] = _extract_heuristic_slice(node, self.code_bytes)

        # 复用现有函数找包裹函数
        func_node = _find_enclosing_function(node)
        if func_node:
            func_name = _get_function_name(func_node, self.code_bytes)
            result["wrapper_func"] = func_name or ""

            # 找调用者 (可复用或新增)
            if func_name:
                result["callers"] = self._find_callers(func_name)

        return result

    def _find_callers(self, func_name: str) -> List[str]:
        return _find_callers_of_function(self.tree.root_node, func_name, self.code_bytes)