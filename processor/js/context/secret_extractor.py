from typing import Any, Dict, Optional, List

from tree_sitter import Node

from processor.js.context.context_extractor import _extract_heuristic_slice, _find_enclosing_function, \
    _get_function_name, _find_callers_of_function
from processor.js.context.parse import get_parser, get_logger


class SenInfoContextExtractor:
    """
    敏感字符串上下文溯源提取器

    复用现有的 AST 分析函数（_extract_heuristic_slice, _find_enclosing_function 等）
    来定位敏感字符串在代码中的声明位置和调用者信息。
    """

    def __init__(self, js_code: str):
        """
        初始化上下文提取器

        Args:
            js_code: JS 源代码字符串
        """
        self.js_code = js_code
        self.code_bytes = js_code.encode('utf-8', errors='replace')
        self.tree = None
        self.parser = get_parser()
        self.logger = get_logger()
        self._parse()

    def _parse(self):
        """解析 JS 代码为 AST（复用全局 Tree-sitter Parser）"""
        if self.parser is None:
            return
        try:
            self.tree = self.parser.parse(self.code_bytes)
        except Exception as e:
            self.logger.error(f"AST Parse Error: {e}")

    def find_string_node(self, target_value: str) -> Optional[Node]:
        """
        在 AST 中定位目标字符串节点

        尝试多种引号格式匹配（单引号、双引号、反引号），
        支持精确匹配和包含匹配。

        Args:
            target_value: 目标字符串值

        Returns:
            Optional[Node]: 匹配的 AST 节点，未找到返回 None
        """
        if not self.tree:
            return None

        target_bytes = target_value.encode('utf-8', errors='replace')
        # 生成三种引号格式的搜索目标
        target_with_quotes = [
            f'"{target_value}"'.encode(),
            f"'{target_value}'".encode(),
            f'`{target_value}`'.encode(),
        ]

        found_node = None

        def traverse(node):
            """递归遍历 AST 查找字符串节点"""
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

        返回包含声明代码、包裹函数名、调用者列表的完整上下文。

        Args:
            target_value: 目标字符串值

        Returns:
            dict: 包含以下字段：
                - value: 目标字符串
                - found: 是否在 AST 中找到
                - declaration: 声明位置的代码片段
                - wrapper_func: 包裹函数名
                - callers: 调用者代码列表
        """
        result = {
            "value": target_value,
            "found": False,
            "declaration": "",
            "wrapper_func": "",
            "callers": []
        }

        # 在 AST 中定位目标字符串节点
        node = self.find_string_node(target_value)
        if not node:
            return result

        result["found"] = True

        # 复用现有的启发式切片函数提取声明代码
        result["declaration"] = _extract_heuristic_slice(node, self.code_bytes)

        # 查找包裹函数
        func_node = _find_enclosing_function(node)
        if func_node:
            func_name = _get_function_name(func_node, self.code_bytes)
            result["wrapper_func"] = func_name or ""

            # 查找调用者
            if func_name:
                result["callers"] = self._find_callers(func_name)

        return result

    def _find_callers(self, func_name: str) -> List[str]:
        """
        查找指定函数的所有调用者

        Args:
            func_name: 函数名

        Returns:
            List[str]: 调用者代码片段列表
        """
        return _find_callers_of_function(self.tree.root_node, func_name, self.code_bytes)