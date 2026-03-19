import logging
from typing import Any, Dict, Optional, List, Set

import tree_sitter_javascript
from tree_sitter import Language, Parser, Node

logger = logging.getLogger(__name__)

# 全局初始化 Parser
_PARSER: Optional[Parser] = None

try:
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
    _PARSER = Parser(JS_LANGUAGE)
except Exception as e:
    logger.error(f"❌ Tree-sitter Init Error: {e}")


def _node_text_equals(node: Node, source_bytes: bytes, target_bytes: bytes) -> bool:
    if not node:
        return False
    return source_bytes[node.start_byte:node.end_byte] == target_bytes


# =====================================================================
# 核心切片引擎：南大软件分析精髓 (轻量级数据流追溯)
# =====================================================================
def _find_identifiers_in_node(node: Node, code_bytes: bytes) -> Set[str]:
    """提取一个节点内使用的所有标识符 (变量名)"""
    idents = set()
    if node.type == 'identifier':
        idents.add(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
    for child in node.children:
        idents.update(_find_identifiers_in_node(child, code_bytes))
    return idents


def _extract_heuristic_slice(api_node: Node, code_bytes: bytes) -> str:
    """
    轻量级切片 [抗 Webpack 混淆逗号声明增强版]
    专治: var a = 1, b = 2, c = a + 3; 这种连体婴结构。
    """
    stmt_node = api_node
    # 往上找，停在变量声明(Declarator)或独立语句(Statement/Property)
    while stmt_node and not (stmt_node.type.endswith(
            'statement') or stmt_node.type == 'variable_declarator' or stmt_node.type == 'property'):
        stmt_node = stmt_node.parent

    if not stmt_node:
        return code_bytes[api_node.start_byte:api_node.end_byte].decode('utf-8')

    core_line = code_bytes[stmt_node.start_byte:stmt_node.end_byte].decode('utf-8')

    # 获取靶心代码使用的变量
    used_vars = _find_identifiers_in_node(stmt_node, code_bytes)
    ignore_list = {'concat', 'return', 'require', 'window', 'document', 'console', 'JSON', 'Object'}
    used_vars = {v for v in used_vars if v not in ignore_list}

    dependencies = []

    # =========================================================================
    # 🚨 新增：同宗家族内部挖掘 (专治逗号分隔的连体变量声明)
    # =========================================================================
    if stmt_node.type == 'variable_declarator':
        parent_decl = stmt_node.parent
        if parent_decl and parent_decl.type == 'variable_declaration':
            # 遍历同一个 var/let 家族里的哥哥姐姐们
            for sibling_decl in parent_decl.children:
                if sibling_decl.type != 'variable_declarator':
                    continue
                # 只找排在咱们目标代码前面的声明
                if sibling_decl.start_byte >= stmt_node.start_byte:
                    break

                sibling_code = code_bytes[sibling_decl.start_byte:sibling_decl.end_byte].decode('utf-8')
                # 提取那个哥哥声明的变量名，看看是不是我们依赖的 r
                name_node = sibling_decl.child_by_field_name('name')
                if name_node:
                    var_name = code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    if var_name in used_vars:
                        # 找到了！强行给它拼上个 var 关键字，保证语法独立完整
                        decl_kind = code_bytes[parent_decl.start_byte:parent_decl.children[0].end_byte].decode(
                            'utf-8')  # 提取 var/let/const
                        dependencies.append(f"{decl_kind} {sibling_code};")

    # =========================================================================
    # 保持原有的：同级作用域向上溯源 (找前几行的独立语句)
    # =========================================================================
    parent_scope = stmt_node.parent
    # 如果上面进了同宗家族逻辑，作用域还要再往上跳一层
    if stmt_node.type == 'variable_declarator' and parent_scope:
        parent_scope = parent_scope.parent

    max_lookback = 500
    if parent_scope and used_vars:
        for sibling in parent_scope.children:
            max_lookback -= 1
            if max_lookback < 0: break

            # 只找排在整句代码前面的
            target_start = stmt_node.parent.start_byte if stmt_node.type == 'variable_declarator' else stmt_node.start_byte
            if sibling.start_byte >= target_start:
                break

            if sibling.type in ['variable_declaration', 'lexical_declaration']:
                sibling_code = code_bytes[sibling.start_byte:sibling.end_byte].decode('utf-8')
                if any(f" {var} " in sibling_code or f"{var}=" in sibling_code.replace(" ", "") for var in used_vars):
                    dependencies.append(sibling_code)

    # 4. 完美缝合
    final_slice = "\n".join(dependencies) + "\n" + core_line
    return final_slice


# ==========================================
# AST 辅助工具函数 (用于跨函数追踪 Call Graph)
# ==========================================
def _find_enclosing_function(node: Node) -> Optional[Node]:
    """获取函数节点，用于获取函数名"""
    current = node
    while current:
        if current.type in {'function_declaration', 'arrow_function', 'function_expression', 'method_definition'}:
            return current
        current = current.parent
    return None


def _get_function_name(func_node: Node, code_bytes: bytes) -> Optional[str]:
    """获取函数的名称"""
    if not func_node: return None
    if func_node.type == 'function_declaration':
        name_node = func_node.child_by_field_name('name')
        if name_node: return code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
    parent = func_node.parent
    if parent:
        if parent.type == 'variable_declarator':
            name_node = parent.child_by_field_name('name')
            if name_node: return code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
        elif parent.type == 'assignment_expression':
            left_node = parent.child_by_field_name('left')
            if left_node: return code_bytes[left_node.start_byte:left_node.end_byte].decode('utf-8')
    return None


def _find_callers_of_function(root_node: Node, func_name: str, code_bytes: bytes) -> List[str]:
    """遍历 AST，寻找所有调用了 func_name 的地方 (同样采用切片思想截取上下文)"""
    callers_code = []
    target_name_bytes = func_name.encode('utf-8')

    def traverse(node):
        if node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'identifier' and _node_text_equals(callee, code_bytes, target_name_bytes):
                # 找到调用点后，不再提取整个外层函数，而是提取这个调用点所在的完整语句
                stmt_node = node
                while stmt_node and not (
                        stmt_node.type.endswith('statement') or stmt_node.type == 'variable_declarator'):
                    stmt_node = stmt_node.parent

                if stmt_node:
                    callers_code.append(code_bytes[stmt_node.start_byte:stmt_node.end_byte].decode('utf-8'))
                else:
                    callers_code.append(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
        for child in node.children:
            traverse(child)

    traverse(root_node)
    return list(set(callers_code))


# ==========================================
# 核心业务逻辑：一次解析，批量提取多个 API
# ==========================================
def _extract_multiple_apis_from_bytes(code_bytes: bytes, target_apis: list) -> Dict[str, Dict[str, Any]]:
    results = {
        api: {
            "found": False,
            "api_url": api,
            "wrapper_code": "",
            "caller_codes": []
        } for api in target_apis
    }

    if _PARSER is None:
        logger.error("[-] Parser not initialized.")
        return results

    try:
        tree = _PARSER.parse(code_bytes)
    except Exception as e:
        logger.error(f"[-] Parsing error: {e}")
        return results

    hit_nodes = []

    # =========================================================================
    # ⚡️ 提速核心 1: 预先把要找的 API 和要对比的变量转成 bytes，消除高频 decode
    # =========================================================================
    target_apis_bytes = [api.encode('utf-8') for api in target_apis]

    # ⚡️ 提速核心 2: 建立全局函数调用倒排索引 (Inverted Index)
    # 结构: { b"fn": [call_node_1, call_node_2] }
    # 这样我们在找谁调用了 `fn` 时，就是 O(1) 的字典查找，再也不用全树遍历了！
    call_index = {}

    def _single_pass_traverse(node: Node):
        """仅做一次全树遍历，同时完成所有数据的打标与收集"""

        # 任务 A: 收集目标 API 字符串节点
        if node.type == 'string':
            # 直接在 bytes 层面做包含判断，极速！
            raw_bytes = code_bytes[node.start_byte:node.end_byte]
            for i, api_bytes in enumerate(target_apis_bytes):
                if api_bytes in raw_bytes:
                    hit_nodes.append((target_apis[i], node))
                    break  # 一个节点匹配上就行了

        # 任务 B: 收集所有的函数调用 (为后面找 Caller 做铺垫)
        elif node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'identifier':
                # 提取函数名 (以 bytes 形式存)
                func_name_bytes = code_bytes[callee.start_byte:callee.end_byte]
                if func_name_bytes not in call_index:
                    call_index[func_name_bytes] = []
                call_index[func_name_bytes].append(node)

        # 递归下去
        for child in node.children:
            _single_pass_traverse(child)

    # 🚀 启动全树的唯一一次遍历！
    _single_pass_traverse(tree.root_node)

    # =========================================================================
    # ⚡️ 提速核心 3: 利用内存索引快速组装切片
    # =========================================================================
    for target_api, api_node in hit_nodes:
        result_data = results[target_api]
        result_data["found"] = True

        # 1. 切片提取 (这个因为范围限定在当前语句，不慢)
        result_data["wrapper_code"] = _extract_heuristic_slice(api_node, code_bytes)

        # 2. 寻找调用链 (享受刚才建立的索引带来的极速快感)
        wrapper_func_node = _find_enclosing_function(api_node)
        if wrapper_func_node:
            func_name = _get_function_name(wrapper_func_node, code_bytes)
            if func_name:
                func_name_bytes = func_name.encode('utf-8')

                # 🚀 瞬间拿到所有调用过它的 AST 节点，无需再次全树遍历！
                matching_call_nodes = call_index.get(func_name_bytes, [])

                callers_code = []
                for call_node in matching_call_nodes:
                    # 获取包裹这个调用的外层函数
                    caller_context = _find_enclosing_function(call_node)
                    if caller_context:
                        callers_code.append(
                            code_bytes[caller_context.start_byte:caller_context.end_byte].decode('utf-8'))
                    else:
                        # 获取所在的语句
                        stmt_node = call_node
                        while stmt_node and not (
                                stmt_node.type.endswith('statement') or stmt_node.type == 'variable_declarator'):
                            stmt_node = stmt_node.parent
                        if stmt_node:
                            callers_code.append(code_bytes[stmt_node.start_byte:stmt_node.end_byte].decode('utf-8'))

                result_data["caller_codes"] = list(set(callers_code))

    return results


def extract_multiple_apis_from_raw_code(js_code: str, target_apis: list) -> Dict[str, Dict[str, Any]]:
    if not isinstance(js_code, str) or not isinstance(target_apis, list):
        return {}
    return _extract_multiple_apis_from_bytes(js_code.encode('utf-8', errors='replace'), target_apis)


# =====================================================================
# 【新增】敏感信息上下文提取器 (复用现有切片逻辑)
# =====================================================================
class SenInfoContextExtractor:
    """
    敏感字符串上下文溯源提取器
    复用现有的 _extract_heuristic_slice, _find_enclosing_function 等函数
    """

    def __init__(self, js_code: str):
        self.js_code = js_code
        self.code_bytes = js_code.encode('utf-8', errors='replace')
        self.tree = None
        self._parse()

    def _parse(self):
        """解析 AST (复用全局 Parser)"""
        if _PARSER is None:
            return
        try:
            self.tree = _PARSER.parse(self.code_bytes)
        except Exception as e:
            logger.error(f"AST Parse Error: {e}")

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
        """找函数调用者 (可复用 _find_callers_of_function 或新增)"""
        # 这里可以复用现有的 _find_callers_of_function
        # 或者新增一个更高效的版本
        return _find_callers_of_function(self.tree.root_node, func_name, self.code_bytes)