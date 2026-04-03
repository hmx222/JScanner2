from typing import Any, Dict, Optional, List, Set
from tree_sitter import Node

from processor.js.context.parse import get_parser, get_logger


def _node_text_equals(node: Node, source_bytes: bytes, target_bytes: bytes) -> bool:
    if not node:
        return False
    return source_bytes[node.start_byte:node.end_byte] == target_bytes


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


def _extract_multiple_apis_from_bytes(code_bytes: bytes, target_apis: list) -> Dict[str, Dict[str, Any]]:
    _PARSER = get_parser()
    logger = get_logger()

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

    target_apis_bytes = [api.encode('utf-8') for api in target_apis]

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

    _single_pass_traverse(tree.root_node)

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

