from typing import Any, Dict, Optional, List, Set, Tuple
from tree_sitter import Node

from processor.js.context.parse import get_parser, get_logger

# 上下文大小限制常量
MAX_CONTEXT_BYTES = 5000      # 约 5KB
MAX_CONTEXT_TOKENS_ESTIMATE = 1500
_MAX_OBJECT_BYTES = 50000     # 对象 AST 节点的最大字节数（过大则跳过解析）

# 函数类型集合
_FUNCTION_TYPES = {
    'function_declaration', 'function_expression',
    'arrow_function', 'method_definition'
}


def _node_text_equals(node: Node, source_bytes: bytes, target_bytes: bytes) -> bool:
    """
    比较 AST 节点的文本内容是否与目标字节串匹配

    Args:
        node: AST 节点
        source_bytes: 源代码字节串
        target_bytes: 目标字节串

    Returns:
        bool: 是否匹配
    """
    if not node:
        return False
    return source_bytes[node.start_byte:node.end_byte] == target_bytes


def _find_identifiers_in_node(node: Node, code_bytes: bytes) -> Set[str]:
    """
    提取一个节点内使用的所有标识符（变量名）

    Args:
        node: AST 节点
        code_bytes: 源代码字节串

    Returns:
        Set[str]: 标识符（变量名）集合
    """
    idents = set()
    if node.type == 'identifier':
        idents.add(code_bytes[node.start_byte:node.end_byte].decode('utf-8'))
    for child in node.children:
        idents.update(_find_identifiers_in_node(child, code_bytes))
    return idents


def _find_semantic_boundary(node: Node) -> Optional[Node]:
    """
    寻找包含该节点的最小有意义语义边界

    优先级（从高到低）：
    1. 函数/方法定义（function_declaration, arrow_function 等）
    2. 对象属性（当值为函数时）

    Args:
        node: AST 节点

    Returns:
        Optional[Node]: 语义边界节点，未找到返回 None
    """
    current = node
    while current:
        # 第一优先级：函数/方法定义
        if current.type in {
            'function_declaration',
            'function_expression',
            'arrow_function',
            'method_definition'
        }:
            return current

        # 第二优先级：对象属性（当值是函数时）
        if current.type in {'pair', 'property'}:
            value_node = current.child_by_field_name('value')
            if value_node and value_node.type in {
                'function',
                'function_expression',
                'arrow_function',
                'method_definition'
            }:
                return current

        current = current.parent

    return None


def _extract_complete_boundary(boundary_node: Node, code_bytes: bytes) -> str:
    """
    提取完整的语义边界节点代码

    Args:
        boundary_node: 语义边界节点
        code_bytes: 源代码字节串

    Returns:
        str: 节点对应的代码字符串
    """
    return code_bytes[boundary_node.start_byte:boundary_node.end_byte].decode('utf-8')


# ==================== 变量传播法 ====================


def _is_scope_boundary(node: Node) -> bool:
    """
    判断节点是否为作用域边界（函数或程序入口）

    Args:
        node: AST 节点

    Returns:
        bool: 是否作用域边界
    """
    return node.type in _FUNCTION_TYPES or node.type == 'program'


def _extract_string_content(node_bytes: bytes) -> Optional[str]:
    """
    从 string 节点的原始 bytes 中提取字符串内容（去掉引号）

    Args:
        node_bytes: 字符串节点的字节串

    Returns:
        Optional[str]: 字符串内容，提取失败返回 None
    """
    text = node_bytes.decode('utf-8')
    if len(text) < 2:
        return None
    quote = text[0]
    if quote in ('"', "'", '`') and text[-1] == quote:
        inner = text[1:-1]
        return inner.replace('\\"', '"').replace("\\'", "'").replace('\\\\', '\\')
    return text


def _build_scope_chain(usage_node: Node, code_bytes: bytes) -> List[List[Node]]:
    """
    从使用点向上遍历，构建作用域链（局部 → 全局）

    每个 scope 是该作用域内所有 variable_declaration / lexical_declaration /
    assignment_expression 节点的列表。

    Args:
        usage_node: 变量使用点
        code_bytes: 源代码字节串

    Returns:
        List[List[Node]]: 作用域链，从内到外
    """
    scopes = []
    current = usage_node.parent

    while current:
        if _is_scope_boundary(current):
            scope_decls = []
            _collect_decls_in_subtree(current, scope_decls)
            scopes.append(scope_decls)
            if current.type == 'program':
                break
        current = current.parent

    return scopes


def _collect_decls_in_subtree(node: Node, decls: List[Node]):
    """
    递归收集节点子树中所有声明/赋值节点

    Args:
        node: 当前 AST 节点
        decls: 声明节点收集列表
    """
    if node.type in ('variable_declaration', 'lexical_declaration'):
        decls.append(node)
        return
    if node.type == 'assignment_expression':
        decls.append(node)
    for child in node.children:
        if child.type in _FUNCTION_TYPES:
            continue  # 不进入函数内部（作用域隔离）
        _collect_decls_in_subtree(child, decls)


def _find_var_value_node(var_name: str, usage_node: Node, code_bytes: bytes) -> Optional[Node]:
    """
    带作用域优先级的变量查找：局部作用域 → 全局作用域

    变量声明必须在使用点之前（按字节位置比较）。

    Args:
        var_name: 变量名
        usage_node: 使用点节点
        code_bytes: 源代码字节串

    Returns:
        Optional[Node]: 变量定义的 value 节点，未找到返回 None
    """
    target = var_name.encode('utf-8')
    scopes = _build_scope_chain(usage_node, code_bytes)

    for decls in scopes:
        for decl in decls:
            # 声明必须在使用点之前
            if decl.start_byte >= usage_node.start_byte:
                continue

            if decl.type == 'assignment_expression':
                left_node = decl.child_by_field_name('left')
                if left_node and left_node.type == 'identifier':
                    if code_bytes[left_node.start_byte:left_node.end_byte] == target:
                        value_node = decl.child_by_field_name('right')
                        if value_node:
                            return value_node
                continue

            # variable_declaration / lexical_declaration
            for child in decl.children:
                if child.type != 'variable_declarator':
                    continue
                name_node = child.child_by_field_name('name')
                if not name_node:
                    continue
                if code_bytes[name_node.start_byte:name_node.end_byte] == target:
                    value_node = child.child_by_field_name('value')
                    if value_node:
                        return value_node
    return None


def _resolve_object_lookup(obj_node: Node, prop_name: str, code_bytes: bytes) -> Optional[Node]:
    """
    在对象字面量 AST 节点中查找指定 key 的 value 节点

    Args:
        obj_node: 对象字面量节点
        prop_name: 属性名
        code_bytes: 源代码字节串

    Returns:
        Optional[Node]: 属性值节点，未找到返回 None
    """
    if obj_node.type != 'object':
        return None
    # 过大的对象跳过解析（性能保护）
    if obj_node.end_byte - obj_node.start_byte > _MAX_OBJECT_BYTES:
        return None

    target = prop_name.encode('utf-8')
    for child in obj_node.children:
        if child.type != 'pair':
            continue
        key_node = child.child_by_field_name('key')
        if not key_node:
            continue
        key_text = code_bytes[key_node.start_byte:key_node.end_byte]
        key_str = key_text.decode('utf-8')
        # 去除引号（如果存在）
        if len(key_str) >= 2 and key_str[0] in ('"', "'"):
            key_str = key_str[1:-1]
        if key_str == prop_name:
            return child.child_by_field_name('value')
    return None


def _resolve_array_lookup(arr_node: Node, index: int, code_bytes: bytes) -> Optional[Node]:
    """
    在数组字面量 AST 节点中按索引取值

    Args:
        arr_node: 数组字面量节点
        index: 索引
        code_bytes: 源代码字节串

    Returns:
        Optional[Node]: 对应索引的元素节点
    """
    if arr_node.type != 'array':
        return None
    if arr_node.end_byte - arr_node.start_byte > _MAX_OBJECT_BYTES:
        return None

    elements = [c for c in arr_node.children if c.type not in ('[', ']', ',')]
    if 0 <= index < len(elements):
        return elements[index]
    return None


def _resolve_node_to_string(node: Node, code_bytes: bytes, resolving: Set[str]) -> Optional[str]:
    """
    统一递归解析入口：将 AST 节点解析为字符串值

    支持以下 AST 类型：
    - string: 字符串字面量
    - binary_expression: 二元表达式（字符串拼接）
    - identifier: 变量引用（跟踪到定义处）
    - member_expression: 对象属性访问
    - subscript_expression: 数组索引 / 对象键访问

    Args:
        node: AST 节点
        code_bytes: 源代码字节串
        resolving: 正在解析的变量名集合（用于检测循环引用）

    Returns:
        Optional[str]: 解析后的字符串值
    """
    if not node:
        return None

    # 1. 字符串字面量
    if node.type == 'string':
        return _extract_string_content(code_bytes[node.start_byte:node.end_byte])

    # 2. 字符串拼接（+ 操作）
    if node.type == 'binary_expression':
        op_node = node.child_by_field_name('operator')
        if op_node and code_bytes[op_node.start_byte:op_node.end_byte] == b'+':
            left = _resolve_node_to_string(node.child_by_field_name('left'), code_bytes, resolving)
            right = _resolve_node_to_string(node.child_by_field_name('right'), code_bytes, resolving)
            if left is not None and right is not None:
                return left + right
        return None

    # 3. 变量引用
    if node.type == 'identifier':
        var_name = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
        if var_name in resolving:
            return None  # 防止循环引用
        resolving.add(var_name)
        value_node = _find_var_value_node(var_name, node, code_bytes)
        resolving.discard(var_name)
        if not value_node:
            return None
        return _resolve_node_to_string(value_node, code_bytes, resolving)

    # 4. 成员表达式（obj.prop）
    if node.type == 'member_expression':
        obj_node = node.child_by_field_name('object')
        prop_node = node.child_by_field_name('property')
        if not obj_node or not prop_node:
            return None
        prop_name = code_bytes[prop_node.start_byte:prop_node.end_byte].decode('utf-8')
        if obj_node.type != 'identifier':
            return None
        obj_var_name = code_bytes[obj_node.start_byte:obj_node.end_byte].decode('utf-8')
        obj_ast_node = _find_var_value_node(obj_var_name, obj_node, code_bytes)
        if not obj_ast_node or obj_ast_node.type != 'object':
            return None
        target_node = _resolve_object_lookup(obj_ast_node, prop_name, code_bytes)
        if not target_node:
            return None
        return _resolve_node_to_string(target_node, code_bytes, resolving)

    # 5. 下标表达式（obj[key] 或 arr[index]）
    if node.type == 'subscript_expression':
        obj_node = node.child_by_field_name('object')
        idx_node = node.child_by_field_name('index')
        if not obj_node or not idx_node:
            return None
        if obj_node.type != 'identifier':
            return None
        obj_var_name = code_bytes[obj_node.start_byte:obj_node.end_byte].decode('utf-8')

        # 字符串索引：obj["key"]
        if idx_node.type == 'string':
            prop_name = _extract_string_content(code_bytes[idx_node.start_byte:idx_node.end_byte])
            if prop_name is None:
                return None
            obj_ast_node = _find_var_value_node(obj_var_name, obj_node, code_bytes)
            if not obj_ast_node or obj_ast_node.type != 'object':
                return None
            target_node = _resolve_object_lookup(obj_ast_node, prop_name, code_bytes)
            if not target_node:
                return None
            return _resolve_node_to_string(target_node, code_bytes, resolving)

        # 数字索引：arr[0]
        elif idx_node.type == 'number':
            try:
                index = int(code_bytes[idx_node.start_byte:idx_node.end_byte].decode('utf-8'))
            except ValueError:
                return None
            obj_ast_node = _find_var_value_node(obj_var_name, obj_node, code_bytes)
            if not obj_ast_node or obj_ast_node.type != 'array':
                return None
            target_node = _resolve_array_lookup(obj_ast_node, index, code_bytes)
            if not target_node:
                return None
            return _resolve_node_to_string(target_node, code_bytes, resolving)

    return None


def _propagate_variables(stmt_node: Node, target_node: Node, code_bytes: bytes) -> str:
    """
    对代码切片内的字符串变量执行传播替换

    在字节层面做精确替换，避免编码偏移问题。
    识别出变量引用并将其替换为实际值。

    Args:
        stmt_node: 语句节点
        target_node: 目标节点（用于确定替换范围）
        code_bytes: 源代码字节串

    Returns:
        str: 变量传播替换后的代码
    """
    slice_start = stmt_node.start_byte
    slice_end = stmt_node.end_byte
    slice_bytes = code_bytes[slice_start:slice_end]

    replacements = []
    resolved_ranges = []  # 已解析的成员表达式范围（避免重复替换）

    def _collect(node):
        """收集所有成员表达式和下标表达式的范围"""
        if node.type in ('member_expression', 'subscript_expression'):
            resolved_ranges.append((node.start_byte, node.end_byte))
        for child in node.children:
            _collect(child)

    _collect(stmt_node)

    def _traverse(node):
        """递归遍历，收集需要替换的变量引用"""
        if node.start_byte < slice_start or node.end_byte > slice_end:
            return

        # 跳过目标节点内部
        if node.start_byte >= target_node.start_byte and node.end_byte <= target_node.end_byte:
            for child in node.children:
                _traverse(child)
            return

        if node.type == 'identifier':
            for rs, re in resolved_ranges:
                if node.start_byte >= rs and node.end_byte <= re:
                    return
            resolving = set()
            value = _resolve_node_to_string(node, code_bytes, resolving)
            if value is not None:
                original = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
                replacement = f'"{value}"'
                if replacement != original:
                    replacements.append((
                        node.start_byte - slice_start,
                        node.end_byte - slice_start,
                        replacement.encode('utf-8')
                    ))

        elif node.type in ('member_expression', 'subscript_expression'):
            resolving = set()
            value = _resolve_node_to_string(node, code_bytes, resolving)
            if value is not None:
                original = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
                replacement = f'"{value}"'
                if replacement != original:
                    replacements.append((
                        node.start_byte - slice_start,
                        node.end_byte - slice_start,
                        replacement.encode('utf-8')
                    ))
            return  # 不进入成员/下标表达式内部（已整体解析）

        for child in node.children:
            _traverse(child)

    _traverse(stmt_node)

    if not replacements:
        return slice_bytes.decode('utf-8')

    # 倒序替换，确保偏移量正确
    replacements.sort(key=lambda x: x[0], reverse=True)
    result = bytearray(slice_bytes)
    for start, end, new_bytes in replacements:
        result[start:end] = new_bytes

    return result.decode('utf-8')


# ==================== 变量传播法 END ====================


def _extract_heuristic_slice(api_node: Node, code_bytes: bytes) -> str:
    """
    启发式代码切片提取（增强版语义边界优先策略）

    策略 1：优先提取包含 API 字符串的最小语义边界（函数/方法），并进行变量传播
    策略 2：降级到语句级别提取，收集依赖的变量声明

    Args:
        api_node: API 字符串所在的 AST 节点
        code_bytes: 源代码字节串

    Returns:
        str: 提取的代码片段
    """
    # 策略 1：尝试提取语义边界（函数/方法）
    semantic_boundary = _find_semantic_boundary(api_node)
    if semantic_boundary:
        boundary_code = _extract_complete_boundary(semantic_boundary, code_bytes)

        # 检查大小是否在合理范围内
        if len(boundary_code.encode('utf-8')) <= MAX_CONTEXT_BYTES:
            propagated = _propagate_variables(semantic_boundary, api_node, code_bytes)
            if len(propagated.encode('utf-8')) <= MAX_CONTEXT_BYTES:
                return propagated
            return boundary_code

    # 策略 2：降级到原有的语句级别提取
    stmt_node = api_node
    # 往上找，停在变量声明(Declarator)或独立语句(Statement/Property)
    while stmt_node and not (
            stmt_node.type.endswith('statement') or stmt_node.type == 'variable_declarator'
            or stmt_node.type == 'property'):
        stmt_node = stmt_node.parent

    if not stmt_node:
        return code_bytes[api_node.start_byte:api_node.end_byte].decode('utf-8')

    # 变量传播：在核心代码中解析字符串变量
    core_line = _propagate_variables(stmt_node, api_node, code_bytes)

    # 获取靶心代码使用的变量
    used_vars = _find_identifiers_in_node(stmt_node, code_bytes)
    ignore_list = {'concat', 'return', 'require', 'window', 'document', 'console', 'JSON', 'Object'}
    used_vars = {v for v in used_vars if v not in ignore_list}

    dependencies = []

    # 收集同一 var/let/const 声明家族中的哥哥姐姐变量
    if stmt_node.type == 'variable_declarator':
        parent_decl = stmt_node.parent
        if parent_decl and parent_decl.type == 'variable_declaration':
            for sibling_decl in parent_decl.children:
                if sibling_decl.type != 'variable_declarator':
                    continue
                if sibling_decl.start_byte >= stmt_node.start_byte:
                    break

                sibling_code = code_bytes[sibling_decl.start_byte:sibling_decl.end_byte].decode('utf-8')
                name_node = sibling_decl.child_by_field_name('name')
                if name_node:
                    var_name = code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    if var_name in used_vars:
                        decl_kind = code_bytes[parent_decl.start_byte:parent_decl.children[0].end_byte].decode('utf-8')
                        dependencies.append(f"{decl_kind} {sibling_code};")

    parent_scope = stmt_node.parent
    if stmt_node.type == 'variable_declarator' and parent_scope:
        parent_scope = parent_scope.parent

    # 在父作用域中搜索依赖变量
    max_lookback = 500
    if parent_scope and used_vars:
        for sibling in parent_scope.children:
            max_lookback -= 1
            if max_lookback < 0:
                break

            target_start = stmt_node.parent.start_byte if stmt_node.type == 'variable_declarator' else stmt_node.start_byte
            if sibling.start_byte >= target_start:
                break

            if sibling.type in ['variable_declaration', 'lexical_declaration']:
                sibling_code = code_bytes[sibling.start_byte:sibling.end_byte].decode('utf-8')
                if any(f" {var} " in sibling_code or f"{var}=" in sibling_code.replace(" ", "") for var in used_vars):
                    dependencies.append(sibling_code)

    # 缝合依赖和核心代码
    final_slice = "\n".join(dependencies) + "\n" + core_line

    # 最终大小检查
    if len(final_slice.encode('utf-8')) > MAX_CONTEXT_BYTES:
        return core_line

    return final_slice


def _find_enclosing_function(node: Node) -> Optional[Node]:
    """
    获取包裹指定节点的最近函数节点

    Args:
        node: AST 节点

    Returns:
        Optional[Node]: 函数节点，未找到返回 None
    """
    current = node
    while current:
        if current.type in {'function_declaration', 'arrow_function', 'function_expression', 'method_definition'}:
            return current
        current = current.parent
    return None


def _get_function_name(func_node: Node, code_bytes: bytes) -> Optional[str]:
    """
    获取函数的名称（支持多种声明格式）

    - function_declaration: function foo() {}
    - variable_declarator: const foo = function() {}
    - assignment_expression: foo = function() {}

    Args:
        func_node: 函数节点
        code_bytes: 源代码字节串

    Returns:
        Optional[str]: 函数名，未找到返回 None
    """
    if not func_node:
        return None

    if func_node.type == 'function_declaration':
        name_node = func_node.child_by_field_name('name')
        if name_node:
            return code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')

    # 检查父节点
    parent = func_node.parent
    if parent:
        if parent.type == 'variable_declarator':
            name_node = parent.child_by_field_name('name')
            if name_node:
                return code_bytes[name_node.start_byte:name_node.end_byte].decode('utf-8')
        elif parent.type == 'assignment_expression':
            left_node = parent.child_by_field_name('left')
            if left_node:
                return code_bytes[left_node.start_byte:left_node.end_byte].decode('utf-8')

    return None


def _find_callers_of_function(root_node: Node, func_name: str, code_bytes: bytes) -> List[str]:
    """
    遍历 AST，寻找所有调用了指定函数的地方

    返回调用点所在语句的代码片段（切片式提取）。

    Args:
        root_node: AST 根节点
        func_name: 函数名
        code_bytes: 源代码字节串

    Returns:
        List[str]: 调用者代码片段列表（已去重）
    """
    callers_code = []
    target_name_bytes = func_name.encode('utf-8')

    def traverse(node):
        """递归遍历 AST 查找调用表达式"""
        if node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'identifier' and _node_text_equals(callee, code_bytes, target_name_bytes):
                # 找到调用点后，提取所在的完整语句
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
    """
    批量提取多个 API 路径的上下文（核心实现）

    基于 Tree-sitter AST 分析，使用单次遍历完成所有数据的打标与收集：
    - 任务 A: 收集目标 API 字符串节点（建立 API 路径 -> AST 节点的映射）
    - 任务 B: 收集所有函数调用（为后续找 Caller 建立索引）

    Args:
        code_bytes: JS 源代码字节串
        target_apis: 目标 API 路径列表

    Returns:
        dict: {api_path: {found, api_url, wrapper_code, caller_codes}}
    """
    _PARSER = get_parser()
    logger = get_logger()

    # 初始化结果字典
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

    hit_nodes = []  # (api_path, ast_node) 匹配结果
    target_apis_bytes = [api.encode('utf-8') for api in target_apis]
    call_index = {}  # {func_name_bytes: [call_node, ...]}

    def _single_pass_traverse(node: Node):
        """单遍全树遍历，同时完成所有数据的打标与收集"""

        # 任务 A: 收集目标 API 字符串节点
        if node.type == 'string':
            # 直接在 bytes 层面做包含判断，极速！
            raw_bytes = code_bytes[node.start_byte:node.end_byte]
            for i, api_bytes in enumerate(target_apis_bytes):
                if api_bytes in raw_bytes:
                    hit_nodes.append((target_apis[i], node))
                    break  # 一个节点匹配上就行了

        # 任务 B: 收集所有的函数调用（为后面找 Caller 做铺垫）
        elif node.type == 'call_expression':
            callee = node.child_by_field_name('function')
            if callee and callee.type == 'identifier':
                func_name_bytes = code_bytes[callee.start_byte:callee.end_byte]
                if func_name_bytes not in call_index:
                    call_index[func_name_bytes] = []
                call_index[func_name_bytes].append(node)

        # 递归下去
        for child in node.children:
            _single_pass_traverse(child)

    _single_pass_traverse(tree.root_node)

    # 为每个匹配的 API 路径提取上下文
    for target_api, api_node in hit_nodes:
        result_data = results[target_api]
        result_data["found"] = True

        # 1. 切片提取（使用增强版语义边界优先策略）
        result_data["wrapper_code"] = _extract_heuristic_slice(api_node, code_bytes)

        # 2. 寻找调用链（利用已建立的索引加速）
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
    """
    从原始 JS 代码中批量提取多个 API 路径的上下文（公开入口）

    将 JS 字符串编码为 bytes 后委托给 _extract_multiple_apis_from_bytes 处理。

    Args:
        js_code: 原始 JS 代码字符串
        target_apis: 目标 API 路径列表

    Returns:
        dict: {api_path: {found, api_url, wrapper_code, caller_codes}}
    """
    if not isinstance(js_code, str) or not isinstance(target_apis, list):
        return {}
    return _extract_multiple_apis_from_bytes(js_code.encode('utf-8', errors='replace'), target_apis)