import re
from typing import List, Dict, Any, Optional
from tree_sitter import Node

from processor.js.context.parse import get_parser
from processor.js.context.context_extractor import (
    _propagate_variables,
    _find_identifiers_in_node,
)
from logger import get_logger

logger = get_logger(__name__)

BASE_URL_PROPERTY_NAMES = {
    b'baseURL', b'baseUrl', b'base_url', b'BASE_URL',
    b'BASEURL', b'apiBase', b'API_BASE', b'apiUrl', b'API_URL',
    b'apiBaseURL', b'API_BASE_URL',
}

EMPTY_VALUES = {"", "undefined", "null", "NaN", "0", "false"}

_MAX_SLICE_BYTES = 500
_MAX_DEPENDENCY_STMTS = 3


def _strip_quotes(raw: bytes) -> bytes:
    text = raw.strip()
    if len(text) >= 2 and text[0] in (ord('"'), ord("'")):
        return text[1:-1]
    return text


def _is_base_url_property(name_bytes: bytes) -> bool:
    clean = _strip_quotes(name_bytes)
    return clean in BASE_URL_PROPERTY_NAMES


def _is_empty_string_literal(text: str) -> bool:
    return len(text) == 2 and text[0] == text[-1] and text[0] in ('"', "'", '`')


def _is_empty_value(node: Node, code_bytes: bytes) -> bool:
    if node.type == 'assignment_expression':
        right = node.child_by_field_name('right')
        if not right:
            return True
        text = code_bytes[right.start_byte:right.end_byte].decode('utf-8', errors='replace').strip()
        return text in EMPTY_VALUES or _is_empty_string_literal(text)

    elif node.type == 'pair':
        value = node.child_by_field_name('value')
        if not value:
            return True
        text = code_bytes[value.start_byte:value.end_byte].decode('utf-8', errors='replace').strip()
        return text in EMPTY_VALUES or _is_empty_string_literal(text)

    return False


def _normalize_slice_for_dedup(code_slice: str) -> str:
    return re.sub(r'\s+', ' ', code_slice.strip())


def _find_containing_statement(node: Node) -> Optional[Node]:
    current = node
    while current:
        if current.type.endswith('statement') or current.type in (
            'variable_declarator', 'property', 'pair'
        ):
            return current
        current = current.parent
    return None


def _find_create_call(pair_node: Node) -> Optional[Node]:
    current = pair_node
    for _ in range(6):
        if not current or not current.parent:
            break
        current = current.parent
        if current.type == 'call_expression':
            return current
        if current.type == 'object' and current.parent and current.parent.type == 'arguments':
            continue
    return None


def _collect_preceding_dependencies(
    stmt_node: Node, code_bytes: bytes, max_stmts: int = _MAX_DEPENDENCY_STMTS
) -> List[str]:
    parent_scope = stmt_node.parent
    if not parent_scope:
        return []

    used_vars = _find_identifiers_in_node(stmt_node, code_bytes)
    ignore_list = {
        'concat', 'return', 'require', 'window', 'document',
        'console', 'JSON', 'Object', 'Promise', 'Error',
    }
    used_vars = {v for v in used_vars if v not in ignore_list and len(v) > 1}

    dependencies = []
    lookback_budget = 300

    for sibling in parent_scope.children:
        lookback_budget -= 1
        if lookback_budget < 0:
            break

        if sibling.start_byte >= stmt_node.start_byte:
            break

        if sibling.type not in ('variable_declaration', 'lexical_declaration'):
            continue

        sibling_code = code_bytes[sibling.start_byte:sibling.end_byte].decode('utf-8', errors='replace')
        if any(f" {var} " in sibling_code or f"{var}=" in sibling_code.replace(" ", "") for var in used_vars):
            dependencies.append(sibling_code)
            if len(dependencies) >= max_stmts:
                break

    return dependencies


def _extract_assignment_slice(target_node: Node, code_bytes: bytes) -> str:
    stmt = _find_containing_statement(target_node)
    if not stmt:
        return code_bytes[target_node.start_byte:target_node.end_byte].decode('utf-8', errors='replace')

    try:
        core_line = _propagate_variables(stmt, target_node, code_bytes)
    except Exception:
        core_line = code_bytes[stmt.start_byte:stmt.end_byte].decode('utf-8', errors='replace')

    dependencies = _collect_preceding_dependencies(stmt, code_bytes)

    parts = dependencies + [core_line]
    result = "\n".join(parts)

    if len(result.encode('utf-8')) > _MAX_SLICE_BYTES:
        return core_line[:_MAX_SLICE_BYTES]

    return result


def _extract_pair_slice(pair_node: Node, target_node: Node, code_bytes: bytes) -> str:
    call_node = _find_create_call(pair_node)
    if call_node and (call_node.end_byte - call_node.start_byte) <= _MAX_SLICE_BYTES:
        try:
            result = _propagate_variables(call_node, target_node, code_bytes)
        except Exception:
            result = code_bytes[call_node.start_byte:call_node.end_byte].decode('utf-8', errors='replace')
    else:
        obj_node = pair_node.parent
        while obj_node and obj_node.type != 'object':
            obj_node = obj_node.parent
        if obj_node:
            try:
                result = _propagate_variables(obj_node, target_node, code_bytes)
            except Exception:
                result = code_bytes[obj_node.start_byte:obj_node.end_byte].decode('utf-8', errors='replace')
        else:
            result = code_bytes[pair_node.start_byte:pair_node.end_byte].decode('utf-8', errors='replace')

    if len(result.encode('utf-8')) > _MAX_SLICE_BYTES:
        result = code_bytes[target_node.start_byte:target_node.end_byte].decode('utf-8', errors='replace')

    return result


def find_base_url_definitions(code_bytes: bytes, tree, js_url: str = "") -> List[Dict[str, Any]]:
    write_hits = []

    def traverse(node: Node):

        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            if left and left.type == 'member_expression':
                prop = left.child_by_field_name('property')
                if prop:
                    prop_text = code_bytes[prop.start_byte:prop.end_byte]
                    if _is_base_url_property(prop_text):
                        write_hits.append(('assignment', node))

        elif node.type == 'pair':
            key = node.child_by_field_name('key')
            if key:
                key_text = code_bytes[key.start_byte:key.end_byte]
                if _is_base_url_property(key_text):
                    write_hits.append(('pair', node))

        for child in node.children:
            traverse(child)

    traverse(tree.root_node)

    results = []
    seen_positions = set()
    seen_contents = set()

    for hit_type, target_node in write_hits:
        if hit_type == 'assignment':
            stmt = _find_containing_statement(target_node)
            dedup_pos = stmt.start_byte if stmt else target_node.start_byte
        else:
            dedup_pos = target_node.start_byte

        if dedup_pos in seen_positions:
            continue
        seen_positions.add(dedup_pos)

        if _is_empty_value(target_node, code_bytes):
            continue

        if hit_type == 'assignment':
            code_slice = _extract_assignment_slice(target_node, code_bytes)
        else:
            code_slice = _extract_pair_slice(target_node, target_node, code_bytes)

        if not code_slice.strip():
            continue

        normalized = _normalize_slice_for_dedup(code_slice)
        if normalized in seen_contents:
            continue
        seen_contents.add(normalized)

        results.append({
            "type": hit_type,
            "code": code_slice,
        })

    logger.info(f"🔍 [BaseURL Extractor] {js_url} → 找到 {len(results)} 个写入点 (原始 {len(write_hits)} 个)")
    return results


def extract_base_url_candidates(js_code: str, js_url: str = "") -> List[Dict[str, Any]]:
    if not js_code or not isinstance(js_code, str):
        return []

    parser = get_parser()
    if not parser:
        logger.warning("⚠️ [BaseURL Extractor] Parser 未初始化")
        return []

    code_bytes = js_code.encode('utf-8', errors='replace')

    try:
        tree = parser.parse(code_bytes)
    except Exception as e:
        logger.error(f"❌ [BaseURL Extractor] AST 解析失败 ({js_url}): {e}")
        return []

    return find_base_url_definitions(code_bytes, tree, js_url)
