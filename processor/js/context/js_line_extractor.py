import re
from typing import List

from config.scanner_rules import STATIC_RESOURCE_EXTENSIONS


def has_valid_slash(content: str) -> bool:
    """
    判断内容中是否存在至少一个 /，且其左侧或右侧紧邻数字/字母

    用于过滤无效路径字符串，确保 / 出现在有意义的上下文中。

    Args:
        content: 待检查的字符串

    Returns:
        bool: 是否包含有效斜杠
    """
    VALID_SLASH_PATTERN = re.compile(r'[a-zA-Z0-9]/|/[a-zA-Z0-9]')

    if not isinstance(content, str):
        return False
    return bool(VALID_SLASH_PATTERN.search(content))


def extract_relevant_lines(input_str: str) -> str:
    """
    从 JS 代码中提取可能包含 API 路径的行（用于送入大模型分析）

    处理流程：
    1. 逐行过滤（跳过注释、过长行等）
    2. 快速跳过不含关键字符的行
    3. 去除行内注释和反斜杠
    4. 跳过 HTML 标签行
    5. 提取引号内容并验证是否包含有效的路径

    Args:
        input_str: 原始 JS 代码字符串

    Returns:
        str: 提取后的相关行，用换行符连接
    """
    # 预编译正则表达式以提高性能
    HTML_TAG_PATTERN = re.compile(r'<\s*/?\s*[a-zA-Z][^>]*>')
    REGEX_METACHARS = re.compile(r'[*+?^${}()|[\]\\]')
    SPLIT_COMMENT_PATTERN = re.compile(r'(?<!:)//')  # 分割行内注释（排除协议头 //）
    QUOTED_CONTENT_PATTERN = re.compile(r'["\'](.*?)["\']')

    if not isinstance(input_str, str) or not input_str:
        return ""

    relevant_lines: List[str] = []
    lines = input_str.splitlines()

    for line in lines:
        line_stripped = line.strip()

        # 1. 基础过滤：跳过空行、注释行和超长行
        if not line_stripped or line_stripped.startswith('//'):
            continue
        if len(line_stripped) > 800:
            continue

        # 2. 快速跳过不含关键字符的行
        if not (
                '/' in line_stripped or 'http' in line_stripped or 'api' in line_stripped
                or "=" in line_stripped or ":" in line_stripped):
            continue

        # 3. 去除行内注释
        parts = SPLIT_COMMENT_PATTERN.split(line_stripped, 1)
        line_no_comment = parts[0].rstrip()
        if not line_no_comment:
            continue

        # 4. 去除所有反斜杠（避免转义符干扰）
        line_clean = line_no_comment.replace('\\', '')

        # 5. HTML 标签检测（跳过包含 HTML 标签的行）
        if HTML_TAG_PATTERN.search(line_clean):
            continue

        # 6. 提取引号内容并验证
        quoted_contents = QUOTED_CONTENT_PATTERN.findall(line_clean)
        if not quoted_contents:
            continue

        is_line_valid = False
        for content in quoted_contents:
            # 跳过静态资源扩展名
            if any(content.lower().endswith(ext) for ext in STATIC_RESOURCE_EXTENSIONS):
                continue

            # 跳过正则表达式元字符
            if REGEX_METACHARS.search(content):
                continue

            # 检查是否包含有效斜杠（路径特征）
            if has_valid_slash(content):
                is_line_valid = True
                break

        if is_line_valid:
            # 规范化空白后添加到结果
            normalized_line = ' '.join(line_clean.split())
            relevant_lines.append(normalized_line)

    return "\n".join(relevant_lines)