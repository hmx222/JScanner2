from typing import List

from config.config import VALID_SLASH_PATTERN, SPLIT_COMMENT_PATTERN, HTML_TAG_PATTERN, QUOTED_CONTENT_PATTERN, \
    BLACK_LIST, REGEX_METACHARS


def has_valid_slash(content: str) -> bool:
    """
    判断内容中是否存在至少一个 /，且其左侧或右侧紧邻数字/字母。
    """
    if not isinstance(content, str):
        return False
    return bool(VALID_SLASH_PATTERN.search(content))


def extract_relevant_lines(input_str: str) -> str:
    """
    从 JS 代码中提取可能包含 API 路径的行（用于送入大模型分析）。

    :param input_str: 原始 JS 代码字符串
    :return: 提取后的相关行，用换行符连接
    """
    if not isinstance(input_str, str) or not input_str:
        return ""

    relevant_lines: List[str] = []
    lines = input_str.splitlines()

    for line in lines:
        line_stripped = line.strip()

        # 1. 基础过滤
        if not line_stripped or line_stripped.startswith('//'):
            continue
        if len(line_stripped) > 800:
            continue

        # 2. 快速跳过
        if not (
                '/' in line_stripped or 'http' in line_stripped or 'api' in line_stripped or "=" in line_stripped or ":" in line_stripped):
            continue

        # 3. 去除行内注释
        parts = SPLIT_COMMENT_PATTERN.split(line_stripped, 1)
        line_no_comment = parts[0].rstrip()
        if not line_no_comment:
            continue

        # 4. 去除所有反斜杠
        line_clean = line_no_comment.replace('\\', '')

        # 5. HTML 标签检测
        if HTML_TAG_PATTERN.search(line_clean):
            continue

        # 6. 提取与验证
        quoted_contents = QUOTED_CONTENT_PATTERN.findall(line_clean)
        if not quoted_contents:
            continue

        is_line_valid = False
        for content in quoted_contents:
            if any(content.lower().endswith(ext) for ext in BLACK_LIST):
                continue

            if REGEX_METACHARS.search(content):
                continue

            if has_valid_slash(content):
                is_line_valid = True
                break

        if is_line_valid:
            normalized_line = ' '.join(line_clean.split())
            relevant_lines.append(normalized_line)

    return "\n".join(relevant_lines)
