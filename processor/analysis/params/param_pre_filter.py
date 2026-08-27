import re


_PARAM_SIGNAL_PATTERNS = [
    # ========================
    # 1. Query String 拼接
    # ========================
    re.compile(r'''['"]\?\w{1,4}='''),
    re.compile(r'''URLSearchParams'''),

    # ========================
    # 2. Request Body / Data 对象
    # ========================
    re.compile(r'\bparams\s*:'),
    re.compile(r'\bdata\s*:\s*[\{a-zA-Z(]'),
    re.compile(r'\bbody\s*:'),

    # ========================
    # 3. 序列化
    # ========================
    re.compile(r'JSON\.stringify\s*\('),
    re.compile(r'\w+\.stringify\s*\(\s*[a-zA-Z]'),

    # ========================
    # 4. FormData
    # ========================
    re.compile(r'\.append\s*\(\s*["\']\w{2,}'),

    # ========================
    # 5. 对象构造 / 合并
    # ========================
    re.compile(r'Object\.assign\s*\('),

    # ========================
    # 6. HTTP 方法 + 第二参数
    # ========================
    re.compile(r'\.(?:get|post|put|patch|delete|request)\s*\([^)]+,\s*[\{(]'),

    # ========================
    # 7. 函数签名含多参数（说明接受配置/参数）
    # ========================
    re.compile(r'function\s*\([^()]*\w[^()]*,\s*\w'),
    re.compile(r'\([^()]*\w[^()]*,\s*\w[^()]*\)\s*=>'),
]

_SIGNAL_THRESHOLD = 1


def _has_param_signals(code: str) -> bool:
    if not code:
        return False
    score = 0
    for pattern in _PARAM_SIGNAL_PATTERNS:
        if pattern.search(code):
            score += 1
            if score >= _SIGNAL_THRESHOLD:
                return True
    return False


def pre_filter_has_params(wrapper_code: str, caller_codes: list, api_path: str = "") -> bool:
    """
    规则预筛：判断代码上下文中是否存在 HTTP 参数构造痕迹。

    返回值:
        True  → 可能有参数，需要送 AI 分析
        False → 大概率无参数，可跳过 AI（宁可多送，不可漏判）
    """
    if '?' in api_path:
        return True

    if _has_param_signals(wrapper_code):
        return True

    for caller in (caller_codes or [])[:3]:
        if _has_param_signals(caller):
            return True

    return False