import logging
import os
import shutil
import subprocess
import tempfile
import re
from typing import Optional

import jsbeautifier

from logger import get_logger
from processor.js.format.options import _get_beautifier_options

logger = get_logger(__name__)

def sanitize_js_code_safe(js_code: str) -> str:
    """
    【安全清理策略】不再使用白名单暴力删除！
    改用黑名单策略：只清理已知会破坏 AST 且无意义的控制字符。

    1. 转换：将特殊的 Unicode 行分隔符转换为普通换行，防止单行注释吞噬下一行代码。
    2. 删除：只删除零宽字符、BOM 头和非法 ASCII 控制字符。
    """
    if not js_code:
        return js_code

    # \u2028 是行分隔符, \u2029 是段落分隔符
    js_code = js_code.replace('\u2028', '\n').replace('\u2029', '\n')

    bad_chars_pattern = r'[\x00-\x08\x0b\x0c\x0e-\x1f\u200b-\u200f\ufeff]'
    js_code = re.sub(bad_chars_pattern, '', js_code)

    return js_code


def _find_prettier_path(prettier_path: Optional[str] = None) -> Optional[str]:
    """查找 prettier 可执行文件路径"""
    if prettier_path and os.path.exists(prettier_path):
        return prettier_path

    search_paths = []

    # Windows 常见路径
    if os.name == 'nt':
        search_paths.extend([
            os.path.expandvars(r"%USERPROFILE%\AppData\Roaming\npm\prettier.cmd"),
            os.path.expandvars(r"%APPDATA%\npm\prettier.cmd"),
            r"C:\Program Files\nodejs\node_modules\prettier\bin-prettier.js",
        ])
    # Linux/Mac 常见路径
    else:
        search_paths.extend([
            '/usr/local/bin/prettier',
            '/usr/bin/prettier',
            os.path.expanduser('~/.npm-global/bin/prettier'),
        ])

    # 检查 PATH 中的命令
    prettier_cmd = shutil.which('prettier')
    if prettier_cmd:
        return prettier_cmd

    npx_cmd = shutil.which('npx')
    if npx_cmd:
        return 'npx prettier'

    # 检查预设路径
    for path in search_paths:
        expanded_path = os.path.expandvars(path)
        if os.path.exists(expanded_path):
            return expanded_path

    return None


def _format_with_prettier(
        js_code: str,
        parser: str = "babel",
        print_width: int = 120,
        tab_width: int = 2,
        single_quote: bool = False,
        prettier_path: Optional[str] = None,
        timeout: int = 300
) -> Optional[str]:
    """使用 prettier 格式化代码 (优化文件写入编码)"""
    prettier_cmd = _find_prettier_path(prettier_path)
    if not prettier_cmd:
        logger.error("❌ prettier 不可用")
        return None

    temp_file_path = None
    try:
        fd, temp_file_path = tempfile.mkstemp(suffix='.js', prefix='prettier_')

        with os.fdopen(fd, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(js_code)

        cmd = [
            prettier_cmd,
            "--write", temp_file_path,
            "--parser", parser,
            "--print-width", str(print_width),
            "--tab-width", str(tab_width),
        ]
        if single_quote:
            cmd.append("--single-quote")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=timeout
        )

        if result.returncode == 0:
            with open(temp_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                formatted = f.read()
            return formatted
        else:
            return None

    except subprocess.TimeoutExpired:
        return None
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except:
                pass

def format_code(
        js_code: str,
        fallback_on_error: bool = True,
        # prettier 参数
        parser: str = "babel",
        print_width: int = 120,
        tab_width: int = 2,
        single_quote: bool = False,
        prettier_path: Optional[str] = None,
        prettier_timeout: int = 300,
        sanitize_code: bool = True
) -> str:
    if not isinstance(js_code, str) or not js_code.strip():
        return js_code

    if sanitize_code:
        js_code = sanitize_js_code_safe(js_code)


    is_huge_file = len(js_code) > 1024 * 1024

    if not is_huge_file:
        try:
            beautified = jsbeautifier.beautify(js_code, _get_beautifier_options())
            if beautified:
                return beautified
        except Exception as e:
            logger.warning(f"⚠️ jsbeautifier 失败，降级 prettier: {type(e).__name__}")


    prettier_result = _format_with_prettier(
        js_code=js_code,
        parser=parser,
        print_width=print_width,
        tab_width=tab_width,
        single_quote=single_quote,
        prettier_path=prettier_path,
        timeout=prettier_timeout
    )

    if prettier_result is not None:
        return prettier_result


    if fallback_on_error:
        # 即使无法漂亮格式化，也可尝试把代码按分号强制分行，便于安全扫描正则匹配
        if is_huge_file and ";" in js_code[:10000]:
            # 简单的应急分行：遇到分号或左大括号加换行
            js_code = js_code.replace(";", ";\n").replace("{", "{\n")
        return js_code
    else:
        raise RuntimeError("All beautification methods failed")


def check_prettier_available(prettier_path: Optional[str] = None) -> bool:
    """检查 prettier 是否可用"""
    return _find_prettier_path(prettier_path) is not None

