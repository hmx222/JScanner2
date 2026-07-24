import logging
import os
import shutil
import subprocess
import tempfile
import re
from typing import Optional

import jsbeautifier

from logger import get_logger


def _get_beautifier_options():
    """获取 jsbeautifier 的格式化选项配置"""
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.max_preserve_newlines = 1
    opts.keep_array_indentation = False
    opts.break_chained_methods = False
    opts.max_char_per_line = 160
    return opts


logger = get_logger(__name__)


def sanitize_js_code_safe(js_code: str) -> str:
    """
    安全清理 JS 代码中的控制字符

    使用黑名单策略，只清理已知会破坏 AST 且无意义的控制字符：
    1. 将 Unicode 行分隔符（\\u2028）和段落分隔符（\\u2029）转为普通换行
    2. 删除零宽字符、BOM 头和非法 ASCII 控制字符

    Args:
        js_code: 原始 JS 代码

    Returns:
        清理后的 JS 代码
    """
    if not js_code:
        return js_code

    # 将 Unicode 行/段落分隔符转为换行符，防止单行注释吞噬下一行代码
    js_code = js_code.replace(' ', '\n').replace(' ', '\n')

    # 删除零宽字符、BOM 和非法控制字符
    bad_chars_pattern = r'[\x00-\x08\x0b\x0c\x0e-\x1f​-‏﻿]'
    js_code = re.sub(bad_chars_pattern, '', js_code)

    return js_code


def _find_prettier_path(prettier_path: Optional[str] = None) -> Optional[str]:
    """
    查找 prettier 可执行文件路径

    按优先级查找：
    1. 用户指定的路径
    2. PATH 环境变量中的 prettier
    3. npx prettier
    4. 常见安装路径

    Args:
        prettier_path: 用户指定的 prettier 路径（可选）

    Returns:
        Optional[str]: prettier 可执行文件路径，未找到返回 None
    """
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

    # 尝试使用 npx
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
    """
    使用 prettier 格式化 JS 代码

    将代码写入临时文件后调用 prettier 命令进行格式化。

    Args:
        js_code: 待格式化的 JS 代码
        parser: 解析器类型（默认 "babel"）
        print_width: 每行最大宽度
        tab_width: 缩进宽度
        single_quote: 是否使用单引号
        prettier_path: prettier 可执行文件路径
        timeout: 命令超时时间（秒）

    Returns:
        Optional[str]: 格式化后的代码，失败返回 None
    """
    prettier_cmd = _find_prettier_path(prettier_path)
    if not prettier_cmd:
        logger.error("❌ prettier 不可用")
        return None

    temp_file_path = None
    try:
        # 创建临时文件写入原始代码
        fd, temp_file_path = tempfile.mkstemp(suffix='.js', prefix='prettier_')

        with os.fdopen(fd, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(js_code)

        # 构建 prettier 命令
        cmd = [
            prettier_cmd,
            "--write", temp_file_path,  # 原地修改临时文件
            "--parser", parser,
            "--print-width", str(print_width),
            "--tab-width", str(tab_width),
        ]
        if single_quote:
            cmd.append("--single-quote")

        # 执行 prettier 命令
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=timeout
        )

        # 读取格式化后的结果
        if result.returncode == 0:
            with open(temp_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                formatted = f.read()
            return formatted
        else:
            return None

    except subprocess.TimeoutExpired:
        return None
    finally:
        # 清理临时文件
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except:
                pass


def format_code(
        js_code: str,
        fallback_on_error: bool = True,
        parser: str = "babel",
        print_width: int = 120,
        tab_width: int = 2,
        single_quote: bool = False,
        prettier_path: Optional[str] = None,
        prettier_timeout: int = 300,
        sanitize_code: bool = True
) -> str:
    """
    格式化 JS 代码的主入口

    格式化工具有两层降级策略：
    1. 首选 jsbeautifier（Python 原生，速度快）
    2. 降级使用 prettier（外部命令，效果更好）
    3. 最后降级只做基本分行处理（保证至少能让正则匹配）

    Args:
        js_code: 待格式化的 JS 代码
        fallback_on_error: 格式化失败时是否降级
        parser: prettier 的解析器类型
        print_width: prettier 的每行最大宽度
        tab_width: prettier 的缩进宽度
        single_quote: prettier 是否使用单引号
        prettier_path: prettier 可执行文件路径
        prettier_timeout: prettier 超时时间
        sanitize_code: 是否先清理控制字符

    Returns:
        str: 格式化后的 JS 代码（格式化失败时返回原始代码）
    """
    if not isinstance(js_code, str) or not js_code.strip():
        return js_code

    # 先清理可能破坏 AST 的控制字符
    if sanitize_code:
        js_code = sanitize_js_code_safe(js_code)

    # 判断是否为超大文件（超过 1MB）
    is_huge_file = len(js_code) > 1024 * 1024

    # 第一层：jsbeautifier 格式化（Python 原生，非超大文件时使用）
    if not is_huge_file:
        try:
            beautified = jsbeautifier.beautify(js_code, _get_beautifier_options())
            if beautified:
                return beautified
        except Exception as e:
            logger.warning(f"⚠️ jsbeautifier 失败，降级 prettier: {type(e).__name__}")

    # 第二层：prettier 格式化（效果更好，但需要外部命令）
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

    # 第三层：降级处理（仅做基本分行）
    if fallback_on_error:
        if is_huge_file and ";" in js_code[:10000]:
            # 简单应急分行：遇到分号或左大括号加换行
            js_code = js_code.replace(";", ";\n").replace("{", "{\n")
        return js_code
    else:
        raise RuntimeError("All beautification methods failed")


def check_prettier_available(prettier_path: Optional[str] = None) -> bool:
    """
    检查 prettier 是否可用

    Args:
        prettier_path: prettier 可执行文件路径（可选）

    Returns:
        bool: prettier 是否可用
    """
    return _find_prettier_path(prettier_path) is not None