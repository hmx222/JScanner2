import logging

import jsbeautifier


def format_code(js_code: str, fallback_on_error: bool = True) -> str:
    """
    安全的 JS 代码美化函数，带异常处理和降级策略

    :param js_code: 原始 JS 代码
    :param fallback_on_error: 出错时是否返回原文（True）或抛出异常（False）
    :return: 美化后的代码 or 原文 or 空字符串
    """
    if not isinstance(js_code, str):
        if fallback_on_error:
            return ""
        raise TypeError("js_code must be a string")

    if len(js_code.strip()) == 0:
        return js_code  # 空字符串直接返回

    try:
        # 预编译选项（可移到模块级缓存）
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.max_preserve_newlines = 1
        opts.keep_array_indentation = False
        opts.break_chained_methods = False
        opts.max_char_per_line = 160  # 避免超长行

        # 执行美化
        beautified = jsbeautifier.beautify(js_code, opts)

        # 简单验证：美化后不应为空（除非原文就是空）
        if beautified is None or (len(beautified.strip()) == 0 and len(js_code.strip()) > 0):
            raise ValueError("Beautifier returned empty result")

        return beautified

    except (UnicodeDecodeError, MemoryError, RecursionError) as e:
        logging.warning(f"美化失败（资源错误）")
        if fallback_on_error:
            return js_code  # 降级：返回原文
        else:
            raise

    except Exception as e:
        # 捕获 jsbeautifier.ParseError 等所有异常
        logging.warning(f"美化失败（语法错误等）")
        if fallback_on_error:
            return js_code  # 降级：返回原文
        else:
            raise