import jsbeautifier


def _get_beautifier_options():
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.max_preserve_newlines = 1
    opts.keep_array_indentation = False
    opts.break_chained_methods = False
    opts.max_char_per_line = 160
    return opts

