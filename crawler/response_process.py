from infra.dedup import DuplicateChecker

async def process_scan_result(scan_info, checker: DuplicateChecker, args):
    """处理扫描结果（去重 + 提取下一层 URL）"""
    url = scan_info["url"]
    source = scan_info.get("source_code", "")
    status = scan_info["status"]
    title = scan_info.get("title", "NULL")
    length = scan_info.get("length", 0)

    # 1. 基础过滤
    if not checker.is_within_scope(url):
        return False, set(), []
    if status == 404:
        return False, set(), []
    if not source or length < 200:
        return False, set(), []
    if len(source) > 20 * 1024 * 1024:  # 限制 20MB
        return False, set(), []

    # 2. 内容去重 (仅针对非 JS 文件)
    if ".js" not in url:
        if checker.is_page_duplicate(url, source, title):
            return False, set(), []

    # 3. 标记为已访问
    checker.mark_url_visited(url)

    # 4. 提取下一层 URL
    next_urls = set()

    try:
        from processor.analysis.api.api_scan import analysis_by_rex, data_clean
        rex_output = analysis_by_rex(source)
        next_urls = set(data_clean(url, rex_output))
    except Exception:
        rex_output = []

    # 筛选条件：长度>4 且 不包含"."且 至少包含 1 个"/"
    if rex_output:
        filtered_rex_output = []
        for item in rex_output:
            is_string = isinstance(item, str)
            length_ok = len(item) > 4
            no_dot = "." not in item
            enough_slash = item.count('/') >= 1

            if is_string and length_ok and no_dot and enough_slash:
                filtered_rex_output.append(item)
        rex_output = filtered_rex_output

    return True, next_urls, rex_output

