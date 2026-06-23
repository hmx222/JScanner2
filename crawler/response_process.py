from infra.dedup import DuplicateChecker
from config.scanner_rules import API_PATH_BLACKLIST_KEYWORDS


def _is_path_blacklisted(path: str) -> bool:
    """
    检查 API path 是否包含黑名单关键词
    
    Args:
        path: API 路径
        
    Returns:
        bool: 如果包含黑名单关键词返回 True，否则返回 False
    """
    if not path or not isinstance(path, str):
        return True
    
    path_lower = path.lower()
    
    # 检查路径中是否包含黑名单关键词（作为完整单词或路径段）
    for keyword in API_PATH_BLACKLIST_KEYWORDS:
        # 使用 '/' 分割路径，检查每个路径段
        path_segments = path_lower.split('/')
        for segment in path_segments:
            # 移除查询参数部分
            segment_clean = segment.split('?')[0]
            if keyword == segment_clean:
                return True
            # 也检查是否以该关键词开头（如 delete_user, del_item）
            if segment_clean.startswith(keyword + '_') or segment_clean.endswith('_' + keyword):
                return True
    
    return False


async def process_scan_result(scan_info, checker: DuplicateChecker, args, seed_url: str = None):
    """
    处理扫描结果（去重 + 提取下一层 URL）

    Args:
        scan_info: 扫描结果信息
        checker: 去重检查器
        args: 命令行参数
        seed_url: 原始种子URL（用于跨域JS的URL拼接基准）
    """
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
        # 传递seed_url给data_clean，用于正确的URL拼接
        next_urls = set(data_clean(url, rex_output, seed_url=seed_url))
    except Exception:
        rex_output = []

    # 筛选条件：长度>4 且 不包含"."且 至少包含 1 个"/" 且 不在黑名单中
    if rex_output:
        filtered_rex_output = []
        for item in rex_output:
            is_string = isinstance(item, str)
            length_ok = len(item) > 4
            no_dot = "." not in item
            enough_slash = item.count('/') >= 1
            not_blacklisted = not _is_path_blacklisted(item)

            if is_string and length_ok and no_dot and enough_slash and not_blacklisted:
                filtered_rex_output.append(item)
        rex_output = filtered_rex_output

    return True, next_urls, rex_output


