from infra.dedup import DuplicateChecker
from config.scanner_rules import is_api_path_blacklisted
from processor.analysis.api.api_scan import analysis_by_rex, data_clean


async def process_scan_result(scan_info, checker: DuplicateChecker, args, seed_url: str = None):
    """
    处理单次扫描结果

    处理流程：
    1. 基础过滤：检查域名范围、状态码、内容长度
    2. 内容去重：非 JS 文件进行页面去重
    3. 标记已访问
    4. 提取下一层 URL：使用正则从源代码中提取 URL 和 API 路径
    5. 筛选过滤：路径长度、黑名单、静态资源排除

    Args:
        scan_info: 扫描结果信息字典（包含 url, source_code, status, title, length）
        checker: 去重检查器（DuplicateChecker 实例）
        args: 命令行参数
        seed_url: 原始种子 URL（用于跨域 JS 的 URL 拼接基准）

    Returns:
        tuple: (is_valid: bool, next_urls: set, next_paths: list)
            - is_valid: 扫描结果是否有效
            - next_urls: 提取到的下一层 URL 集合
            - next_paths: 提取到的 API 路径列表
    """
    url = scan_info["url"]  # 扫描URL
    source = scan_info.get("source_code", "")  # 源代码
    status = scan_info["status"]  # 状态码
    title = scan_info.get("title", "NULL")  # 页面标题
    length = scan_info.get("length", 0)  # 内容长度

    # 1. 基础过滤：域名范围检查
    if not checker.is_within_scope(url):
        return False, set(), []
    # 404 页面跳过
    if status == 404:
        return False, set(), []
    # 内容过短跳过
    if not source or length < 200:
        return False, set(), []
    # 内容过大跳过（限制 20MB）
    if len(source) > 20 * 1024 * 1024:
        return False, set(), []

    # 2. 内容去重（仅针对非 JS 文件）
    if ".js" not in url:
        if checker.is_page_duplicate(url, source, title):
            return False, set(), []

    # 3. 标记为已访问
    checker.mark_url_visited(url)

    # 4. 提取下一层 URL（使用正则分析源代码）
    next_urls = set()  # 下一层URL集合

    try:
        # 使用正则提取源代码中的 URL/路径
        rex_output = analysis_by_rex(source)  # 正则提取URL路径
        # 将提取到的路径拼接为完整 URL
        next_urls = set(data_clean(url, rex_output, seed_url=seed_url))  # 拼接为完整URL
    except Exception:  # 正则提取异常处理
        rex_output = []  # 异常时置空

    # 5. 筛选过滤：保留符合条件的原始路径
    if rex_output:
        filtered_rex_output = []  # 过滤后的路径列表
        for item in rex_output:  # 遍历候选路径
            is_string = isinstance(item, str)  # 字符串类型检查
            length_ok = len(item) > 4  # 长度大于4
            no_dot = "." not in item  # 排除文件路径
            enough_slash = item.count('/') >= 1  # 包含至少一个/
            not_blacklisted = not is_api_path_blacklisted(item)  # 不在黑名单

            if is_string and length_ok and no_dot and enough_slash and not_blacklisted:
                filtered_rex_output.append(item)
        rex_output = filtered_rex_output  # 替换为过滤结果

    return True, next_urls, rex_output