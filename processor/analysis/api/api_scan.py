import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from tldextract import tldextract

from config.scanner_rules import STATIC_RESOURCE_EXTENSIONS


def analysis_by_rex(source) -> list:
    """
    使用正则表达式从源代码中提取可能的 URL/API 路径

    支持提取：
    - 完整 URL（http/https 开头的绝对 URL）
    - 路径开头（/ 开头的绝对路径）
    - 相对路径（./ 或 ../ 开头）
    - 带扩展名的路径（如 .php, .asp, .jsp 等）
    - 不带扩展名的文件名路径

    Args:
        source: 源代码字符串

    Returns:
        list: 提取到的 URL/路径列表（已去重）
    """
    # 正则模式：匹配引号包裹的各种 URL 格式
    pattern_raw = r"""
              (?:"|')                               # 开始引号
              (
                ((?:[a-zA-Z]{1,10}://|//)           # 协议头 (http/https//)
                [^"'/]{1,}\.                        # 域名
                [a-zA-Z]{2,}(?!png|css|jpeg|mp4|mp3|gif|ico)[^"']{0,}) # 路径（排除图片等静态资源）
                |
                ((?:/|\.\./|\./)                    # 路径起始（/ 或 ./ 或 ../）
                [^"'><,;| *()(%%$^/\\\[\]]+         # 允许的字符
                [^"'><,;|()]{1,})                   # 结尾字符
                |
                ([a-zA-Z0-9_\-/]{1,}/               # 路径
                [a-zA-Z0-9_\-/]{1,}                 # 名称
                \.(?:[a-zA-Z]{1,4}|action)          # 扩展名
                (?:\?[^"|']{0,}|))                  # 可选查询参数
                |
                ([a-zA-Z0-9_\-]{1,}                 # 文件名
                \.(?:php|asp|aspx|jsp|json|
                     action|html|js|txt|xml)        # 常见动态/静态文件扩展名
                (?:\?[^"|']{0,}|))                  # 可选查询参数
              )
              (?:"|')                               # 结束引号
            """
    pattern = re.compile(pattern_raw, re.VERBOSE)  # 编译正则表达式
    links = pattern.findall(source)  # 查找所有匹配
    # 提取每组匹配的第一个元素（完整匹配）
    relist = [link[0] for link in links]  # 提取每组首个匹配
    return list(set(relist))


def is_potential_domain(url: str) -> bool:
    """
    智能判断 URL 是否包含有效域名

    检查条件：
    1. 包含至少一个点号（.）
    2. 不以点号开头或结尾
    3. 第一部分至少包含一个字母
    4. 顶级域名部分至少 2 个字符且包含字母

    Args:
        url: 待检查的 URL 字符串

    Returns:
        bool: 是否包含有效域名
    """
    if '.' not in url or url.startswith('.') or url.endswith('.'):
        return False
    parts = url.split('.', 1)  # 按点号分割域名
    if not any(c.isalpha() for c in parts[0]):
        return False
    tld = parts[1].split('/')[0]  # 提取顶级域名
    if len(tld) < 2 or not any(c.isalpha() for c in tld):
        return False
    return True


def get_root_domain(url):
    """
    提取根域名（例如: www.baidu.com -> baidu.com）

    使用 tldextract 库准确提取，支持各种复杂域名格式。

    Args:
        url: 完整的 URL 字符串

    Returns:
        str: 根域名，提取失败返回 "unknown"
    """
    try:
        parsed_url = urlparse(url)  # 解析URL链接
        full_domain = parsed_url.netloc  # 获取域名部分
        # 使用 tldextract 解析顶级域名和注册域名
        extracted = tldextract.extract(full_domain)  # 提取域名组件
        if not extracted.suffix:
            return full_domain
        root_domain = f"{extracted.domain}.{extracted.suffix}"  # 拼接根域名
        return root_domain
    except:
        return "unknown"


def data_clean(current_url: str, dirty_data, seed_url: str = None) -> list:
    """
    清理和标准化 URL 列表

    将各种格式的路径引用转为完整 URL，支持多种路径格式：
    1. 协议相对 URL（// 开头）
    2. 绝对路径（/ 开头）
    3. 相对路径（./ 或 ../ 开头）
    4. 绝对 URL（http/https 开头）
    5. 缺少协议的完整 URL（如 www.baidu.com/aaa）
    6. 普通相对路径

    Args:
        current_url: 当前正在处理的 URL（可能是跨域 JS 文件）
        dirty_data: 从正则表达式提取的原始 URL 列表
        seed_url: 原始种子 URL（用于跨域 JS 的 URL 拼接基准）。如果为 None，则使用 current_url

    Returns:
        list: 标准化后的 URL 列表
    """
    return_url_list = []  # 初始化结果列表
    if not dirty_data:
        return []

    # 确定拼接基准 URL：优先使用 seed_url，否则使用 current_url
    base_url = seed_url if seed_url else current_url  # 确定拼接基准URL

    # 解析基础 URL
    base_parsed = urlparse(base_url)  # 解析基础URL

    # 确保基础 URL 有协议
    if not base_parsed.scheme:
        base_url = "https://" + base_url  # 补充协议前缀
        base_parsed = urlparse(base_url)  # 重新解析URL

    Protocol = base_parsed.scheme  # 提取协议类型
    Domain = base_parsed.netloc  # 提取域名地址
    Path = base_parsed.path.rstrip('/') or '/'  # 提取路径部分

    # 获取当前 URL 的根域名（用于判断是否跨域）
    current_root_domain = get_root_domain(current_url)  # 获取当前根域名
    base_root_domain = get_root_domain(base_url)  # 获取基准根域名
    is_cross_domain = (current_root_domain != base_root_domain)  # 判断是否跨域

    for main_url in dirty_data:  # 遍历原始URL列表
        # 需要跳过的内容类型黑名单
        SKIP_CONTENT_TYPES = {
            "text/html", "text/plain", "image/gif",
            "image/jpg", "image/jpeg", "image/svg+xml"
        }  # 跳过内容类型黑名单

        # 基础过滤
        if main_url in SKIP_CONTENT_TYPES:
            continue
        if len(main_url) <= 5:
            continue
        if not main_url:
            continue
        if " " in main_url:
            continue

        # 清理反斜杠和多余空格
        main_url = main_url.replace('\\', '/').strip()  # 清理反斜杠和空格

        # 跳过非 HTTP 协议（javascript:, mailto:, tel:, data:）
        if main_url.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
            continue

        # 情况1: 以 // 开头的协议相对 URL -> 添加当前协议
        if main_url.startswith('//'):
            return_url = f"{Protocol}:{main_url}"  # 协议相对URL

        # 情况2: 以 / 开头的绝对路径 -> 拼接域名
        elif main_url.startswith('/'):
            return_url = f"{Protocol}://{Domain}{main_url}"  # 绝对路径拼接

        # 情况3: 以 ./ 或 ../ 开头的相对路径 -> 使用 urljoin 拼接
        elif main_url.startswith(('./', '../')):
            return_url = urljoin(base_url, main_url)  # 相对路径拼接

        # 情况4: 以 http/https 开头的绝对 URL -> 直接使用
        elif main_url.startswith(('http://', 'https://')):
            return_url = main_url  # 直接使用绝对URL

        # 情况5: 可能缺少协议的完整 URL（如 www.baidu.com/aaa）
        elif is_potential_domain(main_url):
            if '/' in main_url:
                return_url = f"{Protocol}://{main_url}"  # 补充协议前缀
            else:
                return_url = f"{Protocol}://{main_url}/"  # 补充协议和斜杠

        # 情况6: 相对路径（如 aaa/bbbb/ccc）
        else:
            if '/' in main_url and not is_potential_domain(main_url.split('/')[0]):
                return_url = f"{Protocol}://{Domain}{Path.rstrip('/')}/{main_url.lstrip('/')}"  # 拼接完整URL
            else:
                # 可能是查询参数或片段
                return_url = f"{Protocol}://{Domain}{Path}?{main_url}"  # 拼接查询参数URL

        # 规范化 URL（移除多余斜杠等）
        return_url = re.sub(r'(?<!:)//+', '/', return_url)  # 规范化多余斜杠

        # 验证并添加到结果
        if check_url(base_url, return_url):
            return_url_list.append(return_url)

    return return_url_list


def check_url(original_url, splicing_url):
    """
    校验 URL 域名范围，防止爬虫跑偏

    只有目标域名范围内的 URL 才允许继续处理。

    Args:
        original_url: 原始 URL（基准域名）
        splicing_url: 拼接后的 URL（待校验）

    Returns:
        bool: True 表示在允许范围内，False 表示跨域
    """
    try:
        urlparse2 = urlparse(splicing_url)  # 解析待校验URL
    except:
        return False

    # 检查是否是静态资源扩展名（跳过）
    if any(ext in urlparse2.path.lower() for ext in STATIC_RESOURCE_EXTENSIONS):
        return False

    # 域名校验：比较根域名或检查是否在白名单中
    root_orig = get_root_domain(original_url)  # 获取原始域名
    root_split = get_root_domain(splicing_url)  # 获取拼接域名

    if root_orig == root_split:
        return True
    return False


def extract_pure_js(html_content):
    """
    从包含 HTML 标签的内容中提取 <pre> 标签内的 JS 代码

    用于从响应中提取美化后的 JS 代码块。

    Args:
        html_content: 包含 HTML 标签的文本

    Returns:
        str: 提取到的纯 JS 代码，如果没有 <pre> 标签则返回原始内容
    """
    try:
        # 使用 BeautifulSoup 解析 HTML
        soup = BeautifulSoup(html_content, 'html.parser')  # 解析HTML内容
        # 查找常见的代码展示格式
        pre_tag = soup.find('pre', style="word-wrap: break-word; white-space: pre-wrap;")  # 查找格式化的pre标签
        if pre_tag:
            return pre_tag.get_text().strip()
        else:
            # 回退：使用第一个 <pre> 标签
            fallback_pre = soup.find('pre')  # 回退查找pre标签
            if fallback_pre:
                return fallback_pre.get_text().strip()
            return html_content
    except:
        return html_content