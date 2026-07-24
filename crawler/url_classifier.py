"""
URL 分类器 - 判断 URL 类型（静态/动态/API）

从 scanner.py 中分离，将所有 URL 分类逻辑集中到 crawler 层。
"""
from urllib.parse import urlparse

from config.scanner_rules import HTTPX_STATIC_EXTENSIONS, STATIC_RESOURCE_EXTENSIONS

# HTML 扩展名集合
HTML_EXTS = {'.html', '.htm', '.xhtml'}


def is_static_url(url: str) -> bool:
    """判断 URL 是否为静态资源文件"""
    url_lower = url.lower().split('?')[0]  # 取小写+去参
    return any(url_lower.endswith(ext) for ext in HTTPX_STATIC_EXTENSIONS)


def is_html_url(url: str) -> bool:
    """判断 URL 是否为 HTML 页面"""
    url_lower = url.lower().split('?')[0]  # 取小写+去参
    return any(url_lower.endswith(ext) for ext in HTML_EXTS)


def is_skip_ext(url: str) -> bool:
    """判断是否需要跳过此 URL（基于静态资源扩展名黑名单）"""
    url_lower = url.lower().split('?')[0]  # 取小写+去参
    return any(url_lower.endswith(ext) for ext in STATIC_RESOURCE_EXTENSIONS)


def classify_url(url, is_seed=False):
    """URL 分类（极简版）"""
    if is_seed:
        return 'dynamic'

    parsed = urlparse(url)  # 解析 URL
    path = parsed.path      # 获取路径
    has_dot = "." in path   # 路径含点号

    if has_dot:
        if is_static_url(url):
            return 'static'
        elif is_html_url(url):
            return 'dynamic'
        return 'dynamic'
    return 'api'
