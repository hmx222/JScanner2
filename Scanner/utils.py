from urllib.parse import urlparse
from config.scanner_rules import (
    UNAUTHORIZED_PAGE_KEYWORDS,
    API_PATH_BLACKLIST_KEYWORDS,
    HTTPX_STATIC_EXTENSIONS,
    STATIC_RESOURCE_EXTENSIONS
)

BATCH_SIZE = 200
BATCH_SLEEP = 0.2
API_MIN_LENGTH = 4
HTML_EXTS = {'.html', '.htm', '.xhtml'}


def _is_static_url(url: str) -> bool:
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in HTTPX_STATIC_EXTENSIONS)


def _is_html_url(url: str) -> bool:
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in HTML_EXTS)


def _is_skip_ext(url: str) -> bool:
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in STATIC_RESOURCE_EXTENSIONS)


def classify_url(url, is_seed=False):
    if is_seed:
        return 'dynamic'

    parsed = urlparse(url)
    path = parsed.path
    has_dot = "." in path

    if has_dot:
        if _is_static_url(url):
            return 'static'
        elif _is_html_url(url):
            return 'dynamic'
        return 'dynamic'
    return 'api'


def is_api_path_blacklisted(api_path: str) -> bool:
    if not api_path or not isinstance(api_path, str):
        return True

    path_lower = api_path.lower()

    for keyword in API_PATH_BLACKLIST_KEYWORDS:
        path_segments = path_lower.split('/')
        for segment in path_segments:
            segment_clean = segment.split('?')[0]
            if keyword == segment_clean:
                return True
            if segment_clean.startswith(keyword + '_') or segment_clean.endswith('_' + keyword):
                return True

    return False
