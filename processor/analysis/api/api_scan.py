import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from tldextract import tldextract
from config.config import BLACK_LIST, WHITE_SCOPE_PATH
from storage.filerw import read


def analysis_by_rex(source) -> list:
    """analysis source code by rex"""
    pattern_raw = r"""
              (?:"|')                               # Start delimiter
              (
                ((?:[a-zA-Z]{1,10}://|//)           # Scheme
                [^"'/]{1,}\.                        # Domain
                [a-zA-Z]{2,}(?!png|css|jpeg|mp4|mp3|gif|ico)[^"']{0,}) # Path
                |
                ((?:/|\.\./|\./)                    # Path start
                [^"'><,;| *()(%%$^/\\\[\]]+         # Allowed chars
                [^"'><,;|()]{1,})                   # End chars
                |
                ([a-zA-Z0-9_\-/]{1,}/               # Path
                [a-zA-Z0-9_\-/]{1,}                 # Name
                \.(?:[a-zA-Z]{1,4}|action)          # Extension
                (?:\?[^"|']{0,}|))                  # Params
                |
                ([a-zA-Z0-9_\-]{1,}                 # Filename
                \.(?:php|asp|aspx|jsp|json|
                     action|html|js|txt|xml)        # Extensions
                (?:\?[^"|']{0,}|))                  # Params
              )
              (?:"|')                               # End delimiter
            """
    pattern = re.compile(pattern_raw, re.VERBOSE)
    links = pattern.findall(source)
    # findall返回的是元组，取第一个元素(整个匹配组)
    relist = [link[0] for link in links]
    return list(set(relist))


def is_potential_domain(url: str) -> bool:
    """
    智能判断URL是否包含有效域名
    """
    if '.' not in url or url.startswith('.') or url.endswith('.'):
        return False
    parts = url.split('.', 1)
    if not any(c.isalpha() for c in parts[0]):
        return False
    tld = parts[1].split('/')[0]
    if len(tld) < 2 or not any(c.isalpha() for c in tld):
        return False
    return True


def data_clean(base_url: str, dirty_data) -> list:
    return_url_list = []
    if not dirty_data:
        return []


    # 解析基础URL
    base_parsed = urlparse(base_url)

    # 确保基础URL有协议
    if not base_parsed.scheme:
        base_url = "https://" + base_url
        base_parsed = urlparse(base_url)

    Protocol = base_parsed.scheme
    Domain = base_parsed.netloc
    Path = base_parsed.path.rstrip('/') or '/'

    for main_url in dirty_data:
        # 增加部分黑名单
        SKIP_CONTENT_TYPES = {
            "text/html",
            "text/plain",
            "image/gif",
            "image/jpg",
            "image/jpeg",
            "image/svg+xml"
        }

        if main_url in SKIP_CONTENT_TYPES:
            continue

        if len(main_url) <= 5:
             continue

        if not main_url:
            continue

        if " " in main_url:
            continue

        # 清理反斜杠和多余空格
        main_url = main_url.replace('\\', '/').strip()

        # 跳过javascript:等非HTTP协议
        if main_url.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
            continue

        # 情况1: 以//开头的协议相对URL
        if main_url.startswith('//'):
            return_url = f"{Protocol}:{main_url}"

        # 情况2: 以/开头的绝对路径
        elif main_url.startswith('/'):
            return_url = f"{Protocol}://{Domain}{main_url}"

        # 情况3: 以./或../开头的相对路径
        elif main_url.startswith(('./', '../')):
            # 使用urljoin处理相对路径（最可靠的方式）
            return_url = urljoin(base_url, main_url)

        # 情况4: 以http/https开头的绝对URL
        elif main_url.startswith(('http://', 'https://')):
            return_url = main_url

        # 情况5: 可能缺少协议的完整URL (如 www.baidu.com/aaa)
        elif is_potential_domain(main_url):
            # 检查是否有路径部分
            if '/' in main_url:
                return_url = f"{Protocol}://{main_url}"
            else:
                return_url = f"{Protocol}://{main_url}/"

        # 情况6: 相对路径 (如 aaa/bbbb/ccc)
        else:
            # 检查是否包含路径分隔符且不像是域名
            if '/' in main_url and not is_potential_domain(main_url.split('/')[0]):
                return_url = f"{Protocol}://{Domain}{Path.rstrip('/')}/{main_url.lstrip('/')}"
            else:
                # 可能是查询参数或片段
                return_url = f"{Protocol}://{Domain}{Path}?{main_url}"

        # 规范化URL（移除多余斜杠等）
        return_url = re.sub(r'(?<!:)//+', '/', return_url)

        # 验证并添加到结果
        if check_url(base_url, return_url):
            return_url_list.append(return_url)

    return return_url_list

def check_url(original_url, splicing_url):
    """
    校验域名范围，防止爬虫跑偏
    """
    try:
        urlparse2 = urlparse(splicing_url)
    except:
        return False

    if any(ext in urlparse2.path.lower() for ext in BLACK_LIST):
        return False

    # 域名校验
    root_orig = get_root_domain(original_url)
    root_split = get_root_domain(splicing_url)

    if (root_orig == root_split) or (root_split in WHITE_SCOPE_PATH):
        return True
    else:
        return False


def get_root_domain(url):
    """
    提取根域名 (例如: www.baidu.com -> baidu.com)
    """
    try:
        parsed_url = urlparse(url)
        full_domain = parsed_url.netloc
        extracted = tldextract.extract(full_domain)
        # 处理 IP 地址的情况
        if not extracted.suffix:
            return full_domain
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        return root_domain
    except:
        return "unknown"


def is_js_file(url):
    js_pattern = re.compile(r'\.js(?=[^a-zA-Z]|$)')
    json_pattern = re.compile(r'\.json')
    return not json_pattern.search(url) and bool(js_pattern.search(url))


def extract_pure_js(html_content):
    """从包含HTML标签的内容中提取<pre>标签内的JS代码"""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        pre_tag = soup.find('pre', style="word-wrap: break-word; white-space: pre-wrap;")
        if pre_tag:
            return pre_tag.get_text().strip()
        else:
            fallback_pre = soup.find('pre')
            if fallback_pre:
                return fallback_pre.get_text().strip()
            return html_content
    except:
        return html_content
