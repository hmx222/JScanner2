import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from tldextract import tldextract
from FileIO.filerw import read

# load whiteList
whiteList = read("./config/whiteList")


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


def data_clean(base_url: str, dirty_data: list) -> list:
    """
    智能清洗URL数据 - 最终增强版
    策略：
    1. 提取所有 Host 和 Path。
    2. API 路径 -> 全排列拼接所有 Host (宁可错杀)。
    3. JS/静态资源路径 -> 仅拼接当前 Base URL (减少垃圾请求)。
    """
    if not dirty_data:
        return []

    # 1. 初始化 Base URL
    base_parsed = urlparse(base_url)
    if not base_parsed.scheme:
        base_url = "https://" + base_url
        base_parsed = urlparse(base_url)

    current_root_url = f"{base_parsed.scheme}://{base_parsed.netloc}"

    # 候选 Host 集合 (包含当前域名)
    candidate_hosts = {current_root_url}

    # 分两个 Path 集合
    api_paths = set()
    static_paths = set()

    final_urls = set()

    for item in dirty_data:
        # 黑名单与基础过滤
        SKIP_CONTENT_TYPES = {
            "text/html", "text/plain", "image/gif", "image/jpg",
            "image/jpeg", "image/svg+xml", "application/json"
        }
        if item in SKIP_CONTENT_TYPES: continue
        if not item or " " in item: continue

        item = item.replace('\\', '/').strip()
        if item.startswith(('javascript:', 'mailto:', 'tel:', 'data:')): continue

        if item.startswith(('http://', 'https://')):
            final_urls.add(item)
            # 尝试提取 Host，用于后续拼接
            try:
                p = urlparse(item)
                path_lower = p.path.lower()
                if not path_lower.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico')):
                    host = f"{p.scheme}://{p.netloc}"
                    candidate_hosts.add(host)
            except:
                pass

        # 情况B: 协议相对 URL
        elif item.startswith('//'):
            url = f"{base_parsed.scheme}:{item}"
            final_urls.add(url)
            try:
                p = urlparse(url)
                candidate_hosts.add(f"{p.scheme}://{p.netloc}")
            except:
                pass

        else:
            # 1. 判定是否为静态资源
            is_static = False
            static_exts = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
                           '.svg', '.woff', '.ttf', '.ico', '.eot', '.xml')

            # 去掉参数后判断后缀
            path_no_query = item.split('?')[0].lower()
            if path_no_query.endswith(static_exts):
                is_static = True

            # 2. 格式化路径 (确保以 / 开头，方便统一处理，除非是 ../)
            if not item.startswith('/') and not item.startswith('.'):
                item = '/' + item

            # 3. 分类入库
            if is_static:
                static_paths.add(item)
            else:
                api_paths.add(item)


    for host in candidate_hosts:
        for path in api_paths:
            try:
                combined = urljoin(host, path)
                # 规范化 // 为 /
                combined = re.sub(r'(?<!:)//+', '/', combined)
                final_urls.add(combined)
            except:
                pass

    for path in static_paths:
        try:

            combined = urljoin(base_url, path)
            combined = re.sub(r'(?<!:)//+', '/', combined)
            final_urls.add(combined)
        except:
            pass


    return_url_list = []
    for url in final_urls:
        if check_url(base_url, url):
            return_url_list.append(url)

    return list(return_url_list)


def check_url(original_url, splicing_url):
    """
    校验域名范围，防止爬虫跑偏
    策略：
    1. 必须是同一根域名
    2.或者是白名单内的域名
    """
    try:
        urlparse2 = urlparse(splicing_url)
    except:
        return False

    if any(ext in urlparse2.path.lower() for ext in (
            '.png', '.jpg', '.jpeg', '.ico', '.mp4', '.mp3', '.gif', '.ttf',
            '.css', '.svg', '.m4v', '.aac', '.woff', '.woff2', '.eot',
            '.otf', '.apk', '.exe', '.swf', '.webp'
    )):
        return False

    # 域名校验
    root_orig = get_root_domain(original_url)
    root_split = get_root_domain(splicing_url)

    if (root_orig == root_split) or (root_split in whiteList):
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
