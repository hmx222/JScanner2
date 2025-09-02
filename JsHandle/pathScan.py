import os
import re
from urllib.parse import urlparse, urljoin

from attr.validators import instance_of
from bs4 import BeautifulSoup
from esprima import esprima
from tldextract import tldextract

from FileIO.filerw import read

# load whiteList
whiteList = read("./config/whiteList")

def extract_js_api_params(js_code):
    """
    从JavaScript代码中提取所有可能向后端发送参数的点
    返回格式: {端点URL: [参数变量名称或对象]}
    """
    results = {}

    patterns = [
        # 匹配Fetch API
        (r"fetch\(['\"]([^'\"]+)['\"][^)]*body:\s*([\w$]+)", "FETCH"),
        # 匹配XMLHttpRequest
        (r"\.send\(([\w$]+)\)", "XHR"),
        # 匹配jQuery AJAX
        (r"\.ajax\({[^{}]*url:\s*['\"]([^'\"]+)['\"][^{}]*data:\s*([\w$\[]+)", "AJAX"),
        (r"\.(?:post|get)\(['\"]([^'\"]+)['\"],\s*([\w$]+)", "AJAX"),
        # 匹配Axios
        (r"axios\.(?:post|get)\(['\"]([^'\"]+)['\"][^)]*params:\s*{([^}]+)}", "AXIOS"),
        # 匹配表单提交
        (r"document\.(?:getElementById|querySelector)\(['\"]([^'\"]+)['\"]\)\.submit\(\)", "FORM"),
        (r"\.submit\(\);?\s*\/\/\s*Form:\s*(\w+)", "FORM"),
        # 匹配WebSocket
        (r"new\s+WebSocket\(['\"]([^'\"]+)['\"]\)", "WEBSOCKET")
    ]

    for pattern, method in patterns:
        for match in re.finditer(pattern, js_code, re.DOTALL):
            groups = [g for g in match.groups() if g]
            if len(groups) >= 2:
                url, param = groups[0], groups[1]
                if url not in results:
                    results[url] = set()
                results[url].add(param)

    try:
        ast = esprima.parseScript(js_code, {'jsx': True})

        def traverse(node):
            # 处理Fetch调用
            if (node.type == 'CallExpression' and
                    node.callee.name == 'fetch' and
                    node.arguments):
                url = node.arguments[0].value if node.arguments[0].type == 'Literal' else '动态URL'
                if len(node.arguments) > 1 and node.arguments[1].type == 'ObjectExpression':
                    for prop in node.arguments[1].properties:
                        if prop.key.name == 'body' and prop.value.type == 'Identifier':
                            results.setdefault(url, set()).add(prop.value.name)

            # 处理jQuery AJAX
            elif (node.type == 'CallExpression' and
                  node.callee.property and
                  node.callee.property.name in ('ajax', 'post', 'get') and
                  node.arguments and node.arguments[0].type == 'ObjectExpression'):

                url = None
                param = None
                for prop in node.arguments[0].properties:
                    if prop.key.name == 'url' and prop.value.type == 'Literal':
                        url = prop.value.value
                    elif prop.key.name == 'data' and prop.value.type == 'Identifier':
                        param = prop.value.name

                if url and param:
                    results.setdefault(url, set()).add(param)

            # 继续遍历子节点
            for child in node.__dict__.values():
                if isinstance(child, list):
                    for item in child:
                        if hasattr(item, 'type'):
                            traverse(item)
                elif hasattr(child, 'type'):
                    traverse(child)

        traverse(ast)

    except Exception as e:
        pass

    return {url: list(params) for url, params in results.items()}



def analysis_by_rex(source)->list:
    """analysis source code by rex"""

    pattern_raw = r"""
              (?:"|')                               # Start newline delimiter
              (
                ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
                [^"'/]{1,}\.                        # Match a domainname (any character + dot)
                [a-zA-Z]{2,}(?!png|css|jpeg|mp4|mp3|gif|ico)[^"']{0,})              # The domainextension and/or path, not ending with png/css/jpeg/mp4/mp3
                |
                ((?:/|\.\./|\./)                    # Start with /,../,./
                [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
                [^"'><,;|()]{1,})                   # Rest of the characters can't be
                |
                ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
                [a-zA-Z0-9_\-/]{1,}                 # Resource name
                \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
                (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
                |
                ([a-zA-Z0-9_\-]{1,}                 # filename
                \.(?:php|asp|aspx|jsp|json|
                     action|html|js|txt|xml)             # . + extension
                (?:\?[^"|']{0,}|))                  # ? mark with parameters
              )
              (?:"|')                               # End newline delimiter
            """
    pattern = re.compile(pattern_raw, re.VERBOSE)
    links = pattern.findall(source)
    relist = [link[0] for link in links]

    return list(set(relist))


import os
import re
from urllib.parse import urlparse, urlunparse, urljoin


def is_potential_domain(url: str) -> bool:
    """
    智能判断URL是否包含有效域名（无需额外依赖）

    :param url: 要检查的URL片段
    :return: 是否包含有效域名
    """
    # 基本检查：必须包含点且点不在开头/结尾
    if '.' not in url or url.startswith('.') or url.endswith('.'):
        return False

    # 检查点前后是否有字母（排除纯数字IP，但允许带路径的IP）
    parts = url.split('.', 1)
    if not any(c.isalpha() for c in parts[0]):
        return False

    # 检查TLD部分（简单验证）
    tld = parts[1].split('/')[0]  # 取路径前的部分
    if len(tld) < 2 or not any(c.isalpha() for c in tld):
        return False

    return True


def data_clean(base_url: str, dirty_data) -> list:
    """
    智能清洗URL数据，正确区分域名和路径

    :param base_url: 基础URL（用于相对路径解析）
    :param dirty_data: 待清洗的URL列表
    :return: 清洗后的完整URL列表
    """
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
        if not main_url:
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


def check_url(original_url,splicing_url):
    """check the url,and it is a blacklist of url"""
    urlparse2 = urlparse(splicing_url)

    if urlparse2.path.endswith(('.png', '.jpg', '.jpeg','.ico','.mp4','.mp3','.gif','ttf','.css','.svg','.m4v','.aac','.woff','.woff2','.ttf','.eot','.otf','.apk','.exe','.swf')):
        return False


    if (get_root_domain(original_url) == get_root_domain(splicing_url)) or (get_root_domain(splicing_url) in whiteList):
        return True
    else:
        return False


def get_root_domain(url):
    """
    get root domain
    """

    parsed_url = urlparse(url)
    full_domain = parsed_url.netloc
    extracted = tldextract.extract(full_domain)
    root_domain = f"{extracted.domain}.{extracted.suffix}"
    return root_domain

def is_js_file(url):
    js_pattern = re.compile(r'\.js(?=[^a-zA-Z]|$)')  # 关键规则
    json_pattern = re.compile(r'\.json')
    return not json_pattern.search(url) and bool(js_pattern.search(url))


def extract_pure_js(html_content):
    """从包含HTML标签的内容中提取<pre>标签内的JS代码"""
    # 解析HTML内容
    soup = BeautifulSoup(html_content, 'html.parser')

    # 精准匹配带有特定style的<pre>标签（根据你的响应结构定制）
    pre_tag = soup.find(
        'pre',
        style="word-wrap: break-word; white-space: pre-wrap;"
    )

    if pre_tag:
        # 提取标签内文本并去除首尾空白
        js_code = pre_tag.get_text().strip()
        return js_code
    else:
        # 如果未找到目标标签，尝试查找第一个<pre>标签作为备选
        fallback_pre = soup.find('pre')
        if fallback_pre:
            return fallback_pre.get_text().strip()
        else:
            raise ValueError("未在响应中找到包含JS代码的<pre>标签")
