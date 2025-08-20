import os
import re
from urllib.parse import urlparse

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


def data_clean(url, dirty_data)->list:
    """
    dirty data come from request url
    """
    return_url_list = []
    for main_url in dirty_data:
        # 解析输入的url，主要是用来完整的URL的拼接
        handled_url = urlparse(url)
        # 解析http、https协议
        Protocol = handled_url.scheme
        # 解析出域名
        Domain = handled_url.hostname
        # 解析出路径
        Path = handled_url.path

        if main_url.startswith('/'):
            # 处理以斜杠开头的相对路径
            if main_url.startswith('//'):
                return_url = Protocol + ':' + main_url
            else:  # 此时也就是 / 开头的
                return_url = Protocol + '://' + Domain + main_url
        elif main_url.startswith('./'):
            # 处理以./开头的相对路径
            return_url = Protocol + '://' + Domain + main_url[2:]
        elif main_url.startswith('../'):
            # 处理以../开头的相对路径
            return_url = Protocol + '://' + Domain + os.path.normpath(os.path.join(Path, main_url))
        elif main_url.startswith('http') or main_url.startswith('https'):
            # 处理以http或https开头的绝对路径
            return_url = main_url
        else:
            # 处理其他情况
            return_url = Protocol + '://' + Domain + '/' + main_url

        if check_url(original_url=url,splicing_url=return_url):
            return_url_list.append(return_url)

    return return_url_list


def check_url(original_url,splicing_url):
    """check the url,and it is a blacklist of url"""
    urlparse2 = urlparse(splicing_url)

    if urlparse2.path.endswith(('.png', '.jpg', '.jpeg','.ico','.mp4','.mp3','.gif','ttf','.css','.svg','.m4v','.aac','.woff','.woff2','.ttf','.eot','.otf','.apk','.exe')):
        return False

    if "jquery" in urlparse2.path:
        return False

    if "update" in urlparse2.path:
         return False

    if "delete" in urlparse2.path:
         return False

    if "add" in urlparse2.path:
         return False

    if "test" in urlparse2.netloc:
         return False

    if "pre" in urlparse2.netloc:
         return False

    if "dev" in urlparse2.netloc:
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
