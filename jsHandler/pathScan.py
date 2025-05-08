import os
import re
from urllib.parse import urlparse

from tldextract import tldextract

from filerw import read

# load whiteList
whiteList = read("./config/whiteList")


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

def analysis_by_ollama(source)->list:
    """
    wait developer graduated from university, we will use ollama to analysis the source code
    """


def data_clean(url, dirty_data)->list:
    """
    data clean
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

    if urlparse2.path.endswith(('.png', '.jpg', '.jpeg','.ico','.mp4','.mp3','.gif','ttf','.css','.svg','.m4v','.aac','.woff','.woff2','.ttf','.eot','.otf','.apk')):
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