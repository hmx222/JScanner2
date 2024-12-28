import os
import re
from urllib.parse import urlparse

from tldextract import tldextract

from httpHandler.httpSend import send_http
from httpHandler.responseHandler import status


def analysis_by_rex(source)->list:
    """从网页源代码当中进行提取url，并且完成对URL的处理"""

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
    使用ollama进行url的提取
    :param source:
    :return: 未处理的url列表
    """


def data_clean(url,data_list)->list:
    """
    数据清洗，将url和data进行清洗，返回一个列表
    :param url:
    :param data_list:
    :return:
    """
    # 解析传入的url，主要是用作最后与处理后的url的域名的对比，防止误伤
    extracted = tldextract.extract(url)
    # 拼接出用于判断的url main_domain
    main_domain = extracted.domain + '.' + extracted.suffix
    return_url_list = []
    for main_url in data_list:
        # 解析输入的url，主要是用来完整的URL的拼接
        handled_url = urlparse(url)
        # 解析http、https协议
        Protocol = handled_url.scheme
        # 解析出域名
        Domain = handled_url.netloc
        # 解析出路径
        Path = handled_url.path

        if Path.endswith(('.png', '.jpg', '.jpeg','.ico','.mp4','.mp3','.gif','.css')):
            continue
        if "jquery" in Path:
            continue

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

        # 解析url获取子域名
        extracted1 = tldextract.extract(return_url)
        # 拼接出用于判断的 main_domain1
        main_domain1 = extracted1.domain + '.' + extracted1.suffix

        if main_domain == main_domain1:
            # 如果上述二者相同，则说明为正常资产，否则为无数
            return_url_list.append(return_url)
    return return_url_list

def height_scan(urls, method, header, high):
    """深度查找"""
    return_murl_list = []
    for num in range(high):
        for url in urls:
            response_object = send_http(url, method, header)
            response_body = response_object.text
            # object = url_request(i, header=header, wait_time=wait_time)
            if status(object) == 200:
                urlResult = data_clean(url,analysis_by_rex(response_body))
                return_murl_list.extend(urlResult)
        urls = []
        urls.extend(return_murl_list)
    return return_murl_list