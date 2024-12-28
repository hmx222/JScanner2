from typing import Union

import chardet
from bs4 import BeautifulSoup


def charset_setting(requests)->str:
    """
    调整合适的网站编码
    :param requests:
    :return: 返回根据网页编码调整的网页源码
    """
    # 使用 BeautifulSoup 解析 HTML
    html_str = requests.content
    # 处理编码问题
    charset = chardet.detect(html_str)['encoding']
    html = html_str.decode(charset)

    return html


def get_title(requests)->str:
    """
    提取网页标题
    :param requests:
    :return: 网页标题
    """
    encoding_html = charset_setting(requests)
    # 解析 HTML 内容并获取网站标题
    soup = BeautifulSoup(encoding_html, 'html.parser')
    # 获取网页标题
    try:
        title_str = soup.title.string
    # 返回网页标题
    except:
        return "NULL"
    else:
        return title_str

def status(requests)->str:
    """变更为对状态码的提取"""
    try:
        status_code = requests.status_code
    except:
        return "NULL"
    else:
        return status_code


def return_length(requests)-> Union[str, int]:
    """返回值长度"""
    try:
        return_length = requests.text
    except:
        return "NULL"
    else:
        return len(return_length)

