import json
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from DrissionPage._pages.chromium_page import ChromiumPage
from colorama import Fore
from urllib3.exceptions import InsecureRequestWarning

from filerw import write2json
from httpHandler.responseHandler import get_webpage_title


# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 标签页队列，用于管理标签页
tab_queue = queue.Queue()

def get_source(page: ChromiumPage, urls, headers, thread_num):
    """
    获取多个 URL 的页面源码及相关信息
    """

    def fetch_page(url):
        try:

            # 新建标签页
            tab = page.new_tab()

            tab.set.headers(headers)

            # tab.set.cert_errors(accept=True)
            tab.get(url, timeout=5)

            # 取消弹窗
            tab.handle_alert(False)

            # 如果遇到证书错误页面，强制继续访问
            if '证书' in tab.title or '私密连接' in tab.title:
                tab.ele('text:继续访问').click()

            tab.wait.doc_loaded(timeout=2)

            # 设置下载路径
            tab.set.download_path("./download_file")
            # 设置同名文件取消下载
            tab.set.when_download_file_exists('skip')

            # 设置对于弹窗的处理
            tab.set.auto_handle_alert(on_off=True,accept=False)

            # 暂时使用了requests库，后续考虑使用DrissionPage的方法
            response = requests.get(url, timeout=3,verify=False)

            # 处理页面源码
            html = tab.html

            # 为了减少正则表达式的压力，html长度小于200，直接进行返回
            if len(html) < 300:
                raise Exception("html length is too short")

            # tab_queue.put(tab)
            return html, url, response.status_code
        except Exception as e:
            page.stop_loading()
            return None, url, None

        finally:
            # 关闭标签页
            threading.Thread(target=tab.close).start()


    # 使用 ThreadPoolExecutor 并行化处理
    with ThreadPoolExecutor(max_workers=thread_num, thread_name_prefix="TabThread") as executor:
        results = list(executor.map(fetch_page, urls))

    # 处理返回结果
    url_source_code = []
    scan_info_list = []
    for page_html, url, status in results:
        if page_html is None:
            continue
        url_source_code.append((url, page_html, status))
        parsed_url = urlparse(url)
        scan_info = {
            "domain": parsed_url.hostname,
            "url": url,
            "path": parsed_url.path,
            "port": parsed_url.port,
            "status": status,
            "title": get_webpage_title(page_html),
            "length": len(page_html)
        }
        scan_info_list.append(scan_info)

    # 输出并保存扫描信息
    for url, page_html, status in url_source_code:
        print(Fore.BLUE + f"url:{url}\n\tstatus:{status}\n\ttitle:{get_webpage_title(page_html)}\n\tlength:{len(page_html)}" + Fore.RESET)
        print('\n')

    # 批量保存信息到 JSON
    if scan_info_list:
        write2json("./result/scanInfo.json", json.dumps(scan_info_list))

    # 返回 URL 和源码列表
    return url_source_code
