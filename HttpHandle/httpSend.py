import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from DrissionPage import ChromiumPage
from colorama import Fore
from tqdm import tqdm  # 导入tqdm库用于进度条显示
from urllib3.exceptions import InsecureRequestWarning

from HttpHandle.responseHandler import get_webpage_title
from JsHandle.pathScan import extract_js_api_params
from filerw import write2json


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_source(browser: ChromiumPage, urls, headers, thread_num, args):
    """线程安全的页面源码获取"""
    # 创建一个线程安全的锁，用于更新进度条
    progress_lock = threading.Lock()
    progress_bar = tqdm(total=len(urls), desc="请求进度", unit="url", ncols=100)

    # 每个线程使用独立的标签页
    def fetch_page(url):
        tab = None
        try:
            # 新建标签页（线程内独立）
            tab = browser.new_tab()
            tab.set.headers(headers)
            tab.get(url, timeout=5)

            # 处理证书错误
            if '证书' in tab.title or '私密连接' in tab.title:
                tab.ele('text:继续访问').click()
            tab.wait.doc_loaded(timeout=2)

            # 暂时使用了requests库，后续考虑使用DrissionPage的方法
            response = requests.head(url, timeout=3, verify=False,proxies={"http":args.proxy,"https":args.proxy})

            # 获取源码和状态码
            html = tab.html


            if "<input" in html:
                # print(f"我们在{url}发现了一个input标签")
                pass


            status = response.status_code if response else None
            if not status:
                status = requests.get(url, timeout=3, verify=False).status_code
            return html, url, status

        except Exception as e:
            # print(f"{Fore.RED}获取 {url} 失败: {str(e)}{Fore.RESET}")
            return None, url, None

        finally:
            # 确保标签页关闭（线程安全）
            if tab:
                try:
                    tab.close()
                except:
                    pass
            # 更新进度条（线程安全）
            with progress_lock:
                progress_bar.update(1)

    # 线程池控制（限制并发）
    with ThreadPoolExecutor(max_workers=thread_num) as executor:
        results = list(executor.map(fetch_page, urls))

    # 关闭进度条
    progress_bar.close()

    # 处理结果
    scan_info_list = []
    for html, url, status in results:
        if not html:
            continue

        js_params = extract_js_api_params(html)
        parsed = urlparse(url)
        scan_info = {
            "domain": parsed.hostname,
            "url": url,
            "path": parsed.path,
            "port": parsed.port or (443 if parsed.scheme == 'https' else 80),
            "status": status,
            "title": get_webpage_title(html),
            "length": len(html),
            "params": list(js_params.values())
        }
        write2json("./result/scanInfo.json", json.dumps(scan_info))

        # 加入源代码返回
        scan_info["source_code"] = html
        scan_info_list.append(scan_info)

    for scan_info_ in scan_info_list:
        print(f"{Fore.BLUE}url:{scan_info_['url']}\n\tstatus:{scan_info_['status']}\n\ttitle:{scan_info_['title']}{Fore.RESET}\n\tlength:{scan_info_['length']}\n\tparams:{scan_info_['params']}\n")

    return scan_info_list