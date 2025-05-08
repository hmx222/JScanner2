import json
import time
from urllib.parse import urlparse

from DrissionPage._configs.chromium_options import ChromiumOptions
from DrissionPage._pages.chromium_page import ChromiumPage
from colorama import init, Fore
from user_agent import generate_user_agent

from filerw import write2json, clear_or_create_file, generate_path_excel
from httpHandler.httpSend import get_source
from jsHandler.pathScan import analysis_by_rex, data_clean, read, get_root_domain
from jsHandler.sensitiveInfoScan import find_all_info_by_rex
from parse_args import parse_args


def is_valid_url(url):
    """
    检查URL是否有效（属于目标域名且未访问过）
    """

    if url in visited_urls:
        return False
    parsed_url = urlparse(url)
    return parsed_url.netloc.endswith(get_root_domain(url))


def main(_page, urls, depth):
    global read_url_from_file
    global visited_urls
    global hashed_source_codes

    depth += 1

    if depth > args.height:
        return

    header = {
        "User-Agent": generate_user_agent()
    }

    try:
        source_code_list = get_source(_page, urls, header, args.thread_num)
        tem_set = set()

        for url_info in source_code_list:

            # 检查URL是否有效
            if not is_valid_url(url_info[0]):
                continue

            if url_info[2] >= 404:
                continue

            # 为了减少正则表达式重复匹配，此处计算源代码的哈希值
            source_hash = hash(url_info[1])
            # 检查是否已经处理过这个URL
            if source_hash in hashed_source_codes:
                continue

            # 将当前URL标记为已访问
            visited_urls.add(url_info[0])

            if ".js" in url_info[0] or url_info[0] in read_url_from_file:
                dirty_data = analysis_by_rex(url_info[1])
                import_info = find_all_info_by_rex(url_info[1])
                clean_data = data_clean(url_info[0], dirty_data)

                write2json("./result/sensitiveInfo.json", json.dumps({
                "url": url_info[0],
                "sensitive_info": import_info
                }))

                print(Fore.RED + f"url:{url_info[0]}\n\tsensitive_info:{import_info}" + Fore.RESET)
                print('\n')

                if clean_data is None:
                    continue

                tem_set.update(clean_data)

        main(_page, tem_set, depth)
    except Exception as e:
        pass


if __name__ == '__main__':
    # init colorama，
    init()

    # get user args
    args = parse_args()

    # 初始化浏览器
    co = (ChromiumOptions()
          .auto_port()
          .ignore_certificate_errors()
          .no_imgs()
          .headless(False))

    # co.set_proxy(args.proxy)

    # init page
    page = ChromiumPage(co)

    # 自动取消弹窗
    page.set.auto_handle_alert(on_off=True, accept=False)

    # 全局已访问URL集合，用于避免重复爬取
    visited_urls = set()

    # 创建文件并清空内容，scanInfo.json和sensitiveInfo.json
    clear_or_create_file("./result/scanInfo.json")
    clear_or_create_file("./result/sensitiveInfo.json")

    # read url info
    if args.batch:
        read_url_from_file = read(args.batch)

    else:
        read_url_from_file = [args.url]

    start = time.time()

    for urls in read_url_from_file:
        main(page,[urls],0)

    page.close()

    if args.excel:
        generate_path_excel("./result/scanInfo.json",args.excel)

    end = time.time()
    print(f"耗时：{end - start}")