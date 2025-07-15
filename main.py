import json
import time
import os
import threading
from urllib.parse import urlparse
from DrissionPage import ChromiumOptions, ChromiumPage, WebPage
from colorama import init, Fore
from user_agent import generate_user_agent

from filerw import write2json, clear_or_create_file, generate_path_excel
from httpHandler.httpSend import get_source  # 后续需同步优化此模块
from jsHandler.pathScan import analysis_by_rex, data_clean, read, get_root_domain, extract_js_api_params
from jsHandler.sensitiveInfoScan import find_all_info_by_rex
from parse_args import parse_args


class Scanner:
    def __init__(self, args):
        # 初始化配置
        self.args = args
        self.visited_urls = set()
        self.hashed_source_codes = set()
        self.read_url_from_file = []
        # 线程锁（解决多线程资源竞争）
        self.url_lock = threading.Lock()
        self.hash_lock = threading.Lock()
        # 初始化浏览器
        self.browser = self._init_browser()


    def _init_browser(self):
        """初始化浏览器配置，优化稳定性"""
        co = (ChromiumOptions()
              .auto_port()  # 自动选择端口，避免冲突
              .ignore_certificate_errors()  # 忽略证书错误
              .no_imgs()  # 禁止加载图片，提升速度
              .headless(not self.args.visible)  # 控制无头模式
              .set_user_agent(generate_user_agent())  # 随机UA
              )

        # 配置代理
        if self.args.proxy:
            co.set_proxy(self.args.proxy)

        # 配置下载
        co.set_download_path("./download_file")
        # co.set_download_policy('skip')  # 同名文件跳过

        # 创建浏览器实例（使用WebPage更灵活）
        browser = WebPage(chromium_options=co)
        # 自动处理弹窗
        browser.set.auto_handle_alert(True, accept=False)
        return browser


    def is_valid_url(self, url):
        """线程安全的URL有效性检查"""
        with self.url_lock:
            if url in self.visited_urls:
                return False
            parsed_url = urlparse(url)
            target_root = get_root_domain(self.read_url_from_file[0]) if self.read_url_from_file else ""
            return parsed_url.netloc.endswith(target_root)


    def add_visited_url(self, url):
        """线程安全地添加已访问URL"""
        with self.url_lock:
            self.visited_urls.add(url)


    def check_and_add_hash(self, source):
        """线程安全地检查并添加源码哈希"""
        # 使用MD5替代内置hash，避免哈希值不稳定
        import hashlib
        source_hash = hashlib.md5(source[:400].encode()).hexdigest()
        with self.hash_lock:
            if source_hash in self.hashed_source_codes:
                return False
            self.hashed_source_codes.add(source_hash)
        return True


    def scan(self, urls, depth):
        """迭代替代递归，避免栈溢出"""
        stack = [(urls, depth)]
        while stack:
            current_urls, current_depth = stack.pop()
            if current_depth > self.args.height:
                continue

            # 生成请求头
            header = {"User-Agent": generate_user_agent()}

            try:
                # 获取页面源码（后续需优化get_source使其线程安全）
                source_code_list = get_source(
                    self.browser,
                    current_urls,
                    header,
                    self.args.thread_num
                )
                next_urls = set()

                for url_info in source_code_list:
                    if len(url_info) < 3:
                        continue
                    url, page_html, status = url_info[0], url_info[1], url_info[2]

                    # 检查URL有效性
                    if not self.is_valid_url(url):
                        continue

                    # 过滤错误状态码
                    if status and status >= 404:
                        continue

                    # 过滤过短源码
                    if not page_html or len(page_html) < 300:
                        print(f"{Fore.YELLOW}跳过短内容URL: {url}{Fore.RESET}")
                        continue

                    # 检查源码哈希
                    if not self.check_and_add_hash(page_html):
                        print(f"{Fore.YELLOW}跳过重复URL: {url}{Fore.RESET}")
                        continue

                    # 标记为已访问
                    self.add_visited_url(url)

                    # 处理JS文件和初始URL
                    if ".js" in url or url in self.read_url_from_file:
                        dirty_data = analysis_by_rex(page_html)
                        import_info = find_all_info_by_rex(page_html)
                        clean_data = data_clean(url, dirty_data)

                        # 写入敏感信息
                        write2json("./result/sensitiveInfo.json", json.dumps({
                            "url": url,
                            "sensitive_info": import_info
                        }))
                        print(f"{Fore.RED}url:{url}\n\tsensitive_info:{import_info}{Fore.RESET}\n")

                        if clean_data:
                            next_urls.update(clean_data)

                # 将下一层URL加入栈（迭代替代递归）
                if next_urls:
                    stack.append((next_urls, current_depth + 1))

            except Exception as e:
                print(f"{Fore.RED}扫描出错: {str(e)}{Fore.RESET}")
                # 出错时尝试重启浏览器恢复
                self.browser.quit()
                self.browser = self._init_browser()


    def run(self):
        """主运行逻辑"""
        # 初始化文件
        os.makedirs("./result", exist_ok=True)
        clear_or_create_file("./result/scanInfo.json")
        clear_or_create_file("./result/sensitiveInfo.json")

        # 读取目标URL
        if self.args.batch:
            self.read_url_from_file = read(self.args.batch)
            if not self.read_url_from_file:
                print(f"{Fore.RED}批量文件为空或读取失败{Fore.RESET}")
                return
        else:
            if not self.args.url:
                print(f"{Fore.RED}请指定URL或批量文件{Fore.RESET}")
                return
            self.read_url_from_file = [self.args.url]

        # 开始扫描
        start_time = time.time()
        for url in self.read_url_from_file:
            # print(f"{Fore.GREEN}开始扫描: {url}{Fore.RESET}")
            self.scan([url], 0)

        # 清理资源
        self.browser.quit()

        # 导出Excel
        if self.args.excel:
            generate_path_excel("./result/scanInfo.json", self.args.excel)
            print(f"{Fore.GREEN}结果已导出到: {self.args.excel}{Fore.RESET}")

        # 输出耗时
        end_time = time.time()
        print(f"{Fore.CYAN}总耗时: {end_time - start_time:.2f}秒{Fore.RESET}")


if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()
    scanner = Scanner(args)
    scanner.run()