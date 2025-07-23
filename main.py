import json
import os
import re
import threading
import time
import traceback
from urllib.parse import urlparse

from DrissionPage import ChromiumOptions, WebPage
from colorama import init, Fore
from user_agent import generate_user_agent

from HttpHandle.httpSend import get_source  # 后续需同步优化此模块
from JsHandle.Similarity_HTML import compare_html_similarity, similarity, get_simhash
from JsHandle.pathScan import analysis_by_rex, data_clean, read, get_root_domain
from JsHandle.sensitiveInfoScan import find_all_info_by_rex
from filerw import write2json, clear_or_create_file, generate_path_excel
from parse_args import parse_args


class Scanner:
    def __init__(self, args):
        # 初始化配置
        self.args = args
        self.visited_urls = set()
        self.hashed_source_codes = set()
        self.simhash_dict = dict()
        self.title_visited_urls = dict()
        self.read_url_from_file = []
        self.length_visited_urls = dict()
        # 线程锁（解决多线程资源竞争）
        self.url_lock = threading.Lock()
        self.hash_lock = threading.Lock()
        self.simhash_lock = threading.Lock()
        self.title_lock = threading.Lock()
        self.length_lock = threading.Lock()
        # 初始化浏览器
        self.browser = self._init_browser()


    def _init_browser(self):
        """初始化浏览器配置，优化稳定性"""
        co = (ChromiumOptions()
              .auto_port()
              .headless(not self.args.visible)  # 控制无头模式
              .set_argument('--blink-settings=imagesEnabled=false,stylesheetEnabled=false,fontEnabled=false')
              .set_argument('--disable-gpu')
              .set_argument('--disable-software-rasterizer')
              .set_argument('--disable-notifications')
              .set_argument('--disable-popup-blocking')
              .set_argument("--ignore-certificate-errors")
              # .set_argument("--blink-settings=stylesheetEnabled=false")
              # .set_argument("--blink-settings=imagesEnabled=false")
              # .set_argument("--blink-settings=fontEnabled=false")
              # .set_user_agent(generate_user_agent())  # 随机UA
              # .ignore_certificate_errors()  # 忽略证书错误
              # .no_imgs(True)  # 禁止加载图片，提升速度
              )

        # 配置代理
        if self.args.proxy:
            co.set_proxy(self.args.proxy)

        # 配置下载
        co.set_download_path("./download_file")

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

    def check_and_add_title(self, title, url):
        """线程安全地检查并添加标题，且标题一样的前提是域名一样"""
        if title is None or title == "" or title == " ":
            return True

        parsed_url = urlparse(url)
        current_domain = parsed_url.netloc

        with self.url_lock:  # 使用url_lock保证visited_urls遍历安全
            # 检查同域名URL时需要先获取锁
            same_domain_urls = [
                d_url for d_url in self.visited_urls
                if urlparse(d_url).netloc == current_domain
            ]

        # 仅在发现同域名URL时检查标题重复
        if same_domain_urls:
            with self.hash_lock:  # 复用hash_lock保证标题集合操作安全
                if title in self.title_visited_urls:
                    # print("跳过重复URL: ", url, " 标题: ", title, " 原因: 标题重复")
                    return False
                self.title_visited_urls.add(title)
        else:
            with self.hash_lock:
                self.title_visited_urls.add(title)

        return True



    def scan(self, urls, depth):
        stack = [(urls, depth)]
        while stack:
            current_urls, current_depth = stack.pop()
            if current_depth > self.args.height:
                continue

            # 生成请求头
            header = {"User-Agent": generate_user_agent()}

            try:
                # 获取页面源码
                source_code_dict = get_source(
                    self.browser,
                    current_urls,
                    header,
                    self.args.thread_num,
                    self.args
                )
                next_urls = set()

                for scan_info in source_code_dict:
                    # if len(url_info) < 3:
                    #     continue

                    # 检查URL有效性
                    if not self.is_valid_url(scan_info['url']):
                        continue

                    # 过滤错误状态码
                    if scan_info['status'] and scan_info['status'] >= 404:
                        continue

                    # 过滤过短源码
                    if not scan_info['source_code'] or scan_info['length'] < 300:
                        # print(f"{Fore.YELLOW}跳过短内容URL: {url}{Fore.RESET}")
                        continue

                    if scan_info['source_code'].lower().startswith("<!doctype html>"):

                        if args.de_duplication_hash:
                            # 检查源码哈希
                            if not self.check_and_add_hash(scan_info['source_code']):
                                # print(f"{Fore.YELLOW}跳过重复URL: {url}{Fore.RESET}")
                                continue

                        if args.de_duplication_title:
                            # 检擦标题去重也要考虑域名，像simhash一样
                            with self.title_lock:
                                # 初始化域名对应的集合
                                if scan_info['domain'] not in self.title_visited_urls:
                                    self.title_visited_urls[scan_info['domain']] = set()
                                # 检查相似度前先检查是否重复
                                if scan_info['title'] in self.title_visited_urls[scan_info['domain']]:
                                    # print(f"{Fore.YELLOW}跳过重复URL: {url}{Fore.RESET}")
                                    continue
                                # 添加新标题
                                self.title_visited_urls[scan_info['domain']].add(scan_info['title'])


                        # 按照返回值长度进行去重
                        if args.de_duplication_length:
                            # 检查源码长度
                            with self.length_lock:
                                # 初始化域名对应的集合
                                if scan_info['domain'] not in self.length_visited_urls:
                                    self.length_visited_urls[scan_info['domain']] = set()
                                # 检查相似度前先检查是否重复
                                if scan_info['length'] in self.length_visited_urls[scan_info['domain']]:
                                    # print(f"{Fore.YELLOW}跳过重复URL: {url}{Fore.RESET}")
                                    continue
                                # 添加新长度
                                self.length_visited_urls[scan_info['domain']].add(scan_info['length'])

                        # 按照simhash进行去重
                        if args.de_duplication_similarity:
                            # 判断是不是html页面，非JavaScript页面
                            if scan_info['source_code'].startswith("<!DOCTYPE html>"):
                                # 计算simhash
                                simhash = get_simhash(scan_info['source_code'])

                                with self.hash_lock:
                                    # 初始化域名对应的集合
                                    if scan_info['domain'] not in self.simhash_dict:
                                        self.simhash_dict[scan_info['domain']] = set()

                                    # 检查相似度前先检查是否重复
                                    if any(similarity(simhash, h) > float(args.de_duplication_similarity)
                                          for h in self.simhash_dict[scan_info['domain']]):
                                        print(f"{Fore.YELLOW}跳过重复URL: {scan_info['url']}{Fore.RESET}")
                                        continue

                                    # 添加新simhash
                                    self.simhash_dict[scan_info['domain']].add(simhash)

                    # 标记为已访问
                    self.add_visited_url(scan_info['url'])

                    # 处理JS文件和初始URL
                    if ".js" in scan_info['url'] or scan_info['url'] in self.read_url_from_file:
                        dirty_data = analysis_by_rex(scan_info['source_code'])
                        # import_info = find_all_info_by_rex(scan_info['source_code'])
                        clean_data = data_clean(scan_info['url'], dirty_data)
                        if ".js" in scan_info['url']:
                            import_info = find_all_info_by_rex(scan_info['source_code'])
                        else:
                            import_info = []

                        # 写入敏感信息
                        write2json("./result/sensitiveInfo.json", json.dumps({
                            "url": scan_info['url'],
                            "sensitive_info": import_info
                        }))
                        print(f"{Fore.RED}url:{scan_info['url']}\n\tsensitive_info:{import_info}{Fore.RESET}\n")

                        if clean_data:
                            next_urls.update(clean_data)

                # 将下一层URL加入栈（迭代替代递归）
                if next_urls:
                    stack.append((next_urls, current_depth + 1))

            except Exception as e:
                print(f"{Fore.RED}扫描出错: {str(e)}{Fore.RESET}")
                stack_trace = traceback.format_exc()
                print(stack_trace)
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