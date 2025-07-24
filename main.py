import asyncio
import json
import os
import time

from colorama import init, Fore

from HttpHandle.DuplicateChecker import DuplicateChecker
from HttpHandle.httpSend import get_source_async
from JsHandle.pathScan import get_root_domain
from filerw import write2json, clear_or_create_file, generate_path_excel
from parse_args import parse_args
from JsHandle.sensitiveInfoScan import find_all_info_by_rex


# Scanner类核心修改
class Scanner:
    def __init__(self, args):
        self.args = args
        self.initial_urls = []  # 初始URL
        self.checker = None  # 去重管理器（后续初始化）


    def run(self):
        """主运行逻辑"""
        # 初始化结果目录
        os.makedirs("./result", exist_ok=True)
        clear_or_create_file("./result/scanInfo.json")
        clear_or_create_file("./result/sensitiveInfo.json")

        # 读取初始URL
        self.initial_urls = self._load_initial_urls()
        if not self.initial_urls:
            print(f"{Fore.RED}未找到初始URL{Fore.RESET}")
            return

        # 初始化去重管理器（传入目标根域名）
        target_root = get_root_domain(self.initial_urls[0])
        self.checker = DuplicateChecker(initial_root_domain=target_root)
        self.args.initial_urls = self.initial_urls  # 传递初始URL到args，供后续使用

        # 开始扫描
        start_time = time.time()
        self._scan_recursive(self.initial_urls, 0)

        # 导出结果
        if self.args.excel:
            generate_path_excel("./result/scanInfo.json", self.args.excel)
        print(f"{Fore.CYAN}总耗时: {time.time() - start_time:.2f}秒{Fore.RESET}")


    def _scan_recursive(self, urls, depth):
        """递归扫描（按深度迭代）"""
        if depth > self.args.height:
            return

        # 异步请求+去重处理
        scan_info_list, next_urls = asyncio.run(
            get_source_async(
                urls=urls,
                thread_num=self.args.thread_num,
                args=self.args,
                checker=self.checker  # 传递去重管理器
            )
        )

        # 提取敏感信息（单独处理，与请求逻辑解耦）
        self._extract_sensitive_info(scan_info_list)

        # 扫描下一层
        if next_urls:
            self._scan_recursive(next_urls, depth + 1)


    def _extract_sensitive_info(self, scan_info_list):
        """提取敏感信息（从有效扫描结果中）"""
        for scan_info in scan_info_list:
            url = scan_info["url"]
            source = scan_info["source_code"]
            if ".js" in url or url in self.initial_urls:

                sensitive_info = find_all_info_by_rex(source)
                write2json(
                    "./result/sensitiveInfo.json",
                    json.dumps({"url": url, "sensitive_info": sensitive_info})
                )
                print(f"{Fore.RED}URL: {url}\n\t敏感信息: {sensitive_info}{Fore.RESET}")


    def _load_initial_urls(self):
        """加载初始URL（从批量文件或参数）"""
        if self.args.batch:
            from JsHandle.pathScan import read
            return read(self.args.batch) or []
        elif self.args.url:
            return [self.args.url]
        return []

if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()
    scanner = Scanner(args)
    scanner.run()