import asyncio
import json
import os
import time
from colorama import init, Fore

# from AI.Get_API import run_analysis
from FileIO.Excelrw import SafePathExcelGenerator
from HttpHandle.DuplicateChecker import DuplicateChecker
from HttpHandle.httpSend import get_source_async, fail_url
from JsHandle.pathScan import get_root_domain
from FileIO.filerw import write2json, clear_or_create_file, read
from parse_args import parse_args
from JsHandle.sensitiveInfoScan import find_all_info_by_rex


class Scanner:
    def __init__(self, args):
        self.args = args
        self.initial_urls = []  # 初始URL
        self.checker = None  # 去重管理器（后续初始化）
        self.tmp_urls = set()  # 临时URL列表


    def run(self):
        """主运行逻辑"""
        os.makedirs("./result", exist_ok=True)
        clear_or_create_file("./result/scanInfo.json")
        clear_or_create_file("./result/sensitiveInfo.json")

        self.initial_urls = self._load_initial_urls()
        if not self.initial_urls and not self.args.url:
            print(f"{Fore.RED}未找到初始URL{Fore.RESET}")
            return

        self.checker = DuplicateChecker(initial_root_domain=self.initial_urls)
        # 主要是在httpsend模块使用
        self.args.initial_urls = self.initial_urls

        # 开始扫描
        start_time = time.time()
        self._scan_recursive(self.load_url(self.args), 0)

        print(f"{Fore.CYAN}总耗时: {time.time() - start_time:.2f}秒{Fore.RESET}")


    def _scan_recursive(self, urls, depth):
        """递归扫描（按深度迭代）"""
        if depth > self.args.height:
            return

        unprocessed_scan_info_list, scan_info_list, next_urls = asyncio.run(
            get_source_async(
                urls=urls,
                thread_num=self.args.thread_num,
                args=self.args,
                checker=self.checker
            )
        )

        next_urls = next_urls - self.tmp_urls
        if next_urls:
            self.tmp_urls |= next_urls

        for i in next_urls:
            print(f"{Fore.BLUE}next_urls:{i}{Fore.RESET}")
        print("\n")

        # 默认不进行API扫描，data_source = next_urls
        data_source = next_urls if not args.api else unprocessed_scan_info_list
        excel_handler.append_data(data_source)

        if not args.api:
            next_urls = [url for url in next_urls if ".js" in url]

        if args.sensitiveInfo:
            self._extract_sensitive_info(scan_info_list)

        if next_urls:
            self._scan_recursive(next_urls, depth + 1)

    def _extract_sensitive_info(self, scan_info_list):
        """提取敏感信息（从有效扫描结果中）"""
        for scan_info in scan_info_list:
            url = scan_info["url"]
            if scan_info["is_valid"] == 1 or url in self.initial_urls:

                sensitive_info = find_all_info_by_rex(scan_info["source_code"])
                if len(sensitive_info) == 0:
                    continue
                write2json(
                    "./result/sensitiveInfo.json",
                    json.dumps({"url": url, "sensitive_info": sensitive_info})
                )
                print(f"{Fore.RED}URL: {url}\n\t敏感信息: {sensitive_info}{Fore.RESET}")

    def load_url(self,args):
        if args.url is not None:
            return [args.url]
        if args.batch is not None:
            return read(args.batch)
        return []

    def _load_initial_urls(self):
        """加载初始URL（从批量文件或参数）"""
        if self.args.batch:
            from JsHandle.pathScan import read
            domains = read("./config/whiteList")
            if len(domains) == 0:
                domains = [get_root_domain(url) for url in read(self.args.batch)]
            return domains
        elif self.args.url:
            return [get_root_domain(self.args.url)]
        return []

if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()
    excel_handler = SafePathExcelGenerator('./result/result.xlsx')
    scanner = Scanner(args)
    scanner.run()
    print("请求失败的url：",str(fail_url))
