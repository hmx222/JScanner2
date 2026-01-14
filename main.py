import asyncio
import json
import os
import time
import warnings

import requests
from tqdm import tqdm

from AI.SenInfo import qwen_scan_js_code

warnings.filterwarnings("ignore")
from colorama import init
from rich import print as rich_print
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
        self.initial_urls = []  # 初始URL根域（白名单+传入URL根域）
        self.checker = None  # 去重管理器（后续初始化）
        self.tmp_urls = set()  # 临时URL列表
        self.whiteList = read("./config/whiteList")  # 保留原白名单读取，未改动

    def run(self):
        """主运行逻辑"""
        os.makedirs("Result", exist_ok=True)
        clear_or_create_file("Result/sensitiveInfo.json")

        self.initial_urls = self._load_initial_urls()
        scan_seed_urls = self.load_url(self.args)

        if not scan_seed_urls:
            rich_print("[red]未传入要扫描的初始URL，请指定--url参数[/red]")
            return

        self.checker = DuplicateChecker(initial_root_domain=self.initial_urls)
        # 主要是在httpsend模块使用
        self.args.initial_urls = self.initial_urls

        # 开始扫描
        start_time = time.time()
        self._scan_recursive(self.load_url(self.args), 0)

        rich_print(f"[cyan]总耗时: {time.time() - start_time:.2f}秒[/cyan]")

    def load_url(self, args):
        if args.url and args.url.strip():
            return [args.url.strip()]
        return []

    def _load_initial_urls(self):
        # 第一步：强制加载白名单，无条件必加载
        white_list_domains = read("./config/whiteList")
        # 第二步：如果传入了扫描URL，解析根域名并追加
        if self.args.url and self.args.url.strip():
            try:
                seed_root_domain = get_root_domain(self.args.url.strip())
                if seed_root_domain and seed_root_domain not in white_list_domains:
                    white_list_domains.append(seed_root_domain)
            except Exception:
                pass
        # 去重+过滤空字符串，返回最终校验用的根域名列表
        return list(set(filter(None, white_list_domains)))

    def _scan_recursive(self, urls, depth):
        """递归扫描（按深度迭代）"""
        if depth > self.args.height:
            return

        # 转换为列表，确保顺序
        urls_list = list(urls) if isinstance(urls, set) else urls

        # 清理URL空格
        urls_list = [url.strip() for url in urls_list if url.strip()]

        print(f"[bold green]🔍 深度 {depth} 扫描开始，URL总数: {len(urls_list)}[/bold green]")

        # 分批次处理（每批1000个）
        batch_size = 500
        total_batches = (len(urls_list) + batch_size - 1) // batch_size

        # 存储所有批次的结果（只用于递归和敏感信息提取）
        all_scan_info_list = []
        all_next_urls = set()

        for batch_idx in range(0, len(urls_list), batch_size):
            batch_urls = urls_list[batch_idx:batch_idx + batch_size]
            current_batch = batch_idx // batch_size + 1

            print(
                f"\n[bold cyan]📦 深度 {depth} - URL扫描批次 {current_batch}/{total_batches} (URL数量: {len(batch_urls)})[/bold cyan]")

            # 调用get_source_async处理当前批次
            batch_all_next_urls_with_source, batch_scan_info_list, batch_next_urls = asyncio.run(
                get_source_async(
                    urls=batch_urls,
                    thread_num=self.args.thread_num,
                    args=self.args,
                    checker=self.checker
                )
            )

            # 去重处理
            batch_next_urls = batch_next_urls - self.tmp_urls
            if batch_next_urls:
                self.tmp_urls |= batch_next_urls

            # 统计当前批次的URL数量
            current_batch_urls_count = 0
            for item in batch_all_next_urls_with_source:
                if isinstance(item, dict) and "next_urls" in item:
                    next_urls = item["next_urls"]
                    if isinstance(next_urls, (list, set, tuple)):
                        current_batch_urls_count += len(next_urls)

            # 立即将当前批次结果写入Excel
            if batch_all_next_urls_with_source:
                print(f"[bold blue]💾 立即写入深度 {depth} - 批次 {current_batch} 的数据到Excel "
                      f"({len(batch_all_next_urls_with_source)} 个批次条目，约 {current_batch_urls_count} 个URL)[/bold blue]")

                try:
                    excel_handler.append_data_batch(
                        input_data=batch_all_next_urls_with_source,
                        batch_size=500,
                        show_progress=False  # 避免嵌套进度条
                    )
                    print(f"[green]✅ 深度 {depth} - 批次 {current_batch} 数据写入Excel成功[/green]")
                except Exception as e:
                    print(f"[red]❌ 深度 {depth} - 批次 {current_batch} 数据写入Excel失败: {str(e)}[/red]")

            # 合并结果用于后续处理
            all_scan_info_list.extend(batch_scan_info_list)
            all_next_urls.update(batch_next_urls)

            # 批次间休息，释放资源
            if current_batch < total_batches:
                print(f"[yellow]⏳ 深度 {depth} - URL扫描批次 {current_batch} 完成，等待 1 秒释放资源...[/yellow]")
                time.sleep(1)

        # 处理敏感信息（所有批次完成后统一处理）
        if self.args.sensitiveInfo or self.args.sensitiveInfoQwen:
            print(f"[bold magenta]🔍 开始敏感信息提取，总数据量: {len(all_scan_info_list)}[/bold magenta]")
            self._extract_sensitive_info(all_scan_info_list)

        # 递归下一层
        if all_next_urls:
            print(
                f"[bold blue]➡️  深度 {depth} 完成，发现 {len(all_next_urls)} 个新URL，进入深度 {depth + 1}[/bold blue]")
            self._scan_recursive(all_next_urls, depth + 1)
        else:
            print(f"[bold green]✅ 深度 {depth} 完成，未发现新URL[/bold green]")

    def _extract_sensitive_info(self, scan_info_list):
        """提取敏感信息（从有效扫描结果中）"""
        sensitive_info = []
        for scan_info in scan_info_list:
            url = scan_info["url"]
            if scan_info["is_valid"] == 1 or url in self.initial_urls:
                if ".js" not in scan_info["url"]:
                    continue
                # ========== 【修复致命语法错误：args → self.args 否则运行必报错】 ==========
                if self.args.sensitiveInfoQwen:
                    sensitive_info = qwen_scan_js_code(scan_info["source_code"])
                elif self.args.sensitiveInfo:
                    sensitive_info = find_all_info_by_rex(scan_info["source_code"])
                if len(sensitive_info) == 0:
                    print(f"URL: {url} 没有敏感信息")
                    continue
                write2json(
                    "Result/sensitiveInfo.json",
                    json.dumps(
                        {"url": url, "sensitive_info": sensitive_info},
                        indent=4,  # 加缩进，生成格式化JSON字符串
                        ensure_ascii=False  # 避免非ASCII字符转义（和writer里的参数对齐）
                    )
                )
                rich_print(
                    f"[bold orange]URL:[/bold orange] {url}\n"
                    f"\t[bold orange]敏感信息:[/bold orange] {sensitive_info}"
                )

FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


def send_feishu_notify(title, content=""):
    """飞书推送【纯文本万能版】- 100%兼容所有飞书机器人，彻底解决10208错误"""
    if not FEISHU_WEBHOOK or "你的正确飞书地址" in FEISHU_WEBHOOK:
        rich_print("[red][bold]⚠️ 未配置正确的飞书Webhook地址，跳过推送[/bold][/red]")
        return
    try:
        send_data = {
            "msg_type": "text",  # 必须是text，不能是markdown
            "content": {
                "text": f"{title}\n{content}"  # \n 就是换行，排版和之前一样清晰
            }
        }
        headers = {"Content-Type": "application/json; charset=utf-8"}
        res = requests.post(FEISHU_WEBHOOK, json=send_data, headers=headers, timeout=10)
        res_json = res.json()
        # 飞书纯文本推送成功的返回码是 0
        if res_json.get("StatusCode") == 0:
            rich_print("[green][bold]✅ 飞书消息推送成功 ✅[/bold][/green]")
        else:
            rich_print(f"[red][bold]❌ 飞书推送失败: {res.text}[/bold][/red]")
    except Exception as e:
        rich_print(f"[yellow][bold]⚠️ 飞书推送接口异常: {str(e)}[/bold][/yellow]")


if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()

    start_time = time.time()
    # 1. 确保Result文件夹存在
    os.makedirs("Result", exist_ok=True)
    # 2. 获取扫描的目标URL并提取根域名
    target_url = args.url.strip() if args.url else "unknown_url"
    try:
        url_domain = get_root_domain(target_url)
    except:
        url_domain = "unknown_domain"
    # 3. 格式化域名：替换特殊字符，兼容Windows/Linux文件名规则
    format_domain = url_domain.replace(".", "_").replace("/", "_").replace(":", "_")
    # 4. 生成精确时间戳：年月日_时分秒 (无非法字符，排序友好)
    time_str = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    # 5. 拼接最终Excel文件名：Result/Result_域名_时间.xlsx
    excel_filename = f"Result/Result_{format_domain}_{time_str}.xlsx"
    # 6. 实例化Excel处理器
    excel_handler = SafePathExcelGenerator(excel_filename)
    scanner = Scanner(args)

    try:
        # 执行核心扫描逻辑
        scanner.run()

        run_time = round(time.time() - start_time, 2)
        # 飞书推送的内容，包含你需要的【失败url】+【耗时】+运行结果
        notify_content = f"""
✅ **程序运行完成！扫描任务结束**
📊 运行耗时：{run_time} 秒
📄 结果文件：Result/Result.xlsx
🕒 完成时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
"""
        send_feishu_notify("【服务器-扫描任务✅执行完成】", notify_content)

        rich_print(f"[bold]耗时：{run_time}[/bold]")

    except Exception as e:
        # 捕获所有报错，获取完整报错堆栈信息
        run_time = round(time.time() - start_time, 2)
        # 报错的飞书报警内容，醒目红色提醒
        error_content = f"""
            ❌ **程序运行出错！扫描任务终止**
            ⚠️ 错误类型：{type(e).__name__}
            ⚠️ 错误详情：{str(e)}
            ⏱️ 运行耗时：{run_time} 秒
            🕒 报错时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}

            """
        send_feishu_notify("【服务器-扫描任务❌崩溃报警】", error_content)
