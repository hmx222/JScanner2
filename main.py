import asyncio
import json
import os
import time
import uuid
import warnings
import psutil
import requests
from AI.SenInfo import qwen_scan_js_code
from config.config import FEISHU_WEBHOOK

warnings.filterwarnings("ignore")
from colorama import init
from rich import print as rich_print

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
        self.initial_urls = []  # 初始URL根域
        # checker 在 run 中初始化，确保能拿到完整的 initial_root_domain
        self.checker = None
        self.whiteList = read("./config/whiteList")

    def run(self):
        """主运行逻辑"""
        os.makedirs("Result", exist_ok=True)
        clear_or_create_file("Result/sensitiveInfo.json")

        self.initial_urls = self._load_initial_urls()

        self.checker = DuplicateChecker(initial_root_domain=self.initial_urls)
        self.args.initial_urls = self.initial_urls

        # 加载并清洗种子URL
        raw_seed_urls = self.load_url(self.args)
        scan_seed_urls = []

        for url in raw_seed_urls:
            url = url.strip()
            if not url: continue

            if not self.checker.visited_urls.contains(url):
                # 标记为已访问 (防止本次运行重复)
                self.checker.visited_urls.add(url)
                scan_seed_urls.append(url)
            else:
                rich_print(f"[yellow]⏩ 初始URL已在历史记录中，自动跳过: {url}[/yellow]")

        if not scan_seed_urls:
            rich_print("[red]没有新的有效URL需要扫描（可能全部已过滤）[/red]")
            return

        # 开始扫描
        start_time = time.time()
        self._scan_recursive(scan_seed_urls, 0)

        rich_print(f"[cyan]总耗时: {time.time() - start_time:.2f}秒[/cyan]")

    def load_url(self, args):
        if args.url and args.url.strip():
            return [args.url.strip()]
        return []

    def _load_initial_urls(self):
        # 第一步：强制加载白名单
        white_list_domains = read("./config/whiteList")
        # 第二步：如果传入了扫描URL，解析根域名并追加
        if self.args.url and self.args.url.strip():
            try:
                seed_root_domain = get_root_domain(self.args.url.strip())
                if seed_root_domain and seed_root_domain not in white_list_domains:
                    white_list_domains.append(seed_root_domain)
            except Exception:
                pass
        return list(set(filter(None, white_list_domains)))

    def _scan_recursive(self, urls, depth):
        """递归扫描（按深度迭代）- 修正版：循环内内存熔断 + 持久化去重"""
        if depth > self.args.height:
            return

        # 转换为列表
        raw_urls_list = list(urls) if isinstance(urls, set) else urls
        raw_urls_list = [url.strip() for url in raw_urls_list if url.strip()]

        urls_list = []
        if depth > 0:
            # 深度>0，严格检查是否已访问
            for u in raw_urls_list:
                if self.checker.should_scan(u):
                    # 立即占位，防止同批次其他逻辑重复
                    self.checker.visited_urls.add(u)
                    urls_list.append(u)
        else:
            for u in raw_urls_list:
                if self.checker.is_within_scope(u):
                    urls_list.append(u)

        if not urls_list:
            return

        print(f"[bold green]🔍 深度 {depth} 扫描开始，URL总数: {len(urls_list)}[/bold green]")

        batch_size = 200
        total_batches = (len(urls_list) + batch_size - 1) // batch_size

        all_scan_info_list = []
        all_next_urls = set()

        for batch_idx in range(0, len(urls_list), batch_size):
            # 1. 准备当前批次
            batch_urls = urls_list[batch_idx:batch_idx + batch_size]
            current_batch = batch_idx // batch_size + 1

            print(
                f"\n[bold cyan]📦 深度 {depth} - URL扫描批次 {current_batch}/{total_batches} (URL数量: {len(batch_urls)})[/bold cyan]")

            # 2. 执行扫描
            # 注意：checker 已经初始化好了，传进去给 process_scan_result 用
            batch_all_next_urls_with_source, batch_scan_info_list, batch_next_urls = asyncio.run(
                get_source_async(
                    urls=batch_urls,
                    thread_num=self.args.thread_num,
                    args=self.args,
                    checker=self.checker
                )
            )

            for n_url in batch_next_urls:
                if self.checker.should_scan(n_url):
                    all_next_urls.add(n_url)

            # 写入Excel
            if batch_all_next_urls_with_source:
                try:
                    excel_handler.append_data_batch(batch_all_next_urls_with_source, batch_size=500,
                                                    show_progress=False)
                    print(f"[green]✅ 深度 {depth} - 批次 {current_batch} 数据写入Excel成功[/green]")
                except Exception as e:
                    print(f"[red]❌ 深度 {depth} - 批次 {current_batch} 数据写入Excel失败: {str(e)}[/red]")

            # 添加到总列表
            all_scan_info_list.extend(batch_scan_info_list)

            # 批次间休息
            if current_batch < total_batches:
                time.sleep(0.2)

            mem = psutil.virtual_memory()
            mem_percent = mem.percent

            # 阈值 70%
            if mem_percent > 70.0:
                rich_print(f"\n[bold red]⚠️  内存告警: 当前 {mem_percent}% > 70% | 触发循环内熔断保护[/bold red]")

                overflow_dir = "Overflow_Queue"
                os.makedirs(overflow_dir, exist_ok=True)
                file_id = uuid.uuid4().hex[:8]

                # --- 任务A: 保存【下一层】的任务 (Children) ---
                rem_height_children = self.args.height - (depth + 1)

                # 双重保险：写入前确保 filter 里的 url 确实是新的
                final_children_urls = []
                for u in all_next_urls:
                    if self.checker.should_scan(u):
                        final_children_urls.append(u)

                if final_children_urls and rem_height_children >= 0:
                    filename_child = f"{overflow_dir}/overflow_depth_{rem_height_children}_{file_id}_children.txt"
                    with open(filename_child, "w", encoding="utf-8") as f:
                        for u in final_children_urls:
                            f.write(f"{u}\n")
                    rich_print(
                        f"[yellow]💾 [熔断-子集] 已保存 {len(final_children_urls)} 个发现的URL (下层) 到: {filename_child}[/yellow]")

                # --- 任务B: 保存【本层未完成】的任务 (Siblings) ---
                rem_height_siblings = self.args.height - depth
                next_start_idx = batch_idx + batch_size
                unprocessed_urls = urls_list[next_start_idx:]

                if unprocessed_urls and rem_height_siblings >= 0:
                    filename_sibling = f"{overflow_dir}/overflow_depth_{rem_height_siblings}_{file_id}_siblings.txt"
                    with open(filename_sibling, "w", encoding="utf-8") as f:
                        for u in unprocessed_urls:
                            if ".js" in u:
                                f.write(f"{u}\n")
                    rich_print(
                        f"[yellow]💾 [熔断-同层] 已保存 {len(unprocessed_urls)} 个未扫URL (本层) 到: {filename_sibling}[/yellow]")

                # --- 紧急处理：释放内存并退出 ---
                if (self.args.sensitiveInfo or self.args.sensitiveInfoQwen) and all_scan_info_list:
                    try:
                        self._extract_sensitive_info(all_scan_info_list)
                    except:
                        pass

                        # 强制清理
                del all_scan_info_list
                del all_next_urls
                del urls_list
                import gc
                gc.collect()

                rich_print(f"[bold red]🛑 进程已终止递归，等待 Shell 脚本接力...[/bold red]")
                return

        # 循环正常结束
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
        """提取敏感信息"""
        sensitive_info = []
        for scan_info in scan_info_list:
            url = scan_info["url"]
            if scan_info["is_valid"] == 1 or url in self.initial_urls:
                if ".js" not in scan_info["url"]:
                    continue

                if self.args.sensitiveInfoQwen:
                    sensitive_info = qwen_scan_js_code(scan_info["source_code"])
                elif self.args.sensitiveInfo:
                    sensitive_info = find_all_info_by_rex(scan_info["source_code"])

                if len(sensitive_info) == 0:
                    # print(f"URL: {url} 没有敏感信息") # 减少刷屏
                    continue

                write2json(
                    "Result/sensitiveInfo.json",
                    json.dumps(
                        {"url": url, "sensitive_info": sensitive_info},
                        indent=4,
                        ensure_ascii=False
                    )
                )
                rich_print(
                    f"[bold orange]URL:[/bold orange] {url}\n"
                    f"\t[bold orange]敏感信息:[/bold orange] {sensitive_info}"
                )

def send_feishu_notify(title, content=""):
    """飞书推送"""
    if not FEISHU_WEBHOOK or "你的正确飞书地址" in FEISHU_WEBHOOK:
        rich_print("[red][bold]⚠️ 未配置正确的飞书Webhook地址，跳过推送[/bold][/red]")
        return
    try:
        send_data = {
            "msg_type": "text",
            "content": {
                "text": f"{title}\n{content}"
            }
        }
        headers = {"Content-Type": "application/json; charset=utf-8"}
        res = requests.post(FEISHU_WEBHOOK, json=send_data, headers=headers, timeout=10)
        res_json = res.json()
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
    os.makedirs("Result", exist_ok=True)

    target_url = args.url.strip() if args.url else "unknown_url"
    try:
        url_domain = get_root_domain(target_url)
    except:
        url_domain = "unknown_domain"

    format_domain = url_domain.replace(".", "_").replace("/", "_").replace(":", "_")

    time_str = time.strftime("%Y%m%d", time.localtime())
    excel_filename = f"Result/Result_{format_domain}_{time_str}.xlsx"

    excel_handler = SafePathExcelGenerator(excel_filename)
    scanner = Scanner(args)

    try:
        scanner.run()
        run_time = round(time.time() - start_time, 2)

        rich_print(f"[bold]本轮进程耗时：{run_time}[/bold]")

    except Exception as e:
        run_time = round(time.time() - start_time, 2)
        error_content = f"""
            ❌ **程序运行出错！扫描任务终止**
            ⚠️ 错误类型：{type(e).__name__}
            ⚠️ 错误详情：{str(e)}
            ⏱️ 运行耗时：{run_time} 秒
            🕒 报错时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
            """
        send_feishu_notify("【服务器-扫描任务❌崩溃报警】", error_content)

