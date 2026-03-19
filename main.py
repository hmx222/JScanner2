import asyncio
import json
import os
import time
import uuid
import warnings
import logging
import atexit
from traceback import print_exc

import psutil
import requests

from FileIO.db_manager import SQLiteStorage
from FileIO.filerw import write2json, clear_or_create_file, read
from HttpHandle.DuplicateChecker import DuplicateChecker
from HttpHandle.httpSend import get_source_async
from JsHandle.pathScan import get_root_domain
from JsHandle.sensitiveInfoScan import find_all_info_by_rex
from ai_security_scanner.analysis import AISecurityAuditor
from ai_security_scanner.analysis.secret_scanner import remove_html_tags, SensitiveInfoScanner, \
    cleanup_bloom_filters
from config.config import FEISHU_WEBHOOK
from parse_args import parse_args
from HttpHandle.AI_Req import client

warnings.filterwarnings("ignore")
from colorama import init

# 初始化日志
logger = logging.getLogger(__name__)

proxies = {
    "http": "",
    "https": "",
    "no_proxy": "*"
}


class Scanner:
    """
    主扫描器类
    """

    def __init__(self, args, db_handler):
        """
        初始化扫描器
        """
        self.args = args
        self.db_handler = db_handler

        self.initial_urls = []
        self.checker = None
        self.whiteList = read("./config/whiteList")
        self.param_file = None

        self.ai_auditor = None
        if self.args.autoConstructPoc:
            try:
                self.ai_auditor = AISecurityAuditor()
                print("[AI] AI 安全审计器初始化成功")
            except Exception as e:
                print(f"[AI] AI 安全审计器初始化失败：{e}")
                self.ai_auditor = None

        self.sensitive_scanner = None
        if self.args.analyzeSensitiveInfoAI:
            try:

                # 初始化扫描器 (传入 db_handler 实现统一存储)
                self.sensitive_scanner = SensitiveInfoScanner(
                    client=client,
                    db=self.db_handler,
                    max_ast_analysis=50,  # AST 溯源数量限制 (性能保护)
                    max_llm=80  # LLM 验证数量限制 (成本保护)
                )
            except Exception as e:
                print(f"[Scanner] 敏感信息扫描器初始化失败：{e}")
                self.sensitive_scanner = None

        atexit.register(self._cleanup_resources)

    def _cleanup_resources(self):
        """
        清理资源 (程序退出时自动调用)
        """
        try:
            # 1. 清理布隆过滤器
            try:
                cleanup_bloom_filters()
            except Exception:
                pass

            # 2. 关闭数据库连接
            if self.db_handler:
                self.db_handler.close()

        except Exception as e:
            print(f"[Cleanup] 清理失败：{e}")

    def run(self):
        """主运行逻辑"""
        os.makedirs("Result", exist_ok=True)
        clear_or_create_file("Result/sensitiveInfo.json")

        self.initial_urls = self._load_initial_urls()
        self.checker = DuplicateChecker(initial_root_domain=self.initial_urls)
        self.args.initial_urls = self.initial_urls

        raw_seed_urls = self.load_url()
        scan_seed_urls = []

        # 参数提取结果文件名
        target_url_for_name = self.args.url.strip() if self.args.url else "batch_task"
        try:
            domain_part = get_root_domain(target_url_for_name).replace(".", "_")
        except:
            domain_part = "unknown"
        time_part = time.strftime("%Y%m%d", time.localtime())
        self.param_file = f"Result/params_{domain_part}_{time_part}.txt"

        for url in raw_seed_urls:
            url = url.strip()
            if not url:
                continue
            if not self.checker.visited_urls.contains(url):
                self.checker.visited_urls.add(url)
                scan_seed_urls.append(url)
            else:
                print(f"初始 URL 已在历史记录中，跳过：{url}")

        if not scan_seed_urls:
            print("没有新的有效 URL 需要扫描")
            return

        start_time = time.time()
        self._scan_recursive(scan_seed_urls, 0)
        print(f"🏁 任务结束 | 总耗时：{time.time() - start_time:.2f}秒")

    def load_url(self):
        if self.args.url and self.args.url.strip():
            return [self.args.url.strip()]
        return []

    def _load_initial_urls(self):
        white_list_domains = read("./config/whiteList")
        if self.args.url and self.args.url.strip():
            try:
                seed_root_domain = get_root_domain(self.args.url.strip())
                if seed_root_domain and seed_root_domain not in white_list_domains:
                    white_list_domains.append(seed_root_domain)
            except Exception:
                pass
        return list(set(filter(None, white_list_domains)))

    def _process_ai_batch(self, batch_all_next_urls_with_source, batch_scan_info_list):
        """
        批量处理 AI 审计任务
        """
        if not self.ai_auditor:
            return

        # 1. 构建源码索引
        source_map = {}
        for info in batch_scan_info_list:
            if info.get("source_code") and info.get("url") and ".js" in info["url"]:
                try:
                    clean_code = remove_html_tags(info["source_code"])
                    source_map[info["url"]] = clean_code
                except:
                    source_map[info["url"]] = info["source_code"]

        # 2. 遍历 JS 文件并分析其中的 API
        processed_count = 0
        for item in batch_all_next_urls_with_source:
            js_url = item.get("sourceURL")
            found_apis = item.get("next_paths", [])

            if not js_url or js_url not in source_map:
                continue

            js_source = source_map[js_url]

            # 3. 过滤高质量待分析 API
            unique_apis = set(found_apis)
            apis_to_scan = []
            for api_path in unique_apis:
                if len(api_path) < 4 or api_path.startswith("http") or api_path.startswith("//"):
                    continue
                if any(api_path.lower().endswith(ext) for ext in ['.png', '.jpg', '.css', '.woff', '.ico']):
                    continue
                apis_to_scan.append(api_path)

            # 4. 批量执行 AI 审计建议生成
            if apis_to_scan and getattr(self.args, 'autoConstructPoc', False):
                try:
                    # 调用重构后的顾问模式 scan_multiple_apis
                    batch_ai_advisories = self.ai_auditor.scan_multiple_apis(
                        js_code=js_source,
                        api_paths=apis_to_scan,
                        target_url=self.args.url.strip()
                    )

                    for api_path, advisory_report in batch_ai_advisories.items():
                        if not advisory_report:
                            continue

                        processed_count += 1

                        self.db_handler.save_ai_result(
                            js_url=js_url,
                            api_endpoint=api_path,
                            advisory_report=advisory_report
                        )

                except Exception:
                    print_exc()

        if processed_count > 0:
            print(f"🤖 [AI Advisor] Batch completed. Generated {processed_count} Advisories.")

    def _scan_recursive(self, urls, depth):
        """递归扫描主流程"""
        if depth > self.args.height:
            return

        raw_urls_list = [url.strip() for url in urls if url.strip()]
        urls_list = []

        if depth > 0:
            for u in raw_urls_list:
                if self.checker.should_scan(u):
                    self.checker.visited_urls.add(u)
                    urls_list.append(u)
        else:
            for u in raw_urls_list:
                if self.checker.is_within_scope(u):
                    urls_list.append(u)

        if not urls_list:
            return

        print(f"🔍 深度 {depth} 扫描开始 | URL 数：{len(urls_list)}")

        batch_size = 200
        total_batches = (len(urls_list) + batch_size - 1) // batch_size

        all_scan_info_list = []
        all_next_urls = set()

        for batch_idx in range(0, len(urls_list), batch_size):
            batch_urls = urls_list[batch_idx:batch_idx + batch_size]
            current_batch = batch_idx // batch_size + 1

            print(f"\n[D{depth}] 批次 {current_batch}/{total_batches} (Size: {len(batch_urls)})")

            batch_all_next_urls_with_source, batch_scan_info_list, batch_next_urls, batch_all_next_paths_with_source = asyncio.run(
                get_source_async(
                    urls=batch_urls,
                    thread_num=self.args.thread_num,
                    args=self.args,
                    checker=self.checker
                )
            )

            # 收集下一层 URL
            for n_url in batch_next_urls:
                if self.checker.should_scan(n_url):
                    all_next_urls.add(n_url)

            if batch_all_next_urls_with_source:
                try:
                    self.db_handler.append_data_batch(batch_all_next_urls_with_source, depth=depth)
                    print(f"✅ [DB] 基础数据已存入")
                except Exception as e:
                    print(f"❌ [DB] 基础数据存储失败：{e}")

            if self.args.autoConstructPoc and self.ai_auditor:
                print(f"🤖 [AI] 正在进行 API 逻辑审计...")
                self._process_ai_batch(batch_all_next_paths_with_source, batch_scan_info_list)

            all_scan_info_list.extend(batch_scan_info_list)

            if current_batch < total_batches:
                time.sleep(0.2)

            try:
                mem = psutil.virtual_memory()
                if mem.percent > 99.0:
                    print(f"\n⚠️  内存告警：{mem.percent}% > 99% | 触发熔断保护.")

                    overflow_dir = "Overflow_Queue"
                    os.makedirs(overflow_dir, exist_ok=True)
                    file_id = uuid.uuid4().hex[:8]

                    # 保存未完成的任务到文件，供下次 Resume
                    rem_height_children = self.args.height - (depth + 1)
                    final_children_urls = [u for u in all_next_urls if self.checker.should_scan(u)]
                    if final_children_urls and rem_height_children >= 0:
                        with open(f"{overflow_dir}/overflow_depth_{rem_height_children}_{file_id}_children.txt",
                                  "w") as f:
                            f.write("\n".join(final_children_urls))

                    unprocessed_urls = urls_list[batch_idx + batch_size:]
                    rem_height_siblings = self.args.height - depth
                    if unprocessed_urls and rem_height_siblings >= 0:
                        with open(f"{overflow_dir}/overflow_depth_{rem_height_siblings}_{file_id}_siblings.txt",
                                  "w") as f:
                            f.write("\n".join([u for u in unprocessed_urls if ".js" in u]))

                    self.db_handler.close()
                    print(f"🛑 进程主动退出 (Memory Safety)")
                    return
            except Exception:
                pass

        if self.args.analyzeSensitiveInfoRex or self.args.analyzeSensitiveInfoAI:
            print(f"🔍 正在提取敏感信息 (Regex/Qwen)...")
            self._extract_sensitive_info(all_scan_info_list)

        # 递归下一层
        if all_next_urls:
            print(f"➡️  进入深度 {depth + 1}")
            self._scan_recursive(all_next_urls, depth + 1)
        else:
            print(f"✅ 深度 {depth} 完成")


    def _extract_sensitive_info(self, scan_info_list):
        """
        提取敏感信息 (v2.0 重构版)

        支持：
        1. 正则匹配 (Rex)
        2. AI 分析 + AST 上下文溯源 (新版本)
        3. 自动存入 SQLite 数据库
        """
        for scan_info in scan_info_list:
            url = scan_info["url"]

            # 只分析 JS 文件，且忽略无效页面
            if not (scan_info["is_valid"] == 1 or url in self.initial_urls):
                continue
            if ".js" not in scan_info["url"]:
                continue

            combined_sensitive_info = set()

            # ========== AI 分析 (新版本) ==========
            if self.args.analyzeSensitiveInfoAI and self.sensitive_scanner:
                try:
                    # 使用新扫描器，返回结构化数据
                    ai_results = self.sensitive_scanner.scan(
                        js_code=scan_info["source_code"],
                        js_url=url
                    )

                    if ai_results:
                        # 提取敏感值用于 JSON 输出 (兼容旧格式)
                        for item in ai_results:
                            combined_sensitive_info.add(item.get("value", ""))

                        # 打印高危发现
                        high_risk = [r for r in ai_results if r.get("risk_level") == "High"]
                        if high_risk:
                            print(f"🔥 [High Risk] URL: {url}")
                            for hr in high_risk[:5]:  # 最多显示 5 条
                                value_preview = hr.get('value', '')[:50]
                                print(f"   └─ {value_preview}...")
                                print(f"      类型：{hr.get('secret_type', 'unknown')}")
                                suggestion = hr.get('test_suggestion', '')[:50]
                                print(f"      建议：{suggestion}...")

                except Exception as e:
                    print_exc()
                    logger.error(f"❌ [AI Scan] 分析失败 {url}: {e}")
                    print(f"❌ [AI Scan] 分析失败 {url}: {e}")

            # ========== 正则分析 (保持不变) ==========
            if self.args.analyzeSensitiveInfoRex:
                try:
                    rex_results = find_all_info_by_rex(scan_info["source_code"])
                    if rex_results:
                        combined_sensitive_info.update(rex_results)
                except Exception:
                    pass


def send_feishu_notify(title, content=""):
    """发送飞书通知"""
    if not FEISHU_WEBHOOK:
        return
    try:
        requests.post(FEISHU_WEBHOOK,
                      json={"msg_type": "text", "content": {"text": f"{title}\n{content}"}},
                      timeout=10,
                      proxies=proxies)
    except:
        pass


if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()

    start_time = time.time()
    os.makedirs("Result", exist_ok=True)

    target_url = args.url.strip() if args.url else "unknown"
    try:
        root_domain = get_root_domain(target_url)
    except:
        root_domain = "unknown"

    safe_db_name = root_domain.replace(".", "_").replace("/", "_").replace(":", "_")
    time_str = time.strftime("%Y%m%d", time.localtime())
    db_filename = f"Result/Result_{safe_db_name}_{time_str}.db"

    print(f"📂 扫描结果将存入数据库：{db_filename}")

    # 初始化数据库
    db_handler = SQLiteStorage(db_filename)

    # 初始化扫描器
    scanner = Scanner(args, db_handler)

    try:
        scanner.run()
        run_time = round(time.time() - start_time, 2)
        print(f"本次扫描耗时：{run_time}s")

    except Exception as e:
        run_time = round(time.time() - start_time, 2)
        error_content = f"❌ 错误：{str(e)}\n⏱️ 耗时：{run_time}s"
        send_feishu_notify("【扫描任务报警】", error_content)
        print(error_content)

    finally:
        # 手动清理资源 (atexit 也会自动调用)
        scanner._cleanup_resources()