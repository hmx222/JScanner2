import atexit
import logging
import os
import time
import uuid
import warnings
from traceback import print_exc
from urllib.parse import urlparse

import psutil
import requests
from user_agent import generate_user_agent

from FileIO.db_manager import SQLiteStorage
from FileIO.filerw import read
from HttpHandle.AI_Req import client
from HttpHandle.DuplicateChecker import DuplicateChecker
from HttpHandle.httpSend import fetch_urls_with_dedup
from JsHandle.pathScan import get_root_domain
from JsHandle.sensitiveInfoScan import find_all_info_by_rex
from ai_security_scanner.analysis import AISecurityAuditor
from ai_security_scanner.analysis.secret_scanner import remove_html_tags, SensitiveInfoScanner, \
    cleanup_bloom_filters
from config.config import FEISHU_WEBHOOK
from parse_args import parse_args

warnings.filterwarnings("ignore")
from colorama import init

# 初始化日志
logger = logging.getLogger(__name__)

proxies = {
    "http": "",
    "https": "",
    "no_proxy": "*"
}


def classify_url(url, is_seed=False):
    """
    URL 分类（极简版）

    Args:
        url: 目标 URL
        is_seed: 是否为初始种子 URL

    Returns:
        'static' / 'dynamic' / 'api'
    """
    # 初始种子 URL 全部用 Playwright 请求
    if is_seed:
        return 'dynamic'

    # 路径解析
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path
    url_lower = url.lower()

    # 判断路径中是否包含 "."
    has_dot = "." in path

    if has_dot:
        # ========== 包含 "." ==========
        static_extensions = ['.js', '.json', '.css', '.xml', '.txt', '.map', '.xlsx', '.xls', '.csv']
        html_extensions = ['.html', '.htm', '.xhtml']

        if any(url_lower.endswith(ext) for ext in static_extensions):
            return 'static'  # httpx
        elif any(url_lower.endswith(ext) for ext in html_extensions):
            return 'dynamic'  # Playwright
        else:
            return 'dynamic'  # 未知扩展名，安全兜底
    else:
        # ========== 不包含 "." ==========
        # 全部视为 API 路径，不请求
        return 'api'

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
                self.sensitive_scanner = SensitiveInfoScanner(
                    client=client,
                    db=self.db_handler,
                    max_ast_analysis=50,
                    max_llm=80
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
            try:
                cleanup_bloom_filters()
            except Exception:
                pass

            if self.db_handler:
                self.db_handler.close()

        except Exception as e:
            print(f"[Cleanup] 清理失败：{e}")

    async def _quick_scan_filter(self, url, status_code, snippet):
        """
        快速扫描过滤器
        0=跳过（401 未授权 / 200 但响应包含未登录关键词）
        1=保留（其他所有情况，宽松策略）
        """
        url_lower = url.lower()
        snippet_lower = snippet.lower() if snippet else ""

        # 401 未授权
        if status_code == 401:
            return "0"

        # 纯静态资源
        static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf',
                             '.eot', '.mp3', '.wav', '.mp4']
        if any(url_lower.endswith(ext) for ext in static_extensions):
            return "0"

        # 200 但响应包含未登录关键词
        if status_code in [200, 201, 301, 302, 404, 502]:
            unauth_keywords = [
                '未登录', '请先登录', '登录过期', '会话过期', '未授权', '身份验证失败',
                '请登录', '重新登录', '登录失效', '会话已过期', '认证失败',
                'unauthorized', 'unauth', 'not logged in', 'login required',
                'authentication required', 'session expired', 'access denied',
                'please login', 'sign in required', 'token expired', 'invalid token',
                '401', 'login', 'signin', 'jwt expired'
            ]
            if any(kw in snippet_lower for kw in unauth_keywords):
                return "0"

        return "1"

    def run(self):
        """主运行逻辑"""
        os.makedirs("Result", exist_ok=True)

        self.initial_urls = self._load_initial_urls()
        self.checker = DuplicateChecker(initial_root_domain=self.initial_urls)
        self.args.initial_urls = self.initial_urls

        raw_seed_urls = self.load_url()
        scan_seed_urls = []

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
        self._scan_recursive(scan_seed_urls, 0, is_seed=True)
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

    async def _process_ai_batch(self, batch_all_next_paths_with_source, batch_scan_info_list, batch_next_urls):
        """
        批量处理 AI 审计任务
        """
        if not self.ai_auditor:
            return

        qualified_api_paths = set()

        if getattr(self.args, 'fastscan', False) and batch_next_urls:
            print("⚡ [FastScan] 快速扫描模式已启用")

            static_extensions = ['.wav', '.mp3', '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.woff', '.woff2',
                                 '.ico', '.svg']
            urls_to_scan = []

            for url in batch_next_urls:
                url = url.strip()
                if not url:
                    continue
                if any(url.lower().split('?')[0].endswith(ext) for ext in static_extensions):
                    continue
                urls_to_scan.append(url)

            if urls_to_scan:
                # 调用封装的去重函数
                unique_results, dup_count, stats = await fetch_urls_with_dedup(
                    urls=urls_to_scan,
                    thread_num=50,
                    headers={"User-Agent": generate_user_agent()},
                    cookies=None,
                    timeout=10
                )

                url_scan_results = {}
                for result in unique_results:
                    url = result["url"].strip()
                    url_scan_results[url] = {
                        "status_code": result["status_code"],
                        "length": result["length"],
                        "response_content": result["response_content"],
                        "fingerprint": result.get("fingerprint"),
                    }

                filter_count = 0
                for item in batch_all_next_paths_with_source:
                    source_url = item.get("sourceURL", "").strip()
                    next_paths = item.get("next_paths", [])

                    if not source_url or not next_paths:
                        continue

                    parsed = urlparse(source_url)
                    domain_prefix = f"{parsed.scheme}://{parsed.netloc}"

                    for api_path in next_paths:
                        api_path = api_path.strip()
                        if not api_path or len(api_path) < 4:
                            continue

                        if api_path.startswith("http"):
                            full_url = api_path
                        else:
                            full_url = f"{domain_prefix}{api_path}"

                        full_url = full_url.strip()

                        if full_url in url_scan_results:
                            scan_result = url_scan_results[full_url]

                            should_test = await self._quick_scan_filter(
                                url=full_url,
                                status_code=scan_result["status_code"],
                                snippet=scan_result["response_content"][:500]
                            )

                            if should_test == "1":
                                qualified_api_paths.add(api_path)
                            else:
                                filter_count += 1

                print(
                    f"🌐 [Quick Scan] {len(urls_to_scan)} URLs → {dup_count} duplicates → {len(qualified_api_paths)} qualified")
                print(f"🔍 [Filter Stats] Filtered: {filter_count}, Passed: {len(qualified_api_paths)}")
        else:
            print("ℹ️  [FastScan] 快速扫描模式未启用，将分析所有 API")

        source_map = {}
        for info in batch_scan_info_list:
            if info.get("source_code") and info.get("url") and ".js" in info["url"]:
                try:
                    clean_code = remove_html_tags(info["source_code"])
                    source_map[info["url"]] = clean_code
                except:
                    source_map[info["url"]] = info["source_code"]

        processed_count = 0
        for item in batch_all_next_paths_with_source:
            js_url = item.get("sourceURL")
            found_apis = item.get("next_paths", [])

            if not js_url or js_url not in source_map:
                continue

            js_source = source_map[js_url]

            unique_apis = set(found_apis)
            apis_to_scan = []

            for api_path in unique_apis:
                if len(api_path) < 4 or api_path.startswith("http") or api_path.startswith("//"):
                    continue
                if any(api_path.lower().endswith(ext) for ext in ['.png', '.jpg', '.css', '.woff', '.ico']):
                    continue

                if qualified_api_paths:
                    if api_path in qualified_api_paths:
                        apis_to_scan.append(api_path)
                else:
                    apis_to_scan.append(api_path)

            if apis_to_scan and getattr(self.args, 'autoConstructPoc', False):
                try:
                    batch_ai_advisories = self.ai_auditor.scan_multiple_apis(
                        js_code=js_source,
                        api_paths=apis_to_scan,
                        target_url=self.args.url.strip()
                    )

                    for api_path, advisory_report in batch_ai_advisories.items():
                        if not advisory_report:
                            continue

                        print(f"🤖 [AI Advisor] Generated Advisory for {api_path}")
                        print(advisory_report)

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

    def _scan_recursive(self, urls, depth, is_seed=False):
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

        # ========== URL 三分类 ==========
        static_urls = []
        dynamic_urls = []
        api_urls = []

        for url in urls_list:
            url_type = classify_url(url, is_seed=(depth == 0))
            if url_type == 'static':
                static_urls.append(url)
            elif url_type == 'dynamic':
                dynamic_urls.append(url)
            else:
                api_urls.append(url)

        if static_urls:
            print(f"   📦 静态资源：{len(static_urls)} 个（使用 httpx 快速请求）")
        if dynamic_urls:
            print(f"   🚀 动态页面：{len(dynamic_urls)} 个（使用 Playwright）")
        if api_urls:
            print(f"   ⏭️ API 路径：{len(api_urls)} 个（不请求，从 JS 分析）")

        batch_size = 200
        total_batches = (len(urls_list) + batch_size - 1) // batch_size

        all_scan_info_list = []
        all_next_urls = set()

        # ========== 批次处理 ==========
        for batch_idx in range(0, len(urls_list), batch_size):
            batch_urls = urls_list[batch_idx:batch_idx + batch_size]
            current_batch = batch_idx // batch_size + 1

            print(f"\n[D{depth}] 批次 {current_batch}/{total_batches} (Size: {len(batch_urls)})")

            # 分离当前批次的静态和动态 URL
            batch_dynamic = []
            batch_static = []
            for url in batch_urls:
                url_type = classify_url(url, is_seed=(depth == 0))
                if url_type == 'static':
                    batch_static.append(url)
                elif url_type == 'dynamic':
                    batch_dynamic.append(url)
                # api 类型不加入请求队列

            # 并行请求：静态 + 动态
            import asyncio
            from HttpHandle.httpSend import fetch_urls_async, get_source_async, process_scan_result

            async def parallel_fetch():
                dynamic_task = None
                static_task = None

                # 动态资源任务（Playwright）
                if batch_dynamic:
                    dynamic_task = get_source_async(
                        urls=batch_dynamic,
                        thread_num=self.args.thread_num,
                        args=self.args,
                        checker=self.checker
                    )

                # 静态资源任务（httpx）
                if batch_static:
                    static_task = fetch_urls_async(
                        urls=batch_static,
                        thread_num=min(self.args.thread_num, 50),
                        headers={"User-Agent": generate_user_agent()},
                        timeout=10
                    )

                # 等待两个任务完成
                dynamic_result = await dynamic_task if dynamic_task else ([], [], set(), [])
                static_result = await static_task if static_task else []

                return dynamic_result, static_result

            batch_all_next_urls_with_source = []
            batch_scan_info_list = []
            batch_next_urls = set()
            batch_all_next_paths_with_source = []

            try:
                dynamic_result, static_result = asyncio.run(parallel_fetch())

                if dynamic_result:
                    batch_all_next_urls_with_source, batch_scan_info_list, batch_next_urls, batch_all_next_paths_with_source = dynamic_result

                if static_result:
                    for static_resp in static_result:
                        if not static_resp.get("error"):
                            parsed = urlparse(static_resp["url"])
                            static_info = {
                                "domain": parsed.hostname,
                                "url": static_resp["url"],
                                "path": parsed.path,
                                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                                "status": static_resp["status_code"],
                                "title": "Static Resource",
                                "length": static_resp["length"],
                                "source_code": static_resp["response_content"],
                                "is_valid": 0,
                                "redirect_count": static_resp.get("redirect_count", 0),
                                "redirect_locations": [],
                                "original_url": static_resp["url"]
                            }

                            try:
                                # 调用 process_scan_result 提取数据
                                is_valid, next_urls, next_paths = asyncio.run(
                                    process_scan_result(static_info, self.checker, self.args)
                                )

                                if is_valid:
                                    static_info["is_valid"] = 1

                                    batch_scan_info_list.append(static_info)

                                    if next_urls:
                                        batch_next_urls.update(next_urls)

                                    if next_urls:
                                        next_urls_with_source = {
                                            "next_urls": list(next_urls),
                                            "sourceURL": static_resp["url"]
                                        }
                                        batch_all_next_urls_with_source.append(next_urls_with_source)

                                    if next_paths:
                                        next_paths_with_source = {
                                            "next_paths": next_paths,
                                            "sourceURL": static_resp["url"]
                                        }
                                        batch_all_next_paths_with_source.append(next_paths_with_source)
                                else:
                                    batch_scan_info_list.append(static_info)

                            except Exception as e:
                                print(f"⚠️ 静态资源处理失败 {static_resp['url']}: {e}")
                                batch_scan_info_list.append(static_info)

            except Exception as e:
                print(f"❌ [Fetch Error] 批次 {current_batch} 请求失败：{e}")
                import traceback
                traceback.print_exc()
                continue

            print(f"[D{depth}] 批次 {current_batch}/{total_batches} 扫描完成")
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
                asyncio.run(
                    self._process_ai_batch(batch_all_next_paths_with_source, batch_scan_info_list, batch_next_urls))

            all_scan_info_list.extend(batch_scan_info_list)

            if current_batch < total_batches:
                time.sleep(0.2)

            try:
                mem = psutil.virtual_memory()
                if mem.percent > 85.0:
                    print(f"\n⚠️  内存告警：{mem.percent}% > 99% | 触发熔断保护.")

                    overflow_dir = "Overflow_Queue"
                    os.makedirs(overflow_dir, exist_ok=True)
                    file_id = uuid.uuid4().hex[:8]

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

        if all_next_urls:
            print(f"➡️  进入深度 {depth + 1}")
            self._scan_recursive(all_next_urls, depth + 1, is_seed=False)
        else:
            print(f"✅ 深度 {depth} 完成")

    def _extract_sensitive_info(self, scan_info_list):
        """
        提取敏感信息 (v2.0 重构版)
        """
        for scan_info in scan_info_list:
            url = scan_info["url"]

            if not (scan_info["is_valid"] == 1 or url in self.initial_urls):
                continue
            if ".js" not in scan_info["url"]:
                continue

            combined_sensitive_info = set()

            if self.args.analyzeSensitiveInfoAI and self.sensitive_scanner:
                try:
                    ai_results = self.sensitive_scanner.scan(
                        js_code=scan_info["source_code"],
                        js_url=url
                    )

                    if ai_results:
                        for item in ai_results:
                            combined_sensitive_info.add(item.get("value", ""))

                        high_risk = [r for r in ai_results if r.get("risk_level") == "High"]
                        if high_risk:
                            print(f"🔥 [High Risk] URL: {url}")
                            for hr in high_risk[:5]:
                                value_preview = hr.get('value', '')[:50]
                                print(f"   └─ {value_preview}...")
                                print(f"      类型：{hr.get('secret_type', 'unknown')}")
                                suggestion = hr.get('test_suggestion', '')[:50]
                                print(f"      建议：{suggestion}...")

                except Exception as e:
                    print_exc()
                    logger.error(f"❌ [AI Scan] 分析失败 {url}: {e}")
                    print(f"❌ [AI Scan] 分析失败 {url}: {e}")

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

    db_handler = SQLiteStorage(db_filename)
    scanner = Scanner(args, db_handler)

    try:
        scanner.run()
        run_time = round(time.time() - start_time, 2)
        print(f"本次扫描耗时：{run_time}s")

    except Exception as e:
        run_time = round(time.time() - start_time, 2)
        error_content = f"❌ 错误：{str(e)}\n⏱️ 耗时：{run_time}s"
        send_feishu_notify("【扫描任务报警】", error_content)
        print_exc()

    finally:
        scanner._cleanup_resources()