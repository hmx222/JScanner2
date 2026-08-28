import asyncio
import atexit
import logging
import os
import time
import uuid
import warnings
from traceback import print_exc
from urllib.parse import urlparse

import psutil
from user_agent import generate_user_agent

from config.scanner_rules import UNAUTHORIZED_PAGE_KEYWORDS, \
    HTTPX_STATIC_EXTENSIONS, STATIC_RESOURCE_EXTENSIONS
from config.scanner_rules import is_api_path_blacklisted
from config.config import WHITE_SCOPE_PATH, db_filename, MEMORY_LIMIT, OVERFLOW_DIR
from crawler.browser_crawler import get_source_async
from crawler.httpx_crawler import fetch_urls_with_dedup, fetch_urls_async
from crawler.response_process import process_scan_result
from infra.ai_client import client
from infra.dedup import DuplicateChecker
from infra.feishu import send_feishu_notify
from parse_args import parse_args
from processor.analysis import AISecurityAuditor
from processor.analysis.api.api_scan import get_root_domain
from processor.analysis.secret.js_sensitive_rex import find_all_info_by_rex
from processor.analysis.secret.secret_scanner import SensitiveInfoScanner, cleanup_bloom_filters, remove_html_tags, \
    SQLiteStorage
from processor.analysis.api.request_executor import batch_execute_requests
from storage.filerw import read

warnings.filterwarnings("ignore")
from colorama import init

BATCH_SIZE = 200
BATCH_SLEEP = 0.2
API_MIN_LENGTH = 4
HTML_EXTS = {'.html', '.htm', '.xhtml'}


def _is_more_specific(new_url: str, old_url: str) -> bool:
    """新 baseURL 的路径前缀比旧的更长，说明更精确"""
    from urllib.parse import urlparse
    new_path = urlparse(new_url).path.rstrip('/')
    old_path = urlparse(old_url).path.rstrip('/')
    return len(new_path) > len(old_path)


def _is_already_base_url(url: str) -> bool:
    """判断 URL 是否已经是一个验证过的 baseURL（含路径前缀）"""
    if not url:
        return False
    parsed = urlparse(url)
    path = parsed.path.rstrip('/')
    return bool(path) and path != '/'


def _get_first_level_prefix(api_path):
    path = api_path.strip().lstrip('/')
    parts = path.split('/')
    return parts[0] if parts else ""


# 初始化日志
logger = logging.getLogger(__name__)


def _is_static_url(url: str) -> bool:
    """判断是否是静态资源"""
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in HTTPX_STATIC_EXTENSIONS)


def _is_html_url(url: str) -> bool:
    """判断是否是 HTML 页面"""
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in HTML_EXTS)


def _is_skip_ext(url: str) -> bool:
    """判断是否是需要跳过的扩展名"""
    url_lower = url.lower().split('?')[0]
    return any(url_lower.endswith(ext) for ext in STATIC_RESOURCE_EXTENSIONS)


def classify_url(url, is_seed=False):
    """URL 分类（极简版）"""
    if is_seed:
        return 'dynamic'

    parsed = urlparse(url)
    path = parsed.path
    has_dot = "." in path

    if has_dot:
        if _is_static_url(url):
            return 'static'
        elif _is_html_url(url):
            return 'dynamic'
        return 'dynamic'
    return 'api'


# ==================== Scanner 类 ====================

class Scanner:
    def __init__(self, args, db_handler):
        self.args = args
        self.db_handler = db_handler
        self.initial_urls = []
        self.checker = None
        self.whiteList = read(WHITE_SCOPE_PATH)
        self.domain_base_urls = {}

        self.ai_auditor = None
        if self.args.findparam:
            try:
                self.ai_auditor = AISecurityAuditor(request_validation=self.args.request_validation)
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
        try:
            try:
                cleanup_bloom_filters()
            except Exception:
                pass
            if self.db_handler:
                self.db_handler.close()
        except Exception as e:
            print(f"[Cleanup] 清理失败：{e}")

    @staticmethod
    def _is_api_path_blacklisted(api_path: str) -> bool:
        """
        检查 API path 是否匹配黑名单正则

        Args:
            api_path: API 路径

        Returns:
            bool: 如果匹配黑名单返回 True，否则返回 False
        """
        return is_api_path_blacklisted(api_path)

    async def _quick_scan_filter(self, url, status_code, snippet):
        """快速扫描过滤器"""
        url_lower = url.lower()
        snippet_lower = snippet.lower() if snippet else ""

        if status_code == 401:
            return "0"
        if _is_skip_ext(url):
            return "0"
        if (200 <= status_code <= 300) or (500 <= status_code < 600):
            if any(kw in snippet_lower for kw in UNAUTHORIZED_PAGE_KEYWORDS):
                return "0"
            if "<!doctype" in snippet_lower or "<html" in snippet_lower or "<head" in snippet_lower:
                return "0"
        return "1"

    async def run(self):
        """主运行逻辑"""
        os.makedirs("Result", exist_ok=True)
        self.initial_urls = self._load_initial_urls()
        self.checker = DuplicateChecker(db_handler=self.db_handler, initial_root_domain=self.initial_urls)
        self.args.initial_urls = self.initial_urls

        raw_seed_urls = self.load_url()
        scan_seed_urls = []
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
            return

        start_time = time.time()
        await self._scan_recursive(scan_seed_urls, 0, is_seed=True)
        print(f"🏁 任务结束 | 总耗时：{time.time() - start_time:.2f}秒")

    def load_url(self):
        if self.args.url and self.args.url.strip():
            return [self.args.url.strip()]
        return []

    def _load_initial_urls(self):
        white_list_domains = read(WHITE_SCOPE_PATH)
        if self.args.url and self.args.url.strip():
            try:
                seed_root_domain = get_root_domain(self.args.url.strip())
                if seed_root_domain and seed_root_domain not in white_list_domains:
                    white_list_domains.append(seed_root_domain)
            except Exception:
                pass
        return list(set(filter(None, white_list_domains)))

    async def _process_ai_batch(self, batch_all_next_paths_with_source, batch_scan_info_list, batch_next_urls):
        if not self.ai_auditor:
            return

        if not getattr(self.args, 'findparam', False):
            return

        effective_seed = self._get_effective_seed()
        base_prefix = effective_seed.rstrip('/') if effective_seed else None
        origin_url = self.args.url

        all_raw_paths = []
        for item in batch_all_next_paths_with_source:
            for p in item.get("next_paths", []):
                p = p.strip()
                if p and len(p) >= API_MIN_LENGTH:
                    all_raw_paths.append(p)

        verified_clusters = {}
        if base_prefix and _is_already_base_url(base_prefix) and all_raw_paths:
            verified_clusters = self._verify_prefix_clusters(all_raw_paths, origin_url)

        qualified_api_paths = set()
        if getattr(self.args, 'fastscan', False) and batch_next_urls:
            print("⚡ [FastScan] 快速扫描模式已启用")

            urls_to_scan = []
            path_to_url_map = {}
            for item in batch_all_next_paths_with_source:
                source_url = item.get("sourceURL", "").strip()
                next_paths = item.get("next_paths", [])
                if not source_url or not next_paths:
                    continue

                for api_path in next_paths:
                    api_path = api_path.strip()
                    if not api_path or len(api_path) < API_MIN_LENGTH:
                        continue
                    if self._is_api_path_blacklisted(api_path):
                        continue

                    cluster = _get_first_level_prefix(api_path)
                    use_prefix = verified_clusters.get(cluster, True)

                    if use_prefix and base_prefix and _is_already_base_url(base_prefix):
                        full_url = f"{base_prefix}/{api_path.lstrip('/')}"
                    else:
                        parsed = urlparse(source_url)
                        domain_prefix = f"{parsed.scheme}://{parsed.netloc}"
                        full_url = api_path if api_path.startswith("http") else f"{domain_prefix}{api_path}"

                    full_url = full_url.strip()
                    if full_url and full_url not in path_to_url_map:
                        path_to_url_map[full_url] = api_path
                        if not _is_skip_ext(full_url):
                            urls_to_scan.append(full_url)

            if urls_to_scan:
                unique_results, dup_count, stats = await fetch_urls_with_dedup(
                    urls=urls_to_scan, thread_num=50,
                    headers={"User-Agent": generate_user_agent()}, cookies=None, timeout=10)
                url_scan_results = {}
                for result in unique_results:
                    url = result["url"].strip()
                    url_scan_results[url] = {
                        "status_code": result["status_code"], "length": result["length"],
                        "response_content": result["response_content"], "fingerprint": result.get("fingerprint"),
                    }
                filter_count = 0
                for full_url, api_path in path_to_url_map.items():
                    if full_url in url_scan_results:
                        scan_result = url_scan_results[full_url]
                        should_test = await self._quick_scan_filter(
                            url=full_url, status_code=scan_result["status_code"],
                            snippet=scan_result["response_content"][:600])
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
        skipped_dup_count = 0

        all_unique_apis = {}

        for item in batch_all_next_paths_with_source:
            js_url = item.get("sourceURL")
            found_apis = item.get("next_paths", [])

            if not js_url or js_url not in source_map:
                continue

            for api_path in found_apis:
                api_path = api_path.strip()

                if len(api_path) < API_MIN_LENGTH:
                    continue
                if api_path.startswith("http") or api_path.startswith("//"):
                    continue
                if any(api_path.lower().endswith(ext) for ext in ['.png', '.jpg', '.css', '.woff', '.ico']):
                    continue
                if self._is_api_path_blacklisted(api_path):
                    continue

                if api_path not in all_unique_apis:
                    all_unique_apis[api_path] = js_url

        apis_to_scan = []
        for api_path, js_url in all_unique_apis.items():
            if self.checker.is_api_path_processed(api_path):
                skipped_dup_count += 1
            else:
                apis_to_scan.append((api_path, js_url))

        if skipped_dup_count > 0:
            print(f"⏭️ [Path Dedup] Skipped {skipped_dup_count} duplicate API paths in this batch")

        if not apis_to_scan:
            print(f"✅ [Batch] All APIs already processed, skipping AI analysis...")
            return

        mark_data = [(api_path, js_url) for api_path, js_url in apis_to_scan]
        self.checker.mark_api_paths_processed_batch(mark_data)
        print(f"✅ [Dedup] Marked {len(apis_to_scan)} API paths as processed BEFORE analysis")

        js_groups = {}
        for api_path, js_url in apis_to_scan:
            if js_url not in js_groups:
                js_groups[js_url] = []

            cluster = _get_first_level_prefix(api_path)
            use_prefix = verified_clusters.get(cluster, True)

            if use_prefix and base_prefix and _is_already_base_url(base_prefix):
                full_url = f"{base_prefix}/{api_path.lstrip('/')}"
            else:
                from processor.analysis.api.api_scan import data_clean
                cleaned_urls = data_clean(js_url, [api_path], seed_url=effective_seed)
                if cleaned_urls and len(cleaned_urls) > 0:
                    full_url = cleaned_urls[0]
                else:
                    parsed = urlparse(js_url)
                    domain_prefix = f"{parsed.scheme}://{parsed.netloc}"
                    full_url = api_path if api_path.startswith("http") else f"{domain_prefix}{api_path}"

            js_groups[js_url].append((api_path, full_url))

        vuln_records_for_request = []

        for js_url, api_data_list in js_groups.items():
            js_source = source_map.get(js_url, "")
            if not js_source:
                continue

            api_paths = [item[0] for item in api_data_list]

            try:
                batch_ai_advisories = self.ai_auditor.scan_multiple_apis(
                    js_code=js_source,
                    api_paths=api_paths,
                    target_url=effective_seed.strip() if effective_seed else self.args.url.strip()
                )

                for api_path, advisory_report in batch_ai_advisories.items():
                    if not advisory_report:
                        continue

                    print(f"🤖 [AI Advisor] Generated Advisory for {api_path}")
                    print(advisory_report)
                    processed_count += 1

                    full_url = next((item[1] for item in api_data_list if item[0] == api_path), "")

                    record_id = self.db_handler.save_ai_result_with_id(
                        js_url=js_url,
                        full_url=full_url,
                        advisory_report=advisory_report
                    )

                    if record_id:
                        vuln_records_for_request.append({
                            "id": record_id,
                            "full_url": full_url,
                            "http_method": advisory_report.get("method", ""),
                            "params": advisory_report.get("params", ""),
                            "path": advisory_report.get("path", "")
                        })
            except Exception as e:
                print_exc()
                logger.error(f"❌ [AI] Failed to analyze APIs from {js_url}: {e}")

        if processed_count > 0:
            print(f"🤖 [AI Advisor] Batch completed. Generated {processed_count} Advisories.")

        if vuln_records_for_request:
            if not self.args.request_validation:
                print(f"ℹ️  [Request Validation] 未开启请求验证，{len(vuln_records_for_request)} 条记录仅存档")
            else:
                print(f"🏷️ [Classifier] Starting operation type classification for {len(vuln_records_for_request)} records...")

                read_records = []
                write_records = []

                for record in vuln_records_for_request:
                    op_type = self.ai_auditor.classify_operation_type(
                        path=record.get("path", ""),
                        method=record.get("http_method", ""),
                        params=record.get("params", "")
                    )

                    if op_type == "READ":
                        read_records.append(record)
                    else:
                        write_records.append(record)
                        print(f"🚫 [{record.get('path', '')}] 分类: {op_type} → 需人工确认")

                if write_records:
                    self.db_handler.batch_mark_needs_manual_review([r["id"] for r in write_records])
                    print(f"📋 [Classifier] {len(write_records)} records marked as needs_manual_review")

                if read_records:
                    print(f"🚀 [Request Validation] Starting {len(read_records)} READ requests...")
                    try:
                        request_results = await batch_execute_requests(read_records)

                        updated_count = self.db_handler.batch_update_ai_vuln_request_results(request_results)
                        print(f"✅ [Request Validation] Completed. Updated {updated_count} records.")

                    except Exception as e:
                        print_exc()
                        logger.error(f"❌ [Request Validation] Batch request failed: {e}")
                        print(f"❌ [Request Validation] 批量请求失败: {e}")
                else:
                    print(f"ℹ️  [Request Validation] No READ records to validate.")
        else:
            print(f"ℹ️  [Request Validation] No records to validate.")

    async def parallel_fetch(self, batch_dynamic, batch_static, effective_seed=None):
        """异步并行请求：静态 + 动态"""
        tasks = []
        task_order = []
        seed = effective_seed if effective_seed else self.args.url
        if batch_dynamic:
            dynamic_task = get_source_async(urls=batch_dynamic, thread_num=self.args.thread_num, args=self.args,
                                            checker=self.checker, effective_seed=seed)
            tasks.append(dynamic_task)
            task_order.append('dynamic')
        if batch_static:
            static_task = fetch_urls_async(urls=batch_static, thread_num=min(self.args.thread_num, 50),
                                           headers={"User-Agent": generate_user_agent()}, timeout=10)
            tasks.append(static_task)
            task_order.append('static')
        if not tasks:
            return ([], [], set(), []), []
        results = await asyncio.gather(*tasks)
        dynamic_result = ([], [], set(), [])
        static_result = []
        for i, task_type in enumerate(task_order):
            if task_type == 'dynamic':
                dynamic_result = results[i]
            elif task_type == 'static':
                static_result = results[i]
        return dynamic_result, static_result

    def _get_effective_seed(self) -> str:
        """获取当前域名已缓存的 baseURL，如果没有则返回原始 seed_url"""
        if not self.args.url:
            return self.args.url
        root_domain = get_root_domain(self.args.url)
        return self.domain_base_urls.get(root_domain, self.args.url)

    def _collect_base_urls_from_batch(self, scan_info_list):
        """从本批次的 scan_info 中收集已验证的 baseURL，存入域名级缓存"""
        root_domain = get_root_domain(self.args.url) if self.args.url else None
        if not root_domain:
            return
        for info in scan_info_list:
            detected = info.get("detected_base_url")
            if detected:
                existing = self.domain_base_urls.get(root_domain)
                if not existing or _is_more_specific(detected, existing):
                    self.domain_base_urls[root_domain] = detected
                    print(f"🎯 [BaseURL] 域名 {root_domain} → {detected}")

    def _verify_prefix_clusters(self, api_paths, origin_url):
        """
        对 API paths 按第一级前缀聚类，对大类别进行 prefix 验证。

        Returns:
            verified_clusters: {prefix: bool} — 每个类别是否使用 prefix
            未在 dict 中的类别默认使用 prefix
        """
        base_prefix = self._get_effective_seed().rstrip('/')
        if not base_prefix or not _is_already_base_url(base_prefix):
            return {}

        from processor.analysis.api.prefix_agent import (
            _cluster_paths_by_prefix,
            _get_large_clusters,
            verify_prefix_for_clusters,
        )

        all_paths = list(set(p.strip() for p in api_paths if p and len(p) >= 4))
        clusters = _cluster_paths_by_prefix(all_paths)
        large = _get_large_clusters(clusters)

        if not large:
            return {}

        print(f"📊 [Prefix] 发现 {len(large)} 个大类别需验证: {', '.join(f'{k}({len(v)})' for k, v in large.items())}")

        verified = verify_prefix_for_clusters(
            base_prefix=base_prefix,
            seed_url=origin_url,
            api_paths_by_cluster=large,
        )

        return verified

    async def _process_single_batch(self, batch_urls: list, depth: int) -> dict:
        """处理单个批次（提取自 _scan_recursive）"""
        batch_dynamic = [u for u in batch_urls if classify_url(u, is_seed=(depth == 0)) == 'dynamic']
        batch_static = [u for u in batch_urls if classify_url(u, is_seed=(depth == 0)) == 'static']

        effective_seed = self._get_effective_seed()
        dynamic_result, static_result = await self.parallel_fetch(batch_dynamic=batch_dynamic,
                                                                  batch_static=batch_static,
                                                                  effective_seed=effective_seed)

        batch_all_next_urls_with_source = []
        batch_scan_info_list = []
        batch_next_urls = set()
        batch_all_next_paths_with_source = []

        if dynamic_result:
            batch_all_next_urls_with_source, batch_scan_info_list, batch_next_urls, batch_all_next_paths_with_source = dynamic_result

        if static_result:
            for static_resp in static_result:
                if not static_resp.get("error"):
                    parsed = urlparse(static_resp["url"])
                    static_info = {
                        "domain": parsed.hostname, "url": static_resp["url"], "path": parsed.path,
                        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                        "status": static_resp["status_code"], "title": "Static Resource",
                        "length": static_resp["length"], "source_code": static_resp["response_content"],
                        "is_valid": 0, "redirect_count": static_resp.get("redirect_count", 0),
                        "redirect_locations": [], "original_url": static_resp["url"]
                    }
                    try:
                        is_valid, next_urls, next_paths = await process_scan_result(static_info, self.checker,
                                                                                    self.args,
                                                                                    seed_url=effective_seed)
                        if is_valid:
                            static_info["is_valid"] = 1
                            batch_scan_info_list.append(static_info)
                            if next_urls:
                                batch_next_urls.update(next_urls)
                                batch_all_next_urls_with_source.append(
                                    {"next_urls": list(next_urls), "sourceURL": static_resp["url"]})
                                batch_all_next_paths_with_source.append(
                                    {"next_paths": next_paths, "sourceURL": static_resp["url"]})
                        else:
                            batch_scan_info_list.append(static_info)
                    except Exception as e:
                        print(f"⚠️ 静态资源处理失败 {static_resp['url']}: {e}")
                        batch_scan_info_list.append(static_info)
        return {
            "next_urls": batch_next_urls,
            "scan_info_list": batch_scan_info_list,
            "all_next_urls_with_source": batch_all_next_urls_with_source,
            "all_next_paths_with_source": batch_all_next_paths_with_source
        }

    def _check_memory_and_handle(self, depth: int, next_urls: set, remaining_urls: list) -> bool:
        """检查内存并处理溢出，返回是否继续"""
        try:
            mem = psutil.virtual_memory()
            if mem.percent > MEMORY_LIMIT:
                print(f"\n⚠️  内存告警：{mem.percent}% > {MEMORY_LIMIT}% | 触发熔断保护.")
                os.makedirs(OVERFLOW_DIR, exist_ok=True)
                file_id = uuid.uuid4().hex[:8]
                rem_height_children = self.args.height - (depth + 1)
                final_children = [u for u in next_urls if self.checker.should_scan(u)]
                if final_children and rem_height_children >= 0:
                    with open(f"{OVERFLOW_DIR}/overflow_depth_{rem_height_children}_{file_id}_children.txt", "w") as f:
                        f.write("\n".join(final_children))
                rem_height_siblings = self.args.height - depth
                if remaining_urls and rem_height_siblings >= 0:
                    with open(f"{OVERFLOW_DIR}/overflow_depth_{rem_height_siblings}_{file_id}_siblings.txt", "w") as f:
                        f.write("\n".join([u for u in remaining_urls if ".js" in u]))
                self.db_handler.close()
                print(f"🛑 进程主动退出 (Memory Safety)")
                return False
            return True
        except Exception:
            return True

    async def _scan_recursive(self, urls, depth, is_seed=False):
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

        static_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'static']
        dynamic_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'dynamic']
        api_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'api']

        if static_urls: print(f"   📦 静态资源：{len(static_urls)} 个（使用 httpx 快速请求）")
        if dynamic_urls: print(f"   🚀 动态页面：{len(dynamic_urls)} 个（使用 Playwright）")
        if api_urls: print(f"   ⏭️ API 路径：{len(api_urls)} 个（不请求，从 JS 分析）")

        batch_size = BATCH_SIZE
        total_batches = (len(urls_list) + batch_size - 1) // batch_size
        all_scan_info_list = []
        all_next_urls = set()

        for batch_idx in range(0, len(urls_list), batch_size):
            batch_urls = urls_list[batch_idx:batch_idx + batch_size]
            current_batch = batch_idx // batch_size + 1
            print(f"\n[D{depth}] 批次 {current_batch}/{total_batches} (Size: {len(batch_urls)})")

            try:
                batch_result = await asyncio.wait_for(
                    self._process_single_batch(batch_urls, depth),
                    timeout=BATCH_SIZE * 5
                )

                all_scan_info_list.extend(batch_result["scan_info_list"])

                self._collect_base_urls_from_batch(batch_result["scan_info_list"])

                for n_url in batch_result["next_urls"]:
                    if self.checker.should_scan(n_url):
                        all_next_urls.add(n_url)
                if batch_result["all_next_urls_with_source"]:
                    try:
                        self.db_handler.append_data_batch(batch_result["all_next_urls_with_source"], depth=depth)
                        print(f"✅ [DB] 基础数据已存入")
                    except Exception as e:
                        print(f"❌ [DB] 基础数据存储失败：{e}")
                if self.args.findparam and self.ai_auditor:
                    print(f"🤖 [AI] 正在进行 API 逻辑审计...")
                    await self._process_ai_batch(
                        batch_result["all_next_paths_with_source"],
                        batch_result["scan_info_list"],
                        batch_result["next_urls"]
                    )
            except Exception as e:
                print(f"❌ [Fetch Error] 批次 {current_batch} 请求失败：{e}")
                import traceback
                traceback.print_exc()
                continue

            print(f"[D{depth}] 批次 {current_batch}/{total_batches} 扫描完成")
            if current_batch < total_batches:
                await asyncio.sleep(BATCH_SLEEP)

            # 内存熔断检查
            remaining = urls_list[batch_idx + batch_size:]
            if not self._check_memory_and_handle(depth, all_next_urls, remaining):
                return

        if self.args.analyzeSensitiveInfoRex or self.args.analyzeSensitiveInfoAI:
            print(f"🔍 正在提取敏感信息 (Regex/Qwen)...")
            await self._extract_sensitive_info(all_scan_info_list)

        if all_next_urls:
            print(f"➡️  进入深度 {depth + 1}")
            await self._scan_recursive(all_next_urls, depth + 1, is_seed=False)
        else:
            print(f"✅ 深度 {depth} 完成")

    async def _extract_sensitive_info(self, scan_info_list):
        source_map_results = []
        for scan_info in scan_info_list:
            url = scan_info["url"]
            if not (scan_info["is_valid"] == 1 or url in self.initial_urls):
                continue
            if ".js" not in scan_info["url"]:
                continue

            source_code = scan_info.get("source_code", "")
            tail = source_code[-300:] if len(source_code) > 300 else source_code
            has_source_map = "Y" if "sourceMappingURL=" in tail else "N"
            source_map_results.append((url, has_source_map))
            if has_source_map == "Y":
                print(f"🗺️ [SourceMap] 发现 SourceMap 暴露：{url}")

            combined_sensitive_info = set()
            if self.args.analyzeSensitiveInfoAI and self.sensitive_scanner:
                try:
                    ai_results = self.sensitive_scanner.scan(js_code=scan_info["source_code"], js_url=url)
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

        if source_map_results:
            self.db_handler.batch_save_source_map_results(source_map_results)
            yes_count = sum(1 for _, flag in source_map_results if flag == "Y")
            print(f"🗺️ [SourceMap] 检测完成：{len(source_map_results)} 个JS文件，{yes_count} 个暴露了 SourceMap")



if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()
    start_time = time.time()
    os.makedirs("Result", exist_ok=True)
    target_url = args.url.strip() if args.url else "unknown"
    print(f"📂 扫描结果将存入数据库：{db_filename}")
    db_handler = SQLiteStorage(db_filename)
    scanner = Scanner(args, db_handler)
    try:
        asyncio.run(scanner.run())
        run_time = round(time.time() - start_time, 2)
        print(f"本次扫描耗时：{run_time}s")
    except Exception as e:
        run_time = round(time.time() - start_time, 2)
        error_content = f"❌ 错误：{str(e)}\n⏱️ 耗时：{run_time}s"
        send_feishu_notify("【扫描任务报警】", error_content)
        print_exc()
    finally:
        scanner._cleanup_resources()