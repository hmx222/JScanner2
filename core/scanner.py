import asyncio
import atexit
import logging
import os
import time
import traceback
import uuid
import warnings
from traceback import print_exc
from urllib.parse import urlparse

import psutil
from user_agent import generate_user_agent

from config.scanner_rules import UNAUTHORIZED_PAGE_KEYWORDS, is_api_path_blacklisted
from config.config import MEMORY_LIMIT, OVERFLOW_DIR
from crawler.httpx_crawler import fetch_urls_with_dedup
from crawler.response_process import process_scan_result
from crawler.url_classifier import classify_url, is_skip_ext  # URL 分类器
from crawler.fetcher import parallel_fetch                    # 并发爬取器
from infra.dedup import DuplicateChecker
from processor.analysis.api.api_scan import data_clean
from processor.analysis.secret.js_sensitive_rex import find_all_info_by_rex
from processor.analysis.secret.secret_scanner import cleanup_bloom_filters, remove_html_tags
from processor.analysis.api.request_executor import batch_execute_requests

warnings.filterwarnings("ignore")

# ==================== 全局常量 ====================
BATCH_SIZE = 200          # 每批处理数
BATCH_SLEEP = 0.2         # 批次间隔秒
API_MIN_LENGTH = 4        # API 最小长度

# 初始化日志
logger = logging.getLogger(__name__)  # 模块日志器


class Scanner:
    """
    扫描器主类

    协调整个扫描流程的各个阶段：
    1. URL 加载和初始化
    2. 递归爬取（Playwright 动态 + httpx 静态）
    3. AI 驱动的 API 参数分析
    4. 敏感信息检测（正则 + AI）
    5. HTTP 请求验证
    6. 内存熔断保护
    """

    def __init__(self, args, db_handler, checker=None,
                 ai_auditor=None, sensitive_scanner=None):
        """
        初始化扫描器

        Args:
            args: 命令行参数对象
            db_handler: 数据库处理器（SQLiteStorage 实例）
            checker: 去重管理器（可选，外部传入）
            ai_auditor: AI 安全审计器（可选，外部传入）
            sensitive_scanner: 敏感信息扫描器（可选，外部传入）
        """
        self.args = args                    # 命令行参数
        self.db_handler = db_handler        # 数据库处理器
        self.checker = checker              # 去重管理器
        self.ai_auditor = ai_auditor        # AI 审计器
        self.sensitive_scanner = sensitive_scanner  # 敏感扫描器

        atexit.register(self._cleanup_resources)  # 注册退出清理

    def _cleanup_resources(self):
        """清理资源：关闭布隆过滤器和数据库连接"""
        try:
            try:
                cleanup_bloom_filters()
            except Exception:
                pass
            if self.db_handler:
                self.db_handler.close()
        except Exception as e:  # 捕获清理异常
            print(f"[Cleanup] 清理失败：{e}")

    async def _quick_scan_filter(self, url, status_code, snippet):
        """
        快速扫描过滤器

        Args:
            url: 目标 URL
            status_code: HTTP 状态码
            snippet: 响应内容片段（前 600 字符）

        Returns:
            str: "0" 表示跳过，"1" 表示值得分析
        """
        url_lower = url.lower()                 # URL 转小写
        snippet_lower = snippet.lower() if snippet else ""  # 片段转小写

        if status_code == 401:
            return "0"
        if is_skip_ext(url):
            return "0"
        if (200 <= status_code <= 300) or (500 <= status_code < 600):
            if any(kw in snippet_lower for kw in UNAUTHORIZED_PAGE_KEYWORDS):
                return "0"
            if "<!doctype" in snippet_lower or "<html" in snippet_lower or "<head" in snippet_lower:
                return "0"
        return "1"

    async def run(self):
        """主运行逻辑"""
        seed_url = self.args.url.strip() if self.args.url and self.args.url.strip() else None  # 种子URL
        if not seed_url:
            return
        if not self.checker.is_url_visited(seed_url):
            self.checker.mark_url_visited(seed_url)
        else:
            print(f"初始 URL 已在历史记录中，跳过：{seed_url}")
            return

        start_time = time.time()  # 记录开始时间
        await self._scan_recursive([seed_url], 0, is_seed=True)
        print(f"🏁 任务结束 | 总耗时：{time.time() - start_time:.2f}秒")

    async def _fastscan_prefilter(self, batch_all_next_paths_with_source, batch_next_urls) -> set:
        """FastScan 预过滤：快速请求筛选有价值的 API"""
        qualified_api_paths = set()  # 合格 API 路径集

        if getattr(self.args, 'fastscan', False) and batch_next_urls:
            print("⚡ [FastScan] 快速扫描模式已启用")
            urls_to_scan = []  # 待扫描 URL 列表
            for url in batch_next_urls:  # 遍历下一批 URL
                url = url.strip()       # 去除空格
                if not url or is_skip_ext(url):
                    continue
                urls_to_scan.append(url)

            if urls_to_scan:
                unique_results, dup_count, stats = await fetch_urls_with_dedup(  # 批量去重请求
                    urls=urls_to_scan, thread_num=50,
                    headers={"User-Agent": generate_user_agent()}, cookies=None, timeout=10)

                url_scan_results = {}  # URL 扫描结果字典
                for result in unique_results:  # 遍历唯一结果
                    url = result["url"].strip()  # 取出 URL
                    url_scan_results[url] = {    # 存入扫描结果
                        "status_code": result["status_code"],
                        "length": result["length"],
                        "response_content": result["response_content"],
                        "fingerprint": result.get("fingerprint"),
                    }

                filter_count = 0  # 过滤计数
                for item in batch_all_next_paths_with_source:  # 遍历路径来源
                    source_url = item.get("sourceURL", "").strip()  # 来源 URL
                    next_paths = item.get("next_paths", [])         # 提取路径列表
                    if not source_url or not next_paths:
                        continue

                    for api_path in next_paths:  # 遍历 API 路径
                        api_path = api_path.strip()  # 去除空格
                        if not api_path or len(api_path) < API_MIN_LENGTH:
                            continue
                        if is_api_path_blacklisted(api_path):
                            filter_count += 1
                            continue

                        cleaned_urls = data_clean(source_url, [api_path], seed_url=self.args.url)  # 清洗 URL
                        if cleaned_urls and len(cleaned_urls) > 0:
                            full_url = cleaned_urls[0]  # 取完整 URL
                        else:
                            parsed = urlparse(source_url)  # 解析来源 URL
                            domain_prefix = f"{parsed.scheme}://{parsed.netloc}"  # 拼接域名前缀
                            full_url = api_path if api_path.startswith("http") else f"{domain_prefix}{api_path}"  # 拼接完整 URL

                        full_url = full_url.strip()  # 去空格
                        if full_url in url_scan_results:
                            scan_result = url_scan_results[full_url]  # 获取扫描结果
                            should_test = await self._quick_scan_filter(  # 快速过滤器判断
                                url=full_url, status_code=scan_result["status_code"],
                                snippet=scan_result["response_content"][:600])
                            if should_test == "1":
                                qualified_api_paths.add(api_path)
                            else:
                                filter_count += 1

                print(f"🌐 [Quick Scan] {len(urls_to_scan)} URLs → {dup_count} duplicates → {len(qualified_api_paths)} qualified")
                print(f"🔍 [Filter Stats] Filtered: {filter_count}, Passed: {len(qualified_api_paths)}")
        else:
            print("ℹ️ [FastScan] 快速扫描模式未启用，将分析所有 API")

        return qualified_api_paths

    def _build_source_map(self, batch_scan_info_list) -> dict:
        """构建 JS 源代码映射（JS URL -> 源码）"""
        source_map = {}  # 源码映射字典
        for info in batch_scan_info_list:  # 遍历扫描信息
            if info.get("source_code") and info.get("url") and ".js" in info["url"]:
                try:
                    clean_code = remove_html_tags(info["source_code"])  # 去除 HTML 标签
                    source_map[info["url"]] = clean_code  # 存入清洗后源码
                except:
                    source_map[info["url"]] = info["source_code"]  # 存原始源码
        return source_map

    def _collect_and_dedup_apis(self, batch_all_next_paths_with_source, source_map, qualified_api_paths):
        """收集唯一 API paths → 全局去重 → 标记已处理"""
        all_unique_apis = {}  # 去重后的 API 路径

        for item in batch_all_next_paths_with_source:  # 遍历路径来源
            js_url = item.get("sourceURL")       # 来源 JS URL
            found_apis = item.get("next_paths", [])  # 发现的 API 列表

            if not js_url or js_url not in source_map:
                continue

            for api_path in found_apis:  # 遍历发现 API
                api_path = api_path.strip()  # 去空格

                if len(api_path) < API_MIN_LENGTH:
                    continue
                if api_path.startswith("http") or api_path.startswith("//"):
                    continue
                if any(api_path.lower().endswith(ext) for ext in ['.png', '.jpg', '.css', '.woff', '.ico']):
                    continue
                if is_api_path_blacklisted(api_path):
                    continue
                if getattr(self.args, 'fastscan', False):
                    if qualified_api_paths and api_path not in qualified_api_paths:
                        continue

                if api_path not in all_unique_apis:
                    all_unique_apis[api_path] = js_url  # 记录唯一 API

        apis_to_scan = []          # 待扫描 API 列表
        skipped_dup_count = 0      # 跳过重复数
        for api_path, js_url in all_unique_apis.items():  # 遍历唯一 API
            if self.checker.is_api_path_processed(api_path):
                skipped_dup_count += 1
            else:
                apis_to_scan.append((api_path, js_url))

        if skipped_dup_count > 0:
            print(f"⏭️ [Path Dedup] Skipped {skipped_dup_count} duplicate API paths in this batch")

        if not apis_to_scan:
            print(f"✅ [Batch] All APIs already processed, skipping AI analysis...")
            return None

        mark_data = [(api_path, js_url) for api_path, js_url in apis_to_scan]  # 待标记数据
        self.checker.mark_api_paths_processed_batch(mark_data)
        print(f"✅ [Dedup] Marked {len(apis_to_scan)} API paths as processed BEFORE analysis")

        return apis_to_scan

    async def _run_ai_and_validate(self, apis_to_scan, source_map):
        """按 JS 文件分组进行 AI 分析 + HTTP 请求验证"""
        processed_count = 0  # 已处理计数

        js_groups = {}  # JS 分组字典
        for api_path, js_url in apis_to_scan:  # 遍历待扫描 API
            if js_url not in js_groups:
                js_groups[js_url] = []  # 初始化分组

            cleaned_urls = data_clean(js_url, [api_path], seed_url=self.args.url)  # 清洗 URL
            if cleaned_urls and len(cleaned_urls) > 0:
                full_url = cleaned_urls[0]  # 取完整 URL
            else:
                parsed = urlparse(js_url)  # 解析 JS URL
                domain_prefix = f"{parsed.scheme}://{parsed.netloc}"  # 域名前缀
                full_url = api_path if api_path.startswith("http") else f"{domain_prefix}{api_path}"  # 拼接完整 URL

            js_groups[js_url].append((api_path, full_url))

        vuln_records_for_request = []  # 待验证漏洞记录

        for js_url, api_data_list in js_groups.items():  # 遍历 JS 分组
            js_source = source_map.get(js_url, "")  # 获取 JS 源码
            if not js_source:
                continue

            api_paths = [item[0] for item in api_data_list]  # 提取 API 路径列表

            try:
                batch_ai_advisories = self.ai_auditor.scan_multiple_apis(  # AI 批量审计
                    js_code=js_source,
                    api_paths=api_paths,
                    target_url=self.args.url.strip()
                )

                for api_path, advisory_report in batch_ai_advisories.items():  # 遍历审计报告
                    if not advisory_report:
                        continue

                    print(f"🤖 [AI Advisor] Generated Advisory for {api_path}")
                    print(advisory_report)
                    processed_count += 1

                    full_url = next((item[1] for item in api_data_list if item[0] == api_path), "")  # 匹配完整 URL
                    record_id = self.db_handler.save_ai_result_with_id(  # 保存 AI 结果
                        js_url=js_url,
                        full_url=full_url,
                        advisory_report=advisory_report
                    )

                    if record_id:
                        vuln_records_for_request.append({  # 追加验证记录
                            "id": record_id,
                            "full_url": full_url,
                            "http_method": advisory_report.get("method", ""),
                            "params": advisory_report.get("params", "")
                        })

            except Exception as e:  # 捕获分析异常
                print_exc()
                logger.error(f"❌ [AI] Failed to analyze APIs from {js_url}: {e}")

        if processed_count > 0:
            print(f"🤖 [AI Advisor] Batch completed. Generated {processed_count} Advisories.")

        if vuln_records_for_request:
            print(f"🚀 [Request Validation] Starting {len(vuln_records_for_request)} requests...")
            try:
                request_results = await batch_execute_requests(vuln_records_for_request)  # 批量请求验证
                updated_count = self.db_handler.batch_update_ai_vuln_request_results(request_results)  # 更新结果
                print(f"✅ [Request Validation] Completed. Updated {updated_count} records.")
            except Exception as e:  # 捕获请求异常
                print_exc()
                logger.error(f"❌ [Request Validation] Batch request failed: {e}")
                print(f"❌ [Request Validation] 批量请求失败: {e}")
        else:
            print(f"ℹ️ [Request Validation] No records to validate.")

    async def _process_ai_batch(self, batch_all_next_paths_with_source, batch_scan_info_list, batch_next_urls):
        """
        AI 批量分析处理（核心 AI 流水线 - 编排层）

        将分析流程委派给 4 个子步骤：
        1. _fastscan_prefilter — 快速请求预过滤
        2. _build_source_map — 构建 JS 源码映射
        3. _collect_and_dedup_apis — 收集+去重 API paths
        4. _run_ai_and_validate — AI 分析 + 请求验证
        """
        if not self.ai_auditor:
            return

        if not getattr(self.args, 'findparam', False):
            return

        qualified_api_paths = await self._fastscan_prefilter(batch_all_next_paths_with_source, batch_next_urls)  # 快速预过滤
        source_map = self._build_source_map(batch_scan_info_list)                  # 构建源码映射
        apis_to_scan = self._collect_and_dedup_apis(batch_all_next_paths_with_source, source_map, qualified_api_paths)  # 收集去重 API
        if not apis_to_scan:
            return

        await self._run_ai_and_validate(apis_to_scan, source_map)

    async def _process_single_batch(self, batch_urls: list, depth: int) -> dict:
        """处理单个批次的 URL"""
        batch_dynamic = [u for u in batch_urls if classify_url(u, is_seed=(depth == 0)) == 'dynamic']  # 动态 URL 列表
        batch_static = [u for u in batch_urls if classify_url(u, is_seed=(depth == 0)) == 'static']    # 静态 URL 列表

        dynamic_result, static_result = await parallel_fetch(batch_dynamic=batch_dynamic,
                                                            batch_static=batch_static,
                                                            thread_num=self.args.thread_num,
                                                            args=self.args,
                                                            checker=self.checker)  # 并行获取结果

        batch_all_next_urls_with_source = []   # 带来源的下一级 URL
        batch_scan_info_list = []              # 批次扫描信息列表
        batch_next_urls = set()                # 下一批 URL 集合
        batch_all_next_paths_with_source = []  # 带来源的下一级路径

        if dynamic_result:
            batch_all_next_urls_with_source, batch_scan_info_list, batch_next_urls, batch_all_next_paths_with_source = dynamic_result  # 解包动态结果

        if static_result:
            for static_resp in static_result:  # 遍历静态响应
                if not static_resp.get("error"):
                    parsed = urlparse(static_resp["url"])  # 解析 URL
                    static_info = {                        # 静态资源信息
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
                        is_valid, next_urls, next_paths = await process_scan_result(static_info, self.checker,
                                                                                    self.args, seed_url=self.args.url)  # 处理扫描结果
                        if is_valid:
                            static_info["is_valid"] = 1  # 标记为有效
                            batch_scan_info_list.append(static_info)
                            if next_urls:
                                batch_next_urls.update(next_urls)
                                batch_all_next_urls_with_source.append(
                                    {"next_urls": list(next_urls), "sourceURL": static_resp["url"]})
                                batch_all_next_paths_with_source.append(
                                    {"next_paths": next_paths, "sourceURL": static_resp["url"]})
                        else:
                            batch_scan_info_list.append(static_info)
                    except Exception as e:  # 捕获处理异常
                        print(f"⚠️ 静态资源处理失败 {static_resp['url']}: {e}")
                        batch_scan_info_list.append(static_info)

        return {
            "next_urls": batch_next_urls,
            "scan_info_list": batch_scan_info_list,
            "all_next_urls_with_source": batch_all_next_urls_with_source,
            "all_next_paths_with_source": batch_all_next_paths_with_source
        }

    def _check_memory_and_handle(self, depth: int, next_urls: set, remaining_urls: list) -> bool:
        """检查内存使用并处理熔断保护"""
        try:
            mem = psutil.virtual_memory()  # 获取内存状态
            if mem.percent > MEMORY_LIMIT:
                print(f"\n⚠️ 内存告警：{mem.percent}% > {MEMORY_LIMIT}% | 触发熔断保护.")
                os.makedirs(OVERFLOW_DIR, exist_ok=True)
                file_id = uuid.uuid4().hex[:8]  # 生成唯一文件 ID

                rem_height_children = self.args.height - (depth + 1)  # 剩余子层高度
                final_children = [u for u in next_urls if self.checker.should_scan(u)]  # 可扫描子 URL
                if final_children and rem_height_children >= 0:
                    with open(f"{OVERFLOW_DIR}/overflow_depth_{rem_height_children}_{file_id}_children.txt", "w") as f:  # 写入文件
                        f.write("\n".join(final_children))

                rem_height_siblings = self.args.height - depth  # 剩余同级高度
                if remaining_urls and rem_height_siblings >= 0:
                    with open(f"{OVERFLOW_DIR}/overflow_depth_{rem_height_siblings}_{file_id}_siblings.txt", "w") as f:  # 写入文件
                        f.write("\n".join([u for u in remaining_urls if ".js" in u]))

                self.db_handler.close()
                print(f"🛑 进程主动退出 (Memory Safety)")
                return False
            return True
        except Exception:
            return True

    async def _scan_recursive(self, urls, depth, is_seed=False):
        """递归扫描主流程（深度优先）"""
        if depth > self.args.height:
            return

        raw_urls_list = [url.strip() for url in urls if url.strip()]  # 原始 URL 列表
        urls_list = []  # 有效 URL 列表
        if depth > 0:
            for u in raw_urls_list:  # 遍历原始 URL
                if self.checker.should_scan(u):
                    self.checker.mark_url_visited(u)
                    urls_list.append(u)
        else:
            for u in raw_urls_list:  # 遍历种子 URL
                if self.checker.is_within_scope(u):
                    urls_list.append(u)

        if not urls_list:
            return
        print(f"🔍 深度 {depth} 扫描开始 | URL 数：{len(urls_list)}")

        static_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'static']    # 静态 URL 列表
        dynamic_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'dynamic']  # 动态 URL 列表
        api_urls = [u for u in urls_list if classify_url(u, is_seed=(depth == 0)) == 'api']          # API URL 列表

        if static_urls: print(f"   📦 静态资源：{len(static_urls)} 个（使用 httpx 快速请求）")
        if dynamic_urls: print(f"   🚀 动态页面：{len(dynamic_urls)} 个（使用 Playwright）")
        if api_urls: print(f"   ⏭️ API 路径：{len(api_urls)} 个（不请求，从 JS 分析）")

        batch_size = BATCH_SIZE  # 批次大小
        total_batches = (len(urls_list) + batch_size - 1) // batch_size  # 总批次数
        all_scan_info_list = []  # 全部扫描信息
        all_next_urls = set()    # 全部下一级 URL

        for batch_idx in range(0, len(urls_list), batch_size):  # 按批次遍历
            batch_urls = urls_list[batch_idx:batch_idx + batch_size]  # 当前批次 URL
            current_batch = batch_idx // batch_size + 1  # 当前批次号
            print(f"\n[D{depth}] 批次 {current_batch}/{total_batches} (Size: {len(batch_urls)})")

            try:
                batch_result = await asyncio.wait_for(  # 超时等待批次结果
                    self._process_single_batch(batch_urls, depth),
                    timeout=BATCH_SIZE * 5
                )

                all_scan_info_list.extend(batch_result["scan_info_list"])
                for n_url in batch_result["next_urls"]:  # 遍历下一级 URL
                    if self.checker.should_scan(n_url):
                        all_next_urls.add(n_url)

                if batch_result["all_next_urls_with_source"]:
                    try:
                        self.db_handler.append_data_batch(batch_result["all_next_urls_with_source"], depth=depth)
                        print(f"✅ [DB] 基础数据已存入")
                    except Exception as e:  # 捕获存储异常
                        print(f"❌ [DB] 基础数据存储失败：{e}")

                if self.args.findparam and self.ai_auditor:
                    print(f"🤖 [AI] 正在进行 API 逻辑审计...")
                    await self._process_ai_batch(
                        batch_result["all_next_paths_with_source"],
                        batch_result["scan_info_list"],
                        batch_result["next_urls"]
                    )

            except Exception as e:  # 捕获批次异常
                print(f"❌ [Fetch Error] 批次 {current_batch} 请求失败：{e}")
                traceback.print_exc()
                continue

            print(f"[D{depth}] 批次 {current_batch}/{total_batches} 扫描完成")
            if current_batch < total_batches:
                await asyncio.sleep(BATCH_SLEEP)

            remaining = urls_list[batch_idx + batch_size:]  # 剩余 URL
            if not self._check_memory_and_handle(depth, all_next_urls, remaining):
                return

        if self.args.analyzeSensitiveInfoRex or self.args.analyzeSensitiveInfoAI:
            print(f"🔍 正在提取敏感信息 (Regex/Qwen)...")
            await self._extract_sensitive_info(all_scan_info_list)

        if all_next_urls:
            print(f"➡️ 进入深度 {depth + 1}")
            await self._scan_recursive(all_next_urls, depth + 1, is_seed=False)
        else:
            print(f"✅ 深度 {depth} 完成")

    async def _extract_sensitive_info(self, scan_info_list):
        """提取敏感信息（正则 + AI 双模式）"""
        source_map_results = []  # SourceMap 检测结果
        for scan_info in scan_info_list:  # 遍历扫描信息
            url = scan_info["url"]  # 当前 URL
            if scan_info["is_valid"] != 1:
                continue
            if ".js" not in scan_info["url"]:
                continue

            source_code = scan_info.get("source_code", "")  # 获取源码
            tail = source_code[-300:] if len(source_code) > 300 else source_code  # 取末尾 300 字符
            has_source_map = "Y" if "sourceMappingURL=" in tail else "N"  # 是否含 SourceMap
            source_map_results.append((url, has_source_map))
            if has_source_map == "Y":
                print(f"🗺️ [SourceMap] 发现 SourceMap 暴露：{url}")

            combined_sensitive_info = set()  # 合并敏感信息集合

            if self.args.analyzeSensitiveInfoAI and self.sensitive_scanner:
                try:
                    ai_results = self.sensitive_scanner.scan(js_code=scan_info["source_code"], js_url=url)  # AI 扫描敏感信息
                    if ai_results:
                        for item in ai_results:  # 遍历 AI 结果
                            combined_sensitive_info.add(item.get("value", ""))
                        high_risk = [r for r in ai_results if r.get("risk_level") == "High"]  # 高风险项
                        if high_risk:
                            print(f"🔥 [High Risk] URL: {url}")
                            for hr in high_risk[:5]:  # 遍历前 5 高风险
                                value_preview = hr.get('value', '')[:50]  # 值预览
                                print(f"   └─ {value_preview}...")
                                print(f"      类型：{hr.get('secret_type', 'unknown')}")
                                suggestion = hr.get('test_suggestion', '')[:50]  # 测试建议
                                print(f"      建议：{suggestion}...")
                except Exception as e:  # 捕获 AI 扫描异常
                    print_exc()
                    logger.error(f"❌ [AI Scan] 分析失败 {url}: {e}")
                    print(f"❌ [AI Scan] 分析失败 {url}: {e}")

            if self.args.analyzeSensitiveInfoRex:
                try:
                    rex_results = find_all_info_by_rex(scan_info["source_code"])  # 正则扫描敏感信息
                    if rex_results:
                        combined_sensitive_info.update(rex_results)
                except Exception:
                    pass

        if source_map_results:
            self.db_handler.batch_save_source_map_results(source_map_results)
            yes_count = sum(1 for _, flag in source_map_results if flag == "Y")  # 暴露 SourceMap 数
            print(f"🗺️ [SourceMap] 检测完成：{len(source_map_results)} 个JS文件，{yes_count} 个暴露了 SourceMap")
