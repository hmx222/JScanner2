import asyncio
import hashlib
import re
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import httpx
from httpx import Limits
from playwright.async_api import Request, async_playwright, Page, BrowserContext
from rich.markup import escape
from tqdm.asyncio import tqdm_asyncio
from user_agent import generate_user_agent

# 从你的项目导入
from HttpHandle.DuplicateChecker import DuplicateChecker

# 不需要加载的资源类型，节省带宽和内存
BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

# 全局超时设置 (秒)
GLOBAL_TIMEOUT = 30

# 最大允许跳转次数 (0=不允许跳转，1=允许 1 次，2=允许 2 次...)
MAX_REDIRECT_COUNT = 1


# def get_webpage_title(html_source):
#     """获取页面标题"""
#     try:
#         if not html_source:
#             return "NULL"
#         soup = BeautifulSoup(html_source, 'html.parser')
#         title_tag = soup.find('title')
#         if title_tag and title_tag.text:
#             return title_tag.text.strip()[:100]
#         return "NULL"
#     except:
#         return "NULL"
#

def normalize_response(text):
    """响应归一化（移除动态字段）"""
    if not text:
        return ""

    dynamic_patterns = [
        (r'"requestId"\s*:\s*"[^"]*"', '"requestId":"{{DYNAMIC}}"'),
        (r'"traceId"\s*:\s*"[^"]*"', '"traceId":"{{DYNAMIC}}"'),
        (r'"timestamp"\s*:\s*\d+', '"timestamp":{{DYNAMIC}}'),
        (r'"nonce"\s*:\s*"[^"]*"', '"nonce":"{{DYNAMIC}}"'),
        (r'"uuid"\s*:\s*"[^"]*"', '"uuid":"{{DYNAMIC}}"'),
        (r'"sign"\s*:\s*"[^"]*"', '"sign":"{{DYNAMIC}}"'),
    ]

    for pattern, replacement in dynamic_patterns:
        text = re.sub(pattern, replacement, text)
    text = re.sub(r'\s+', '', text)
    return text


def get_response_fingerprint(text):
    """计算响应指纹 Hash"""
    normalized = normalize_response(text)
    return hashlib.md5(normalized.encode()).hexdigest()


def _get_status_priority(status_code):
    """状态码优先级（越高越有价值）"""
    if status_code in [401, 403]:
        return 3
    if status_code >= 500:
        return 3
    if status_code in [200, 201, 301, 302]:
        return 2
    if status_code == 404:
        return 1
    return 2


@asynccontextmanager
async def get_playwright_page(context: BrowserContext):
    """异步上下文管理器：创建和自动关闭页面"""
    page = await context.new_page()
    try:
        yield page
    finally:
        try:
            # 强制超时关闭，防止僵尸页面占用内存
            await asyncio.wait_for(page.close(), timeout=3.0)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass


async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio,
                           follow_redirects: bool = True):
    """
    Args:
        page: Playwright Page 对象
        url: 目标 URL
        progress: 进度条
    """
    captured_resources = set()
    redirect_count = 0  # 跳转次数计数器
    redirect_locations = []  # 记录所有跳转目标
    final_status = None
    final_url = url

    try:
        # 路由拦截：过滤图片字体等无用资源
        await page.route("**/*", lambda route: route.abort()
        if route.request.resource_type in BLOCKED_RESOURCE_TYPES
        else route.continue_())

        # 监听请求：捕获动态加载的 JS 文件
        def handle_request(request: Request):
            res_url = request.url
            res_type = request.resource_type

            if res_type == "script" or res_url.split('?')[0].endswith('.js'):
                captured_resources.add(res_url)
            elif res_type == "document" and res_url != "about:blank":
                captured_resources.add(res_url)

        page.on("request", handle_request)

        # 监听响应：统计 302 跳转次数
        def handle_response(response):
            nonlocal redirect_count, final_url
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('location')
                redirect_count += 1
                redirect_locations.append(location)
                final_url = response.url

        page.on("response", handle_response)

        # 访问页面，超时 30s
        timeout_ms = GLOBAL_TIMEOUT * 1000
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

        # 获取最终状态和 URL
        if response:
            final_status = response.status
            final_url = response.url

        if redirect_count > MAX_REDIRECT_COUNT:
            print(f"❌ 跳转次数过多 ({redirect_count} 次)，超过限制 ({MAX_REDIRECT_COUNT} 次)，已终止处理")
            print(f"   跳转链：{' -> '.join(redirect_locations)}")
            return {
                "type": "redirect_loop",
                "redirect_count": redirect_count,
                "redirect_locations": redirect_locations,
                "url": url,
                "status": final_status
            }, url, final_status

        if redirect_count > 0:
            print(f"✅ 允许 {redirect_count} 次跳转，继续抓取最终页面：{final_url}")

        # 获取页面内容
        html_content = await page.content()

        # 将捕获到的动态资源拼接到 HTML 尾部
        if captured_resources:
            append_html = "\n<!-- JScanner Captured Resources (Dynamic) -->\n"
            for res in captured_resources:
                safe_res = escape(res)
                append_html += f'<script src="{safe_res}"></script>\n'
            html_content += append_html

        return {
            "type": "success",
            "html": html_content,
            "url": final_url,
            "status": final_status,
            "redirect_count": redirect_count,
            "redirect_locations": redirect_locations
        }, final_url, final_status

    except Exception as e:
        error_msg = str(e)
        if "timeout" in error_msg.lower():
            print(f"⚠️ 抓取超时（30s）：{url}")
        else:
            print(f"❌ 抓取失败：{url} - {error_msg}")

        return {
            "type": "error",
            "error": error_msg,
            "url": url,
            "status": None
        }, url, None
    finally:
        progress.update(1)


async def process_scan_result(scan_info, checker: DuplicateChecker, args):
    """处理扫描结果（去重 + 提取下一层 URL）"""
    url = scan_info["url"]
    source = scan_info.get("source_code", "")
    status = scan_info["status"]
    title = scan_info.get("title", "NULL")
    length = scan_info.get("length", 0)

    # 1. 基础过滤
    if not checker.is_within_scope(url):
        return False, set(), []
    if status == 404:
        return False, set(), []
    if not source or length < 200:
        return False, set(), []
    if len(source) > 20 * 1024 * 1024:  # 限制 20MB
        return False, set(), []

    # 2. 内容去重 (仅针对非 JS 文件)
    if ".js" not in url:
        if checker.is_page_duplicate(url, source, title):
            return False, set(), []

    # 3. 标记为已访问
    checker.mark_url_visited(url)

    # 4. 提取下一层 URL
    next_urls = set()
    rex_output = []

    try:
        from JsHandle.pathScan import analysis_by_rex, data_clean
        rex_output = analysis_by_rex(source)
        next_urls = set(data_clean(url, rex_output))
    except Exception:
        rex_output = []

    # 筛选条件：长度>4 且 不包含"."且 至少包含 1 个"/"
    if rex_output:
        filtered_rex_output = []
        for item in rex_output:
            is_string = isinstance(item, str)
            length_ok = len(item) > 4
            no_dot = "." not in item
            enough_slash = item.count('/') >= 1

            if is_string and length_ok and no_dot and enough_slash:
                filtered_rex_output.append(item)
        rex_output = filtered_rex_output

    return True, next_urls, rex_output


async def get_source_async(urls, thread_num, args, checker: DuplicateChecker,
                           storage_state: str = None):
    """
    Playwright 异步批量请求入口

    Args:
        urls: URL 列表
        thread_num: 并发线程数
        args: 命令行参数
        checker: 去重检查器
        storage_state: Cookie 存储文件路径 (用于保持登录状态)

    Returns:
        all_next_urls_with_source: 来源 URL -> 子 URL 关系
        scan_info_list: 扫描详情列表
        all_next_urls: 下一层待爬取的纯 URL 集合
        all_next_paths_with_source: 来源 URL -> 子路径关系
        redirect_stats: 跳转统计信息
    """
    progress = tqdm_asyncio(total=len(urls), desc="🕷️ Crawling", unit="url", ncols=100)

    # 局部变量，避免全局状态污染
    request_failed_urls = set()
    redirect_stats = {
        "total": 0,
        "success": 0,
        "error": 0,
        "redirect_0": 0,  # 0 次跳转
        "redirect_1": 0,  # 1 次跳转 (允许)
        "redirect_loop": 0  # 多次跳转 (禁止)
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=not getattr(args, 'visible', False),
            proxy={"server": args.proxy} if getattr(args, 'proxy', None) else None,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
        )

        # 创建全局上下文
        context_kwargs = {
            "user_agent": generate_user_agent(),
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }

        if storage_state:
            try:
                context_kwargs["storage_state"] = storage_state
                print(f"📦 加载 Cookie 状态：{storage_state}")
            except Exception as e:
                print(f"⚠️ 加载 Cookie 状态失败：{e}")

        global_context = await browser.new_context(**context_kwargs)

        try:
            semaphore = asyncio.Semaphore(thread_num)

            async def bounded_fetch(url):
                async with semaphore:
                    async with get_playwright_page(global_context) as page:
                        return await fetch_page_async(page, url, progress, follow_redirects=True)

            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])

        finally:
            await global_context.close()
            await browser.close()
            progress.close()

    # 处理失败 URL 的 fallback (使用 httpx)
    for scan_result, url, status in results:
        if scan_result and scan_result.get("type") == "error":
            request_failed_urls.add(url)

    if request_failed_urls:
        print(f"🔄 尝试使用 httpx 补救 {len(request_failed_urls)} 个失败的 URL...")
        fallback_results = await fetch_urls_async(
            urls=list(request_failed_urls),
            thread_num=min(thread_num, 10),
            headers=None,
            cookies=None,
            timeout=GLOBAL_TIMEOUT,
            method="GET"
        )

        for fb_result in fallback_results:
            if not fb_result.get("error"):
                html = fb_result.get("response_content", "")
                fb_url = fb_result.get("url", "")
                fb_status = fb_result.get("status_code", 500)
                results.append(({
                                    "type": "success",
                                    "html": html,
                                    "url": fb_url,
                                    "status": fb_status,
                                    "redirect_count": 0,
                                    "redirect_locations": []
                                }, fb_url, fb_status))

    # 处理结果
    scan_info_list = []
    all_next_urls_with_source = []
    all_next_paths_with_source = []
    all_next_urls = set()

    for item in results:
        if not item or item[0] is None:
            continue

        scan_result, url, status = item

        # 处理多次跳转情况 (超过 1 次)
        if scan_result.get("type") == "redirect_loop":
            redirect_stats["redirect_loop"] += 1
            redirect_count = scan_result.get("redirect_count", 0)
            print(f"🚫 跳过 {url} (跳转 {redirect_count} 次，超过限制)")
            continue

        # 处理错误情况
        if scan_result.get("type") == "error":
            redirect_stats["error"] += 1
            continue

        # 处理成功情况 (包含 0 次和 1 次跳转)
        if scan_result.get("type") == "success":
            redirect_count = scan_result.get("redirect_count", 0)

            if redirect_count == 0:
                redirect_stats["redirect_0"] += 1
            elif redirect_count == 1:
                redirect_stats["redirect_1"] += 1

            redirect_stats["success"] += 1

            html = scan_result.get("html", "")
            final_url = scan_result.get("url", url)
            final_status = scan_result.get("status", status)

            parsed = urlparse(final_url)

            scan_info = {
                "domain": parsed.hostname,
                "url": final_url,
                "path": parsed.path,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "status": final_status,
                # "title": get_webpage_title(html),
                "length": len(html),
                "source_code": html,
                "is_valid": 0,
                "redirect_count": redirect_count,
                "redirect_locations": scan_result.get("redirect_locations", []),
                "original_url": url  # 记录原始请求 URL
            }

            is_valid, next_urls_without_source, next_paths_without_source = \
                await process_scan_result(scan_info, checker, args)

            if is_valid:
                scan_info["is_valid"] = 1

                next_urls_with_source = {
                    "next_urls": next_urls_without_source,
                    "sourceURL": final_url
                }
                all_next_urls_with_source.append(next_urls_with_source)
                all_next_urls.update(next_urls_without_source)

                next_paths_with_source = {
                    "next_paths": next_paths_without_source,
                    "sourceURL": final_url
                }
                all_next_paths_with_source.append(next_paths_with_source)

            scan_info_list.append(scan_info)

    return (
        all_next_urls_with_source,
        scan_info_list,
        all_next_urls,
        all_next_paths_with_source
    )


async def fetch_urls_async(urls, thread_num=50, headers=None, cookies=None,
                           timeout=GLOBAL_TIMEOUT, method="GET", follow_redirects=True):
    """
    异步批量请求 URL 列表

    Args:
        follow_redirects: 是否跟随 302 跳转 (默认 True)
    """
    results = []
    progress = tqdm_asyncio(total=len(urls), desc="📡 HTTP", unit="url", ncols=100)

    limits = Limits(max_connections=thread_num, max_keepalive_connections=thread_num)

    async with httpx.AsyncClient(
            limits=limits,
            timeout=httpx.Timeout(timeout),
            follow_redirects=follow_redirects,
            verify=False
    ) as client:

        semaphore = asyncio.Semaphore(thread_num)

        async def single_request(url):
            async with semaphore:
                result = {
                    "url": url,
                    "method": method,
                    "status_code": None,
                    "length": 0,
                    "response_content": "",
                    "redirect_location": None,
                    "redirect_count": 0,
                    "error": None
                }

                try:
                    if method.upper() == "GET":
                        resp = await client.get(url, headers=headers, cookies=cookies)
                    elif method.upper() == "POST":
                        resp = await client.post(url, json={}, headers=headers, cookies=cookies)
                    else:
                        resp = await client.request(method, url, json={}, headers=headers, cookies=cookies)

                    result["status_code"] = resp.status_code
                    result["response_content"] = resp.text
                    result["length"] = len(resp.content)

                    # 记录跳转信息 (httpx 需要 follow_redirects=False 才能捕获中间跳转)
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        result["redirect_location"] = resp.headers.get('location')
                        result["redirect_count"] = 1

                except httpx.TimeoutException as e:
                    result["error"] = f"Timeout: {str(e)}"
                except httpx.ConnectError as e:
                    result["error"] = f"Connection Error: {str(e)}"
                except httpx.RequestError as e:
                    result["error"] = f"Request Error: {str(e)}"
                except Exception as e:
                    result["error"] = f"Unknown Error: {str(e)}"
                finally:
                    progress.update(1)

                return result

        tasks = [single_request(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    progress.close()
    return results


async def fetch_urls_smart(urls, thread_num=50, headers=None, cookies=None,
                           timeout=GLOBAL_TIMEOUT, follow_redirects=True):
    """
    智能双方法请求（POST 优先，405 自动切换 GET）
    """
    # 第 1 轮：全部 POST
    post_results = await fetch_urls_async(
        urls=urls,
        thread_num=thread_num,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
        method="POST",
        follow_redirects=follow_redirects
    )

    # 筛选需要 GET 的 URL
    need_get_urls = []
    final_results = []
    stats = {
        "post_only": 0,
        "post_then_get": 0,
        "405_count": 0,
    }

    for result in post_results:
        if result.get("error"):
            final_results.append(result)
            continue

        status = result["status_code"]

        if status == 405:
            need_get_urls.append(result["url"])
            stats["405_count"] += 1
        else:
            final_results.append(result)
            stats["post_only"] += 1

    # 第 2 轮：对 405 的 URL 尝试 GET
    if need_get_urls:
        get_results = await fetch_urls_async(
            urls=need_get_urls,
            thread_num=thread_num,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            method="GET",
            follow_redirects=follow_redirects
        )

        for get_result in get_results:
            stats["post_then_get"] += 1
            final_results.append(get_result)

    stats["total_urls"] = len(urls)
    stats["total_requests"] = len(urls) + len(need_get_urls)

    return final_results, stats


async def fetch_urls_with_dedup(urls, thread_num=50, headers=None, cookies=None,
                                timeout=GLOBAL_TIMEOUT, follow_redirects=True):
    """带响应去重的异步批量请求"""
    all_results, stats = await fetch_urls_smart(
        urls=urls,
        thread_num=thread_num,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
        follow_redirects=follow_redirects
    )

    url_result_map = {}
    duplicates_count = 0
    seen_fingerprints = set()

    for result in all_results:
        if result.get("error"):
            continue

        url = result["url"]
        fingerprint = get_response_fingerprint(result.get("response_content", ""))
        result["fingerprint"] = fingerprint

        if url in url_result_map:
            current = url_result_map[url]
            current_priority = _get_status_priority(current["status_code"])
            new_priority = _get_status_priority(result["status_code"])

            if new_priority > current_priority:
                url_result_map[url] = result
            duplicates_count += 1
        else:
            url_result_map[url] = result
            seen_fingerprints.add(fingerprint)

    unique_results = list(url_result_map.values())

    return unique_results, duplicates_count, stats