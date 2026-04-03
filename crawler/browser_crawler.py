import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from playwright.async_api import Request, async_playwright, Page, BrowserContext
from rich.markup import escape
from tqdm.asyncio import tqdm_asyncio
from user_agent import generate_user_agent

from config.config import BLOCKED_RESOURCE_TYPES, GLOBAL_TIMEOUT, MAX_REDIRECT_COUNT
from infra.dedup import DuplicateChecker
from crawler.httpx_crawler import fetch_urls_async
from crawler.response_process import process_scan_result
from logger import get_logger

logger = get_logger(__name__)

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


async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio):
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
            return {
                "type": "redirect_loop",
                "redirect_count": redirect_count,
                "redirect_locations": redirect_locations,
                "url": url,
                "status": final_status
            }, url, final_status

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
                        return await fetch_page_async(page, url, progress)

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


