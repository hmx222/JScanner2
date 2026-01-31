import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import requests
from playwright.async_api import Request, async_playwright, Page, BrowserContext
from rich.markup import escape
from tqdm.asyncio import tqdm_asyncio
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup

from HttpHandle.DuplicateChecker import DuplicateChecker
from parse_args import parse_headers
from user_agent import generate_user_agent

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}


@asynccontextmanager
async def get_playwright_page(context: BrowserContext):
    """异步上下文管理器：创建和自动关闭页面【仅创建Tab，全局一个浏览器环境】"""
    page = await context.new_page()
    try:
        yield page
    finally:
        try:
            await asyncio.wait_for(page.close(), timeout=3.0)
        except asyncio.TimeoutError:
            pass


fail_url = set()


async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio, headers_: dict):
    """
    加强版抓取：无论页面如何跳转，捕获加载过程中的所有 JS 和中间 URL
    """
    # 记录加载过的所有资源 (JS 和 中间跳转页)
    captured_resources = set()

    try:
        await page.route("**/*", lambda route: route.abort()
        if route.request.resource_type in BLOCKED_RESOURCE_TYPES
        else route.continue_())

        def handle_request(request: Request):
            res_url = request.url
            res_type = request.resource_type

            # 捕获 JS 文件
            if res_type == "script" or res_url.split('?')[0].endswith('.js'):
                captured_resources.add(res_url)

            elif res_type == "document" and res_url != "about:blank":
                captured_resources.add(res_url)

        page.on("request", handle_request)

        if headers_:
            await page.set_extra_http_headers(parse_headers(headers_))

        response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        status = response.status if response else 500

        html_content = await page.content()

        if captured_resources:
            append_html = "\n<!-- JScanner Captured Resources (History & Dynamic) -->\n"
            for res in captured_resources:
                # 简单转义防止破坏 HTML 结构，虽然是塞在最后
                safe_res = escape(res)
                # 构造成 script 标签或注释，确保正则能提取到 http://...
                append_html += f'<script src="{safe_res}"></script>\n'

            html_content += append_html

        return html_content, url, status

    except Exception:
        fail_url.add(url)
        return None, url, None
    finally:
        progress.update(1)


async def process_scan_result(scan_info, checker: DuplicateChecker, args):
    """处理扫描结果（去重+提取下一层URL）- 最终定稿版"""
    url = scan_info["url"]
    source = scan_info["source_code"]
    status = scan_info["status"]
    title = scan_info["title"]
    length = scan_info["length"]

    if not checker.is_within_scope(url):
        del source, scan_info, title, length
        return False, set()

    if status and status == 404:
        del source, scan_info, title, length
        return False, set()

    if not source or length < 200:
        del source, scan_info, title, length
        return False, set()

    # 过滤超大响应
    if len(source) > 712000:
        del source, scan_info, title, length
        return False, set()

    # --- 2. 内容去重 (仅针对非JS文件) ---
    if ".js" not in url:
        if checker.is_page_duplicate(url, source, title):
            del source, scan_info, title, length
            return False, set()

    # --- 3. 标记为已访问 ---
    checker.mark_url_visited(url)

    # --- 4. 提取下一层 URL ---
    next_urls = set()

    try:
        from JsHandle.pathScan import analysis_by_rex, data_clean
        all_dirty = []

        # 正则暴力提取 (此时 source 已经包含了我们拼接的动态 JS 链接)
        rex_output = analysis_by_rex(source)
        all_dirty.extend(rex_output)

        # 清洗提取到的链接
        next_urls = set(data_clean(url, all_dirty))
    except Exception:
        pass

    # --- 5. 资源清理 ---
    del source, scan_info, title, length
    if 'all_dirty' in locals(): del all_dirty

    return True, next_urls


def get_webpage_title(html_source):
    """
    get webpage title
    """
    try:
        soup = BeautifulSoup(html_source, 'html.parser')
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.text
        return "NULL"
    except:
        return "NULL"


async def get_source_async(urls, thread_num, args, checker: DuplicateChecker):
    """Playwright异步批量请求+去重处理入口"""

    progress = tqdm_asyncio(total=len(urls), desc="Process", unit="url", ncols=100)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=not args.visible,
            proxy={"server": args.proxy} if args.proxy else None,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
        )
        global_context = await browser.new_context(
            user_agent=generate_user_agent(),
            ignore_https_errors=True,
            java_script_enabled=False
        )

        try:
            semaphore = asyncio.Semaphore(thread_num)

            async def bounded_fetch(url):
                async with semaphore:
                    async with get_playwright_page(global_context) as page:
                        return await fetch_page_async(page, url, progress, args.headers)

            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])

        finally:
            await global_context.close()
            await browser.close()
            progress.close()

    # 处理请求结果（生成scan_info并去重）
    scan_info_list = []
    # 未处理的scan_info_list(主要是给excel传值)
    all_next_urls_with_source = []
    all_next_urls = set()

    for item in results:
        if not item or item[0] is None:  # html 为 None
            continue

        html, url, status = item

        # 生成基础扫描信息
        parsed = urlparse(url)
        scan_info = {
            "domain": parsed.hostname,
            "url": url,
            "path": parsed.path,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "status": status,
            "title": get_webpage_title(html),
            "length": len(html),
            "source_code": html,
            "is_valid": 0,
        }

        # 去重并提取下一层URL
        is_valid, next_urls_without_source = await process_scan_result(scan_info, checker, args)

        if is_valid:
            scan_info["is_valid"] = 1

            next_urls_with_source = {
                "next_urls": next_urls_without_source,
                "sourceURL": url
            }

            all_next_urls_with_source.append(next_urls_with_source)
            all_next_urls.update(next_urls_without_source)

        scan_info_list.append(scan_info)

    return all_next_urls_with_source, scan_info_list, all_next_urls
