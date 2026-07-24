import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from playwright.async_api import Request, async_playwright, Page, BrowserContext
from rich.markup import escape
from tqdm.asyncio import tqdm_asyncio
from user_agent import generate_user_agent

from config.scanner_rules import PLAYWRIGHT_BLOCKED_RESOURCES
from config.config import GLOBAL_TIMEOUT, MAX_REDIRECT_COUNT
from infra.dedup import DuplicateChecker
from crawler.httpx_crawler import fetch_urls_async
from crawler.response_process import process_scan_result
from logger import get_logger

logger = get_logger(__name__)  # 获取日志记录器


@asynccontextmanager
async def get_playwright_page(context: BrowserContext):
    """
    异步上下文管理器：创建和自动关闭 Playwright 页面

    确保页面在使用完毕后自动关闭，如果关闭超时（超过 3 秒），
    则强制忽略错误以避免僵尸页面占用内存。

    Args:
        context: Playwright 浏览器上下文

    Yields:
        Page: Playwright 页面对象
    """
    page = await context.new_page()  # 创建新页面
    try:
        yield page
    finally:
        try:
            await asyncio.wait_for(page.close(), timeout=3.0)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass


async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio):
    """
    使用 Playwright 抓取单个页面

    工作流程：
    1. 设置资源拦截（过滤图片、字体等无用资源）
    2. 监听请求，捕获动态加载的 JS 文件
    3. 统计 302/301 跳转次数
    4. 获取页面 HTML 内容
    5. 将动态捕获的资源拼接到 HTML 尾部

    Args:
        page: Playwright Page 对象
        url: 目标 URL
        progress: 进度条对象

    Returns:
        tuple: (scan_result: dict, final_url: str, final_status: int or None)
            scan_result 字典包含 type, html, url, status, redirect_count, redirect_locations
    """
    captured_resources = set()  # 已捕获资源集合
    redirect_count = 0  # 跳转次数计数器
    redirect_locations = []  # 记录所有跳转目标
    final_status = None  # 最终状态码
    final_url = url  # 最终URL

    try:
        await page.route("**/*", lambda route: route.abort()
        if route.request.resource_type in PLAYWRIGHT_BLOCKED_RESOURCES
        else route.continue_())

        def handle_request(request: Request):
            """请求事件处理器：捕获 JS 资源 URL"""
            res_url = request.url  # 请求URL
            res_type = request.resource_type  # 资源类型

            if res_type == "script" or res_url.split('?')[0].endswith('.js'):
                captured_resources.add(res_url)
            elif res_type == "document" and res_url != "about:blank":
                captured_resources.add(res_url)

        page.on("request", handle_request)

        def handle_response(response):
            """响应事件处理器：跟踪跳转链"""
            nonlocal redirect_count, final_url
            if response.status in [301, 302, 303, 307, 308]:
                location = response.headers.get('location')  # 跳转目标URL
                redirect_count += 1  # 跳转计数加一
                redirect_locations.append(location)
                final_url = response.url  # 更新为响应URL

        page.on("response", handle_response)

        timeout_ms = GLOBAL_TIMEOUT * 1000  # 超时时间毫秒
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)  # 发送页面请求

        if response:
            final_status = response.status  # 记录响应状态码
            final_url = response.url  # 记录最终URL

        if redirect_count > MAX_REDIRECT_COUNT:
            return {
                "type": "redirect_loop",
                "redirect_count": redirect_count,
                "redirect_locations": redirect_locations,
                "url": url,
                "status": final_status
            }, url, final_status

        html_content = await page.content()  # 获取页面HTML

        if captured_resources:
            append_html = "\n<!-- JScanner Captured Resources (Dynamic) -->\n"  # 资源标记注释
            for res in captured_resources:  # 遍历捕获的资源
                safe_res = escape(res)  # 转义特殊字符
                append_html += f'<script src="{safe_res}"></script>\n'  # 拼接脚本标签
            html_content += append_html  # 拼接到HTML尾部

        return {
            "type": "success",
            "html": html_content,
            "url": final_url,
            "status": final_status,
            "redirect_count": redirect_count,
            "redirect_locations": redirect_locations
        }, final_url, final_status

    except Exception as e:  # 捕获所有异常
        error_msg = str(e)  # 提取错误信息
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

    工作流程：
    1. 启动 Chromium 浏览器（支持有头/无头模式、代理）
    2. 使用信号量限制并发数，批量抓取页面
    3. 对抓取失败的 URL 使用 httpx 进行补救
    4. 处理结果：提取 URL、路径、统计跳转信息

    Args:
        urls: URL 列表
        thread_num: 并发线程数
        args: 命令行参数（包含 proxy, visible, url 等）
        checker: 去重检查器（DuplicateChecker 实例）
        storage_state: Cookie 存储文件路径（用于保持登录状态）

    Returns:
        tuple: (all_next_urls_with_source, scan_info_list, all_next_urls, all_next_paths_with_source)
            - all_next_urls_with_source: 来源 URL -> 子 URL 关系列表
            - scan_info_list: 扫描详情列表（包含域名、URL、状态码、源代码等）
            - all_next_urls: 下一层待爬取的纯 URL 集合
            - all_next_paths_with_source: 来源 URL -> 子路径关系列表
    """
    progress = tqdm_asyncio(total=len(urls), desc="🕷️ Crawling", unit="url", ncols=100)  # 创建进度条

    request_failed_urls = set()  # 失败URL集合
    redirect_stats = {  # 跳转统计字典
        "total": 0,
        "success": 0,
        "error": 0,
        "redirect_0": 0,
        "redirect_1": 0,
        "redirect_loop": 0
    }

    async with async_playwright() as p:  # 启动Playwright上下文
        browser = await p.chromium.launch(executable_path= r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",  # 启动浏览器实例
            headless=not getattr(args, 'visible', False),
            proxy={"server": args.proxy} if getattr(args, 'proxy', None) else None,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
        )

        context_kwargs = {  # 浏览器上下文参数
            "user_agent": generate_user_agent(),
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }

        if storage_state:
            try:
                context_kwargs["storage_state"] = storage_state  # 设置Cookie状态
                print(f"📦 加载 Cookie 状态：{storage_state}")
            except Exception as e:  # 捕获异常
                print(f"⚠️ 加载 Cookie 状态失败：{e}")

        global_context = await browser.new_context(**context_kwargs)  # 创建浏览器上下文

        try:
            semaphore = asyncio.Semaphore(thread_num)  # 并发信号量

            async def bounded_fetch(url):
                """
                带信号量限制的页面抓取函数

                Args:
                    url: 目标 URL

                Returns:
                    tuple: (scan_result, url, final_status)
                """
                async with semaphore:
                    async with get_playwright_page(global_context) as page:  # 获取Playwright页面
                        return await fetch_page_async(page, url, progress)

            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])  # 并发执行所有任务

        finally:
            await global_context.close()
            await browser.close()
            progress.close()

    for scan_result, url, status in results:  # 遍历所有结果
        if scan_result and scan_result.get("type") == "error":
            request_failed_urls.add(url)

    if request_failed_urls:
        print(f"🔄 尝试使用 httpx 补救 {len(request_failed_urls)} 个失败的 URL...")
        fallback_results = await fetch_urls_async(  # httpx补救结果
            urls=list(request_failed_urls),
            thread_num=min(thread_num, 10),
            headers=None,
            cookies=None,
            timeout=10
        )
        updated_count = 0  # 成功补救计数
        for i, (scan_result, url, status) in enumerate(results):  # 遍历并尝试补救
            if scan_result and scan_result.get("type") == "error":
                for fb_result in fallback_results:  # 遍历httpx结果
                    if fb_result["url"] == url and not fb_result.get("error"):
                        results[i] = (  # 用httpx结果替换
                            {
                                "type": "success",
                                "html": fb_result["response_content"],
                                "url": url,
                                "status": fb_result["status_code"],
                                "redirect_count": fb_result.get("redirect_count", 0),
                                "redirect_locations": []
                            },
                            url,
                            fb_result["status_code"]
                        )
                        updated_count += 1  # 补救计数加一
                        break
        print(f"✅ 成功补救 {updated_count} 个 URL")

    all_next_urls_with_source = []  # 来源子URL列表
    scan_info_list = []  # 扫描信息列表
    all_next_urls = set()  # 下一层URL集合
    all_next_paths_with_source = []  # 来源子路径列表

    seed_url = getattr(args, 'url', None)  # 获取种子URL

    for scan_result, url, final_status in results:  # 遍历处理所有结果
        if not scan_result or scan_result.get("type") != "success":
            continue

        html = scan_result.get("html", "")  # 获取HTML内容
        final_url = scan_result.get("url", url)  # 获取最终URL
        redirect_count = scan_result.get("redirect_count", 0)  # 获取跳转次数

        if not html:
            continue

        redirect_stats["total"] += 1  # 总计加一
        if final_status and 200 <= final_status < 400:
            redirect_stats["success"] += 1  # 成功计数加一
            if redirect_count == 0:
                redirect_stats["redirect_0"] += 1  # 零次跳转加一
            elif redirect_count == 1:
                redirect_stats["redirect_1"] += 1  # 一次跳转加一
            else:
                redirect_stats["redirect_loop"] += 1  # 多次跳转加一
        else:
            redirect_stats["error"] += 1  # 错误计数加一

        parsed = urlparse(final_url)  # 解析最终URL

        scan_info = {  # 构建扫描信息字典
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
            "original_url": url
        }

        is_valid, next_urls_without_source, next_paths_without_source = \
            await process_scan_result(scan_info, checker, args, seed_url=seed_url)  # 去重并提取下一层URL

        if is_valid:
            scan_info["is_valid"] = 1  # 标记为有效

            next_urls_with_source = {  # 来源子URL关系
                "next_urls": next_urls_without_source,
                "sourceURL": final_url
            }
            all_next_urls_with_source.append(next_urls_with_source)
            all_next_urls.update(next_urls_without_source)

            next_paths_with_source = {  # 来源子路径关系
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
