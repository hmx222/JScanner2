import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse, urljoin

import requests
from playwright.async_api import Request
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import requests
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from rich import print
from rich.markup import escape
from tqdm.asyncio import tqdm_asyncio
from urllib3.exceptions import InsecureRequestWarning
from user_agent import generate_user_agent

from HttpHandle.DuplicateChecker import DuplicateChecker
from JsHandle.pathScan import get_root_domain
from parse_args import parse_headers

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# 定义不需要加载的资源类型，节省带宽和渲染时间
BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

def fix_encoding(text):
    """尝试修复乱码字符串"""
    encodings = ['utf-8', 'gbk', 'gb2312', 'latin1', 'iso-8859-1']

    for enc in encodings:
        try:
            # 先用当前编码编码，再用utf-8解码
            return text.encode(enc).decode('utf-8')
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue

    # 如果所有尝试都失败，返回原始字符串
    return text

# ✅ 修改点1：【核心】接收全局唯一Context，只创建Page(Tab)，用完仅关闭Tab，Context全局复用
# 效果：一个浏览器窗口内的多个Tab，10线程=10个Tab，完全独立，无进程泄漏
@asynccontextmanager
async def get_playwright_page(context: BrowserContext):
    """异步上下文管理器：创建和自动关闭页面【仅创建Tab，全局一个浏览器环境】"""
    page = await context.new_page()
    try:
        yield page
    finally:
        # 核心修复：给page.close()增加【超时强制兜底】，破解异步死锁永不返回的问题
        try:
            await asyncio.wait_for(page.close(), timeout=3.0)
        except asyncio.TimeoutError:
            pass  # 超时就放弃，不报错、不阻塞、程序继续走

fail_url = set()

async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio, headers_: dict):
    """
    保持原有返回值结构: (html_content, url, status)
    但通过监听，确保 html_content 包含了所有动态发现的 JS
    """
    discovered_js = set()
    handle_request = None
    try:
        # 1. 拦截无关资源（提速核心）
        await page.route("**/*", lambda route: route.abort()
        if route.request.resource_type in BLOCKED_RESOURCE_TYPES
        else route.continue_())

        # 2. 监听所有 JS 请求
        def handle_request(request: Request):
            if request.resource_type == "script" or request.url.split('?')[0].endswith('.js'):
                discovered_js.add(request.url)

        page.on("request", handle_request)

        if headers_:
            await page.set_extra_http_headers(parse_headers(headers_))

        # 3. 导航
        response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        status = response.status if response else 500

        # 4. 获取当前页面的 HTML
        html_content = await page.content()

        if discovered_js:
            extra_scripts = "".join([f'<script src="{escape(js)}"></script>' for js in discovered_js])
            html_content = html_content.replace("</body>", f"{extra_scripts}</body>")

        return html_content, url, status

    except Exception:
        fail_url.add(url)
        return None, url, None
    finally:
        # ✅ 补充：移除监听，无内存泄漏，不影响你的逻辑
        if handle_request:
            page.remove_listener("request", handle_request)
        progress.update(1)

async def process_scan_result(scan_info, checker: DuplicateChecker, args):
    """处理扫描结果（去重+提取下一层URL）"""
    url = scan_info["url"]
    source = scan_info["source_code"]
    status = scan_info["status"]
    title = scan_info["title"]
    length = scan_info["length"]

    # 基础过滤（无效URL/错误状态码/过短源码）
    if not checker.is_valid_url(url):
        return False, set()
    if status and status >= 404:
        return False, set()
    if not source or length < 200:
        return False, set()

    if ".js" not in url:
        # 去重检查（按配置的策略执行）
        if (args.de_duplication_hash and checker.check_duplicate_by_DOM_simhash(source,args.de_duplication_hash)) or \
                (args.de_duplication_title and checker.check_duplicate_by_title(title, url)) or \
                (args.de_duplication_length and checker.check_duplicate_by_length(length, url)) or \
                (args.de_duplication_similarity and checker.check_duplicate_by_simhash(
                    source, url, float(args.de_duplication_similarity))):
            return False, set()

    checker.mark_url_visited(url)

    # 提取下一层URL（仅JS文件或初始URL需要）
    next_urls = set()
    all_dirty = []
    if ".js" in url or get_root_domain(url) in args.initial_urls:
        from JsHandle.pathScan import analysis_by_rex, data_clean

        if not args.ollama:
            all_dirty = analysis_by_rex(source)
        else:
            rex_output = analysis_by_rex(source)
            all_dirty.extend(rex_output)
            # if is_js_file(url) and not source.startswith("<!DOCTYPE html>") and len(source) > 1000 and len(rex_output) >= 6 :
            #     try:
            #         print("🤔 大模型正在分析中 🔍💡")
            #         source = extract_pure_js(source)
            #         ollama_output = clean_output(run_analysis(source))
            #         all_dirty.extend(ollama_output)
            #     except:
            #         print(
            #             f"[bold]当前处理的URL:[/bold]\n"
            #             f"  [blue underline]{url}[/blue underline]\n"
            #             f"[orange]⚠️ 美化JavaScript时可能出现错误[/orange]\n"
            #             f"[green]→ 继续执行正常任务[/green]"
            #         )

        next_urls = set(data_clean(url, all_dirty))

    return True, next_urls

def get_webpage_title(html_source):
    """
    get webpage title
    """
    soup = BeautifulSoup(html_source, 'html.parser')
    title_tag = soup.find('title')
    if title_tag:
        return title_tag.text
    return "NULL"

async def get_source_async(urls, thread_num, args, checker: DuplicateChecker):
    """Playwright异步批量请求+去重处理入口"""

    progress = tqdm_asyncio(total=len(urls), desc="Process", unit="url", ncols=100)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=not args.visible,
            proxy={"server": args.proxy} if args.proxy else None,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"] # ✅ 补全Linux必加参数，解决内存不足，无副作用
        )
        # ✅ 修改点2：【核心】全局只创建1个Context → 对应1个浏览器窗口，所有Tab都在这个窗口内
        global_context = await browser.new_context(
            user_agent=generate_user_agent(),
            ignore_https_errors=True,
            java_script_enabled=False
        )

        try:
            # 并发控制：线程数=同时打开的Tab数，10线程=10个Tab，完美匹配你的需求
            semaphore = asyncio.Semaphore(thread_num)
            async def bounded_fetch(url):
                async with semaphore:
                    # ✅ 修改点3：传入全局Context，只创建Tab，用完关Tab，无进程泄漏
                    async with get_playwright_page(global_context) as page:
                        return await fetch_page_async(page, url, progress, args.headers)

            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])

        finally:
            # 先关闭全局上下文，再关闭浏览器，顺序正确，无残留
            await global_context.close()
            await browser.close()
            progress.close()

    # 处理请求结果（生成scan_info并去重）
    scan_info_list = []
    # 未处理的scan_info_list(主要是给excel传值，靠北了)
    all_next_urls_with_source = []
    all_next_urls = set()
    for html, url, status in results:
        if not html:
            continue

        # 修复编码
        html = fix_encoding(html)

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
        # 又tnd绕了一圈
        # scan_info.pop("source_code")
        # all_next_urls_with_source.append(scan_info)
        # scan_info["source_code"] = html

        # 去重并提取下一层URL
        is_valid, next_urls_without_source = await process_scan_result(scan_info, checker, args)
        if is_valid:
            scan_info["is_valid"] = 1

            next_urls_with_source = {
                "next_urls":next_urls_without_source,
                "sourceURL":url
            }

            all_next_urls_with_source.append(next_urls_with_source)
            all_next_urls.update(next_urls_without_source)

        print(
            f"[bold blue]URL:[/bold blue] {escape(str(scan_info['url']))}\n"  # 确保转为字符串
            f"\t[bold green]Status:[/bold green] {escape(str(scan_info['status']))}\n"  # 状态码（整数）转字符串
            f"\t[bold cyan]Title:[/bold cyan] {escape(str(scan_info['title']))}\n"  # title可能为None，转字符串
            f"\t[bold yellow]Content Length:[/bold yellow] {escape(str(scan_info['length']))}\n"  # 长度（整数）转字符串
#            f"\t[bold magenta]Valid Elements:[/bold magenta] {escape(str(scan_info['valid_Element']))}\n"  # 确保是字符串
        )
        scan_info_list.append(scan_info)

    return all_next_urls_with_source, scan_info_list, all_next_urls