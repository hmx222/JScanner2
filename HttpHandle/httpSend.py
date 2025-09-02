import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from rich import print
import requests
from bs4 import BeautifulSoup
from colorama import Fore
from playwright.async_api import async_playwright, Page, Browser
from tqdm.asyncio import tqdm_asyncio
from urllib3.exceptions import InsecureRequestWarning
from user_agent import generate_user_agent

from AI.Get_API2 import run_analysis, clean_output
from HttpHandle.DuplicateChecker import DuplicateChecker
from JsHandle.pathScan import get_root_domain, extract_pure_js, is_js_file
from JsHandle.valid_page import check_valid_page
from parse_args import parse_headers

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@asynccontextmanager
async def get_playwright_page(browser: Browser):
    """异步上下文管理器：创建和自动关闭页面"""
    page = await browser.new_page()
    try:
        yield page
    finally:
        await page.close()

fail_url = set()

async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio, headers_: dict):
    """异步获取单个页面源码（核心请求逻辑）"""
    try:
        headers = {"User-Agent": generate_user_agent()}
        if headers_ is not None:
            headers.update(parse_headers(headers_))
        await page.set_extra_http_headers(headers)
        await page.route("**/*.{png,jpg,jpeg,gif,css,font,ico}", lambda route: route.abort())

        # 导航到页面
        response = await page.goto(url, wait_until="networkidle")
        status = response.status if response else 500
        html = await page.content()
        return html, url, status

    except Exception:
        fail_url.add(url)
        return None, url, None
    finally:
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
    if not source or length < 100:
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
            if is_js_file(url) and not source.startswith("<!DOCTYPE html>"):
                try:
                    source = extract_pure_js(source)
                    ollama_output = clean_output(run_analysis(source))
                    all_dirty.extend(ollama_output)
                except:
                    print(
                        f"[bold]当前处理的URL:[/bold]\n"
                        f"  [blue underline]{url}[/blue underline]\n"
                        f"[orange]⚠️ 美化JavaScript时可能出现错误[/orange]\n"
                        f"[green]→ 继续执行正常任务[/green]"
                    )
            rex_output = analysis_by_rex(source)
            all_dirty.extend(rex_output)
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
            args=["--disable-gpu", "--no-sandbox"]
        )

        try:
            # 并发控制
            semaphore = asyncio.Semaphore(thread_num)
            async def bounded_fetch(url):
                async with semaphore:
                    async with get_playwright_page(browser) as page:
                        return await fetch_page_async(page, url, progress, args.headers)

            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])

        finally:
            await browser.close()
            progress.close()

    # 处理请求结果（生成scan_info并去重）
    scan_info_list = []
    # 未处理的scan_info_list(主要是给excel传值，靠北了)
    unprocessed_scan_info_list = []
    all_next_urls = set()
    for html, url, status in results:
        if not html:
            continue

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
            "valid_Element": check_valid_page(html),
            "source_code": html,
            "is_valid": 0,
        }
        # 又tnd绕了一圈
        scan_info.pop("source_code")
        unprocessed_scan_info_list.append(scan_info)
        scan_info["source_code"] = html

        # 去重并提取下一层URL
        is_valid, next_urls = await process_scan_result(scan_info, checker, args)
        if is_valid:
            scan_info["is_valid"] = 1
            all_next_urls.update(next_urls)

        print(
            f"[bold blue]URL:[/bold blue] {scan_info['url']}\n"
            f"\t[bold green]Status:[/bold green] {scan_info['status']}\n"
            f"\t[bold cyan]Title:[/bold cyan] {scan_info['title']}\n"
            f"\t[bold yellow]Content Length:[/bold yellow] {scan_info['length']}\n"
            f"\t[bold magenta]Valid Elements:[/bold magenta] {scan_info['valid_Element']}\n"
        )
        scan_info_list.append(scan_info)

    return unprocessed_scan_info_list, scan_info_list, all_next_urls