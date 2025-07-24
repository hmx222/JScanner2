# 导入必要依赖
import asyncio
import json
from contextlib import asynccontextmanager
from traceback import print_exception
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore
from playwright.async_api import async_playwright, Page, Browser
from tqdm.asyncio import tqdm_asyncio
from urllib3.exceptions import InsecureRequestWarning
from user_agent import generate_user_agent

from HttpHandle.DuplicateChecker import DuplicateChecker
from JsHandle.valid_page import check_valid_page
from filerw import write2json
from parse_args import parse_headers

# 忽略SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@asynccontextmanager
async def get_playwright_page(browser: Browser):
    """异步上下文管理器：创建和自动关闭页面"""
    page = await browser.new_page()
    try:
        yield page
    finally:
        await page.close()


async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio, headers_: dict):
    """异步获取单个页面源码（核心请求逻辑）"""
    try:
        headers = {"User-Agent": generate_user_agent()}
        if headers_ is not None:
            headers.update(parse_headers(headers_))
        # 设置请求头
        await page.set_extra_http_headers(headers)
        # 拦截非必要资源（加速加载）
        await page.route("**/*.{png,jpg,jpeg,gif,css,font,ico}", lambda route: route.abort())

        # 导航到页面
        response = await page.goto(url, timeout=15000)
        status = response.status if response else 500
        html = await page.content()  # 获取源码
        return html, url, status

    except Exception as e:
        print_exception(e)
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
    if not source or length < 300:
        return False, set()

    # 去重检查（按配置的策略执行）
    if (args.de_duplication_hash and checker.check_duplicate_by_DOM_simhash(source,args.de_duplication_hash)) or \
            (args.de_duplication_title and checker.check_duplicate_by_title(title, url)) or \
            (args.de_duplication_length and checker.check_duplicate_by_length(length, url)) or \
            (args.de_duplication_similarity and checker.check_duplicate_by_simhash(
                source, url, float(args.de_duplication_similarity))):
        return False, set()  # 触发去重，不继续处理

    # 标记为已访问
    checker.mark_url_visited(url)

    # 提取下一层URL（仅JS文件或初始URL需要）
    next_urls = set()
    if ".js" in url or url in args.initial_urls:
        from JsHandle.pathScan import analysis_by_rex, data_clean  # 延迟导入，避免循环依赖
        dirty_data = analysis_by_rex(source)
        next_urls = set(data_clean(url, dirty_data))

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
        # 启动浏览器
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

            # 批量请求
            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])

        finally:
            await browser.close()
            progress.close()

    # 处理请求结果（生成scan_info并去重）
    scan_info_list = []
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
            "source_code": html
        }

        # 去重并提取下一层URL
        is_valid, next_urls = await process_scan_result(scan_info, checker, args)
        # TODO 此处写入Excel
        print(next_urls)
        if is_valid:
            scan_info.pop("source_code")
            # 写入基础扫描信息
            write2json("./result/scanInfo.json", json.dumps(scan_info))
            print(
                f"{Fore.BLUE}url:{scan_info['url']}\n\tstatus:{scan_info['status']}\n\ttitle:{scan_info['title']}{Fore.RESET}\n\tlength:{scan_info['length']}\n\tvalid_Element:{scan_info['valid_Element']}\n")
            scan_info["source_code"] = html
            scan_info_list.append(scan_info)
            all_next_urls.update(next_urls)

    return scan_info_list, all_next_urls