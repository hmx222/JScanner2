import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import requests
from playwright.async_api import Request, async_playwright, Page, BrowserContext
from rich.markup import escape
from tqdm.asyncio import tqdm_asyncio
from urllib3 import request
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup

# 引入你的去重和工具模块
from HttpHandle.DuplicateChecker import DuplicateChecker
from parse_args import parse_headers
from user_agent import generate_user_agent

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 不需要加载的资源类型，节省带宽和内存
BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}


@asynccontextmanager
async def get_playwright_page(context: BrowserContext):
    """异步上下文管理器：创建和自动关闭页面【仅创建Tab，全局复用一个浏览器上下文】"""
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

request_failed_url = set()

async def fetch_page_async(page: Page, url: str, progress: tqdm_asyncio):
    """
    加强版抓取：无论页面如何跳转，捕获加载过程中的所有 JS 和中间 URL
    """
    captured_resources = set()

    try:
        # 路由拦截：过滤图片字体等无用资源
        await page.route("**/*", lambda route: route.abort()
        if route.request.resource_type in BLOCKED_RESOURCE_TYPES
        else route.continue_())

        # 监听请求：捕获动态加载的 JS 文件
        def handle_request(request: Request):
            res_url = request.url
            res_type = request.resource_type

            # 捕获 script 类型或后缀为 .js 的请求
            if res_type == "script" or res_url.split('?')[0].endswith('.js'):
                captured_resources.add(res_url)
            # 捕获子文档 (frame/iframe)
            elif res_type == "document" and res_url != "about:blank":
                captured_resources.add(res_url)

        page.on("request", handle_request)

        # 设置自定义 Header
        # if headers_:
        #     await page.set_extra_http_headers(parse_headers(headers_))

        # 访问页面，超时 15s
        response = await page.goto(url, wait_until="domcontentloaded", timeout=55000)
        status = response.status if response else 500

        html_content = await page.content()

        # 将捕获到的动态资源拼接到 HTML 尾部，方便后续正则提取
        if captured_resources:
            append_html = "\n<!-- JScanner Captured Resources (Dynamic) -->\n"
            for res in captured_resources:
                safe_res = escape(res)
                append_html += f'<script src="{safe_res}"></script>\n'
            html_content += append_html

        return html_content, url, status

    except Exception as e:
        request_failed_url.add(url)
        return None, url, None
    finally:
        progress.update(1)


async def process_scan_result(scan_info, checker: DuplicateChecker, args):
    """处理扫描结果（去重 + 提取下一层 URL）"""
    url = scan_info["url"]
    source = scan_info["source_code"]
    status = scan_info["status"]
    title = scan_info["title"]
    length = scan_info["length"]

    # 1. 基础过滤
    if not checker.is_within_scope(url):
        return False, set(), []  # 统一返回 3 个值
    if status == 404:
        return False, set(), []  # 统一返回 3 个值
    if not source or length < 200:
        return False, set(), []  # 统一返回 3 个值
    if len(source) > 20 * 1024 * 1024:  # 限制 20MB，防止正则卡死
        return False, set(), []  # 统一返回 3 个值

    # 2. 内容去重 (仅针对非 JS 文件)
    if ".js" not in url:
        if checker.is_page_duplicate(url, source, title):
            return False, set(), []  # 统一返回 3 个值

    # 3. 标记为已访问
    checker.mark_url_visited(url)

    # 4. 提取下一层 URL
    next_urls = set()
    rex_output = []  # 初始化变量，防止 except 中未定义

    try:
        from JsHandle.pathScan import analysis_by_rex, data_clean
        # 正则暴力提取
        rex_output = analysis_by_rex(source)
        # 清洗提取到的链接 (使用原始 rex_output 生成 next_urls，确保不漏链)
        next_urls = set(data_clean(url, rex_output))

    except Exception:
        rex_output = []


    # 条件：长度>7 且 不包含"."且 至少包含 2 个"/"
    # 检查 rex_output 是否有值（非空）
    if rex_output:
        # 初始化一个空列表，用于存放筛选后的结果
        filtered_rex_output = []
        # 遍历原 rex_output 中的每一个元素
        for item in rex_output:
            # 逐一判断所有筛选条件
            # 条件1：item 是字符串类型
            is_string = isinstance(item, str)
            # 条件2：item 的长度大于 4
            length_ok = len(item) > 4
            # 条件3：item 中不包含小数点 "."
            no_dot = "." not in item
            # 条件4：item 中包含的斜杠 "/" 数量大于等于 2
            enough_slash = item.count('/') >= 1

            # 如果所有条件都满足，就把 item 加入筛选后的列表
            if is_string and length_ok and no_dot and enough_slash:
                filtered_rex_output.append(item)

        # 将筛选后的列表重新赋值给 rex_output
        rex_output = filtered_rex_output

    return True, next_urls, rex_output


def get_webpage_title(html_source):
    """获取页面标题"""
    try:
        soup = BeautifulSoup(html_source, 'html.parser')
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.text.strip()[:100]
        return "NULL"
    except:
        return "NULL"


async def get_source_async(urls, thread_num, args, checker: DuplicateChecker):
    """
    Playwright 异步批量请求入口
    返回:
    1. all_next_urls_with_source: 用于构建调用链和数据库存储 [{'sourceURL':..., 'next_urls':...}]
    2. scan_info_list: 包含源码的详细信息，用于 AI 分析和参数提取
    3. all_next_urls: 下一层待爬取的纯 URL 集合
    """
    progress = tqdm_asyncio(total=len(urls), desc="🕷️ Crawling", unit="url", ncols=100)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=not args.visible,
            proxy={"server": args.proxy} if args.proxy else None,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
        )

        # 创建全局上下文，禁用图片加载以提速
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
                        return await fetch_page_async(page, url, progress)

            results = await asyncio.gather(*[bounded_fetch(url) for url in urls])

        finally:
            await global_context.close()
            await browser.close()
            progress.close()

    for url in request_failed_url:
        try:
            failed_url_resp = requests.request("GET", url)
            html = failed_url_resp.text
            status = failed_url_resp.status_code
            _item = html, url, status
            results.append(_item)
        except:
            continue

    scan_info_list = []
    all_next_urls_with_source = []
    all_next_paths_with_source = []
    all_next_urls = set()

    for item in results:
        if not item or item[0] is None: continue

        html, url, status = item
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

        # 处理结果：去重、提取子链接
        is_valid, next_urls_without_source, next_paths_without_source = await process_scan_result(scan_info, checker, args)

        if is_valid:
            scan_info["is_valid"] = 1

            # 记录 来源URL -> 发现的子URL 关系
            next_urls_with_source = {
                "next_urls": next_urls_without_source,
                "sourceURL": url
            }
            all_next_urls_with_source.append(next_urls_with_source)
            all_next_urls.update(next_urls_without_source)

            next_paths_with_source = {
                "next_paths": next_paths_without_source,
                "sourceURL": url
            }
            all_next_paths_with_source.append(next_paths_with_source)


        scan_info_list.append(scan_info)

    return all_next_urls_with_source, scan_info_list, all_next_urls, all_next_paths_with_source
