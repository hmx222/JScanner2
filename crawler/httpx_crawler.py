import asyncio
import hashlib
import re

import httpx
from httpx import Limits
from tqdm.asyncio import tqdm_asyncio

from config.config import GLOBAL_TIMEOUT


def normalize_response(text):
    """
    响应归一化：移除响应中的动态字段

    将 requestId、traceId、timestamp、nonce、uuid、sign 等动态值替换为固定占位符，
    用于响应指纹计算和去重。

    Args:
        text: 原始响应文本

    Returns:
        str: 归一化后的文本
    """
    if not text:
        return ""

    # 动态字段替换规则（正则模式 -> 占位符）
    dynamic_patterns = [  # 动态字段替换规则列表
        (r'"requestId"\s*:\s*"[^"]*"', '"requestId":"{{DYNAMIC}}"'),
        (r'"traceId"\s*:\s*"[^"]*"', '"traceId":"{{DYNAMIC}}"'),
        (r'"timestamp"\s*:\s*\d+', '"timestamp":{{DYNAMIC}}'),
        (r'"nonce"\s*:\s*"[^"]*"', '"nonce":"{{DYNAMIC}}"'),
        (r'"uuid"\s*:\s*"[^"]*"', '"uuid":"{{DYNAMIC}}"'),
        (r'"sign"\s*:\s*"[^"]*"', '"sign":"{{DYNAMIC}}"'),
    ]

    for pattern, replacement in dynamic_patterns:  # 遍历替换规则
        text = re.sub(pattern, replacement, text)  # 替换动态字段
    # 移除所有空白字符（压缩文本）
    text = re.sub(r'\s+', '', text)  # 压缩空白字符
    return text


def get_response_fingerprint(text):
    """
    计算响应指纹哈希

    先对响应进行归一化处理（移除动态字段），再计算 MD5 哈希值。
    用于判断两个响应内容是否实质相同（忽略动态值差异）。

    Args:
        text: 原始响应文本

    Returns:
        str: MD5 哈希指纹
    """
    normalized = normalize_response(text)  # 归一化响应文本
    return hashlib.md5(normalized.encode()).hexdigest()


def _get_status_priority(status_code):
    """
    获取状态码优先级（越高越有价值）

    优先级规则：
    - 401/403（未授权）：3（最有价值，可能是认证绕过目标）
    - >= 500（服务器错误）：3（可能是信息泄露）
    - 200/201/301/302（正常）：2
    - 404（不存在）：1（价值最低）

    Args:
        status_code: HTTP 状态码

    Returns:
        int: 优先级分数
    """
    if status_code in [401, 403]:
        return 3
    if status_code >= 500:
        return 3
    if status_code in [200, 201, 301, 302]:
        return 2
    if status_code == 404:
        return 1
    return 2


async def fetch_urls_async(urls, thread_num=50, headers=None, cookies=None,
                           timeout=GLOBAL_TIMEOUT, method="GET", follow_redirects=True):
    """
    异步批量请求 URL 列表

    使用 httpx.AsyncClient 并发请求多个 URL，支持 GET/POST 方法。

    Args:
        urls: URL 列表
        thread_num: 并发线程数
        headers: 自定义请求头
        cookies: Cookie
        timeout: 请求超时时间（秒）
        method: HTTP 方法（GET/POST）
        follow_redirects: 是否跟随 302 跳转

    Returns:
        list: 请求结果字典列表，每个字典包含 url, status_code, length, response_content 等字段
    """
    progress = tqdm_asyncio(total=len(urls), desc="📡 HTTP", unit="url", ncols=100)  # 创建进度条

    # 设置 httpx 连接池限制
    limits = Limits(max_connections=thread_num, max_keepalive_connections=thread_num)  # 连接池限制

    async with httpx.AsyncClient(  # 创建异步 HTTP 客户端
            limits=limits,
            timeout=httpx.Timeout(timeout),
            follow_redirects=follow_redirects,
            verify=False  # 跳过 SSL 证书验证
    ) as client:

        semaphore = asyncio.Semaphore(thread_num)  # 创建并发信号量

        async def single_request(url):
            """
            单个 URL 的异步请求（受信号量限制）

            Args:
                url: 目标 URL

            Returns:
                dict: 请求结果
            """
            async with semaphore:  # 获取信号量
                result = {  # 初始化结果字典
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
                    # 根据方法发起不同请求
                    if method.upper() == "GET":
                        resp = await client.get(url, headers=headers, cookies=cookies)  # GET 请求
                    elif method.upper() == "POST":
                        resp = await client.post(url, json={}, headers=headers, cookies=cookies)  # POST 请求
                    else:
                        resp = await client.request(method, url, json={}, headers=headers, cookies=cookies)  # 自定义方法请求

                    result["status_code"] = resp.status_code  # 记录状态码
                    result["response_content"] = resp.text  # 记录响应内容
                    result["length"] = len(resp.content)  # 记录响应长度

                    # 记录跳转信息
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        result["redirect_location"] = resp.headers.get('location')  # 记录跳转地址
                        result["redirect_count"] = 1  # 记录跳转次数

                except httpx.TimeoutException as e:  # 超时异常
                    result["error"] = f"Timeout: {str(e)}"
                except httpx.ConnectError as e:  # 连接异常
                    result["error"] = f"Connection Error: {str(e)}"
                except httpx.RequestError as e:  # 请求异常
                    result["error"] = f"Request Error: {str(e)}"
                except Exception as e:  # 其他异常
                    result["error"] = f"Unknown Error: {str(e)}"
                finally:
                    progress.update(1)

                return result

        # 并发执行所有请求
        tasks = [single_request(url) for url in urls]  # 创建所有请求任务
        results = await asyncio.gather(*tasks, return_exceptions=False)  # 并发执行所有任务

    progress.close()  # 关闭进度条
    return results


async def fetch_urls_smart(urls, thread_num=50, headers=None, cookies=None,
                           timeout=GLOBAL_TIMEOUT, follow_redirects=True):
    """
    智能双方法请求（POST 优先，405 自动切换 GET）

    两轮请求策略：
    1. 第一轮：全部使用 POST 方法请求
    2. 对返回 405 Method Not Allowed 的 URL，第二轮使用 GET 方法重试

    Args:
        urls: URL 列表
        thread_num: 并发线程数
        headers: 自定义请求头
        cookies: Cookie
        timeout: 请求超时时间
        follow_redirects: 是否跟随跳转

    Returns:
        tuple: (最终结果列表, 统计信息字典)
    """
    # 第 1 轮：全部 POST
    post_results = await fetch_urls_async(  # 第一轮 POST 请求
        urls=urls,
        thread_num=thread_num,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
        method="POST",
        follow_redirects=follow_redirects
    )

    # 筛选需要 GET 的 URL（405 的响应）
    need_get_urls = []  # 需要 GET 重试的 URL 列表
    final_results = []  # 最终结果列表
    stats = {  # 统计信息
        "post_only": 0,
        "post_then_get": 0,
        "405_count": 0,
    }

    for result in post_results:  # 遍历第一轮结果
        if result.get("error"):
            final_results.append(result)
            continue

        status = result["status_code"]  # 获取状态码

        if status == 405:
            need_get_urls.append(result["url"])  # 加入重试列表
            stats["405_count"] += 1  # 统计 405 数量
        else:
            final_results.append(result)
            stats["post_only"] += 1  # 统计 POST 成功数量

    # 第 2 轮：对 405 的 URL 尝试 GET
    if need_get_urls:
        get_results = await fetch_urls_async(  # 第二轮 GET 请求
            urls=need_get_urls,
            thread_num=thread_num,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            method="GET",
            follow_redirects=follow_redirects
        )

        for get_result in get_results:  # 遍历第二轮结果
            stats["post_then_get"] += 1  # 统计 POST 转 GET 数量
            final_results.append(get_result)

    stats["total_urls"] = len(urls)  # 总计 URL 数
    stats["total_requests"] = len(urls) + len(need_get_urls)  # 总计请求数

    return final_results, stats


async def fetch_urls_with_dedup(urls, thread_num=50, headers=None, cookies=None,
                                timeout=GLOBAL_TIMEOUT, follow_redirects=True):
    """
    带响应去重的异步批量请求

    使用 fetch_urls_smart 智能请求后，对响应进行指纹去重：
    - 相同 URL 保留状态码优先级最高的结果
    - 相同响应指纹只计一次

    Args:
        urls: URL 列表
        thread_num: 并发线程数
        headers: 自定义请求头
        cookies: Cookie
        timeout: 请求超时时间
        follow_redirects: 是否跟随跳转

    Returns:
        tuple: (去重后的结果列表, 重复计数, 统计信息)
    """
    # 先执行智能请求
    all_results, stats = await fetch_urls_smart(  # 执行智能双方法请求
        urls=urls,
        thread_num=thread_num,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
        follow_redirects=follow_redirects
    )

    url_result_map = {}  # URL 结果映射表
    duplicates_count = 0  # 重复计数
    seen_fingerprints = set()  # 已见指纹集合

    for result in all_results:  # 遍历所有结果
        if result.get("error"):
            continue

        url = result["url"]  # 获取 URL
        # 计算响应指纹
        fingerprint = get_response_fingerprint(result.get("response_content", ""))  # 计算响应指纹
        result["fingerprint"] = fingerprint  # 存储指纹

        # 对同一 URL 的多个结果，保留优先级最高的
        if url in url_result_map:
            current = url_result_map[url]  # 获取当前最优结果
            current_priority = _get_status_priority(current["status_code"])  # 当前优先级
            new_priority = _get_status_priority(result["status_code"])  # 新结果优先级

            if new_priority > current_priority:
                url_result_map[url] = result  # 更新为更优结果
            duplicates_count += 1  # 计数重复
        else:
            url_result_map[url] = result  # 首次记录该 URL
            seen_fingerprints.add(fingerprint)

    unique_results = list(url_result_map.values())  # 提取去重结果

    return unique_results, duplicates_count, stats
