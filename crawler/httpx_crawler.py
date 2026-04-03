import asyncio
import hashlib
import re

import httpx
from httpx import Limits
from tqdm.asyncio import tqdm_asyncio

from config.config import GLOBAL_TIMEOUT


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

async def fetch_urls_async(urls, thread_num=50, headers=None, cookies=None,
                           timeout=GLOBAL_TIMEOUT, method="GET", follow_redirects=True):
    """
    异步批量请求 URL 列表

    Args:
        follow_redirects: 是否跟随 302 跳转 (默认 True)
    """
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