"""
并发爬取器 - 同时驱动 Playwright（动态）和 httpx（静态）

从 scanner.py 的 parallel_fetch 方法中分离，
将并发爬取调度逻辑放在 crawler 层，Scanner 只需调用结果。
"""
import asyncio

from user_agent import generate_user_agent

from crawler.browser_crawler import get_source_async
from crawler.httpx_crawler import fetch_urls_async


async def parallel_fetch(batch_dynamic, batch_static, thread_num, args=None, checker=None):
    """
    异步并行请求：同时处理静态和动态资源

    Args:
        batch_dynamic: 需要 Playwright 动态渲染的 URL 列表
        batch_static: 使用 httpx 直接请求的 URL 列表
        thread_num: 最大并发数
        args: 命令行参数（传给 get_source_async）
        checker: 去重管理器（传给 get_source_async）

    Returns:
        tuple: (dynamic_result, static_result)
            dynamic_result = (all_next_urls_with_source, scan_info_list, all_next_urls, all_next_paths_with_source)
            static_result = httpx 响应列表
    """
    tasks = []       # 任务列表
    task_order = []  # 任务顺序列表
    if batch_dynamic:
        dynamic_task = get_source_async(urls=batch_dynamic, thread_num=thread_num, args=args,
                                        checker=checker)  # 动态爬取任务
        tasks.append(dynamic_task)
        task_order.append('dynamic')
    if batch_static:
        static_task = fetch_urls_async(urls=batch_static, thread_num=min(thread_num, 50),
                                       headers={"User-Agent": generate_user_agent()}, timeout=10)  # 静态请求任务
        tasks.append(static_task)
        task_order.append('static')
    if not tasks:
        return ([], [], set(), []), []

    results = await asyncio.gather(*tasks)  # 并发执行所有任务
    dynamic_result = ([], [], set(), [])     # 动态结果默认值
    static_result = []                       # 静态结果默认值
    for i, task_type in enumerate(task_order):  # 遍历任务类型
        if task_type == 'dynamic':
            dynamic_result = results[i]  # 取动态结果
        elif task_type == 'static':
            static_result = results[i]   # 取静态结果
    return dynamic_result, static_result
