import json
import re
import httpx
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from config.scanner_rules import (
    REQUEST_HEADERS,
    REQUEST_TIMEOUT,
    CONTENT_SUMMARY_MAX_LENGTH,
    SUPPORTED_REQUEST_METHODS,
    DEFAULT_REQUEST_METHOD
)
from logger import get_logger

logger = get_logger(__name__)  # 获取日志记录器


def _strip_html_tags(text: str) -> str:
    """
    去除文本中的所有 HTML 标签

    Args:
        text: 包含 HTML 标签的文本

    Returns:
        去除 HTML 标签后的纯文本
    """
    if not text:
        return ""

    # 使用正则表达式去除所有 HTML 标签
    clean_text = re.sub(r'<[^>]+>', '', text)  # 去除HTML标签

    # 去除多余的空格和换行符
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()  # 合并空白字符

    return clean_text


def _parse_params_string(params_str: str) -> Dict[str, Any]:
    """
    解析参数字符串为字典

    支持格式：
    - "key1=value1,key2=value2"
    - "key1=value1&key2=value2"
    - JSON 字符串（兼容）

    Args:
        params_str: 参数字符串

    Returns:
        解析后的参数字典
    """
    if not params_str or not isinstance(params_str, str):
        return {}

    params_str = params_str.strip()  # 去除首尾空格
    if not params_str:
        return {}

    # 尝试作为 JSON 解析（兼容情况）
    if params_str.startswith('{'):
        try:
            parsed = json.loads(params_str)  # 尝试解析JSON
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    # 按逗号或 & 分割
    params = {}  # 初始化参数字典
    # 检测使用哪种分隔符
    separator = ',' if ',' in params_str else '&'  # 确定分隔符

    for item in params_str.split(separator):  # 遍历参数项
        item = item.strip()  # 去除项的首尾空格
        if not item:
            continue

        if '=' in item:
            key, value = item.split('=', 1)  # 分割键值对
            params[key.strip()] = value.strip()  # 存入参数字典
        else:
            # 没有 = 的情况，作为键名处理
            params[item] = ""  # 无值参数设为空

    return params


def execute_api_request(
        full_url: str,
        method: str,
        params_json: Optional[str] = None
) -> Dict[str, Any]:
    """
    执行单个 API 请求并返回状态码和内容摘要

    流程：
    1. 标准化 HTTP 方法
    2. 解析参数
    3. 构建请求头
    4. 发起 HTTP 请求
    5. 提取结果（去 HTML 标签后截取摘要）

    Args:
        full_url: 完整的 API URL
        method: HTTP 方法（GET/POST/PUT，其他方法会降级为 GET）
        params_json: 参数字符串（格式为 "key=value,key2=value2"）

    Returns:
        dict: 包含 status_code 和 content_summary 的字典
    """
    result = {  # 初始化结果字典
        "status_code": -1,
        "content_summary": ""
    }

    try:
        # Step 1: 标准化 method
        normalized_method = _normalize_method(method)  # 标准化HTTP方法

        # Step 2: 解析 params
        params_dict = {}  # 初始化参数字典
        if params_json:
            try:
                params_dict = _parse_params_string(params_json)  # 解析参数字符串
            except Exception as e:  # 捕获参数解析异常
                logger.warning(f"⚠️ [Request] 参数解析失败: {full_url} | Error: {e}")
                result["status_code"] = -2  # 设置参数错误码
                result["content_summary"] = f"Params Parse Exception: {str(e)}"  # 记录异常摘要
                return result

        # Step 3: 构建请求头（从配置中复制默认请求头）
        headers = REQUEST_HEADERS.copy()  # 复制默认请求头

        # Step 4: 根据方法发起不同的 HTTP 请求
        with httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:  # 创建HTTP客户端
            if normalized_method == "POST":
                response = client.post(full_url, headers=headers, json=params_dict if params_dict else None)  # 发送POST请求
            elif normalized_method == "PUT":
                response = client.put(full_url, headers=headers, json=params_dict if params_dict else None)  # 发送PUT请求
            else:
                response = client.get(full_url, headers=headers)  # 发送GET请求

        # Step 5: 提取结果（先去除 HTML 标签，再截取长度）
        clean_content = _strip_html_tags(response.text)  # 去除响应HTML标签
        result["status_code"] = response.status_code  # 记录响应状态码
        result["content_summary"] = clean_content[:CONTENT_SUMMARY_MAX_LENGTH]  # 截取内容摘要

        logger.info(f"✅ [Request] {normalized_method} {full_url} → {result['status_code']}")

    except httpx.TimeoutException as e:  # 捕获请求超时异常
        result["status_code"] = -1  # 设置超时状态码
        result["content_summary"] = "Request Failed: timeout"  # 记录超时摘要
        logger.warning(f"⏱️ [Request] 超时: {full_url}")

    except httpx.NetworkError as e:  # 捕获网络错误异常
        result["status_code"] = -1  # 设置网络错误码
        result["content_summary"] = "Request Failed: connection error"  # 记录网络错误摘要
        logger.warning(f"🌐 [Request] 网络错误: {full_url} | {e}")

    except Exception as e:  # 捕获其他未知异常
        result["status_code"] = -1  # 设置未知错误码
        result["content_summary"] = f"Request Failed: {str(e)[:100]}"  # 记录错误摘要
        logger.error(f"❌ [Request] 未知错误: {full_url} | {e}")

    return result


def _normalize_method(method: str) -> str:
    """
    标准化 HTTP 方法

    将方法名转为大写并验证是否在支持的列表中，
    不支持的方法将降级为默认方法（GET）。

    Args:
        method: 原始方法字符串

    Returns:
        标准化的方法（GET/POST/PUT），无效方法降级为 GET
    """
    if not method or not isinstance(method, str):
        return DEFAULT_REQUEST_METHOD

    method_upper = method.upper().strip()  # 转为大写并去空格

    if method_upper in SUPPORTED_REQUEST_METHODS:
        return method_upper

    # 非标准方法降级为默认方法
    logger.debug(f"⚠️ [Request] 不支持的方法 '{method}'，降级为 {DEFAULT_REQUEST_METHOD}")
    return DEFAULT_REQUEST_METHOD


async def batch_execute_requests(
        vuln_records: list
) -> list:
    """
    批量执行 HTTP 请求验证（异步版本，提高并发效率）

    使用 asyncio 的事件循环在线程池中并发执行同步请求函数。

    Args:
        vuln_records: AI 漏洞记录列表，每个记录包含:
            - id: 数据库记录 ID
            - full_url: 完整 URL
            - http_method: HTTP 方法
            - params: JSON 格式的参数

    Returns:
        list: 结果列表，每个元素包含:
            - id: 记录 ID
            - status_code: 状态码
            - content_summary: 内容摘要
    """
    import asyncio

    async def single_request(record: Dict[str, Any]) -> Dict[str, Any]:
        """
        单个请求的异步包装

        使用 run_in_executor 将同步的 execute_api_request 调用转为异步执行。

        Args:
            record: 漏洞记录字典

        Returns:
            dict: 包含 id, status_code, content_summary 的结果
        """
        loop = asyncio.get_event_loop()  # 获取事件循环
        result = await loop.run_in_executor(  # 在线程池中执行同步请求
            None,  # 使用默认线程池
            execute_api_request,
            record["full_url"],
            record["http_method"],
            record.get("params")
        )
        result["id"] = record["id"]  # 添加记录ID
        return result

    # 并发执行所有请求
    tasks = [single_request(record) for record in vuln_records]  # 创建异步任务列表
    results = await asyncio.gather(*tasks, return_exceptions=True)  # 并发执行所有任务

    # 处理异常结果（将异常转换为标准错误格式）
    final_results = []  # 初始化最终结果列表
    for i, result in enumerate(results):  # 遍历执行结果
        if isinstance(result, Exception):
            logger.error(f"❌ [Batch Request] 任务 {i} 执行失败: {result}")
            final_results.append({
                "id": vuln_records[i]["id"],
                "status_code": -1,
                "content_summary": f"Request Failed: {str(result)[:100]}"
            })
        else:
            final_results.append(result)

    return final_results
