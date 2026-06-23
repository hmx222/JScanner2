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

logger = get_logger(__name__)


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
    clean_text = re.sub(r'<[^>]+>', '', text)
    
    # 去除多余的空格和换行符
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    
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
    
    params_str = params_str.strip()
    if not params_str:
        return {}
    
    # 尝试作为 JSON 解析（兼容情况）
    if params_str.startswith('{'):
        try:
            parsed = json.loads(params_str)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    
    # 按逗号或 & 分割
    params = {}
    separators = [',', '&']
    
    # 检测使用哪种分隔符
    separator = ',' if ',' in params_str else '&'
    
    for item in params_str.split(separator):
        item = item.strip()
        if not item:
            continue
        
        if '=' in item:
            key, value = item.split('=', 1)
            params[key.strip()] = value.strip()
        else:
            # 没有 = 的情况，作为键名处理
            params[item] = ""
    
    return params


def execute_api_request(
        full_url: str,
        method: str,
        params_json: Optional[str] = None
) -> Dict[str, Any]:
    """
    执行 API 请求并返回状态码和内容摘要

    Args:
        full_url: 完整的 API URL
        method: HTTP 方法（GET/POST/PUT，其他方法会降级为 GET）
        params_json: 参数串（来自 ai_vulns 表的 params 字段，格式为 "key=value,key2=value2"）

    Returns:
        {
            "status_code": int,      # HTTP 状态码，失败时为 -1 或 -2
            "content_summary": str   # 响应前500字符（已去除HTML标签），或错误描述
        }
    """
    result = {
        "status_code": -1,
        "content_summary": ""
    }

    try:
        # Step 1: 标准化 method
        normalized_method = _normalize_method(method)

        # Step 2: 解析 params
        params_dict = {}
        if params_json:
            try:
                params_dict = _parse_params_string(params_json)
            except Exception as e:
                logger.warning(f"⚠️ [Request] 参数解析失败: {full_url} | Error: {e}")
                result["status_code"] = -2
                result["content_summary"] = f"Params Parse Exception: {str(e)}"
                return result

        # Step 3: 构建请求头
        headers = REQUEST_HEADERS.copy()

        # Step 4: 根据 method 发起请求
        if normalized_method == "GET":
            response = _execute_get(full_url, headers, params_dict)
        elif normalized_method == "POST":
            response = _execute_post_put("POST", full_url, headers, params_dict)
        elif normalized_method == "PUT":
            response = _execute_post_put("PUT", full_url, headers, params_dict)
        else:
            # 理论上不会到这里，因为 _normalize_method 已经处理了
            response = _execute_get(full_url, headers, params_dict)

        # Step 5: 提取结果（先去除HTML标签，再截取长度）
        clean_content = _strip_html_tags(response.text)
        result["status_code"] = response.status_code
        result["content_summary"] = clean_content[:CONTENT_SUMMARY_MAX_LENGTH]

        logger.info(f"✅ [Request] {normalized_method} {full_url} → {result['status_code']}")

    except httpx.TimeoutException as e:
        result["status_code"] = -1
        result["content_summary"] = "Request Failed: timeout"
        logger.warning(f"⏱️ [Request] 超时: {full_url}")

    except httpx.NetworkError as e:
        result["status_code"] = -1
        result["content_summary"] = "Request Failed: connection error"
        logger.warning(f"🌐 [Request] 网络错误: {full_url} | {e}")

    except Exception as e:
        result["status_code"] = -1
        result["content_summary"] = f"Request Failed: {str(e)[:100]}"
        logger.error(f"❌ [Request] 未知错误: {full_url} | {e}")

    return result


def _normalize_method(method: str) -> str:
    """
    标准化 HTTP 方法

    Args:
        method: 原始方法字符串

    Returns:
        标准化的方法（GET/POST/PUT），无效方法降级为 GET
    """
    if not method or not isinstance(method, str):
        return DEFAULT_REQUEST_METHOD

    method_upper = method.upper().strip()

    if method_upper in SUPPORTED_REQUEST_METHODS:
        return method_upper

    # 非标准方法降级为 GET
    logger.debug(f"⚠️ [Request] 不支持的方法 '{method}'，降级为 GET")
    return DEFAULT_REQUEST_METHOD


def _execute_get(
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any]
) -> httpx.Response:
    """
    执行 GET 请求

    Args:
        url: 目标 URL
        headers: 请求头
        params: 查询参数（会自动拼接到 URL）

    Returns:
        httpx 响应对象
    """
    with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
        response = client.get(url, headers=headers, params=params)
        return response


def _execute_post_put(
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Dict[str, Any]
) -> httpx.Response:
    """
    执行 POST 或 PUT 请求

    Args:
        method: "POST" 或 "PUT"
        url: 目标 URL
        headers: 请求头
        body: 请求体（会自动序列化为 JSON）

    Returns:
        httpx 响应对象
    """
    with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
        if method == "POST":
            response = client.post(url, headers=headers, json=body)
        else:  # PUT
            response = client.put(url, headers=headers, json=body)
        return response


async def batch_execute_requests(
        vuln_records: list
) -> list:
    """
    批量执行请求（异步版本，提高并发效率）

    Args:
        vuln_records: AI 漏洞记录列表，每个记录包含:
            - id: 数据库记录 ID
            - full_url: 完整 URL
            - http_method: HTTP 方法
            - params: JSON 格式的参数

    Returns:
        结果列表，每个元素包含:
            - id: 记录 ID
            - status_code: 状态码
            - content_summary: 内容摘要
    """
    import asyncio

    async def single_request(record: Dict[str, Any]) -> Dict[str, Any]:
        """单个请求的异步包装"""
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            execute_api_request,
            record["full_url"],
            record["http_method"],
            record.get("params")
        )
        result["id"] = record["id"]
        return result

    # 并发执行所有请求
    tasks = [single_request(record) for record in vuln_records]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理异常结果
    final_results = []
    for i, result in enumerate(results):
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
