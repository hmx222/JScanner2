import re
import json
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from infra.ai_client import client
from config.scanner_rules import is_api_path_blacklisted
from logger import get_logger

logger = get_logger(__name__)

MIN_CLUSTER_SIZE = 9
SAMPLE_SIZE = 3
PROBE_TIMEOUT = 10
FINGERPRINT_CHARS = 500
GENERIC_200_KEYWORDS = {
    '访问地址不存在', '页面未找到', '页面不存在', 'not found', 'page not found',
    '404',
}


def _strip_html(text):
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean


def _fingerprint(text):
    if not text:
        return ""
    return _strip_html(text)[:FINGERPRINT_CHARS]


def _is_structured_json(text: str) -> bool:
    """判断响应是否为结构化 JSON（API 网关的典型响应）"""
    if not text:
        return False
    stripped = text.strip()
    if not stripped.startswith('{'):
        return False
    try:
        data = json.loads(stripped)
        if not isinstance(data, dict):
            return False
        json_indicators = {'code', 'status', 'msg', 'message', 'data', 'errcode', 'errmsg', 'ret', 'result'}
        return bool(json_indicators & set(data.keys()))
    except (json.JSONDecodeError, TypeError):
        return False


def _is_generic_page(text: str) -> bool:
    """判断响应是否为通用兜底页面（假 200）"""
    if not text:
        return False
    text_lower = text.strip().lower()
    for kw in GENERIC_200_KEYWORDS:
        if kw.lower() in text_lower:
            return True
    return False


def _get_first_level_prefix(api_path):
    path = api_path.strip().lstrip('/')
    parts = path.split('/')
    if parts:
        return parts[0]
    return ""


def _cluster_paths_by_prefix(api_paths):
    clusters = {}
    for path in api_paths:
        prefix = _get_first_level_prefix(path)
        if not prefix:
            continue
        if prefix not in clusters:
            clusters[prefix] = []
        clusters[prefix].append(path)
    return clusters


def _get_large_clusters(clusters):
    return {k: v for k, v in clusters.items() if len(v) >= MIN_CLUSTER_SIZE}


DANGEROUS_KEYWORDS = {
    'delete', 'del', 'remove', 'rm', 'destroy', 'drop',
    'update', 'modify', 'create', 'add', 'save', 'submit',
    'pay', 'transfer', 'withdraw', 'export', 'import',
    'upload', 'batch', 'clear', 'purge', 'erase',
    'reset', 'revoke', 'disable', 'suspend', 'ban',
}


def _is_path_dangerous(path: str) -> bool:
    """检查路径是否匹配黑名单正则"""
    return is_api_path_blacklisted(path)


def _pick_sample_paths(paths, count=SAMPLE_SIZE):
    safe = []
    for path in paths:
        if not path or len(path) < 6 or path.count('/') < 2:
            continue
        if '.' in path.split('/')[-1]:
            continue
        if _is_path_dangerous(path):
            continue
        safe.append(path)
        if len(safe) >= count:
            break

    return safe[:count]


def _send_probe(url):
    result = {
        "url": url,
        "status_code": -1,
        "fingerprint": "",
        "error": None,
    }
    try:
        headers = {"Content-Type": "application/json"}
        with httpx.Client(timeout=PROBE_TIMEOUT, follow_redirects=False) as c:
            resp = c.post(url, json={}, headers=headers)
            result["status_code"] = resp.status_code
            text = resp.text or ""
            result["fingerprint"] = _fingerprint(text)
    except httpx.TimeoutException:
        result["error"] = "timeout"
    except httpx.ConnectError:
        result["error"] = "connection_error"
    except Exception as e:
        result["error"] = str(e)[:100]

    logger.info(f"🔬 [Prefix Probe] {url} → status={result['status_code']}, error={result['error']}")
    return result


def _is_prefix_better(ai_text):
    if not ai_text or not isinstance(ai_text, str):
        return False

    text = ai_text.strip()

    winner_idx = text.find('winner')
    if winner_idx != -1:
        colon_idx = text.find(':', winner_idx)
        if colon_idx != -1 and colon_idx - winner_idx < 15:
            after = text[colon_idx + 1:colon_idx + 10].strip()
            if after.startswith('"B"') or after.startswith("'B'"):
                return True
            if after.startswith('"A"') or after.startswith("'A'"):
                return False

    if "B组更好" in text or "B 组更好" in text:
        return True
    if "prefix有效" in text or "prefix 有效" in text or "前缀有效" in text:
        return True
    if "A组更好" in text or "A 组更好" in text:
        return False

    return False


def verify_prefix_for_clusters(
    base_prefix,
    seed_url,
    api_paths_by_cluster,
):
    """
    对大类别进行 baseURL prefix 验证。

    规则：
      - 每个类别抽 3 个 path
      - 每个 path 发 2 个请求：A(无 prefix) 和 B(有 prefix)
      - AI 对比 A/B 响应（各取前 500 字符）
      - 3 个中至少 1 个判定 B 更好 → 该类别使用 prefix
      - 否则 → 该类别回退到无 prefix

    Returns:
        {cluster_prefix: use_prefix(bool)}
        未在结果中的类别默认使用 prefix
    """
    try:
        return _verify_prefix_inner(base_prefix, seed_url, api_paths_by_cluster)
    except Exception as e:
        logger.error(f"❌ [PrefixAgent] 顶层异常: {type(e).__name__}: {e}")
        return {}


def _verify_prefix_inner(base_prefix, seed_url, api_paths_by_cluster):
    parsed = urlparse(seed_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    results = {}

    for cluster_name, paths in api_paths_by_cluster.items():
        sample_paths = _pick_sample_paths(paths)
        if not sample_paths:
            continue

        logger.info(f"🧪 [PrefixAgent] 验证类别 '{cluster_name}': {len(paths)} 个 API, 抽样 {len(sample_paths)} 个")

        comparison_data = []
        mechanical_b_wins = 0

        for i, path in enumerate(sample_paths):
            url_a = f"{origin}/{path.lstrip('/')}"
            url_b = f"{base_prefix}/{path.lstrip('/')}"

            probe_a = _send_probe(url_a)
            probe_b = _send_probe(url_b)

            comparison_data.append({
                "idx": i + 1,
                "path": path,
                "url_a": url_a,
                "url_b": url_b,
                "a": probe_a,
                "b": probe_b,
            })

            a_fp = probe_a.get("fingerprint", "")
            b_fp = probe_b.get("fingerprint", "")
            b_is_json = _is_structured_json(b_fp)
            a_is_json = _is_structured_json(a_fp)
            a_is_generic = _is_generic_page(a_fp)
            a_status = probe_a.get("status_code", -1)
            b_status = probe_b.get("status_code", -1)

            # 机械预判跳过 AI 的条件（必须全部满足才算"非常有信心"）：
            # 1. B 返回结构化 JSON
            # 2. B 的 HTTP 状态码是 200
            # 3. A 不是 200 或 A 是假 200 页面
            # 4. A 和 B 的响应内容明显不同（排除全站统一返回 JSON 的情况）
            responses_differ = a_fp != b_fp and a_status != b_status
            b_healthy = b_is_json and b_status == 200
            a_unhealthy = a_is_generic or a_status != 200

            if b_healthy and a_unhealthy and responses_differ:
                mechanical_b_wins += 1

        if mechanical_b_wins >= len(sample_paths):
            logger.info(f"✅ [PrefixAgent] '{cluster_name}' → 机械预判: B 有效响应且与 A 显著不同, 使用 prefix (跳过 AI)")
            results[cluster_name] = True
            continue

        from processor.analysis.prompts.prompts import _SYSTEM_PROMPT_PREFIX_VERIFY

        comparison_text = ""
        for item in comparison_data:
            a_status = item["a"].get("status_code", -1)
            b_status = item["b"].get("status_code", -1)
            a_fp = item["a"].get("fingerprint", "")[:FINGERPRINT_CHARS]
            b_fp = item["b"].get("fingerprint", "")[:FINGERPRINT_CHARS]
            a_err = item["a"].get("error")
            b_err = item["b"].get("error")

            comparison_text += f"\n===== 抽样 {item['idx']}: {item['path']} =====\n"

            if a_err:
                comparison_text += f"A (无前缀) {item['url_a']}: 请求失败 ({a_err})\n"
            else:
                comparison_text += f"A (无前缀) {item['url_a']}: HTTP {a_status}\n  响应: {a_fp}\n"

            if b_err:
                comparison_text += f"B (有前缀) {item['url_b']}: 请求失败 ({b_err})\n"
            else:
                comparison_text += f"B (有前缀) {item['url_b']}: HTTP {b_status}\n  响应: {b_fp}\n"

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT_PREFIX_VERIFY},
            {"role": "user", "content": f"请对比以下 {len(sample_paths)} 组 A/B 响应：\n{comparison_text}"},
        ]

        raw_response = client.chat(messages=messages, require_json=False, max_tokens=800)
        raw_str = str(raw_response) if raw_response else ""
        logger.info(f"🗳️ [PrefixAgent] '{cluster_name}' AI 返回: {raw_str[:300]}")

        prefix_is_better = _is_prefix_better(raw_str)
        results[cluster_name] = prefix_is_better

        if prefix_is_better:
            logger.info(f"✅ [PrefixAgent] '{cluster_name}' → 使用 prefix")
        else:
            logger.info(f"❌ [PrefixAgent] '{cluster_name}' → 不使用 prefix (回退)")

    return results