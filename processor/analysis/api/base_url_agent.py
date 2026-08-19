import re
from collections import Counter
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import httpx

from infra.ai_client import client
from config.scanner_rules import API_PATH_BLACKLIST_KEYWORDS
from logger import get_logger

logger = get_logger(__name__)

AGENT_REQUEST_TIMEOUT = 10
VERIFICATION_ROUNDS = 3
FINGERPRINT_MAX_CHARS = 500
DANGEROUS_PATH_KEYWORDS = {
    'delete', 'del', 'remove', 'rm', 'destroy', 'drop',
    'update', 'modify', 'create', 'add', 'save', 'submit',
    'pay', 'transfer', 'withdraw', 'export', 'import',
    'upload', 'batch', 'clear', 'purge', 'erase',
    'reset', 'revoke', 'disable', 'suspend', 'ban',
}

_INVALID_CANDIDATE_PATTERNS = [
    re.compile(r'^(base[_\s]?url|api[_\s]?base|api[_\s]?url|基础路径|基础地址|接口地址|请求地址)$', re.IGNORECASE),
    re.compile(r'^(https?://)?\{'),
    re.compile(r'^(https?://)?\$'),
    re.compile(r'^(https?://)?<'),
    re.compile(r'[\u4e00-\u9fff]'),
]


def _strip_html_tags(text: str) -> str:
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean


def _is_valid_candidate(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    url_stripped = url.strip()
    if len(url_stripped) < 4:
        return False
    for pattern in _INVALID_CANDIDATE_PATTERNS:
        if pattern.search(url_stripped):
            return False
    return True


def _normalize_base_url(base_url: str, seed_url: str) -> str:
    parsed = urlparse(seed_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    result = base_url
    result = result.replace("location.origin", origin)
    result = result.replace("window.location.origin", origin)
    result = result.replace("<origin>", origin)
    if not result.startswith("http"):
        first_segment = result.split('/')[0]
        if '.' in first_segment:
            result = f"{parsed.scheme}://{result}"
        else:
            result = f"{origin}/{result.lstrip('/')}"
    return result.rstrip('/')


def _is_path_dangerous(path: str) -> bool:
    """检查路径是否包含黑名单关键词（子串匹配）"""
    path_lower = path.lower().split('?')[0]
    for kw in API_PATH_BLACKLIST_KEYWORDS:
        if kw in path_lower:
            return True
    return False


def _pick_safe_paths(api_paths: List[str], count: int = 3) -> List[str]:
    safe = []
    for path in api_paths:
        if not path or not isinstance(path, str):
            continue
        if len(path) < 6 or path.count('/') < 2:
            continue
        if '.' in path.split('/')[-1]:
            continue
        if _is_path_dangerous(path):
            continue
        safe.append(path)
        if len(safe) >= count:
            break

    return safe[:count]


def _send_probe_request(url: str) -> Dict[str, Any]:
    result = {
        "url": url,
        "status_code": -1,
        "fingerprint": "",
        "error": None,
    }
    try:
        headers = {"Content-Type": "application/json"}
        with httpx.Client(timeout=AGENT_REQUEST_TIMEOUT, follow_redirects=False) as c:
            resp = c.post(url, json={}, headers=headers)
            result["status_code"] = resp.status_code
            text = resp.text or ""
            text = _strip_html_tags(text)
            result["fingerprint"] = text[:FINGERPRINT_MAX_CHARS]
    except httpx.TimeoutException:
        result["error"] = "timeout"
    except httpx.ConnectError:
        result["error"] = "connection_error"
    except Exception as e:
        result["error"] = str(e)[:100]

    logger.info(f"🔬 [Agent Probe] {url} → status={result['status_code']}, error={result['error']}")
    return result


def _resolve_candidates(combined_code: str, seed_url: str) -> List[str]:
    """Round 0：让 AI 分析代码 + 去重，输出去重后的候选 baseURL 列表"""
    from processor.analysis.prompts.prompts import _SYSTEM_PROMPT_BASEURL_RESOLVE

    parsed = urlparse(seed_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    system_prompt = _SYSTEM_PROMPT_BASEURL_RESOLVE.replace("{origin}", origin)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"目标站点 origin: {origin}\n\n代码段:\n{combined_code}"},
    ]

    result = client.chat(messages=messages, require_json=True, max_tokens=1000)

    if not isinstance(result, dict):
        logger.warning(f"⚠️ [Agent] Round 0 AI 返回非 JSON: {str(result)[:200]}")
        return []

    raw_candidates = result.get("candidates", [])
    if not isinstance(raw_candidates, list):
        return []

    normalized = []
    seen = set()
    for c in raw_candidates:
        if not c or not isinstance(c, str):
            continue
        if not _is_valid_candidate(c):
            logger.info(f"🚫 [Agent] 过滤无效候选: {c}")
            continue
        norm = _normalize_base_url(c, seed_url)
        if norm not in seen:
            seen.add(norm)
            normalized.append(norm)

    logger.info(f"🎯 [Agent] Round 0 去重后候选 baseURL: {normalized}")
    return normalized


def _judge_round(
    candidate_urls: List[str],
    probe_results: List[Dict],
    seed_url: str,
    round_num: int,
) -> Optional[str]:
    try:
        return _judge_round_inner(candidate_urls, probe_results, seed_url, round_num)
    except Exception as e:
        import traceback
        logger.error(f"❌ [Agent] Round {round_num} 判定异常: {type(e).__name__}: {e}")
        logger.error(traceback.format_exc())
        return None


def _extract_winner_from_text(text: str, candidate_count: int) -> Optional[int]:
    """
    从 AI 返回的原始文本中提取 winner 数字
    使用纯字符串操作，不依赖 json_repair，不用 dict 访问
    """
    if not text or not isinstance(text, str):
        return None

    idx = text.find('"winner"')
    if idx == -1:
        idx = text.find("'winner'")
    if idx == -1:
        idx = text.find("winner")
    if idx == -1:
        return None

    colon_idx = text.find(':', idx)
    if colon_idx == -1 or colon_idx - idx > 20:
        return None

    after_colon = text[colon_idx + 1:colon_idx + 10].strip()

    digits = ""
    for ch in after_colon:
        if ch.isdigit():
            digits += ch
        elif digits:
            break

    if not digits:
        return None

    winner = int(digits)
    if 1 <= winner <= candidate_count:
        return winner
    return None


def _judge_round_inner(
    candidate_urls: List[str],
    probe_results: List[Dict],
    seed_url: str,
    round_num: int,
) -> Optional[str]:
    from processor.analysis.prompts.prompts import _SYSTEM_PROMPT_BASEURL_JUDGE_ROUND

    system_prompt = _SYSTEM_PROMPT_BASEURL_JUDGE_ROUND \
        .replace("{round_num}", str(round_num)) \
        .replace("{seed_url}", seed_url)

    results_text = ""
    for i, result in enumerate(probe_results):
        url = candidate_urls[i] if i < len(candidate_urls) else f"候选{i+1}"
        if result.get("error"):
            results_text += f"\n[候选 {i + 1}] {url}\n    状态: 请求失败 ({result['error']})\n"
        else:
            preview = result.get("fingerprint", "")[:200]
            results_text += (
                f"\n[候选 {i + 1}] {url}\n"
                f"    HTTP 状态码: {result.get('status_code', -1)}\n"
                f"    响应内容(前200字符): {preview}\n"
            )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"请求结果:\n{results_text}"},
    ]

    raw_response = client.chat(messages=messages, require_json=False, max_tokens=500)
    raw_str = str(raw_response) if raw_response else ""
    logger.info(f"🗳️ [Agent] Round {round_num} AI 原始返回(type={type(raw_response).__name__}): {raw_str[:300]}")

    winner_idx = _extract_winner_from_text(raw_str, len(candidate_urls))
    logger.info(f"🗳️ [Agent] Round {round_num} 投票: winner={winner_idx}")

    if winner_idx:
        return candidate_urls[winner_idx - 1]
    return None


def _majority_vote(round_votes: List[Optional[str]], total_rounds: int) -> Optional[str]:
    valid_votes = [v for v in round_votes if v is not None]
    if not valid_votes:
        return None

    counter = Counter(valid_votes)
    most_common_url, most_common_count = counter.most_common(1)[0]

    min_required = max(2, total_rounds // 2 + 1)
    if most_common_count >= min_required:
        logger.info(f"🏆 [Agent] 投票结果: {most_common_url} ({most_common_count}/{total_rounds} 票)")
        return most_common_url

    logger.warning(f"⚠️ [Agent] 投票未达多数: {dict(counter)} (需 ≥{min_required} 票)")
    return None


def verify_base_url(
    candidates: List[Dict[str, Any]],
    seed_url: str,
    api_paths: List[str],
) -> Optional[str]:
    """
    验证 Agent 主入口：通过实际请求验证哪个 baseURL 是正确的

    流程：
      Round 0: AI 分析代码 → 去重 → 输出去重后的候选列表
      Round 1-3: 每轮换一个安全 path，对所有候选发请求，AI 投票
      最终投票: ≥2/3 票一致才算通过

    Args:
        candidates: BaseURL 提取器输出的写入点列表
        seed_url: 目标站点 URL
        api_paths: 已从该 JS 中提取的 API path 列表

    Returns:
        验证通过的 baseURL 字符串，或 None
    """
    try:
        return _verify_base_url_inner(candidates, seed_url, api_paths)
    except Exception as e:
        logger.error(f"❌ [Agent] verify_base_url 顶层异常: {type(e).__name__}: {e}")
        return None


def _verify_base_url_inner(
    candidates: List[Dict[str, Any]],
    seed_url: str,
    api_paths: List[str],
) -> Optional[str]:
    if not candidates:
        return None

    combined_code = "\n\n// ===== 写入点 =====\n\n".join(
        [c.get("code", "") for c in candidates]
    )

    candidate_urls = _resolve_candidates(combined_code, seed_url)

    if not candidate_urls:
        logger.info("ℹ️ [Agent] 无候选 baseURL，跳过验证")
        return None

    if len(candidate_urls) == 1:
        logger.info(f"✅ [Agent] 唯一候选，直接返回: {candidate_urls[0]}")
        return candidate_urls[0]

    safe_paths = _pick_safe_paths(api_paths, count=VERIFICATION_ROUNDS)
    if not safe_paths:
        logger.warning("⚠️ [Agent] 无安全 path 可用于验证")
        return None

    logger.info(f"🧪 [Agent] 开始验证: {len(candidate_urls)} 个候选 × {len(safe_paths)} 轮")

    round_votes = []

    for round_idx, test_path in enumerate(safe_paths):
        round_num = round_idx + 1
        test_urls = []
        for base in candidate_urls:
            full_url = f"{base.rstrip('/')}/{test_path.lstrip('/')}"
            test_urls.append(full_url)

        probe_results = []
        for url in test_urls:
            result = _send_probe_request(url)
            probe_results.append(result)

        winner = _judge_round(candidate_urls, probe_results, seed_url, round_num)
        round_votes.append(winner)

    final = _majority_vote(round_votes, total_rounds=len(safe_paths))

    if final:
        print(f"🎯 [BaseURL Agent] 验证通过: {final}")
    else:
        print(f"⚠️ [BaseURL Agent] 投票未通过，降级到默认逻辑")

    return final