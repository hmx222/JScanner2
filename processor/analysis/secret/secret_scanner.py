import json
import json
import math
import os
import re
import statistics
import sys
import time
import zlib
from collections import Counter
from traceback import print_exc
from typing import List, Dict, Tuple, Any, Optional

import json_repair

from config.config import NLTK_DIR, EXCLUDE_CONTEXTS, SENSITIVE_KEYWORDS, QUOTE_PATTERN, UNICODE_PATTERN, \
    EXCLUDE_VALUES, IGNORE_PREFIX_PATTERN, SECRET_PROMPT
from infra.bloom import DiskBloomFilter
from infra.utils import remove_html_tags
from logger import get_logger
from processor.js.context.secret_extractor import SenInfoContextExtractor
from storage.db import SQLiteStorage

logger = get_logger(__name__)

try:
    import wordninja
    import nltk
    from nltk.corpus import wordnet, words

    try:
        from processor.js.format.js_formatter import format_code
    except ImportError:
        from js_formatter import format_code
except ImportError as e:
    sys.stderr.write(f"⚠️  Missing dependency: {e}\n")
    sys.exit(1)


def _init_nltk_offline():
    """纯离线 NLTK 数据初始化"""
    if NLTK_DIR not in nltk.data.path:
        nltk.data.path.insert(0, NLTK_DIR)

    required_data = {
        'wordnet': 'corpora/wordnet',
        'omw-1.4': 'corpora/omw-1.4',
        'words': 'corpora/words'
    }

    for package_name, search_path in required_data.items():
        try:
            nltk.data.find(search_path)
        except LookupError:
            logger.warning(f"[-] NLTK 本地缓存缺失 [{package_name}]，正在下载至：{NLTK_DIR}")
            try:
                os.makedirs(NLTK_DIR, exist_ok=True)
                nltk.download(package_name, download_dir=NLTK_DIR, quiet=True)
            except Exception as e:
                logger.warning(f"❌ NLTK 下载失败 {package_name}: {str(e)}")


# class SenInfoDiskBloomFilter:
#     """基于磁盘映射的持久化布隆过滤器"""
#
#     def __init__(self, filepath: str, capacity: int = 10_000_000, error_rate: float = 0.001):
#         self.filepath = filepath
#         self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))
#         self.hash_count = int((self.size / capacity) * math.log(2))
#         self.byte_size = (self.size + 7) // 8
#         self._ensure_file()
#         self.file = open(filepath, "r+b")
#         self.mm = mmap.mmap(self.file.fileno(), 0)
#
#     def _ensure_file(self):
#         os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
#         if not os.path.exists(self.filepath):
#             with open(self.filepath, "wb") as f:
#                 f.write(b'\x00' * self.byte_size)
#
#     def _get_hashes(self, item: str) -> Generator[int, None, None]:
#         item_encoded = item.encode("utf8")
#         md5 = int(hashlib.md5(item_encoded).hexdigest(), 16)
#         sha1 = int(hashlib.sha1(item_encoded).hexdigest(), 16)
#         for i in range(self.hash_count):
#             yield (md5 + i * sha1) % self.size
#
#     def add(self, item: str) -> bool:
#         if self.contains(item):
#             return False
#         for pos in self._get_hashes(item):
#             byte_index = pos // 8
#             bit_index = pos % 8
#             self.mm[byte_index] |= (1 << bit_index)
#         return True
#
#     def contains(self, item: str) -> bool:
#         for pos in self._get_hashes(item):
#             byte_index = pos // 8
#             bit_index = pos % 8
#             if not (self.mm[byte_index] & (1 << bit_index)):
#                 return False
#         return True
#
#     def close(self):
#         """关闭文件句柄"""
#         try:
#             self.mm.close()
#             self.file.close()
#         except Exception:
#             pass
#

# 全局去重器

class CodeLineFilter:
    def __init__(self, min_string_length=5, min_sensitive_length=5, max_string_length=1000):
        self.min_string_length = min_string_length
        self.min_sensitive_length = min_sensitive_length
        self.max_string_length = max_string_length

    def extract_candidates(self, js_code: str) -> List[Tuple[str, str]]:
        if not js_code:
            return []
        string_candidates = set()
        for line in js_code.splitlines():
            original_line = line.strip()
            if not original_line or len(original_line) > 3500:
                continue
            if '"' not in original_line and "'" not in original_line:
                continue

            line_lower = original_line.lower()
            is_bad_context = any(ctx in line_lower for ctx in EXCLUDE_CONTEXTS)
            has_sensitive_keyword = any(kw in line_lower for kw in SENSITIVE_KEYWORDS)

            if is_bad_context and not has_sensitive_keyword:
                continue

            for _, content in QUOTE_PATTERN.findall(original_line):
                content = content.strip()
                if self._is_valid_content(content, original_line, has_sensitive_keyword):
                    string_candidates.add((content, original_line))
        return list(string_candidates)

    def _is_valid_content(self, content: str, original_line: str, has_sensitive_keyword: bool) -> bool:
        content_len = len(content)
        if content_len > self.max_string_length:
            return False

        if re.search(r'(_cannot_have_|_that_is_|_called_with_|_\d{4}$)', content, re.IGNORECASE):
            return False

        non_ascii_ratio = sum(1 for c in content if ord(c) > 127) / content_len if content_len > 0 else 0
        if non_ascii_ratio > 0.15:
            return False

        if re.search(r'[\u4e00-\u9fff]{2,}', content):
            return False

        if content.startswith('#') and '-' in content:
            return False

        if content.upper() in ['0123456789ABCDEF', 'FEDCBA9876543210', '0000000000000000']:
            return False

        min_len = self.min_sensitive_length if has_sensitive_keyword else self.min_string_length
        if content_len < min_len:
            return False
        if IGNORE_PREFIX_PATTERN.match(content):
            return False
        if (".js" in content or ".css" in content or ".html" in content) and content_len < 50:
            return False
        if any(c in content for c in [' ', '<', '>', '\\', '__', '(', ')']):
            return False

        special_count = sum(1 for c in content if not c.isalnum())
        if content_len > 0 and (special_count / content_len) > 0.2:
            return False
        if len(UNICODE_PATTERN.findall(content)) >= 3:
            return False
        if sum(1 for c in content if ord(c) > 127) > content_len * 0.3:
            return False
        if content in EXCLUDE_VALUES:
            return False
        if content.isdigit() and content_len < 8:
            return False

        if not has_sensitive_keyword:
            if not any(char in original_line for char in ['=', ':', '{', '(', ',']):
                return False
        return True

class SecretMathScorer:
    """纯数学/统计学驱动的敏感信息评分器 (V4.3)"""
    
    _nltk_initialized = False

    TECH_PATTERNS = {
        'url': re.compile(r'https?://[^\s\'"]{4,}', re.I),
        'path': re.compile(r'(?:^|/)[a-z0-9_\-./]{3,}\.(?:js|css|html|png|jpg|svg|json|map)', re.I),
        'uuid': re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
        'regex': re.compile(r'^/[^/]+/[gimsuy]*$'),
        'func': re.compile(r'^[a-zA-Z_$][\w$]*\s*\(')
    }

    COMMON_BIGRAMS = {
        'th', 'he', 'in', 'er', 'an', 'on', 'en', 'at', 'es', 'ed', 'or', 'te', 'of', 'it', 'is', 'ti', 'le', 're',
        'se', 'nt', 'al', 'ar', 'st', 'to', 'nd', 'ou', 've', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea',
        'ra', 'ce', 'li', 'ch', 'be', 'ma', 'ss', 'pe'
    }
    RARE_BIGRAMS = {'zx', 'qj', 'xk', 'vz', 'jq', 'kx', 'zq', 'xv', 'qz', 'jx', 'vk', 'zj'}

    # JS/Web 技术词表 (弥补 NLTK 词典不足)
    TECH_WORDS = {
        'api', 'http', 'https', 'json', 'xml', 'css', 'html', 'div', 'span', 'click', 'data', 'id',
        'token', 'user', 'admin', 'config', 'env', 'key', 'secret', 'function', 'var', 'let', 'const',
        'return', 'true', 'false', 'null', 'undefined', 'window', 'document', 'console', 'log', 'error',
        'warn', 'info', 'debug', 'test', 'mock', 'stub', 'fake', 'example', 'sample', 'demo', 'temp',
        'tmp', 'cache', 'store', 'db', 'sql', 'mongo', 'redis', 'aws', 'azure', 'gcp', 'google',
        'facebook', 'twitter', 'github', 'gitlab', 'bitbucket', 'npm', 'yarn', 'webpack', 'babel',
        'react', 'vue', 'angular', 'node', 'express', 'django', 'flask', 'spring', 'rails', 'laravel',
        'request', 'response', 'header', 'body', 'query', 'params', 'route', 'path', 'url', 'link',
        'href', 'src', 'alt', 'title', 'class', 'style', 'script', 'meta', 'head', 'body'
    }

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        if not SecretMathScorer._nltk_initialized:
            _init_nltk_offline()
            SecretMathScorer._nltk_initialized = True
            
        self.weights = weights or {
            'w_e': 0.8, 'w_c': 0.6, 'w_k': 0.7, 'w_f': 0.7,
            'w_p': 1.0, 'w_m': 0.9, 'w_t': 1.2, 'w_v': 0.3, 'w_u': 0.5
        }
        self._cache = {}

        try:
            nltk_words = set(w.lower() for w in words.words())
            self.valid_words_set = nltk_words.union(self.TECH_WORDS)
        except:
            self.valid_words_set = self.TECH_WORDS

    def _log2(self, x):
        return math.log2(x) if x > 0 else 0.0

    def calc_E(self, s: str) -> float:
        L = len(s)
        if L == 0: return 0.0
        cnt = Counter(s)
        H = -sum((c / L) * self._log2(c / L) for c in cnt.values())
        max_H = self._log2(min(L, len(cnt)))
        return H / max_H if max_H > 0 else 0.0

    def calc_C(self, s: str) -> float:
        return sum([bool(re.search(p, s)) for p in [r'[a-z]', r'[A-Z]', r'[0-9]', r'[^a-zA-Z0-9\s]']]) / 4.0

    def calc_P_V(self, s: str) -> Tuple[float, float]:
        s_camel = re.sub(r'([A-Z])', r' \1', s)
        alpha_parts = re.findall(r'[a-zA-Z]+', s_camel)

        if not alpha_parts: return 0.0, 0.0

        total_alpha_len = sum(len(p) for p in alpha_parts)
        valid_len = 0
        word_lengths = []

        for part in alpha_parts:
            part_lower = part.lower()
            if len(part) > 2 and part_lower in self.valid_words_set:
                valid_len += len(part)
                word_lengths.append(len(part))

        P = valid_len / total_alpha_len if total_alpha_len > 0 else 0.0
        V = statistics.variance(word_lengths) if len(word_lengths) > 1 else 0.0
        V = min(V / 15.0, 1.0)

        return P, V

    def calc_K(self, s: str) -> float:
        L = len(s)
        if L < 6: return 1.0
        try:
            ratio = len(zlib.compress(s.encode())) / L
            if L < 15: return min(ratio, 0.8)  # 限制短串得分
            return ratio
        except:
            return 0.5

    def calc_M(self, s: str) -> float:
        if len(s) < 2: return 0.0
        bigrams = [s[i:i + 2].lower() for i in range(len(s) - 1)]
        alpha = (sum(b in self.COMMON_BIGRAMS for b in bigrams) - 2 * sum(
            b in self.RARE_BIGRAMS for b in bigrams)) / len(bigrams)
        return 1.0 / (1.0 + math.exp(4.0 * (alpha + 0.2)))

    def calc_U(self, s: str, w=8) -> float:
        L = len(s)
        if L < w: return 1.0
        ents = []
        for i in range(L - w + 1):
            chunk = s[i:i + w]
            cnt = Counter(chunk)
            ents.append(-sum((c / w) * self._log2(c / w) for c in cnt.values()))
        var = statistics.variance(ents) if len(ents) > 1 else 0.0
        return max(0.0, 1.0 - var / 2.0)

    def calc_F(self, s: str) -> float:
        L = len(s)
        if L == 0: return 0.0
        hex_set = set('0123456789abcdefABCDEF')
        b64_set = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        return max(sum(c in hex_set for c in s) / L, sum(c in b64_set for c in s) / L)

    def calc_T(self, s: str) -> float:
        L = len(s)
        if L == 0: return 0.0
        matched = max((m.end() - m.start() for pat in self.TECH_PATTERNS.values() if (m := pat.search(s))), default=0)
        return min(matched / L, 1.0)

    def score(self, s: str) -> Dict[str, float]:
        if s in self._cache: return self._cache[s]

        E, C = self.calc_E(s), self.calc_C(s)
        P, V = self.calc_P_V(s)
        K, M = self.calc_K(s), self.calc_M(s)
        U, F, T = self.calc_U(s), self.calc_F(s), self.calc_T(s)

        w = self.weights
        base = (w['w_e'] * E + w['w_c'] * C + w['w_k'] * K + w['w_f'] * F) - \
               (w['w_p'] * P + w['w_m'] * M + w['w_t'] * T + w['w_v'] * V + w['w_u'] * (1 - U))

        # Sigmoid 拉伸 (斜率 -3.5, 中心 0.85)
        final = 1.0 / (1.0 + math.exp(-3.5 * (base - 0.85)))

        res = {'score': final, 'E': E, 'C': C, 'P': P, 'V': V, 'K': K, 'M': M, 'U': U, 'F': F, 'T': T}
        self._cache[s] = res
        return res


class AdvancedSecretFilter:
    def __init__(self, threshold: float = 0.90, weights: Optional[Dict[str, float]] = None):
        self.threshold = threshold
        self.scorer = SecretMathScorer(weights)
        self.code_syntax_indicators = {'${', '||', '&&', '?', '+=', '-=', '===', '!==', '?.', '??', '=>'}
        self.sensitive_keywords = SENSITIVE_KEYWORDS

    def shannon_entropy(self, data:str) -> float:
        return self.scorer.calc_E(data) * math.log2(len(data)) if len(data) > 0 else 0.0

    def is_secret(self, text: str) -> bool:
        if not text or len(text) < 4: return False
        if any(ind in text for ind in self.code_syntax_indicators): return False
        if text.upper() in ['0123456789ABCDEF', 'FEDCBA9876543210', '0000000000000000']: return False

        res = self.scorer.score(text)
        score = res['score']

        # 动态阈值策略
        L = len(text)
        thr = self.threshold * (0.9 if L < 16 else (1.1 if L > 100 else 1.0))

        # 关键词提权
        if any(kw in text.lower() for kw in self.sensitive_keywords):
            score = min(score * 1.2, 1.0)

        return score >= thr

    def get_debug_info(self, text: str) -> Dict:
        return self.scorer.score(text)


class LLMSecretVerifier:
    def __init__(self, client, max_retries=2, retry_delay=1.0):
        self.client = client
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def verify_with_context(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not candidates:
            return []

        input_data = self._prepare_input(candidates)
        analysis_result = self._call_llm(input_data)
        verified = self._parse_and_merge(candidates, analysis_result)
        return verified

    def _prepare_input(self, candidates: List[Dict[str, Any]]) -> str:
        formatted = {}
        for cand in candidates:
            cand_id = str(cand.get("id", ""))
            formatted[cand_id] = {
                "value": cand.get("value", ""),
                "context": cand.get("context", ""),
                "callers": cand.get("callers", [])
            }
        return json.dumps(formatted, ensure_ascii=False, indent=2)

    def _call_llm(self, input_data: str) -> Dict[str, Any]:
        messages = [
            {"role": "system", "content": SECRET_PROMPT},
            {"role": "user", "content": f"Analyze these hardcoded values:\n\n{input_data}"}
        ]

        for attempt in range(self.max_retries + 1):
            try:
                content = self.client.chat(
                    messages=messages,
                    max_tokens=2048,
                    temperature=0.1
                )

                json_str = self._extract_json(content)
                if json_str:
                    json_str = json_str.replace('"', '"').replace('"', '"')
                    return json_repair.loads(json_str)
                else:
                    logger.warning(f"⚠️ [LLM] 未找到有效 JSON (Attempt {attempt + 1})")

            except Exception as e:
                logger.warning(f"⚠️ [LLM] 调用失败 (Attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (attempt + 1))

        logger.error("❌ [LLM] 所有重试失败...")
        return {}


    def _extract_json(self, content: str) -> Optional[str]:
        try:
            json_repair.loads(content)
            return content
        except json.JSONDecodeError:
            pass
        match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if match: return match.group(1)
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match: return match.group()
        return None


    def _parse_and_merge(self, candidates: List[Dict[str, Any]], analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        verified = []
        for cand in candidates:
            cand_id = str(cand.get("id", ""))
            ai_result = analysis_result.get(cand_id, {})
            is_secret = ai_result.get("is_secret", 1)
            result = {
                **cand,
                "is_secret": bool(is_secret) if isinstance(is_secret, int) else is_secret,
                "secret_type": ai_result.get("secret_type", "unknown"),
                "risk_level": ai_result.get("risk_level", "Low"),
                "confidence": float(ai_result.get("confidence", 0.5)),
                "test_suggestion": ai_result.get("test_suggestion", ""),
                "ai_raw_analysis": ai_result
            }
            if result["is_secret"]: verified.append(result)
        return verified


class SensitiveInfoScanner:
    """敏感信息扫描器 (V4.3 生产版)"""

    def __init__(self, client, db: Optional[SQLiteStorage] = None, max_ast_analysis=50, max_llm=80):
        self.client = client
        self.db = db
        self.max_ast_analysis = max_ast_analysis
        self.max_llm = max_llm

        self.line_filter = CodeLineFilter()
        # 使用 V4.3 数学过滤器，阈值设为 0.90 以平衡召回与 LLM 成本
        self.adv_filter = AdvancedSecretFilter(threshold=0.90)
        self.llm_verifier = LLMSecretVerifier(client)

        self.ast_available = SenInfoContextExtractor is not None

    def scan(self, js_code: str, js_url: str = "") -> List[Dict[str, Any]]:
        if not js_code: return []
        js_code = self._preprocess(js_code)
        candidates = self._extract_candidates(js_code)
        if not candidates: return []

        if self.ast_available: candidates = self._enrich_with_ast(candidates, js_code)
        if len(candidates) > self.max_llm: candidates = self._priority_sort(candidates)[:self.max_llm]
        verified = self._verify_with_llm(candidates)

        if self.db and js_url and verified is not None:
            self.db.save_sensitive_info(js_url, verified)
        return verified

    def _preprocess(self, js_code: str) -> str:
        js_code = remove_html_tags(js_code)
        try:
            js_code = format_code(js_code, fallback_on_error=True)
        except Exception as e:
            logger.error(f"⚠️ 代码格式化失败：{e}")
        return js_code

    def _extract_candidates(self, js_code: str) -> List[Dict[str, Any]]:
        raw_candidates = self.line_filter.extract_candidates(js_code)
        candidate_objects = []
        for i, (content, line) in enumerate(raw_candidates):
            if self.adv_filter.is_secret(content):
                if _AI_CANDIDATE_DEDUP.contains(content): continue
                _AI_CANDIDATE_DEDUP.add(content)
                candidate_objects.append(
                    {"id": i, "value": content, "original_line": line, "context": "", "callers": []})
        return candidate_objects

    def _enrich_with_ast(self, candidates: List[Dict[str, Any]], js_code: str) -> List[Dict[str, Any]]:
        try:
            extractor = SenInfoContextExtractor(js_code)
            if len(candidates) > self.max_ast_analysis: candidates = self._priority_sort(candidates)[
                                                                     :self.max_ast_analysis]
            for cand in candidates:
                context = extractor.get_full_context(cand["value"])
                cand["context"] = context.get("declaration", "")
                cand["callers"] = context.get("callers", [])
        except Exception as e:
            print_exc()
            logger.error(f"⚠️ AST 上下文提取失败：{e}")
        return candidates

    def _priority_sort(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def priority_score(cand):
            value_lower = cand.get("value", "").lower()
            line_lower = cand.get("original_line", "").lower()
            score = 0
            for kw in SENSITIVE_KEYWORDS:
                if kw in value_lower or kw in line_lower: score += 10
            score += int(self.adv_filter.shannon_entropy(cand.get("value", "")) * 2)
            return score

        return sorted(candidates, key=priority_score, reverse=True)

    def _verify_with_llm(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not candidates: return []
        logger.info(f"🚀 Sending {len(candidates)} candidates to LLM...")
        batch_size = 20
        all_verified = []
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(candidates) + batch_size - 1) // batch_size
            logger.info(f"🧠 [LLM] 处理批次 {batch_num}/{total_batches} ({len(batch)} 项)")
            try:
                verified_batch = self.llm_verifier.verify_with_context(batch)
                if verified_batch is None: continue
                all_verified.extend(verified_batch)
            except Exception as e:
                logger.error(f"❌ [LLM] 批次 {batch_num} 处理失败：{e}")
                for cand in batch:
                    cand.update({"is_secret": True, "secret_type": "unknown", "risk_level": "Med", "confidence": 0.3,
                                 "test_suggestion": "LLM 分析失败，建议人工审查", "ai_raw_analysis": {"error": str(e)}})
                    all_verified.append(cand)

        final_results = []
        seen_lines = set()
        for res in all_verified:
            line = res.get("original_line", "")
            if line not in seen_lines:
                if _OUTPUT_LINE_DEDUP.contains(line): continue
                _OUTPUT_LINE_DEDUP.add(line)
                seen_lines.add(line)
                final_results.append(res)
        return final_results


def cleanup_bloom_filters():
    _AI_CANDIDATE_DEDUP.close()
    _OUTPUT_LINE_DEDUP.close()
    _WORD_ANALYSIS_DEDUP.close()

_AI_CANDIDATE_DEDUP = DiskBloomFilter("Result/ai_candidates.bloom", capacity=5_000_000)
_OUTPUT_LINE_DEDUP = DiskBloomFilter("Result/output_lines.bloom", capacity=5_000_000)
_WORD_ANALYSIS_DEDUP = DiskBloomFilter("Result/word_analysis.bloom", capacity=10_000_000)
