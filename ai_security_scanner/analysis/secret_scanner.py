import hashlib
import json
import logging
import math
import mmap
import os
import re
import sys
import time
from collections import Counter
from traceback import print_exc
from typing import List, Dict, Generator, Tuple, Any, Optional

import json_repair
from bs4 import BeautifulSoup

from .context_extractor import SenInfoContextExtractor

# 导入存储模块
try:
    from SQLiteStorage import SQLiteStorage
except ImportError:
    SQLiteStorage = None

logger = logging.getLogger(__name__)

try:
    import wordninja
    import nltk
    from nltk.corpus import wordnet, words

    try:
        from ..utils.js_formatter import format_code
    except ImportError:
        from js_formatter import format_code
except ImportError as e:
    sys.stderr.write(f"⚠️  Missing dependency: {e}\n")
    sys.exit(1)


def _init_nltk_offline():
    """纯离线 NLTK 数据初始化"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    local_nltk_dir = os.path.abspath(os.path.join(current_dir, '../config/nltk_data'))

    if local_nltk_dir not in nltk.data.path:
        nltk.data.path.insert(0, local_nltk_dir)

    required_data = {
        'wordnet': 'corpora/wordnet',
        'omw-1.4': 'corpora/omw-1.4',
        'words': 'corpora/words'
    }

    for package_name, search_path in required_data.items():
        try:
            nltk.data.find(search_path)
        except LookupError:
            logger.warning(f"[-] NLTK 本地缓存缺失 [{package_name}]，正在下载至：{local_nltk_dir}")
            try:
                os.makedirs(local_nltk_dir, exist_ok=True)
                nltk.download(package_name, download_dir=local_nltk_dir, quiet=True)
            except Exception as e:
                logger.error(f"❌ NLTK 下载失败 {package_name}: {str(e)}")


_init_nltk_offline()


class SenInfoDiskBloomFilter:
    """基于磁盘映射的持久化布隆过滤器"""

    def __init__(self, filepath: str, capacity: int = 10_000_000, error_rate: float = 0.001):
        self.filepath = filepath
        self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.hash_count = int((self.size / capacity) * math.log(2))
        self.byte_size = (self.size + 7) // 8
        self._ensure_file()
        self.file = open(filepath, "r+b")
        self.mm = mmap.mmap(self.file.fileno(), 0)

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if not os.path.exists(self.filepath):
            with open(self.filepath, "wb") as f:
                f.write(b'\x00' * self.byte_size)

    def _get_hashes(self, item: str) -> Generator[int, None, None]:
        item_encoded = item.encode("utf8")
        md5 = int(hashlib.md5(item_encoded).hexdigest(), 16)
        sha1 = int(hashlib.sha1(item_encoded).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (md5 + i * sha1) % self.size

    def add(self, item: str) -> bool:
        if self.contains(item):
            return False
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            self.mm[byte_index] |= (1 << bit_index)
        return True

    def contains(self, item: str) -> bool:
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            if not (self.mm[byte_index] & (1 << bit_index)):
                return False
        return True

    def close(self):
        """关闭文件句柄 (新增)"""
        try:
            self.mm.close()
            self.file.close()
        except Exception:
            pass


# 全局去重器
_AI_CANDIDATE_DEDUP = SenInfoDiskBloomFilter("Result/ai_candidates.bloom", capacity=5_000_000)
_OUTPUT_LINE_DEDUP = SenInfoDiskBloomFilter("Result/output_lines.bloom", capacity=5_000_000)
_WORD_ANALYSIS_DEDUP = SenInfoDiskBloomFilter("Result/word_analysis.bloom", capacity=10_000_000)


class CodeLineFilter:
    EXCLUDE_CONTEXTS = {
        'console.log', 'console.warn', 'console.error', 'console.info', 'console.debug',
        'alert(', 'confirm(', 'prompt(',
        'logger.log', 'logger.debug', 'logger.info', 'logger.warn', 'logger.error',
        'import ', 'require(', 'export ',
        'getElementById', 'querySelector', 'querySelectorAll',
        'getElementsByTagName', 'getElementsByClassName',
        'createElement', 'appendChild', 'innerHTML', 'textContent',
        '.css(', '.html(', '.text(', '.val(', '.attr(',
        '<div', '<span', '<a ', '<img', '<link', '<script', '<style',
        'window.location', 'document.cookie', '_sentryDebugIds'
    }
    EXCLUDE_VALUES = {
        'false', 'undefined', 'delete', 'green', 'white', 'black',
        'gray', 'grey', 'color', 'home', 'index', 'login', 'logout',
        'register', 'signup', 'signin', 'user', 'admin', 'dashboard',
        'header', 'footer', 'sidebar', 'submit', 'reset', 'button',
        'input', 'form', 'https', 'localhost', 'base64', 'unicode',
    }
    SENSITIVE_KEYWORDS = {
        'key', 'secret', 'token', 'auth', 'password', 'pass', 'pwd',
        'credential', 'cert', 'api', 'access', 'private', 'private_key',
        'jwt', 'bearer', 'session', 'cookie', 'csrf', 'xsrf',
        'config', 'setting', 'env', 'environment',
    }
    IGNORE_PREFIX_PATTERN = re.compile(
        r'^[\W_]*(chunk-|app-|vendors-|manifest-|data-v-|vue-|bg-|text-|border-|font-|col-|row-|flex-|grid-|btn-|icon-|fa-|el-|mat-)',
        re.IGNORECASE
    )
    QUOTE_PATTERN = re.compile(r'(["\'])(.*?)\1')
    UNICODE_PATTERN = re.compile(r'(\\)+u[0-9a-fA-F]{4}')

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
            is_bad_context = any(ctx in line_lower for ctx in self.EXCLUDE_CONTEXTS)
            has_sensitive_keyword = any(kw in line_lower for kw in self.SENSITIVE_KEYWORDS)

            if is_bad_context and not has_sensitive_keyword:
                continue

            for _, content in self.QUOTE_PATTERN.findall(original_line):
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
        if non_ascii_ratio > 0.15:  # 0.3 → 0.15
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
        if self.IGNORE_PREFIX_PATTERN.match(content):
            return False
        if (".js" in content or ".css" in content or ".html" in content) and content_len < 50:
            return False
        if any(c in content for c in [' ', '<', '>', '\\', '__', '(', ')']):
            return False

        special_count = sum(1 for c in content if not c.isalnum())
        if content_len > 0 and (special_count / content_len) > 0.2:
            return False
        if len(self.UNICODE_PATTERN.findall(content)) >= 3:
            return False
        if sum(1 for c in content if ord(c) > 127) > content_len * 0.3:
            return False
        if content in self.EXCLUDE_VALUES:
            return False
        if content.isdigit() and content_len < 8:
            return False

        if not has_sensitive_keyword:
            if not any(char in original_line for char in ['=', ':', '{', '(', ',']):
                return False
        return True



class AdvancedSecretFilter:
    def __init__(self, entropy_threshold=3.5, coverage_threshold=0.65):
        self.entropy_threshold = entropy_threshold
        self.coverage_threshold = coverage_threshold
        self.bloom_filter = _WORD_ANALYSIS_DEDUP
        self.code_syntax_indicators = {'${', '||', '&&', '?', '+=', '-=', '===', '!==', '?.', '??'}
        self.sensitive_keywords = {'secret', 'key', 'token', 'password', 'auth', 'cred', 'cert'}

    def shannon_entropy(self, data: str) -> float:
        if not data:
            return 0
        counter = Counter(data)
        entropy = 0.0
        total = len(data)
        for count in counter.values():
            p_x = count / total
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def calculate_word_coverage(self, text: str) -> Tuple[float, List[str]]:
        if not text:
            return 1.0, []
        if self.bloom_filter.contains(text):
            return 1.0, []
        self.bloom_filter.add(text)

        clean_text = re.sub(r'[^a-zA-Z0-9_-]', ' ', text)
        if not clean_text:
            return 0.0, []

        raw_words = wordninja.split(clean_text)
        weighted_score = 0.0
        valid_words = []
        for word in raw_words:

            word = word.strip()
            if not word:
                continue

            word_lower = word.lower()
            word_len = len(word)

            if word_len >= 3 and wordnet.synsets(word_lower):
                valid_words.append(word)
                weighted_score += word_len * (2.0 if word_len >= 5 else 1.5)

        alpha_len = sum(1 for c in text if c.isalpha())
        ratio = weighted_score / alpha_len if alpha_len > 0 else 0
        return min(ratio, 1.0), valid_words

    def is_secret(self, text: str) -> bool:
        if not text or len(text) < 4:
            return False

        if text.upper() in ['0123456789ABCDEF', 'FEDCBA9876543210', '0000000000000000']:
            return False

        if any(ind in text for ind in self.code_syntax_indicators):
            return False

        entropy = self.shannon_entropy(text)
        digit_count = sum(c.isdigit() for c in text)
        if (digit_count / len(text)) > 0.20:
            if len(text) in (16, 32) and re.match(r'^[0-9a-fA-F]+$', text) and entropy > 2.0:
                return True

        if entropy < self.entropy_threshold:
            return False
        coverage, _ = self.calculate_word_coverage(text)
        if coverage > self.coverage_threshold:
            return False

        text_lower = text.lower()
        if any(kw in text_lower for kw in self.sensitive_keywords) and coverage > 0.4:
            return True
        return False


# =====================================================================
# 【重构】LLM 验证器 (支持结构化输出)
# =====================================================================

class LLMSecretVerifier:
    """
    LLM 敏感信息验证器 (v2.0 结构化输出版)

    支持两种模式：
    1. 旧模式：verify_candidates() - 保持向后兼容
    2. 新模式：verify_with_context() - 带上下文的完整分析
    """

    def __init__(self, client, max_retries=2, retry_delay=1.0):
        self.client = client
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._system_prompt = """
        角色：资深安全研究员 & 渗透测试专家
        目标：分析 JavaScript 代码中的硬编码敏感字符串，并提供可执行的测试指导

        输入格式：
        - value: 硬编码的字符串值
        - context: 显示该值如何定义/使用的代码片段
        - callers: 调用该值的代码位置列表

        分析标准：
        1. 这是否是真正的秘密？(许可证密钥、API Token、密码等)
        2. 它是什么类型的秘密？
        3. 风险等级是什么？(High/Med/Low)
        4. 渗透测试人员如何利用它？

        输出格式：
        为每个候选 ID 返回一个 JSON 对象，结构如下：
        {
          "id": {
            "is_secret": 1 或 0,
            "secret_type": "license_key|api_key|token|password|endpoint|other",
            "risk_level": "High|Med|Low",
            "confidence": 0.0-1.0,
            "test_suggestion": "具体的、可执行的渗透测试步骤（中文）"
          }
        }

        风险等级指南：
        - High: 可直接用于未授权访问、认证绕过或数据泄露
        - Med: 可能导致信息泄露，或需要额外条件才能利用
        - Low: 可能是误报、构建产物或低影响配置

        策略：如果不确定，标记为 is_secret=1 (召回率 > 精确率)，但降低 confidence 分数。
        """

    def verify_with_context(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        新接口：带上下文的敏感信息验证

        Args:
            candidates: 候选列表，每项包含：
                {
                    "id": str,
                    "value": str,
                    "context": str,
                    "callers": List[str]
                }

        Returns:
            验证结果列表，每项包含完整分析结果
        """
        if not candidates:
            return []

        # 准备输入数据
        input_data = self._prepare_input(candidates)

        # 调用 LLM
        analysis_result = self._call_llm(input_data)

        # 解析并合并结果
        verified = self._parse_and_merge(candidates, analysis_result)

        return verified

    def _prepare_input(self, candidates: List[Dict[str, Any]]) -> str:
        """准备 LLM 输入数据"""
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
        """调用 LLM 进行分析"""
        messages = [
            {"role": "system", "content": self._system_prompt},
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
                print_exc()
                logger.warning(f"⚠️ [LLM] 调用失败 (Attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (attempt + 1))

        logger.error("❌ [LLM] 所有重试失败，返回空结果")
        return {}

    def _extract_json(self, content: str) -> Optional[str]:
        """从 LLM 响应中提取 JSON"""
        # 尝试 1: 直接解析
        try:
            json_repair.loads(content)
            return content
        except json.JSONDecodeError:
            pass

        # 尝试 2: 查找 ```json 代码块
        match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if match:
            return match.group(1)

        # 尝试 3: 查找最外层花括号
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            return match.group()

        return None

    def _parse_and_merge(self, candidates: List[Dict[str, Any]],
                         analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """解析 LLM 结果并与原始候选合并"""
        verified = []

        for cand in candidates:
            cand_id = str(cand.get("id", ""))
            ai_result = analysis_result.get(cand_id, {})

            # 提取 AI 分析结果
            is_secret = ai_result.get("is_secret", 1)
            secret_type = ai_result.get("secret_type", "unknown")
            risk_level = ai_result.get("risk_level", "Low")
            confidence = ai_result.get("confidence", 0.5)
            test_suggestion = ai_result.get("test_suggestion", "")

            # 构建完整结果
            result = {
                **cand,
                "is_secret": bool(is_secret) if isinstance(is_secret, int) else is_secret,
                "secret_type": secret_type,
                "risk_level": risk_level,
                "confidence": float(confidence) if isinstance(confidence, (int, float)) else 0.5,
                "test_suggestion": test_suggestion,
                "ai_raw_analysis": ai_result
            }

            # 只保留被 AI 标记为秘密的项
            if result["is_secret"]:
                verified.append(result)

        return verified


# =====================================================================
# 【重构】敏感信息扫描器 (整合 AST 上下文)
# =====================================================================

class SensitiveInfoScanner:
    """
    敏感信息扫描器 (v2.0 AST 上下文整合版)

    整合：
    1. 候选提取 (CodeLineFilter)
    2. 启发式过滤 (AdvancedSecretFilter)
    3. AST 上下文溯源 (SenInfoContextExtractor)
    4. LLM 验证 (LLMSecretVerifier)
    5. 数据库存储 (SQLiteStorage)
    """

    def __init__(self, client, db: Optional[SQLiteStorage] = None,
                 max_ast_analysis=50, max_llm=80):
        """
        Args:
            client: AIHubClient 实例
            db: SQLiteStorage 实例 (可选)
            max_ast_analysis: 最大 AST 分析数量 (性能保护)
            max_llm: 最大 LLM 验证数量
        """
        self.client = client
        self.db = db
        self.max_ast_analysis = max_ast_analysis
        self.max_llm = max_llm

        self.line_filter = CodeLineFilter()
        self.adv_filter = AdvancedSecretFilter()
        self.llm_verifier = LLMSecretVerifier(client)

        self.ast_available = SenInfoContextExtractor is not None

    def scan(self, js_code: str, js_url: str = "") -> List[Dict[str, Any]]:
        """
        扫描敏感信息并返回结构化结果

        Args:
            js_code: JS 源代码
            js_url: JS 文件 URL (用于存储关联)

        Returns:
            敏感信息列表，每项包含完整上下文和 AI 分析结果
        """
        if not js_code:
            return []

        # 1. 预处理
        js_code = self._preprocess(js_code)

        # 2. 候选提取
        candidates = self._extract_candidates(js_code)

        if not candidates:
            return []

        # 3. AST 上下文溯源 (如果可用)
        if self.ast_available:
            candidates = self._enrich_with_ast(candidates, js_code)

        # 4. 限制 LLM 验证数量
        if len(candidates) > self.max_llm:
            candidates = self._priority_sort(candidates)[:self.max_llm]

        # 5. LLM 验证
        verified = self._verify_with_llm(candidates)

        # 6. 存入数据库
        if self.db and js_url and verified is not None:
            self.db.save_sensitive_info(js_url, verified)

        return verified

    def _preprocess(self, js_code: str) -> str:
        """预处理 JS 代码"""
        # 移除 HTML 标签
        js_code = remove_html_tags(js_code)

        # 格式化代码
        try:
            js_code = format_code(js_code, fallback_on_error=True)
        except Exception as e:
            logger.warning(f"⚠️ 代码格式化失败：{e}")

        return js_code

    def _extract_candidates(self, js_code: str) -> List[Dict[str, Any]]:
        """提取候选敏感信息"""
        raw_candidates = self.line_filter.extract_candidates(js_code)
        candidate_objects = []

        for i, (content, line) in enumerate(raw_candidates):
            if self.adv_filter.is_secret(content):
                if _AI_CANDIDATE_DEDUP.contains(content):
                    continue
                _AI_CANDIDATE_DEDUP.add(content)

                candidate_objects.append({
                    "id": i,
                    "value": content,
                    "original_line": line,
                    "context": "",
                    "callers": []
                })

        return candidate_objects

    def _enrich_with_ast(self, candidates: List[Dict[str, Any]],
                         js_code: str) -> List[Dict[str, Any]]:
        """使用 AST  enrich 上下文信息"""
        try:
            extractor = SenInfoContextExtractor(js_code)

            # 限制 AST 分析数量 (性能保护)
            if len(candidates) > self.max_ast_analysis:
                candidates = self._priority_sort(candidates)[:self.max_ast_analysis]

            for cand in candidates:
                context = extractor.get_full_context(cand["value"])
                cand["context"] = context.get("declaration", "")
                cand["callers"] = context.get("callers", [])

        except Exception as e:
            logger.warning(f"⚠️ AST 上下文提取失败：{e}")

        return candidates

    def _priority_sort(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """按优先级排序 (含关键词的优先)"""

        def priority_score(cand):
            value_lower = cand.get("value", "").lower()
            line_lower = cand.get("original_line", "").lower()

            score = 0
            # 含敏感关键词优先
            for kw in CodeLineFilter.SENSITIVE_KEYWORDS:
                if kw in value_lower or kw in line_lower:
                    score += 10
            # 高熵值优先
            score += int(self.adv_filter.shannon_entropy(cand.get("value", "")) * 2)
            return score

        return sorted(candidates, key=priority_score, reverse=True)

    def _verify_with_llm(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """LLM 验证"""
        if not candidates:
            return []

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
                if verified_batch is None:
                    continue
                all_verified.extend(verified_batch)
            except Exception as e:
                logger.error(f"❌ [LLM] 批次 {batch_num} 处理失败：{e}")
                # 失败时保留原始候选
                for cand in batch:
                    cand["is_secret"] = True
                    cand["secret_type"] = "unknown"
                    cand["risk_level"] = "Med"
                    cand["confidence"] = 0.3
                    cand["test_suggestion"] = "LLM 分析失败，建议人工审查"
                    cand["ai_raw_analysis"] = {"error": str(e)}
                    all_verified.append(cand)

        # 输出去重
        final_results = []
        seen_lines = set()
        for res in all_verified:
            line = res.get("original_line", "")
            if line not in seen_lines:
                if _OUTPUT_LINE_DEDUP.contains(line):
                    continue
                _OUTPUT_LINE_DEDUP.add(line)
                seen_lines.add(line)
                final_results.append(res)

        return final_results

def remove_html_tags(html_text: str) -> str:
    """移除 HTML 标签"""
    soup = BeautifulSoup(html_text, "lxml")
    return soup.get_text(strip=False)


def cleanup_bloom_filters():
    """清理布隆过滤器资源 (程序退出时调用)"""
    _AI_CANDIDATE_DEDUP.close()
    _OUTPUT_LINE_DEDUP.close()
    _WORD_ANALYSIS_DEDUP.close()