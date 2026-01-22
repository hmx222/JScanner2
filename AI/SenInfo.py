import json
import math
import random
import re
import sys
import os
import mmap
import hashlib
from collections import Counter

import nltk
from bs4 import BeautifulSoup
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from nltk.corpus import wordnet
from nltk.corpus import words
from tqdm import tqdm

from AI.beautifyjs import format_code
from config import config

try:
    import wordninja
except ImportError:
    print("⚠️  缺少依赖库 'wordninja'，请运行: pip install wordninja")
    sys.exit(1)

try:
    from langchain_community.chat_models import ChatOllama
    from langchain_core.messages import SystemMessage, HumanMessage
except ImportError:
    print("⚠️  缺少 langchain 依赖库，请运行: pip install langchain-community langchain-core")
    sys.exit(1)

# 加载词库
nltk.download('wordnet', quiet=True)
nltk.download('omw-1.4', quiet=True)
nltk.download('words', quiet=True)
nltk.data.path.append('../config/nltk_data')


class SenInfoDiskBloomFilter:
    def __init__(self, filepath, capacity=10_000_000, error_rate=0.001):
        self.filepath = filepath
        self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.hash_count = int((self.size / capacity) * math.log(2))
        self.byte_size = (self.size + 7) // 8

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        if not os.path.exists(filepath):
            with open(filepath, "wb") as f:
                f.write(b'\x00' * self.byte_size)

        self.file = open(filepath, "r+b")
        self.mm = mmap.mmap(self.file.fileno(), 0)

    def _get_hashes(self, item):
        item_encoded = item.encode("utf8")
        md5 = int(hashlib.md5(item_encoded).hexdigest(), 16)
        sha1 = int(hashlib.sha1(item_encoded).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (md5 + i * sha1) % self.size

    def add(self, item):
        if self.contains(item): return False
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            self.mm[byte_index] |= (1 << bit_index)
        return True

    def contains(self, item):
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            if not (self.mm[byte_index] & (1 << bit_index)):
                return False
        return True


# 初始化持久化去重器
# 1. AI 候选去重 (防止重复问 AI)
ai_candidate_dedup = SenInfoDiskBloomFilter("Result/ai_candidates.bloom", capacity=5_000_000)
# 2. 结果输出去重 (防止重复报告同一行)
output_line_dedup = SenInfoDiskBloomFilter("Result/output_lines.bloom", capacity=5_000_000)
# 3. 单词分析去重 (AdvancedFilter用)
word_analysis_dedup = SenInfoDiskBloomFilter("Result/word_analysis.bloom", capacity=10_000_000)

class CodeLineFilter:
    def __init__(self,
                 min_string_length=5,
                 min_sensitive_length=5,
                 max_string_length=1000):
        self.min_string_length = min_string_length
        self.min_sensitive_length = min_sensitive_length
        self.max_string_length = max_string_length

        self.EXCLUDE_CONTEXTS = {
            'console.log', 'console.warn', 'console.error', 'console.info', 'console.debug',
            'alert(', 'confirm(', 'prompt(',
            'logger.log', 'logger.debug', 'logger.info', 'logger.warn', 'logger.error',
            'import ', 'require(', 'export ',
            'getElementById', 'querySelector', 'querySelectorAll',
            'getElementsByTagName', 'getElementsByClassName',
            'createElement', 'appendChild', 'innerHTML', 'textContent',
            '.css(', '.html(', '.text(', '.val(', '.attr(',
            '<div', '<span', '<a ', '<img', '<link', '<script', '<style',
            'window.location', 'document.cookie',
        }

        self.EXCLUDE_VALUES = {
            'false', 'undefined', 'delete', 'green', 'white', 'black',
            'gray', 'grey', 'color', 'home', 'index', 'login', 'logout',
            'register', 'signup', 'signin', 'user', 'admin', 'dashboard',
            'header', 'footer', 'sidebar', 'submit', 'reset', 'button',
            'input', 'form', 'https', 'localhost', 'base64', 'unicode',
        }

        # ✅ 正则前缀过滤规则 (编译一次，多次使用)
        # 匹配：(开头可选的非单词字符)(特定前缀)(任意后续)
        # 包含了 Webpack chunk, Vue data-v, 以及常见 CSS 类前缀
        self.IGNORE_PREFIX_PATTERN = re.compile(
            r'^[\W_]*(chunk-|app-|vendors-|manifest-|data-v-|vue-|bg-|text-|border-|font-|col-|row-|flex-|grid-|btn-|icon-|fa-|el-|mat-)',
            re.IGNORECASE
        )

        self.SENSITIVE_KEYWORDS = {
            'key', 'secret', 'token', 'auth', 'password', 'pass', 'pwd',
            'credential', 'cert', 'api', 'access', 'private', 'private_key',
            'jwt', 'bearer', 'session', 'cookie', 'csrf', 'xsrf',
            'config', 'setting', 'env', 'environment',
        }

    def extract_candidates(self, js_code):
        if not js_code:
            return []

        string_candidates = []
        lines = js_code.splitlines()
        quote_pattern = re.compile(r'(["\'])(.*?)\1')
        unicode_pattern = re.compile(r'(\\)+u[0-9a-fA-F]{4}')

        for line in lines:
            original_line = line.strip()
            if not original_line: continue
            if len(original_line) > 3500: continue
            if '"' not in original_line and "'" not in original_line: continue

            line_lower = original_line.lower()

            is_bad_context = any(ctx in line_lower for ctx in self.EXCLUDE_CONTEXTS)
            has_sensitive_keyword = any(kw in line_lower for kw in self.SENSITIVE_KEYWORDS)

            if is_bad_context and not has_sensitive_keyword:
                continue

            matches = quote_pattern.findall(original_line)

            for quote_char, content in matches:
                content = content.strip()
                content_len = len(content)

                # 1. 长度过滤
                if content_len > self.max_string_length:
                    continue
                min_len = self.min_sensitive_length if has_sensitive_keyword else self.min_string_length
                if content_len < min_len:
                    continue

                if self.IGNORE_PREFIX_PATTERN.match(content):
                    continue

                # 双重保险：如果直接包含 .js .css .html 且看起来像文件名
                if (".js" in content or ".css" in content or ".html" in content) and len(content) < 50:
                    continue

                # 2. 字符格式限制
                if ' ' in content or '<' in content or '>' in content or \
                        '\\' in content or '__' in content or \
                        '(' in content or ')' in content:
                    continue

                special_count = sum(1 for c in content if not c.isalnum())
                if special_count / content_len > 0.2:
                    continue

                if len(unicode_pattern.findall(content)) >= 3:
                    continue
                if sum(1 for c in content if ord(c) > 127) > len(content) * 0.3:
                    continue

                if content in self.EXCLUDE_VALUES:
                    continue

                if content.isdigit() and content_len < 8:
                    continue

                if not has_sensitive_keyword:
                    if not any(char in original_line for char in ['=', ':', '{', '(', ',']):
                        continue

                string_candidates.append((content, original_line))

        string_candidates = list(set(string_candidates))
        return string_candidates


class AdvancedSecretFilter:
    def __init__(self, entropy_threshold=3.5, coverage_threshold=0.65):
        self.entropy_threshold = entropy_threshold
        self.coverage_threshold = coverage_threshold
        self.bloom_filter = word_analysis_dedup

        self.english_vocab = set(w.lower() for w in words.words())

    def shannon_entropy(self, data):
        if not data: return 0
        counter = Counter(data)
        total_length = len(data)
        entropy = 0
        for char, count in counter.items():
            p_x = count / total_length
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def calculate_word_coverage(self, text):
        if not text: return 1.0, []

        if self.bloom_filter.contains(text):
            return 1.0, []
        self.bloom_filter.add(text)

        clean_text = re.sub(r'[^a-zA-Z0-9-]', ' ', text)
        if not clean_text: return 0.0, []

        raw_words = wordninja.split(clean_text)
        weighted_score = 0
        valid_words = []

        for word in raw_words:
            word_lower = word.lower()
            word_length = len(word)

            if word_length >= 3:
                is_valid_word = bool(wordnet.synsets(word_lower.lower()))
                if is_valid_word:
                    valid_words.append(word)
                    if word_length >= 5:
                        weighted_score += word_length * 2.0
                    else:
                        weighted_score += word_length * 1.5

        ratio = weighted_score / len(clean_text) if len(clean_text) > 0 else 0
        final_ratio = min(ratio, 1.0)
        return final_ratio, valid_words

    def is_secret(self, text):
        if not text or len(text) < 4:
            return False

        code_syntax_indicators = ['${', '||', '&&', '?', '+=', '-=', '===', '!==', '?.', '??']
        if any(indicator in text for indicator in code_syntax_indicators):
            return False

        # ✅ 已移除 CSS/Chunk 检查，上游已拦截

        entropy = self.shannon_entropy(text)

        digit_count = sum(c.isdigit() for c in text)
        digit_ratio = digit_count / len(text)

        if digit_ratio > 0.20:
            if (len(text) == 16 or len(text) == 32) and re.match(r'^[0-9a-fA-F]+$', text):
                if entropy > 2.0:
                    return True, "Hex String Pattern"

        if entropy < self.entropy_threshold:
            return False

        coverage, _ = self.calculate_word_coverage(text)
        if coverage > self.coverage_threshold:
            return False

        sensitive_keywords = ['secret', 'key', 'token', 'password', 'auth', 'cred', 'cert']
        text_lower = text.lower()
        if any(keyword in text_lower for keyword in sensitive_keywords):
            if coverage > 0.4:
                return True

        return True


def remove_html_tags(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "lxml")
    pure_text = soup.get_text(strip=False)
    return pure_text


class LLMSecretVerifier:
    def __init__(self, model_instance):
        self.llm = model_instance

    def _get_system_prompt(self):
        return (
            "Role: Binary Security Classifier.\n"
            "Objective: Identify hardcoded secrets.\n"
            "Instruction: For each ID, output 1 if it is a potential secret/key/token, output 0 if it is safe code/UI text.\n"
            "Policy: If unsure, output 1 (Recall > Precision).\n"
            "Output Format: Strict JSON object: `{\"id\": 1/0, ...}`"
        )

    def verify_candidates(self, candidates):
        if not candidates:
            return []

        input_data = {c['id']: c['value'] for c in candidates}
        formatted_input = json.dumps(input_data, ensure_ascii=False)

        messages = [
            SystemMessage(content=self._get_system_prompt()),
            HumanMessage(content=f"Classify these:\n{formatted_input}")
        ]

        try:
            response = self.llm.invoke(messages)
            content = response.content.strip()

            match = re.search(r'\{.*\}', content, re.DOTALL)
            json_str = match.group() if match else "{}"
            decision_dict = json.loads(json_str)

            verified_secrets = []
            for c in candidates:
                curr_id = str(c['id'])
                decision = decision_dict.get(curr_id, 1)
                if str(decision) == "1":
                    verified_secrets.append(c)

            return verified_secrets

        except Exception as e:
            print(f"LLM Error: {e}. Keeping batch.")
            return candidates


def scan_js_code(js_code):
    line_filter = CodeLineFilter()
    adv_filter = AdvancedSecretFilter()
    candidates = line_filter.extract_candidates(js_code)
    results = []
    for content, original_line in candidates:
        if adv_filter.is_secret(content):
            results.append({
                'secret': content,
                'line': original_line
            })
    return results


def load_ollama_llm():
    return ChatOllama(
        model=config.MODEL_NAME,
        temperature=config.MODEL_TEMPERATURE,
        max_tokens=config.MODEL_MAX_TOKENS,
        keep_alive=-1,
        reasoning=False
    )


def load_bailian_llm():
    return ChatOpenAI(
        model=config.BAILIAN_MODEL_NAME,
        temperature=config.MODEL_TEMPERATURE,
        max_tokens=config.MODEL_MAX_TOKENS,
        api_key=config.DASHSCOPE_API_KEY,
        base_url=config.DASHSCOPE_BASE_URL,
        stream=False,
        timeout=60
    )


def load_llm_model():
    if config.DASHSCOPE_API_KEY and config.DASHSCOPE_BASE_URL:
        print(f"\n🔵 检测到阿里云配置，使用【远程API】模式 - 模型: {config.BAILIAN_MODEL_NAME}")
        return load_bailian_llm()
    else:
        print(f"\n🟢 未检测到阿里云配置，使用【本地Ollama】模式 - 模型: {config.MODEL_NAME}")
        return load_ollama_llm()


def qwen_scan_js_code(js_code):
    js_code = remove_html_tags(js_code)
    js_code = format_code(js_code, True)

    candidates = scan_js_code(js_code)
    if not candidates: return []

    candidate_objects = []
    for i, candidate in enumerate(candidates):
        secret_val = candidate['secret']

        if ai_candidate_dedup.contains(secret_val):
            continue
        ai_candidate_dedup.add(secret_val)

        candidate_objects.append({
            "id": i,
            "value": secret_val,
            "original": candidate
        })

    if not candidate_objects: return []

    MAX_LLM_CANDIDATES = 80
    if len(candidate_objects) > MAX_LLM_CANDIDATES:
        print(f"⚠️ 警告：发现 {len(candidate_objects)} 个候选项，触发熔断限制。")
        print(f"   正在随机采样 {MAX_LLM_CANDIDATES} 个进行检测，其余丢弃...")
        random.shuffle(candidate_objects)
        candidate_objects = candidate_objects[:MAX_LLM_CANDIDATES]
        for idx, obj in enumerate(candidate_objects):
            obj['id'] = idx

    print(f"🚀 准备将 {len(candidate_objects)} 个候选送入 LLM...")

    llm_model = load_llm_model()
    verifier = LLMSecretVerifier(llm_model)

    batch_size = 30
    all_verified_results = []
    total_batches = (len(candidate_objects) + batch_size - 1) // batch_size

    for i in tqdm(range(0, len(candidate_objects), batch_size),
                  desc="🧠 AI 审计中",
                  total=total_batches,
                  unit="批"):
        batch = candidate_objects[i: i + batch_size]
        batch_results = verifier.verify_candidates(batch)
        all_verified_results.extend(batch_results)

    final_results = []
    for result in all_verified_results:
        original_line = result['original']['line']

        if output_line_dedup.contains(original_line):
            continue
        output_line_dedup.add(original_line)

        final_results.append(original_line)

    return final_results
