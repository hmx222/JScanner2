import json
import math
import re
import sys
from collections import Counter

from bs4 import BeautifulSoup

from AI.beautifyjs import format_code

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

from config.config import MODEL_NAME, MODEL_TEMPERATURE, MODEL_MAX_TOKENS


# ==================== 第一步：粗过滤器 ====================
class CodeLineFilter:
    def __init__(self,
                 min_string_length=5,
                 min_sensitive_length=8,
                 max_string_length=500):
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

        self.SENSITIVE_KEYWORDS = {
            'key', 'secret', 'token', 'auth', 'password', 'pass', 'pwd',
            'credential', 'cert', 'api', 'access', 'private', 'private_key',
            'jwt', 'bearer', 'session', 'cookie', 'csrf', 'xsrf',
            'config', 'setting', 'env', 'environment',
        }

    def extract_candidates(self, js_code):
        """
        从JS代码中提取并过滤出合格的字符串列表
        返回: [(content, original_line), ...]
        """
        if not js_code:
            return []

        # 使用更明确的变量名避免冲突
        string_candidates = []
        lines = js_code.splitlines()
        quote_pattern = re.compile(r'(["\'])(.*?)\1')
        unicode_pattern = re.compile(r'(\\)+u[0-9a-fA-F]{4}')

        for line in lines:
            original_line = line.strip()
            if not original_line: continue
            if len(original_line) > 2000: continue
            if '"' not in original_line and "'" not in original_line: continue

            line_lower = original_line.lower()

            # 检查上下文和关键词
            is_bad_context = any(ctx in line_lower for ctx in self.EXCLUDE_CONTEXTS)
            has_sensitive_keyword = any(kw in line_lower for kw in self.SENSITIVE_KEYWORDS)

            if is_bad_context and not has_sensitive_keyword:
                continue

            matches = quote_pattern.findall(original_line)

            for quote_char, content in matches:
                content = content.strip()
                content_len = len(content)

                if content_len > self.max_string_length:
                    continue

                min_len = self.min_sensitive_length if has_sensitive_keyword else self.min_string_length
                if content_len < min_len:
                    continue

                # 字符格式限制
                if ' ' in content or '<' in content or '>' in content or \
                        ':' in content or '\\' in content or '__' in content or \
                        '.' in content or '/' in content or '(' in content or ')' in content:
                    continue

                special_count = sum(1 for c in content if not c.isalnum())
                if special_count / content_len > 0.2:
                    continue

                # Unicode 拦截
                if len(unicode_pattern.findall(content)) >= 3:
                    continue
                if sum(1 for c in content if ord(c) > 127) > len(content) * 0.3:
                    continue

                if content in self.EXCLUDE_VALUES:
                    continue

                if content.isdigit() and content_len < 8:
                    continue

                if not has_sensitive_keyword:
                    if not any(char in original_line for char in ['=', ':', '{', '}']):
                        continue

                # 同时保存内容和原始代码行
                string_candidates.append((content, original_line))

        return string_candidates


# ==================== 第二步：精过滤器 ====================
class AdvancedSecretFilter:
    def __init__(self, entropy_threshold=3.5, coverage_threshold=0.65):
        self.entropy_threshold = entropy_threshold
        self.coverage_threshold = coverage_threshold

        self.COMMON_SHORT_WORDS = {
            'i', 'j', 'k', 'x', 'y', 'z', 'a', 'b', 'c', 'n', 'm', 't', 'p',
            'id', 'db', 'ip', 'to', 'in', 'on', 'up', 'at', 'by', 'of', 'if',
            'is', 'as', 'do', 'go', 'no', 'ok', 're', 'us', 'pi', 'io', 'ui', 'api',
            'ad', 'ae', 'ai', 'al', 'am', 'an', 'be', 'bi', 'bo', 'bu',
            'ca', 'co', 'cu', 'de', 'di', 'ed', 'el', 'em', 'en', 'es', 'ex',
            'fa', 'fi', 'fo', 'fu', 'ga', 'ge', 'gi', 'go', 'gu', 'ha', 'he',
            'hi', 'ho', 'hu', 'im', 'in', 'it', 'la', 'le', 'li', 'lo', 'lu',
            'ma', 'me', 'mi', 'mo', 'mu', 'na', 'ne', 'ni', 'no', 'nu', 'pa',
            'pe', 'pi', 'po', 'pu', 'ra', 're', 'ri', 'ro', 'ru', 'sa', 'se',
            'si', 'so', 'su', 'ta', 'te', 'ti', 'to', 'tu', 'un', 'us', 'va',
            've', 'vi', 'vo', 'vu', 'wa', 'we', 'wi', 'wo', 'wu', 'xa', 'xe',
            'xi', 'xo', 'xu', 'ya', 'ye', 'yi', 'yo', 'yu', 'za', 'ze', 'zi',
            'zo', 'zu'
        }

    def shannon_entropy(self, data):
        if not data:
            return 0
        counter = Counter(data)
        total_length = len(data)
        entropy = 0
        for char, count in counter.items():
            p_x = count / total_length
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def calculate_word_coverage(self, text):
        if not text:
            return 0.0, []
        clean_text = ''.join(c for c in text if c.isalnum() or c == '_')
        if not clean_text:
            return 0.0, []
        words = wordninja.split(clean_text)
        valid_words = []
        for word in words:
            word_lower = word.lower()
            if (len(word) > 2 or
                    word_lower in self.COMMON_SHORT_WORDS or
                    (word.isupper() and len(word) >= 2)):
                valid_words.append(word)
        valid_len = sum(len(w) for w in valid_words)
        ratio = valid_len / len(text) if len(text) > 0 else 0
        return ratio, words

    def is_secret(self, text):
        """判断是否为密钥"""
        if not text or len(text) < 4:
            return False

        code_syntax_indicators = ['${', '||', '&&', '?', '+=', '-=', '===', '!==', '?.', '??']
        if any(indicator in text for indicator in code_syntax_indicators):
            return False

        entropy = self.shannon_entropy(text)
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


# ==================== 第三步：LLM 验证器 ====================
class LLMSecretVerifier:
    def __init__(self, model_instance):
        self.llm = model_instance

    def _get_system_prompt(self):
        return (
            "Role: Paranoid Security Auditor.\n"
            "Objective: Evaluate EACH candidate. ZERO TOLERANCE for missing secrets.\n"
            "Policy: RECALL > PRECISION. Flag as 'keep' if there is ANY doubt.\n\n"
            "### TARGETS:\n"
            "1. High Entropy: Random strings, Hex, Base64, UUID, Hashes, or gibberish etc.\n"
            "2. Credentials: Keys, Tokens, DB connections, Secrets etc.\n\n"
            "### IGNORE:\n"
            "UI text, CSS/JS syntax, file paths, standard URLs, simple integers.\n\n"
            "### OUTPUT (Strict JSON Array for ALL IDs):\n"
            "Return: `[{\"id\": <id>, \"decision\": \"keep/drop\", \"reason\": \"...\"}]`"
        )

    def verify_candidates(self, candidates):
        if not candidates:
            return []

        # 构造输入 Payload
        input_data = [{"id": c['id'], "v": c['value']} for c in candidates]
        formatted_input = json.dumps(input_data, ensure_ascii=False)

        messages = [
            SystemMessage(content=self._get_system_prompt()),
            HumanMessage(content=f"Evaluate these IDs:\n{formatted_input}")
        ]

        try:
            response = self.llm.invoke(messages)
            content = response.content.strip()

            # 正则提取 JSON
            match = re.search(r'\[\s*\{.*\}\s*\]', content, re.DOTALL)
            json_str = match.group() if match else "[]"
            result_list = json.loads(json_str)

            # 建立决策映射
            # 除非模型明确说 'drop'，否则默认为 'keep' 以防漏报
            decision_map = {str(r.get('id')): r.get('decision', 'keep') for r in result_list}
            reason_map = {str(r.get('id')): r.get('reason', '') for r in result_list}

            verified_secrets = []
            for c in candidates:
                curr_id = str(c['id'])
                if decision_map.get(curr_id) != 'drop':
                    c['reason'] = reason_map.get(curr_id, "Potential secret")
                    verified_secrets.append(c)

            return verified_secrets

        except Exception as e:
            print(f"LLM Error: {e}. Fallback: Keeping all.")
            return candidates


# ==================== 封装函数 ====================
def scan_js_code(js_code):
    """
    扫描JS代码，返回敏感信息列表

    Args:
        js_code (str): JS代码字符串

    Returns:
        list: 敏感信息列表，格式为:
            [
                {
                    'secret': '密钥内容',
                    'line': '原始代码行',
                    'entropy': 3.85,
                    'coverage': 0.25
                },
                ...
            ]
    """
    line_filter = CodeLineFilter()
    adv_filter = AdvancedSecretFilter()

    # 提取候选字符串（同时保留原始代码行）
    candidates = line_filter.extract_candidates(js_code)

    results = []
    for content, original_line in candidates:
        if adv_filter.is_secret(content):
            coverage, _ = adv_filter.calculate_word_coverage(content)

            results.append({
                'secret': content,
                'line': original_line
            })

    return results


def load_ollama_llm():
    return ChatOllama(
        model=MODEL_NAME,
        temperature=MODEL_TEMPERATURE,
        max_tokens=MODEL_MAX_TOKENS,
        keep_alive=-1,
        reasoning=False
    )

candidate_all = set()
original_candidate_all = set()


def remove_html_tags(html_text: str) -> str:
    """
    去除HTML标签，保留纯文本（处理嵌套/带属性/自闭合标签）
    """
    # 创建解析对象（推荐用lxml解析器，速度快；无lxml则用html.parser）
    soup = BeautifulSoup(html_text, "lxml")  # 或 "html.parser"
    # 提取所有纯文本（自动忽略标签，合并换行/空格）
    pure_text = soup.get_text(strip=False)  # strip=False 保留原换行/空格，True则去除首尾空白
    return pure_text


def qwen_scan_js_code(js_code):
    """
    运行完整的敏感信息检测 pipeline (增加批处理支持)
    """
    js_code = remove_html_tags(js_code)
    js_code = format_code(js_code, True)
    candidates = scan_js_code(js_code)
    if not candidates:
        return []
    candidate_objects = []
    for i, candidate in enumerate(candidates):
        secret_val = candidate['secret']
        if secret_val in candidate_all:
            continue

        candidate_objects.append({
            "id": i,
            "value": secret_val,
            "original": candidate
        })
        candidate_all.add(secret_val)

    if not candidate_objects:
        print("   所有候选词已在历史记录中，跳过 LLM。")
        return []


    ollama_model = load_ollama_llm()
    verifier = LLMSecretVerifier(ollama_model)

    # 针对 14B 模型，建议每批 15 条，既能保持语义理解，又不会让模型断掉
    batch_size = 15
    all_verified_results = []

    print("开始抽取敏感信息")
    for i in range(0, len(candidate_objects), batch_size):
        batch = candidate_objects[i: i + batch_size]

        # 调用 verifier
        batch_results = verifier.verify_candidates(batch)
        all_verified_results.extend(batch_results)

    # --- 结果汇总与最终去重 ---
    final_results = []
    for result in all_verified_results:
        original_candidate = result['original']

        # 针对最终输出的全局去重（基于 Secret 内容）
        if original_candidate['secret'] in original_candidate_all:
            continue

        final_results.append(original_candidate['secret'])
        original_candidate_all.add(original_candidate['secret'])

    return final_results


