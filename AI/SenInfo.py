import json
import math
import random
import re
import sys
from collections import Counter
from collections import OrderedDict

import nltk
from bs4 import BeautifulSoup
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from nltk.corpus import wordnet
from nltk.corpus import words
from pybloom_live import ScalableBloomFilter
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

# ==================== 第一步：粗过滤器 ====================
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
            if len(original_line) > 3500: continue
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

        # 去重：保持顺序，剔除重复的候选值
        string_candidates = list(set(string_candidates))
        return string_candidates


# ==================== 第二步：精过滤器 ====================
class AdvancedSecretFilter:
    def __init__(self, entropy_threshold=3.5, coverage_threshold=0.65):
        self.entropy_threshold = entropy_threshold
        self.coverage_threshold = coverage_threshold
        self.bloom_filter = ScalableBloomFilter(
    mode=ScalableBloomFilter.LARGE_SET_GROWTH,
    error_rate=0.01  # 全局误判率控制在1%
)
        # 加载 NLTK 词典以实现 O(1) 查询
        self.english_vocab = set(w.lower() for w in words.words())
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
        # 返回结果越大，越认为是非敏感信息
        if not text:
            return 1.0, []

        # 使用bloom filter 过滤掉已经出现过的单词
        if text in self.bloom_filter:
            return 1.0, []
        # 加入bloom filter
        self.bloom_filter.add(text)

        # 1. 预处理：保留字母数字和下划线
        clean_text = re.sub(r'[^a-zA-Z0-9-]', ' ', text)
        if not clean_text:
            return 0.0, []

        # 2. 智能分词
        raw_words = wordninja.split(clean_text)

        weighted_score = 0
        valid_words = []

        for word in raw_words:
            word_lower = word.lower()
            word_length = len(word)

            if word_length >= 3:
                # 验证单词是否为有效的英文单词或编程常用词
                is_valid_word = bool(wordnet.synsets(word_lower.lower()))

                if is_valid_word:
                    valid_words.append(word)

                    # 长单词奖励逻辑：单词越长，越不可能是密钥组成部分
                    # 密钥哈希很少能拆解出多个有意义的长单词
                    if word_length >= 5:
                        weighted_score += word_length * 2.0  # 长单词给予2.0倍权重
                    else:
                        weighted_score += word_length * 1.5  # 中长单词给予1.5倍权重
            else:
                # 短词(<3字符)处理：通常是哈希片段或无意义字符
                # 不给予权重加分，体现其"混乱性"
                pass

        # 3. 计算加权覆盖率
        ratio = weighted_score / len(clean_text) if len(clean_text) > 0 else 0

        # 归一化处理：防止ratio超过1.0（由于长单词奖励）
        final_ratio = min(ratio, 1.0)

        return final_ratio, valid_words

    def is_secret(self, text):
        """判断是否为密钥"""
        if not text or len(text) < 4:
            return False

        code_syntax_indicators = ['${', '||', '&&', '?', '+=', '-=', '===', '!==', '?.', '??']
        if any(indicator in text for indicator in code_syntax_indicators):
            return False

        css_indicators = [
            # '-xs-', '-sm-', '-md-', '-lg-', '-xl-',  # 响应式断点
            # 'ml-', 'mr-', 'mt-', 'mb-', 'mx-', 'my-',  # Margin
            # 'pl-', 'pr-', 'pt-', 'pb-', 'px-', 'py-',  # Padding
            'bg-', 'text-', 'border-', 'font-',  # 常见属性
            'col-', 'row-', 'flex-', 'grid-' , # 布局
            'chunk-','data-' # 自定义

        ]
        if any(ind in text for ind in css_indicators):
            return False, "CSS Class Pattern"

        entropy = self.shannon_entropy(text)

        digit_count = sum(c.isdigit() for c in text)
        digit_ratio = digit_count / len(text)

        if digit_ratio > 0.20:
            # 2. Hex 特征检查
            # 如果字符串只包含 hex 字符且长度较长，直接判定为 Secret，跳过分词检查
            if (len(text) == 16 or len(text) == 32) and re.match(r'^[0-9a-fA-F]+$', text):
                if entropy > 2.0:  # 纯 Hex 很容易被判定为单词，所以这里强制通过
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


candidate_all = OrderedDict()
original_candidate_all = OrderedDict()

def remove_html_tags(html_text: str) -> str:
    """
    去除HTML标签，保留纯文本（处理嵌套/带属性/自闭合标签）
    """
    # 创建解析对象（推荐用lxml解析器，速度快；无lxml则用html.parser）
    soup = BeautifulSoup(html_text, "lxml")  # 或 "html.parser"
    # 提取所有纯文本（自动忽略标签，合并换行/空格）
    pure_text = soup.get_text(strip=False)  # strip=False 保留原换行/空格，True则去除首尾空白
    return pure_text

def _limit_global_set_size(target_dict: OrderedDict, max_size: int):
    """✅ 新增私有函数：全局集合容量控制，超过上限自动删除【最早插入】的元素，主动释放内存"""
    if len(target_dict) > max_size:
        # 计算需要删除的冗余元素数量，多删20%做内存预留
        del_count = len(target_dict) - max_size + int(max_size * 0.2)
        # 批量删除最早插入的元素 (OrderedDict.popitem(last=False) 删最前面的元素)
        for _ in range(del_count):
            if target_dict:
                target_dict.popitem(last=False)
        # 主动触发垃圾回收，立刻释放内存碎片
        # gc.collect()

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

        # 构造极其紧凑的输入，只给 ID 和值
        input_data = {c['id']: c['value'] for c in candidates}
        formatted_input = json.dumps(input_data, ensure_ascii=False)

        messages = [
            SystemMessage(content=self._get_system_prompt()),
            HumanMessage(content=f"Classify these:\n{formatted_input}")
        ]

        try:
            response = self.llm.invoke(messages)
            content = response.content.strip()

            # 提取 JSON 字典
            match = re.search(r'\{.*\}', content, re.DOTALL)
            json_str = match.group() if match else "{}"
            decision_dict = json.loads(json_str)

            verified_secrets = []
            for c in candidates:
                curr_id = str(c['id'])
                # 如果返回 1，或者模型没给结果，或者报错，都保留（宁可错杀）
                decision = decision_dict.get(curr_id, 1)
                if str(decision) == "1":
                    verified_secrets.append(c)

            return verified_secrets

        except Exception as e:
            print(f"LLM Error: {e}. Keeping batch.")
            return candidates


def scan_js_code(js_code):
    """扫描JS代码，返回敏感信息列表"""
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
        model=config.MODEL_NAME,
        temperature=config.MODEL_TEMPERATURE,
        max_tokens=config.MODEL_MAX_TOKENS,
        keep_alive=-1,
        reasoning=False
    )

def load_bailian_llm():
    """加载阿里云百炼模型（OpenAI兼容模式）"""
    return ChatOpenAI(
        model=config.BAILIAN_MODEL_NAME,
        temperature=config.MODEL_TEMPERATURE,  # 复用原有温度配置，分类任务必须0
        max_tokens=config.MODEL_MAX_TOKENS,
        api_key=config.DASHSCOPE_API_KEY,
        base_url=config.DASHSCOPE_BASE_URL,
        stream=False,  # 重中之重：结构化JSON输出必须关闭流式，否则解析失败
        timeout=60     # 超时兜底，防止云端请求卡死
    )


def load_llm_model():
    """
    自动判断加载哪个LLM模型：
    1. 如果config中有阿里云的有效配置 → 返回阿里云百炼模型实例
    2. 否则 → 返回本地Ollama模型实例
    """
    # 判断条件：API密钥不为空 + 地址不为空 → 用阿里云
    if config.DASHSCOPE_API_KEY and config.DASHSCOPE_BASE_URL:
        print(f"\n🔵 检测到阿里云配置，使用【远程API】模式 - 模型: {config.BAILIAN_MODEL_NAME}")
        return load_bailian_llm()
    # 否则使用本地Ollama
    else:
        print(f"\n🟢 未检测到阿里云配置，使用【本地Ollama】模式 - 模型: {config.MODEL_NAME}")
        return load_ollama_llm()

def qwen_scan_js_code(js_code):
    # 1. 预处理
    js_code = remove_html_tags(js_code)
    js_code = format_code(js_code, True)

    # 2. 提取候选
    candidates = scan_js_code(js_code)

    if not candidates:
        return []

    # 3. 转换为对象并去重
    candidate_objects = []
    for i, candidate in enumerate(candidates):
        secret_val = candidate['secret']
        if secret_val in candidate_all:
            continue
        candidate_all[secret_val] = True
        _limit_global_set_size(candidate_all, config.MAX_CANDIDATE_ALL_SIZE)

        candidate_objects.append({
            "id": i,
            "value": secret_val,
            "original": candidate
        })

    if not candidate_objects:
        return []

    # 随机熔断
    MAX_LLM_CANDIDATES = 80  # 硬限制：单次最多只看 80 个

    if len(candidate_objects) > MAX_LLM_CANDIDATES:
        print(f"⚠️ 警告：发现 {len(candidate_objects)} 个候选项，触发熔断限制。")
        print(f"   正在随机采样 {MAX_LLM_CANDIDATES} 个进行检测，其余丢弃...")

        # 1. 随机打乱
        random.shuffle(candidate_objects)

        # 2. 强制截断
        candidate_objects = candidate_objects[:MAX_LLM_CANDIDATES]

        # 3. 重置 ID
        for idx, obj in enumerate(candidate_objects):
            obj['id'] = idx

    print(f"🚀 准备将 {len(candidate_objects)} 个候选送入 LLM...")

    llm_model = load_llm_model()
    verifier = LLMSecretVerifier(llm_model)

    # 提高 batch_size，因为现在剩下的都是精英了，或者数量已经被我们限制住了
    batch_size = 30
    all_verified_results = []
    total_batches = (len(candidate_objects) + batch_size - 1) // batch_size

    # 使用 tqdm 显示进度
    for i in tqdm(range(0, len(candidate_objects), batch_size),
                  desc="🧠 AI 审计中",
                  total=total_batches,
                  unit="批"):
        batch = candidate_objects[i: i + batch_size]
        batch_results = verifier.verify_candidates(batch)
        all_verified_results.extend(batch_results)

    # --- 最终输出：返回涉及到敏感信息的源代码行 ---
    final_results = []
    for result in all_verified_results:
        original_line = result['original']['line']  # 获取原始行

        # 基于行内容去重，防止同一行出现多个 Key 导致重复输出
        if original_line in original_candidate_all:
            continue
        original_candidate_all[original_line] = True
        _limit_global_set_size(original_candidate_all, config.MAX_ORIGINAL_ALL_SIZE)
        final_results.append(original_line)

    return final_results