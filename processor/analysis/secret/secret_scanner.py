import json
import math
import os
import re
import sys
import time
from collections import Counter
from typing import List, Dict, Tuple, Any, Optional

import json_repair

from config.scanner_rules import HTTPX_STATIC_EXTENSIONS, EXCLUDED_CONTEXT_PATTERNS, SENSITIVE_KEYWORD_SET, EXCLUDED_LITERAL_VALUES, \
    SECRET_DETECTION_BLACKLIST, WEB_TECHNICAL_WORDS
from config.config import NLTK_DIR
from infra.bloom import DiskBloomFilter
from infra.utils import remove_html_tags
from logger import get_logger
from config.prompts import SECRET_PROMPT
from processor.js.context.secret_extractor import SenInfoContextExtractor
from storage.db import SQLiteStorage

logger = get_logger(__name__)  # 获取日志器

# 延迟导入 NLTK 相关依赖
try:
    import wordninja
    import nltk
    from nltk.corpus import words

    try:
        from processor.js.format.js_formatter import format_code
    except ImportError:
        from js_formatter import format_code
except ImportError as e:  # 捕获导入异常
    sys.stderr.write(f"⚠️  Missing dependency: {e}\n")
    sys.exit(1)


def _init_nltk_offline():
    """
    初始化 NLTK 离线数据

    从本地配置的 NLTK 数据目录加载所需语料库（wordnet, words），
    如果本地不存在则尝试自动下载。

    所需数据：
    - wordnet: 词义关系数据库
    - omw-1.4: Open Multilingual WordNet
    - words: 英语词汇列表
    """
    if NLTK_DIR not in nltk.data.path:
        nltk.data.path.insert(0, NLTK_DIR)

    required_data = {
        'wordnet': 'corpora/wordnet',
        'omw-1.4': 'corpora/omw-1.4',
        'words': 'corpora/words'
    }

    for package_name, search_path in required_data.items():  # 遍历所需数据包
        try:
            nltk.data.find(search_path)
        except LookupError:
            logger.warning(f"[-] NLTK 本地缓存缺失 [{package_name}]，正在下载至：{NLTK_DIR}")
            try:
                os.makedirs(NLTK_DIR, exist_ok=True)
                nltk.download(package_name, download_dir=NLTK_DIR, quiet=True)
            except Exception as e:  # 捕获下载异常
                logger.warning(f"❌ NLTK 下载失败 {package_name}: {str(e)}")


class CodeLineFilter:
    """
    代码行级过滤器

    从 JS 代码中提取字符串候选值，基于上下文和内容特征进行初步过滤。
    """

    def __init__(self, min_string_length=5, min_sensitive_length=5, max_string_length=1000,
                 blacklist: Optional[List[str]] = None):
        """
        初始化代码行过滤器

        Args:
            min_string_length: 普通字符串最小长度
            min_sensitive_length: 含敏感关键词的字符串最小长度
            max_string_length: 字符串最大长度
            blacklist: 额外的黑名单列表
        """
        self.min_string_length = min_string_length  # 最小字符串长度
        self.min_sensitive_length = min_sensitive_length  # 敏感词最小长度
        self.max_string_length = max_string_length  # 最大字符串长度

        self.DEFAULT_BLACKLIST = SECRET_DETECTION_BLACKLIST  # 默认黑名单

        combined_blacklist = list(self.DEFAULT_BLACKLIST)  # 合并黑名单列表
        if blacklist:
            combined_blacklist.extend(blacklist)

        self.blacklist = set(combined_blacklist)  # 转为集合去重
        # 预编译黑名单正则（提高匹配性能）
        self.blacklist_pattern = re.compile(  # 编译黑名单正则
            '|'.join(re.escape(item) for item in self.blacklist),
            re.IGNORECASE
        ) if self.blacklist else None

        self.static_resource_extensions = tuple(HTTPX_STATIC_EXTENSIONS)  # 静态资源扩展名

    def extract_candidates(self, js_code: str) -> List[Tuple[str, str]]:
        """
        从 JS 代码中提取候选字符串值

        提取过程：
        1. 逐行扫描代码
        2. 跳过上下文匹配排除模式的行（如 console.log）
        3. 提取引号中的内容
        4. 验证内容有效性

        Args:
            js_code: JS 源代码

        Returns:
            List[Tuple[str, str]]: (值, 原始行) 元组列表
        """
        QUOTE_PATTERN = re.compile(r'(["\'])(.*?)\1')  # 编译引号提取正则
        if not js_code:
            return []
        string_candidates = set()  # 候选结果集合
        for line in js_code.splitlines():  # 遍历每行代码
            original_line = line.strip()  # 去除首尾空格
            if not original_line or len(original_line) > 3500:
                continue
            if '"' not in original_line and "'" not in original_line:
                continue

            line_lower = original_line.lower()  # 转小写用于匹配
            is_bad_context = any(ctx in line_lower for ctx in EXCLUDED_CONTEXT_PATTERNS)  # 是否排除上下文
            has_sensitive_keyword = any(kw in line_lower for kw in SENSITIVE_KEYWORD_SET)  # 是否含敏感词

            # 在排除上下文中且没有敏感关键词，跳过
            if is_bad_context and not has_sensitive_keyword:
                continue

            # 提取引号内容
            for _, content in QUOTE_PATTERN.findall(original_line):  # 遍历匹配的引号内容
                content = content.strip()  # 清理引号内容
                if self._is_valid_content(content, original_line, has_sensitive_keyword):
                    string_candidates.add((content, original_line))
        return list(string_candidates)

    def _is_valid_content(self, content: str, original_line: str, has_sensitive_keyword: bool) -> bool:
        """
        验证字符串候选值是否有效（多重过滤规则）

        过滤规则：
        - 长度限制
        - 黑名单过滤
        - 静态资源扩展名过滤
        - 非 ASCII 字符比例限制
        - 中文字符过滤
        - CSS 类名过滤
        - 特殊字符比例限制
        - Unicode 转义数量限制
        - 排除字面量过滤
        - 纯数字过滤
        - 上下文关联性检查

        Args:
            content: 提取的字符串内容
            original_line: 所在原始行
            has_sensitive_keyword: 是否包含敏感关键词

        Returns:
            bool: 是否为有效候选
        """
        # 预编译正则模式（性能优化）
        IGNORE_PREFIX_PATTERN = re.compile(  # 编译忽略前缀正则
            r'^[\W_]*(chunk-|app-|vendors-|manifest-|data-v-|vue-|bg-|text-|border-|font-|col-|row-|flex-|grid-|btn-|icon-|fa-|el-|mat-)',
            re.IGNORECASE
        )
        UNICODE_PATTERN = re.compile(r'(\\)+u[0-9a-fA-F]{4}')  # 编译Unicode转义正则

        content_len = len(content)  # 获取内容长度

        # 1. 超长过滤
        if content_len > self.max_string_length:
            return False

        # 2. 黑名单过滤
        if self.blacklist_pattern and self.blacklist_pattern.search(content):
            return False

        # 3. 静态资源扩展名过滤（较短的文件名）
        if content.lower().endswith(self.static_resource_extensions) and content_len < 50:
            return False

        # 4. 非 ASCII 字符比例检查（过高可能是乱码或非英语内容）
        non_ascii_ratio = sum(1 for c in content if ord(c) > 127) / content_len if content_len > 0 else 0  # 非ASCII比例
        if non_ascii_ratio > 0.15:
            return False

        # 5. 中文字符过滤
        if re.search(r'[一-鿿]{2,}', content):
            return False

        # 6. CSS 类名/哈希值过滤
        if content.startswith('#') and '-' in content:
            return False

        # 7. 长度下限检查
        min_len = self.min_sensitive_length if has_sensitive_keyword else self.min_string_length  # 动态长度阈值
        if content_len < min_len:
            return False

        # 8. 常见前缀过滤（webpack chunk、vue 组件等）
        if IGNORE_PREFIX_PATTERN.match(content):
            return False

        # 9. 空格和特殊字符检查
        if any(c in content for c in [' ', '<', '>', '\\', '__', '(', ')']):
            return False

        # 10. 特殊字符比例检查
        special_count = sum(1 for c in content if not c.isalnum())  # 特殊字符计数
        if content_len > 0 and (special_count / content_len) > 0.2:
            return False

        # 11. Unicode 转义数量检查
        if len(UNICODE_PATTERN.findall(content)) >= 3:
            return False

        # 12. 排除字面量
        if content in EXCLUDED_LITERAL_VALUES:
            return False

        # 13. 纯数字短字符串过滤
        if content.isdigit() and content_len < 8:
            return False

        # 14. 上下文关联性检查
        if not has_sensitive_keyword:
            if not any(char in original_line for char in ['=', ':', '{', '(', ',']):
                return False

        return True


class SecretMathScorer:
    """
    纯数学/统计学驱动的敏感信息评分器（V6.0 极简双特征版）

    基于两个核心特征评分：
    - E（熵值）：信息熵越高，越像是随机生成的秘密
    - P（可识别性）：能被拆分为已知单词的比例，越低越可能是秘密

    最终分数通过 Sigmoid 函数映射到 [0, 1] 区间。
    """

    _nltk_initialized = False

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        初始化评分器

        Args:
            weights: 特征权重字典（w_e: 熵权重, w_p: 可识别性权重）
        """
        # 确保 NLTK 数据已初始化（全局单次）
        if not SecretMathScorer._nltk_initialized:
            _init_nltk_offline()
            SecretMathScorer._nltk_initialized = True  # 标记已初始化

        self.weights = weights or {'w_e': 0.85, 'w_p': 1.2}  # 评分权重参数
        self._cache = {}  # 评分结果缓存
        self._local_logger = get_logger("SecretMathScorer")  # 本地日志器

        # 加载 NLTK 英语词汇列表，合并技术词汇
        try:
            nltk_words = set(w.lower() for w in words.words())  # NLTK词典集合
            self.valid_words_set = nltk_words.union(WEB_TECHNICAL_WORDS)  # 合并技术词汇
        except:
            logger.warning("NLTK words loading failed, using TECH_WORDS instead.")
            self.valid_words_set = WEB_TECHNICAL_WORDS  # 回退技术词汇

    def _log2(self, x):
        """以 2 为底的对数"""
        return math.log2(x) if x > 0 else 0.0

    def calc_E(self, s: str) -> float:
        """
        计算字符串的信息熵特征（E 特征）

        使用 Shannon 熵归一化后经 Sigmoid 调整长度置信度。

        Args:
            s: 待计算的字符串

        Returns:
            float: 熵特征分数 [0, 1]
        """
        L = len(s)  # 字符串长度
        if L == 0: return 0.0
        cnt = Counter(s)  # 字符频率统计
        H = -sum((c / L) * self._log2(c / L) for c in cnt.values())  # 计算香农熵
        max_H = self._log2(min(L, len(cnt)))  # 最大可能熵值
        E_raw = H / max_H if max_H > 0 else 0.0  # 归一化熵值

        # Sigmoid 曲线：长度越长，熵值置信度越高
        # L=7 时系数≈0.4, L=12 时≈0.73, L=20 时≈0.95
        length_confidence = 1.0 / (1.0 + math.exp(-0.3 * (L - 12)))  # 长度置信度
        return E_raw * length_confidence

    def _camel_split(self, s: str) -> List[str]:
        """
        驼峰命名切分

        基于大小写边界将驼峰字符串切分为单词片段。

        Args:
            s: 待切分的字符串

        Returns:
            List[str]: 切分后的单词列表
        """
        parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)', s)  # 驼峰切分结果
        return [p for p in parts if p]

    def _wordninja_split(self, s: str) -> List[str]:
        """
        使用 wordninja 分词（无空格字符串智能分词）

        Args:
            s: 待分词的字符串

        Returns:
            List[str]: 分词结果列表
        """
        return wordninja.split(s)

    def calc_P(self, s: str) -> float:
        """
        计算字符串的可识别性特征（P 特征）

        综合使用 wordninja 分词和驼峰切分，统计可识别的英语单词占比。

        Args:
            s: 待计算的字符串

        Returns:
            float: 可识别性分数 [0, 1]，越高表示越像正常文本
        """
        alpha_only = re.sub(r'[^a-zA-Z]', '', s).lower()  # 提取纯字母并小写
        L_alpha = len(alpha_only)  # 字母部分长度
        if L_alpha < 4: return 0.0

        # 路 1: wordninja 无空格分词
        words_wn = self._wordninja_split(alpha_only)  # wordninja分词结果

        # 路 2: 驼峰切分
        words_camel = self._camel_split(alpha_only)  # 驼峰切分结果

        # 融合：取并集去重
        all_words = list(set(words_wn + words_camel))  # 合并去重单词列表

        # 过滤短词 + 词典匹配
        valid_words = [w for w in all_words if len(w) > 3]  # 过滤短词
        matched_len = sum(len(w) for w in valid_words if w in self.valid_words_set)  # 匹配词总长度

        return min(matched_len / L_alpha, 1.0)

    def score(self, s: str) -> Dict[str, float]:
        """
        计算字符串的敏感信息评分

        核心公式：
        score = sigmoid(3.5 * (w_e * E - w_p * P - 0.45))

        评分越高，越可能是敏感信息。

        Args:
            s: 待评分的字符串

        Returns:
            dict: 包含 score（最终分数）, E（熵特征）, P（可识别性特征）
        """
        if s in self._cache: return self._cache[s]

        E = self.calc_E(s)  # 计算熵特征
        P = self.calc_P(s)  # 计算可识别性
        w = self.weights  # 获取权重参数

        # 核心公式
        base = w['w_e'] * E - w['w_p'] * P  # 计算原始差值
        final = 1.0 / (1.0 + math.exp(-3.5 * (base - 0.45)))  # Sigmoid映射

        res = {'score': final, 'E': E, 'P': P}  # 组合评分结果
        self._cache[s] = res  # 缓存评分结果
        return res


class AdvancedSecretFilter:
    """
    高级敏感信息过滤器

    基于数学评分和关键词提权，判断字符串是否为敏感信息。
    """

    def __init__(self, threshold: float = 0.75, weights: Optional[Dict[str, float]] = None):
        """
        初始化过滤器

        Args:
            threshold: 判定阈值（默认 0.75）
            weights: 评分器权重
        """
        self.threshold = threshold  # 判定阈值
        self.scorer = SecretMathScorer(weights)  # 数学评分器
        self.sensitive_keywords = SENSITIVE_KEYWORD_SET  # 敏感关键词集合
        self._local_logger = get_logger("AdvancedSecretFilter")  # 本地日志器

    def shannon_entropy(self, data: str) -> float:
        """
        计算字符串的 Shannon 信息熵

        Args:
            data: 输入字符串

        Returns:
            float: 信息熵值
        """
        return self.scorer.calc_E(data) * math.log2(len(data)) if len(data) > 0 else 0.0

    def is_secret(self, text: str) -> bool:
        """
        判断字符串是否为敏感信息

        基于数学评分，结合长度和关键词提权。

        Args:
            text: 待判断的字符串

        Returns:
            bool: True 表示可能是敏感信息
        """
        # 排除文件路径格式
        if re.match(r'^\.{0,2}/[a-zA-Z0-9_./-]+$', text): return False
        if not text or len(text) <= 6: return False

        res = self.scorer.score(text)  # 获取评分结果
        score = res['score']  # 提取分数值

        L = len(text)  # 文本长度
        # 长度自适应阈值：短字符串要求更高，长字符串适当放宽
        thr = self.threshold * (0.9 if L < 16 else (1.1 if L > 100 else 1.0))  # 自适应阈值

        # 关键词提权：包含敏感关键词时分数上浮 20%
        if any(kw in text.lower() for kw in self.sensitive_keywords):
            score = min(score * 1.2, 1.0)  # 关键词提权

        result = score >= thr  # 判定是否为秘密
        return result


class LLMSecretVerifier:
    """
    大模型敏感信息验证器

    使用 LLM 对数学筛选后的候选值进行深度验证，识别秘密类型和风险等级。
    """

    def __init__(self, client, max_retries=2, retry_delay=1.0):
        """
        初始化 LLM 验证器

        Args:
            client: AI 客户端实例
            max_retries: 最大重试次数
            retry_delay: 重试延迟基数（秒）
        """
        self.client = client  # AI客户端实例
        self.max_retries = max_retries  # 最大重试次数
        self.retry_delay = retry_delay  # 重试延迟基数
        self._local_logger = get_logger("LLMSecretVerifier")  # 本地日志器

    def verify_with_context(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        使用 LLM 验证候选敏感信息列表

        Args:
            candidates: 候选信息列表

        Returns:
            List[Dict]: 验证后的敏感信息列表
        """
        if not candidates:
            return []

        return self._verify_with_single_api(candidates)

    def _verify_with_single_api(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        单次批量调用 LLM 进行验证

        Args:
            candidates: 候选信息列表

        Returns:
            List[Dict]: 验证后的敏感信息列表
        """
        input_data = self._format_candidates_for_single(candidates)  # 格式化候选数据
        analysis_result = self._call_llm(input_data)  # 调用LLM分析
        if not analysis_result:
            return []
        return self._parse_and_merge(candidates, analysis_result)

    def _format_candidates_for_single(self, candidates: List[Dict[str, Any]]) -> str:
        """
        格式化多个候选对象为 JSON 字符串（单次调用）

        Args:
            candidates: 候选列表

        Returns:
            str: 格式化后的 JSON 字符串
        """
        formatted = {}  # 格式化结果字典
        for cand in candidates:  # 遍历候选列表
            cand_id = str(cand.get("id", ""))  # 获取候选ID
            formatted[cand_id] = {  # 结构化展示
                "value": cand.get("value", ""),
                "context": cand.get("context", ""),
                "callers": cand.get("callers", [])
            }
        return json.dumps(formatted, ensure_ascii=False, indent=2)

    def _call_llm(self, input_data: str) -> Dict[str, Any]:
        """
        调用 LLM 分析敏感信息并返回解析结果

        包含重试机制和 JSON 提取逻辑。

        Args:
            input_data: 格式化后的输入数据

        Returns:
            Dict: LLM 返回的分析结果
        """
        messages = [
            {"role": "system", "content": SECRET_PROMPT},
            {"role": "user", "content": f"Analyze these hardcoded values:\n\n{input_data}"}
        ]
        for attempt in range(self.max_retries + 1):  # 重试循环
            try:
                content = self.client.chat(messages=messages, max_tokens=2048, temperature=0.1)  # 调用LLM获取回复
                json_str = self._extract_json(content)  # 提取JSON字符串
                if json_str:
                    return json_repair.loads(json_str)
                else:
                    self._local_logger.warning(f"⚠️ [LLM] 未找到有效 JSON (Attempt {attempt + 1})")
            except Exception as e:  # 捕获LLM调用异常
                self._local_logger.warning(
                    f"⚠️ [LLM] 调用失败 (Attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (attempt + 1))
        self._local_logger.error("❌ [LLM] 所有重试失败...")
        return {}

    def _extract_json(self, content: str) -> Optional[str]:
        """
        从 LLM 响应中提取 JSON 字符串

        支持格式：
        - 纯 JSON 字符串
        - ```json ... ``` 代码块包裹的 JSON
        - 任意包含 {} 的内容

        Args:
            content: LLM 原始响应

        Returns:
            Optional[str]: 提取的 JSON 字符串
        """
        try:
            json_repair.loads(content)
            return content
        except json.JSONDecodeError:
            pass
        # 尝试匹配 ```json ... ``` 代码块
        match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)  # 匹配JSON代码块
        if match:
            return match.group(1)
        # 回退：匹配第一个 {} 包裹的内容
        match = re.search(r'\{.*\}', content, re.DOTALL)  # 匹配花括号内容
        if match:
            return match.group()
        return None

    def _parse_and_merge(self, candidates: List[Dict[str, Any]],
                         analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        解析并合并 LLM 分析结果到候选信息中

        Args:
            candidates: 原始候选列表
            analysis_result: LLM 分析结果

        Returns:
            List[Dict]: 合并后的敏感信息列表
        """
        verified = []  # 验证结果列表
        for cand in candidates:  # 遍历候选列表
            cand_id = str(cand.get("id", ""))  # 获取候选ID
            ai_result = analysis_result.get(cand_id, {})  # 获取AI分析结果
            is_secret = ai_result.get("is_secret", 1)  # 是否秘密标志
            result = {  # 构建合并结果
                **cand,
                "is_secret": bool(is_secret) if isinstance(is_secret, int) else is_secret,
                "secret_type": ai_result.get("secret_type", "unknown"),
                "risk_level": ai_result.get("risk_level", "Low"),
                "confidence": float(ai_result.get("confidence", 0.5)),
                "test_suggestion": ai_result.get("test_suggestion", ""),
                "ai_raw_analysis": {
                    "is_secret": ai_result.get("is_secret", 1),
                    "secret_type": ai_result.get("secret_type", "unknown"),
                    "risk_level": ai_result.get("risk_level", "Low"),
                    "confidence": ai_result.get("confidence", 0.5),
                    "test_suggestion": ai_result.get("test_suggestion", "")
                }
            }
            if result["is_secret"]:
                verified.append(result)
        return verified


class SensitiveInfoScanner:
    """
    敏感信息扫描器（主入口）

    多阶段处理流水线：
    1. 预处理（HTML 清理 + 代码格式化）
    2. 候选提取（行级过滤 + 数学评分）
    3. AST 上下文补充
    4. LLM 深度验证
    5. 结果去重与持久化
    """

    def __init__(self, client, db: Optional[SQLiteStorage] = None, max_ast_analysis=50, max_llm=80):
        """
        初始化扫描器

        Args:
            client: AI 客户端实例
            db: 数据库处理器（可选，用于持久化结果）
            max_ast_analysis: AST 分析的最大候选数
            max_llm: LLM 验证的最大候选数
        """
        self.client = client  # AI客户端实例
        self.db = db  # 数据库实例
        self.max_ast_analysis = max_ast_analysis  # AST分析上限
        self.max_llm = max_llm  # LLM验证上限
        self.line_filter = CodeLineFilter()  # 行级过滤器
        self.adv_filter = AdvancedSecretFilter(threshold=0.75)  # 高级过滤器
        self.llm_verifier = LLMSecretVerifier(client)  # LLM验证器
        self.ast_available = SenInfoContextExtractor is not None  # AST是否可用
        self._local_logger = get_logger("SensitiveInfoScanner")  # 本地日志器

    def scan(self, js_code: str, js_url: str = "") -> List[Dict[str, Any]]:
        """
        执行完整敏感信息扫描

        流水线：
        1. 预处理清理和格式化代码
        2. 提取候选字符串（行级过滤 + 数学评分）
        3. AST 上下文补充（可选）
        4. 优先级排序并截断
        5. LLM 深度验证
        6. 结果持久化

        Args:
            js_code: JS 源代码
            js_url: JS 文件 URL（可选，用于关联存储）

        Returns:
            List[Dict]: 发现的敏感信息列表
        """
        if not js_code: return []
        # 第一步：预处理
        js_code = self._preprocess(js_code)  # 预处理代码
        # 第二步：提取候选
        candidates = self._extract_candidates(js_code)  # 提取候选列表
        if not candidates: return []
        # 第三步：AST 上下文补充
        if self.ast_available:
            candidates = self._enrich_with_ast(candidates, js_code)  # AST补充上下文
        # 第四步：排序并限制 LLM 验证数量
        if len(candidates) > self.max_llm:
            candidates = self._priority_sort(candidates)[:self.max_llm]  # 截取前N项
        # 第五步：LLM 深度验证
        verified = self._verify_with_llm(candidates)  # LLM验证候选
        # 第六步：持久化到数据库
        if self.db and js_url and verified is not None:
            self.db.save_sensitive_info(js_url, verified)
        return verified

    def _preprocess(self, js_code: str) -> str:
        """
        预处理：清理 HTML 标签 + 代码格式化

        Args:
            js_code: 原始代码

        Returns:
            str: 预处理后的代码
        """
        js_code = remove_html_tags(js_code)  # 移除HTML标签
        try:
            js_code = format_code(js_code, fallback_on_error=True)  # 格式化JS代码
        except Exception as e:  # 捕获格式化异常
            logger.error(f"⚠️ 代码格式化失败：{e}")
        return js_code

    def _extract_candidates(self, js_code: str) -> List[Dict[str, Any]]:
        """
        提取并数学评分过滤候选字符串

        使用 CodeLineFilter 提取候选值后，
        用 AdvancedSecretFilter 进行数学评分过滤。

        Args:
            js_code: 预处理后的 JS 代码

        Returns:
            List[Dict]: 通过数学过滤的候选列表
        """
        raw_candidates = self.line_filter.extract_candidates(js_code)  # 提取原始候选
        candidate_objects = []  # 候选对象列表
        for i, (content, line) in enumerate(raw_candidates):  # 遍历原始候选
            if self.adv_filter.is_secret(content):
                # 全局去重（使用布隆过滤器）
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

    def _enrich_with_ast(self, candidates: List[Dict[str, Any]], js_code: str) -> List[Dict[str, Any]]:
        """
        使用 AST 分析补充上下文信息

        通过 Tree-sitter AST 分析获取敏感字符串的声明位置和调用者信息。

        Args:
            candidates: 候选列表
            js_code: JS 源代码

        Returns:
            List[Dict]: 补充上下文后的候选列表
        """
        try:
            extractor = SenInfoContextExtractor(js_code)  # 创建AST提取器
            # 限制 AST 分析数量（性能优化）
            if len(candidates) > self.max_ast_analysis:
                candidates = self._priority_sort(candidates)[:self.max_ast_analysis]  # 截取前N项
            for cand in candidates:  # 遍历候选列表
                context = extractor.get_full_context(cand["value"])  # 获取AST上下文
                cand["context"] = context.get("declaration", "")  # 补充声明位置
                cand["callers"] = context.get("callers", [])  # 补充调用者信息
        except Exception as e:  # 捕获AST异常
            logger.error(f"⚠️ AST 上下文提取失败：{e}")
        return candidates

    def _priority_sort(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        按优先级排序候选列表

        排序依据：
        1. 敏感关键词匹配（权重 +10）
        2. Shannon 信息熵（权重 ×2）

        Args:
            candidates: 候选列表

        Returns:
            List[Dict]: 排序后的候选列表（高优先级在前）
        """

        def priority_score(cand):
            value_lower = cand.get("value", "").lower()  # 值转小写
            line_lower = cand.get("original_line", "").lower()  # 行内容转小写
            score = 0  # 初始化优先级分
            for kw in SENSITIVE_KEYWORD_SET:  # 遍历敏感关键词
                if kw in value_lower or kw in line_lower:
                    score += 10  # 关键词加分
            score += int(self.adv_filter.shannon_entropy(cand.get("value", "")) * 2)  # 熵值加分
            return score

        return sorted(candidates, key=priority_score, reverse=True)

    def _verify_with_llm(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        使用 LLM 深度验证候选敏感信息

        分批将候选送入 LLM 进行验证，每批 20 个。
        验证失败的候选以中等风险默认值保留。

        Args:
            candidates: 候选列表

        Returns:
            List[Dict]: 验证后的敏感信息列表（按行去重）
        """
        if not candidates: return []
        logger.info(f"🚀 Sending {len(candidates)} candidates to LLM...")
        batch_size = 20  # 每批处理数量
        all_verified = []  # 所有验证结果
        for i in range(0, len(candidates), batch_size):  # 分批遍历
            batch = candidates[i:i + batch_size]  # 当前批次切片
            batch_num = i // batch_size + 1  # 当前批次编号
            total_batches = (len(candidates) + batch_size - 1) // batch_size  # 总批次数
            logger.info(f"🧠 [LLM] 处理批次 {batch_num}/{total_batches} ({len(batch)} 项)")
            try:
                verified_batch = self.llm_verifier.verify_with_context(batch)  # 验证当前批次
                if verified_batch is None: continue
                all_verified.extend(verified_batch)
            except Exception as e:  # 捕获批次处理异常
                self._local_logger.error(f"❌ [LLM] 批次 {batch_num} 处理失败：{e}")
                # LLM 失败时，使用默认值保留候选，避免遗漏
                for cand in batch:  # 遍历当前批次
                    cand.update({  # 使用默认值保留
                        "is_secret": True,
                        "secret_type": "unknown",
                        "risk_level": "Med",
                        "confidence": 0.3,
                        "test_suggestion": "LLM 分析失败，建议人工审查",
                        "ai_raw_analysis": {"error": str(e)}
                    })
                    all_verified.append(cand)

        # 按行去重
        final_results = []  # 最终去重结果
        seen_lines = set()  # 已见行记录
        for res in all_verified:  # 遍历验证结果
            line = res.get("original_line", "")  # 获取原始行
            if line not in seen_lines:
                if _OUTPUT_LINE_DEDUP.contains(line):
                    continue
                _OUTPUT_LINE_DEDUP.add(line)
                seen_lines.add(line)
                final_results.append(res)
        return final_results


def cleanup_bloom_filters():
    """清理全局布隆过滤器资源"""
    _AI_CANDIDATE_DEDUP.close()
    _OUTPUT_LINE_DEDUP.close()


# 全局布隆过滤器实例（用于各阶段去重）
_AI_CANDIDATE_DEDUP = DiskBloomFilter("Result/ai_candidates.bloom", capacity=5_000_000)  # AI候选去重
_OUTPUT_LINE_DEDUP = DiskBloomFilter("Result/output_lines.bloom", capacity=5_000_000)  # 输出去重过滤器