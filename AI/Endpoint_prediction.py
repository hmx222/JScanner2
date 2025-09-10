import os
import logging
import re
import time
import random
from io import StringIO
from collections import deque
from itertools import chain

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity

    SEMANTIC_ANALYSIS_AVAILABLE = True
    _semantic_model = None
except ImportError:
    SEMANTIC_ANALYSIS_AVAILABLE = False
    _semantic_model = None

# OLLAMA GPU内存限制，根据本地显卡内存调整
OLLAMA_GPU_MEMORY = "4GB"

# 日志级别设置
LANGCHAIN_LOG_LEVEL = logging.ERROR
HTTPX_LOG_LEVEL = logging.ERROR

# 调用的OLLAMA模型名称
MODEL_NAME = "qwen2.5:14b-instruct-q2_K"

# 模型生成参数
MODEL_TEMPERATURE = 0.6
MODEL_MAX_TOKENS = 300  # 减少最大令牌数，适合短输出

# 循环检测参数（保持不变）
LOOP_PROTECTION_TOKEN_WINDOW = 30
LOOP_PROTECTION_MAX_TOKEN_REPEAT = 4
LOOP_PROTECTION_SENTENCE_WINDOW = 5
LOOP_PROTECTION_SIMILARITY_THRESHOLD = 0.82
LOOP_PROTECTION_CHECK_INTERVAL = 5

# 恢复策略权重
LOOP_PROTECTION_RECOVERY_STRATEGY = {
    "increase_temperature": 0.6,
    "inject_diversity": 0.3,
    "hard_terminate": 0.1
}

logging.getLogger("langchain").setLevel(LANGCHAIN_LOG_LEVEL)
logging.getLogger("httpx").setLevel(HTTPX_LOG_LEVEL)
os.environ["OLLAMA_GPU_MEMORY"] = OLLAMA_GPU_MEMORY

from langchain_community.chat_models import ChatOllama
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.prompts import PromptTemplate


def get_semantic_model():
    """延迟加载语义模型"""
    global _semantic_model

    if _semantic_model is not None:
        return _semantic_model

    if not SEMANTIC_ANALYSIS_AVAILABLE:
        _semantic_model = "SIMPLE"
        return _semantic_model

    try:
        try:
            from modelscope import snapshot_download
            from sentence_transformers import SentenceTransformer
        except ImportError:
            _semantic_model = "SIMPLE"
            return _semantic_model

        os.environ["MODELSCOPE_CACHE"] = "./modelscope_models"
        model_dir = snapshot_download(
            'Ceceliachenen/paraphrase-multilingual-MiniLM-L12-v2',
            cache_dir='./modelscope_models',
            revision='master'
        )

        _semantic_model = SentenceTransformer(model_dir)
        logging.info("成功加载语义分析模型")
        return _semantic_model

    except Exception as e:
        logging.error(f"模型加载失败: {str(e)}，使用简单相似度检测")
        _semantic_model = "SIMPLE"
        return _semantic_model


class LoopProtectionCallback(BaseCallbackHandler):
    """循环检测与防护回调处理器"""

    def __init__(self,
                 token_window=LOOP_PROTECTION_TOKEN_WINDOW,
                 max_token_repeat=LOOP_PROTECTION_MAX_TOKEN_REPEAT,
                 sentence_window=LOOP_PROTECTION_SENTENCE_WINDOW,
                 similarity_threshold=LOOP_PROTECTION_SIMILARITY_THRESHOLD,
                 check_interval=LOOP_PROTECTION_CHECK_INTERVAL):
        self.buffer = StringIO()
        self.token_count = 0
        self.last_tokens = deque(maxlen=token_window)
        self.token_repetition_count = 0
        self.sentence_history = deque(maxlen=sentence_window)
        self.current_sentence = []
        self.sentence_similarity_checks = 0
        self.check_interval = check_interval
        self.similarity_threshold = similarity_threshold
        self.loop_detected = False
        self.termination_phrase = "\n\n[内容生成已因检测到重复模式而终止]"

        self.token_window = token_window
        self.max_token_repeat = max_token_repeat
        self.sentence_window = sentence_window

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        """处理新生成的token并检测循环"""
        self.buffer.write(token)
        self.token_count += 1
        self.last_tokens.append(token)

        print(token, end="", flush=True)

        if self.token_count % self.check_interval == 0:
            self._check_for_loop()

    def get_output(self) -> str:
        """获取生成的输出内容"""
        return self.buffer.getvalue().strip()

    def _check_for_loop(self):
        """执行多层循环检测"""
        if self.loop_detected:
            return

        # L1: 词级检测
        if self._check_token_repetition():
            self._handle_loop_detection("token_repetition")
            return

        # L2: 句级检测
        if self.token_count > 50 and self._check_sentence_similarity():
            self._handle_loop_detection("sentence_similarity")
            return

    def _check_token_repetition(self) -> bool:
        """检查token级别重复"""
        pattern_len = self.token_window // 2
        if pattern_len > 0:
            first_half = ''.join(list(self.last_tokens)[:pattern_len])
            second_half = ''.join(list(self.last_tokens)[pattern_len:])

            if first_half and first_half in second_half:
                self.token_repetition_count += 1
                return self.token_repetition_count >= self.max_token_repeat

        return False

    def _check_sentence_similarity(self) -> bool:
        """检查句子级别语义重复"""
        if not self.current_sentence:
            self.current_sentence = []

        if self.last_tokens[-1] in ['。', '!', '?', '\n', '.', '!', '?']:
            current_sentence_text = ''.join(self.current_sentence).strip()
            if len(current_sentence_text) > 10 and self.sentence_history:
                max_similarity = self._calculate_similarity(current_sentence_text,
                                                            list(self.sentence_history))
                if max_similarity > self.similarity_threshold:
                    self.sentence_similarity_checks += 1
                    return self.sentence_similarity_checks >= 2

                self.sentence_history.append(current_sentence_text)

            self.current_sentence = []
        else:
            self.current_sentence.append(self.last_tokens[-1])

        return False

    def _calculate_similarity(self, text1, texts):
        """计算文本相似度"""
        if not texts:
            return 0.0

        if not SEMANTIC_ANALYSIS_AVAILABLE or get_semantic_model() == "SIMPLE":
            return self._simple_similarity(text1, texts)

        try:
            model = get_semantic_model()
            if model == "SIMPLE":
                return self._simple_similarity(text1, texts)

            embeddings = model.encode([text1] + texts)
            text1_embed = embeddings[0].reshape(1, -1)
            max_sim = 0

            for i in range(1, len(embeddings)):
                sim = cosine_similarity(text1_embed, embeddings[i].reshape(1, -1))[0][0]
                max_sim = max(max_sim, sim)

            return max_sim
        except Exception as e:
            logging.warning(f"语义相似度计算出错: {str(e)}，使用简单检测")
            return self._simple_similarity(text1, texts)

    def _simple_similarity(self, text1, texts):
        """简单Jaccard相似度计算"""
        set1 = set(text1)
        max_sim = 0

        for text2 in texts:
            set2 = set(text2)
            intersection = len(set1 & set2)
            union = len(set1 | set2)
            sim = intersection / union if union > 0 else 0
            max_sim = max(max_sim, sim)

        return max_sim

    def _handle_loop_detection(self, detection_type):
        """处理检测到的循环"""
        self.loop_detected = True
        print(f"\n检测到{detection_type}循环，尝试恢复...", flush=True)

        strategy = self._select_recovery_strategy()

        if strategy == "increase_temperature":
            self.buffer.write("\n\n换个角度思考这个API端点的相关操作...\n")
        elif strategy == "inject_diversity":
            diversions = [
                "这个API端点可能有其他相关的操作，比如...",
                "从功能相反的角度看，可能存在...",
                "类似的API设计中通常还会包含...",
            ]
            self.buffer.write(f"\n\n{random.choice(diversions)}\n")
        else:
            self.buffer.write(self.termination_phrase)
            raise Exception("Loop detection triggered termination")

    def _select_recovery_strategy(self):
        """选择恢复策略"""
        strategies = list(LOOP_PROTECTION_RECOVERY_STRATEGY.keys())
        weights = list(LOOP_PROTECTION_RECOVERY_STRATEGY.values())
        return random.choices(strategies, weights=weights, k=1)[0]


def load_ollama_llm():
    """加载OLLAMA模型"""
    return ChatOllama(
        model=MODEL_NAME,
        temperature=MODEL_TEMPERATURE,
        max_tokens=MODEL_MAX_TOKENS,
        streaming=True,
        keep_alive=-1
    )


def build_analysis_chain(llm):
    """构建API端点预测链（使用你的提示词）"""
    prompt_template = """
你是一名专业的渗透测试工程师，你的任务是结合渗透测试的思想，从给定的API列表中推测出更多的API，用于辅助渗透测试。
请仔细阅读以下现有的API列表：
<API列表>
{{API_LIST}}
</API列表>
在推测API时，请遵循以下思路和方法：
1. 分析现有API的命名规则、功能特点、参数结构等，找出其中的规律和模式。
2. 考虑常见的业务逻辑和操作流程，推测可能与之相关的其他API。例如，如果有一个获取用户信息的API，可能存在更新用户信息、删除用户信息等相关API。
3. 思考API的权限级别和使用场景，推测不同权限下可能存在的API。
4. 结合渗透测试的经验，考虑可能被攻击者利用的薄弱环节，推测与之对应的API。

如果觉得当前的API列表没有预测的价值，那么可以不预测，直接输出NULL即可。
推测的API要与原API保持80%结构相似度，否则输出NULL。

<推测API>
[在此列出你推测出的API]
</推测API>
请确保你的推测基于合理的分析和渗透测试的思想。
        """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["api_list"]  # 明确使用api_endpoint作为变量
    )
    return prompt | llm


def analyze_api_endpoint(chain, api_endpoint):
    """分析单个API端点并生成预测结果"""
    protection_callback = LoopProtectionCallback(
        token_window=LOOP_PROTECTION_TOKEN_WINDOW,
        max_token_repeat=LOOP_PROTECTION_MAX_TOKEN_REPEAT,
        sentence_window=LOOP_PROTECTION_SENTENCE_WINDOW,
        similarity_threshold=LOOP_PROTECTION_SIMILARITY_THRESHOLD,
        check_interval=LOOP_PROTECTION_CHECK_INTERVAL
    )

    try:
        # 传入api_endpoint参数（而非code）
        chain.invoke(
            {"api_endpoint": api_endpoint},
            config={"callbacks": [protection_callback]}
        )
        return protection_callback.get_output()
    except Exception as e:
        if "Loop detection triggered termination" in str(e):
            return protection_callback.get_output()
        raise

def run_analysis(api_endpoints):
    """运行API端点预测流程（一次性传入所有API）"""
    llm = load_ollama_llm()
    analysis_chain = build_analysis_chain(llm)

    # 将列表拼接成字符串，每行一个API
    api_list_str = "\n".join(api_endpoints)

    print(f"\n🔍 一次性分析 {len(api_endpoints)} 个 API 端点：")
    for api in api_endpoints:
        print(f"   • {api}")

    protection_callback = LoopProtectionCallback(
        token_window=LOOP_PROTECTION_TOKEN_WINDOW,
        max_token_repeat=LOOP_PROTECTION_MAX_TOKEN_REPEAT,
        sentence_window=LOOP_PROTECTION_SENTENCE_WINDOW,
        similarity_threshold=LOOP_PROTECTION_SIMILARITY_THRESHOLD,
        check_interval=LOOP_PROTECTION_CHECK_INTERVAL
    )

    try:
        chain.invoke(
            {"api_list": api_list_str},  # ⚠️ 传入 api_list
            config={"callbacks": [protection_callback]}
        )
        model_output = protection_callback.get_output()
        cleaned = clean_output(model_output)
        return { "input_apis": api_endpoints, "predicted_apis": cleaned }

    except Exception as e:
        if "Loop detection triggered termination" in str(e):
            model_output = protection_callback.get_output()
            cleaned = clean_output(model_output)
            return { "input_apis": api_endpoints, "predicted_apis": cleaned }
        else:
            raise

def clean_output(output):
    """清理模型输出，提取预测的API端点"""
    # 修正正则匹配，适配<STR>和<END>标签
    paths = re.findall(r'<STR>(.*?)<END>', output, re.DOTALL)
    if not paths:
        return ["NULL"]  # 未找到结果时返回NULL

    # 处理提取的内容（按行分割，去重，过滤无效内容）
    all_paths = []
    for path_block in paths:
        lines = [line.strip() for line in path_block.splitlines() if line.strip()]
        all_paths.extend(lines)

    # 去重
    unique_paths = list(set(all_paths))

    # 过滤无效路径（保留NULL和符合API命名规则的路径）
    allowed_pattern = re.compile(r'^[a-zA-Z0-9_/-]+$|^NULL$')
    filtered_paths = [path for path in unique_paths if allowed_pattern.match(path)]

    # 限制最多2个结果
    return filtered_paths[:2] if filtered_paths else ["NULL"]


if __name__ == '__main__':
    print("📌 请输入一个或多个 API 端点（每行一个，或用逗号分隔，输入 q 退出）：")

    while True:
        user_input = input().strip()
        if user_input.lower() == 'q':
            break
        if not user_input:
            print("⚠️  请输入至少一个有效的 API 端点")
            continue

        # 支持逗号分隔或换行输入（如果是粘贴多行）
        if '\n' in user_input:
            api_list = [line.strip() for line in user_input.splitlines() if line.strip()]
        else:
            api_list = [item.strip() for item in user_input.split(',') if item.strip()]

        if not api_list:
            print("⚠️  未检测到有效 API 端点")
            continue

        print(f"\n🚀 开始分析 {len(api_list)} 个 API 端点...\n")

        try:
            all_results = run_analysis(api_list)

            print("\n" + "="*60)
            print("✅ 最终预测结果汇总：")
            print("="*60)

            for api, predictions in all_results.items():
                print(f"\n🔹 原始 API: {api}")
                for i, pred in enumerate(predictions, 1):
                    print(f"  {i}. {pred}")

        except Exception as e:
            print(f"❌ 整体处理出错：{str(e)}")