import os
import logging
import re
import time
import random
from io import StringIO
from collections import deque

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
MODEL_NAME = "qwen2.5:7b-instruct-q4_0"

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
你需要根据给定的 API 端点，预测更多符合常见命名规则的 API 端点，最多预测2个结果，且词性结构保持不变。
以下是给定的 API 端点：
<api_endpoint>
{{api_endpoint}}
</api_endpoint>
请按照以下步骤完成任务：
1. 解析词语：理解每个 API 端点词语的含义，标注词性。如 login（动词，意为登录）；getUserByID（get 为动词，User 为名词，By 为介词，ID 为名词，意为通过 ID 获取 User）；users（名词）。
2. 判断可预测部分：单独的动词或复合结构中的动词部分可进行预测，单独的名词不做预测。例如：login（动词，可预测）；user（单独名词，不可预测）；addcomment（add 动词可预测，comment 名词可参与组合预测）。
3. 进行推测：依据词性和含义进行合理推测。例如：login 可推测为 logout；addcomment 中 add 可推测为 del，comment 可结合含义推测为 article，即 addcomment 可推测出 delcomment、addarticle；getUserByID 中 get 可推测为 del，ID 可推测为 Phone，即 getUserByID 可推测出 delUserByID、getUserByPhone。像“登录”可对应“注册”，“增加评论”可对应“删除评论”“增加文章”。
4. 组合结果：将推测出的部分组合成新的 API 端点，如 logout、delcomment、addarticle、delUserByID、getUserByPhone。
<STR>
[在此给出组合后的新 API 端点]
<END>
        """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["api_endpoint"]  # 明确使用api_endpoint作为变量
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


def run_analysis(api_endpoint):
    """运行API端点预测流程"""
    llm = load_ollama_llm()
    analysis_chain = build_analysis_chain(llm)
    # 直接分析API端点，无需处理JS代码
    model_output = analyze_api_endpoint(analysis_chain, api_endpoint)
    return model_output


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
    # 示例：输入单个API端点进行测试
    while True:
        print("\n请输入API端点（输入q退出）：")
        api_endpoint = input().strip()
        if api_endpoint.lower() == 'q':
            break
        if not api_endpoint:
            print("请输入有效的API端点")
            continue

        print("\n正在预测相关API端点...\n")
        try:
            model_output = run_analysis(api_endpoint)
            print("\n\n预测结果：")
            results = clean_output(model_output)
            for i, result in enumerate(results, 1):
                print(f"{i}. {result}")
        except Exception as e:
            print(f"处理出错：{str(e)}")