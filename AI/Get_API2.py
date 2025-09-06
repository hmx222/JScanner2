import logging
import os
import random
import re
import time
from collections import deque
from io import StringIO

from config.config import LANGCHAIN_LOG_LEVEL, HTTPX_LOG_LEVEL, OLLAMA_MAX_GPU_MEMORY, LOOP_PROTECTION_TOKEN_WINDOW, \
    LOOP_PROTECTION_MAX_TOKEN_REPEAT, LOOP_PROTECTION_SENTENCE_WINDOW, LOOP_PROTECTION_SIMILARITY_THRESHOLD, \
    LOOP_PROTECTION_CHECK_INTERVAL, LOOP_PROTECTION_RECOVERY_STRATEGY, MODEL_NAME, MODEL_TEMPERATURE, MODEL_MAX_TOKENS, \
    MODEL_REPEAT_LAST_N, MODEL_REPEAT_PENALTY, CODE_SLICE_LINES, MODEL_TOP_P, MODEL_TOP_K

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity

    SEMANTIC_ANALYSIS_AVAILABLE = True
    _semantic_model = None
except ImportError:
    SEMANTIC_ANALYSIS_AVAILABLE = False
    _semantic_model = None

logging.getLogger("langchain").setLevel(LANGCHAIN_LOG_LEVEL)
logging.getLogger("httpx").setLevel(HTTPX_LOG_LEVEL)
os.environ["OLLAMA_MAX_GPU_MEMORY"] = OLLAMA_MAX_GPU_MEMORY

from langchain_community.chat_models import ChatOllama
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.prompts import PromptTemplate

from AI.beautifyjs import format_code
from AI.split_api_code import extract_relevant_lines


def get_semantic_model():
    """延迟加载语义模型，直接从ModelScope魔搭加载（国内镜像）"""
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
        logging.info("成功从ModelScope魔搭加载语义分析模型")
        return _semantic_model

    except Exception as e:
        logging.error(f"从ModelScope加载模型失败: {str(e)}，将使用简单相似度检测")
        _semantic_model = "SIMPLE"
        return _semantic_model


class LoopProtectionCallback(BaseCallbackHandler):
    """增强版回调处理器，添加循环检测与防护功能"""

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

        # 配置参数
        self.token_window = token_window
        self.max_token_repeat = max_token_repeat
        self.sentence_window = sentence_window

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        """处理新生成的token，同时进行循环检测"""
        self.buffer.write(token)
        self.token_count += 1
        self.last_tokens.append(token)
        # 是否进行流式输出
        # print(token, end="", flush=True)

        # 每隔N个token检查一次循环
        if self.token_count % self.check_interval == 0:
            self._check_for_loop()

    def get_output(self) -> str:
        """获取当前生成的输出内容"""
        return self.buffer.getvalue().strip()

    def _check_for_loop(self):
        """执行多层循环检测"""
        if self.loop_detected:
            return

        # L1: 词级检测 - 检查最近的token序列是否重复
        if self._check_token_repetition():
            self._handle_loop_detection("token_repetition")
            return

        # L2: 句级检测 - 检查语义相似度
        if self.token_count > 50 and self._check_sentence_similarity():
            self._handle_loop_detection("sentence_similarity")
            return

    def _check_token_repetition(self) -> bool:
        """优化：检测完整路径片段的重复（基于换行或路径分隔符分割）"""
        # 1. 先将token序列拼接成字符串，按换行或路径分隔符分割成“片段”（如路径、标点）
        full_token_str = ''.join(self.last_tokens)
        # 分割符：换行（\n）、路径开头（/）、标点（.、?等），确保能拆分出完整路径
        segments = re.split(r'(\n|/)', full_token_str)  # 保留分割符，方便重组路径
        segments = [s.strip() for s in segments if s.strip()]  # 过滤空字符串

        # 2. 只检测长度>2的片段（避免单个字符的误判，如“a”“b”）
        valid_segments = [seg for seg in segments if len(seg) > 3]
        if len(valid_segments) < 3:  # 至少2个片段才可能重复
            return False

        # 3. 检测是否有连续重复的片段（如“/api/user”出现2次以上）
        repeat_count = 1
        for i in range(1, len(valid_segments)):
            if valid_segments[i] == valid_segments[i - 1]:
                repeat_count += 1
                if repeat_count >= self.max_token_repeat:  # 达到最大重复次数
                    return True
            else:
                repeat_count = 1  # 重置计数

        return False

    def _check_sentence_similarity(self) -> bool:
        """优化：适配路径生成场景的句子分割与相似度检测"""
        # 1. 调整句子结束的判断：路径片段（以/开头或结尾）、换行符，均视为句子结束
        current_token = self.last_tokens[-1]
        is_sentence_end = (
                current_token in ['。', '!', '?', '\n', '.', '!', '?']
                or (len(self.current_sentence) > 0 and (current_token == '/' or self.current_sentence[-1] == '/'))
        )

        # 2. 构建当前句子（包含完整路径片段）
        self.current_sentence.append(current_token)
        current_sentence_text = ''.join(self.current_sentence).strip()

        # 3. 句子结束且长度>5（路径至少如“/api”），才加入历史
        if is_sentence_end and len(current_sentence_text) > 5:
            # 4. 立即检查与历史句子的相似度（不再等50个token，同步触发）
            max_similarity = self._calculate_similarity(current_sentence_text, list(self.sentence_history))
            self.sentence_history.append(current_sentence_text)  # 加入历史
            self.current_sentence = []  # 重置当前句子

            # 5. 连续2次相似度超过阈值，触发循环检测
            if max_similarity > self.similarity_threshold:
                self.sentence_similarity_checks += 1
                return self.sentence_similarity_checks >= 4
            else:
                self.sentence_similarity_checks = 0  # 重置计数

        return False

    def _calculate_similarity(self, text1, texts):
        if not texts:
            return 0.0

        if not SEMANTIC_ANALYSIS_AVAILABLE or get_semantic_model() == "SIMPLE":
            return self._edit_distance_similarity(text1, texts)  # 替换为编辑距离

        try:
            model = get_semantic_model()
            if model == "SIMPLE":
                return self._simple_similarity(text1, texts)

            # 生成嵌入
            embeddings = model.encode([text1] + texts)
            text1_embed = embeddings[0].reshape(1, -1)
            max_sim = 0

            for i in range(1, len(embeddings)):
                sim = cosine_similarity(text1_embed, embeddings[i].reshape(1, -1))[0][0]
                max_sim = max(max_sim, sim)

            return max_sim
        except Exception as e:
            logging.warning(f"语义相似度计算出错: {str(e)}，将使用简单相似度检测")
            return self._simple_similarity(text1, texts)

    def _edit_distance_similarity(self, text1, texts):
        """编辑距离相似度：1 - 编辑距离 / 最长文本长度（值越近1越相似）"""
        max_sim = 0.0
        len_text1 = len(text1)
        for text2 in texts:
            len_text2 = len(text2)
            # 计算编辑距离（Levenshtein距离）
            dp = [[0] * (len_text2 + 1) for _ in range(len_text1 + 1)]
            for i in range(len_text1 + 1):
                dp[i][0] = i
            for j in range(len_text2 + 1):
                dp[0][j] = j
            for i in range(1, len_text1 + 1):
                for j in range(1, len_text2 + 1):
                    if text1[i - 1] == text2[j - 1]:
                        dp[i][j] = dp[i - 1][j - 1]
                    else:
                        dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
            # 计算相似度（避免除以0）
            max_len = max(len_text1, len_text2)
            sim = 1 - (dp[len_text1][len_text2] / max_len) if max_len > 0 else 0.0
            if sim > max_sim:
                max_sim = sim
        return max_sim

    def _simple_similarity(self, text1, texts):
        """简单的Jaccard相似度计算（备用方案）"""
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
        """处理检测到的循环，尝试恢复而非简单终止"""
        self.loop_detected = True
        print(f"\n检测到{detection_type}循环，正在尝试恢复...", flush=True)

        # 选择恢复策略
        strategy = self._select_recovery_strategy()

        if strategy == "increase_temperature":
            print("增加随机性以打破循环...", flush=True)
            # 在缓冲区末尾添加提示，引导模型改变方向
            self.buffer.write("\n\n让我们换个角度思考这个问题...\n")

        elif strategy == "inject_diversity":
            print("注入多样性提示以打破循环...", flush=True)
            diversions = [
                "实际上，这个问题可以从另一个完全不同的视角来看...",
                "值得注意的是，我们可能忽略了某些关键因素...",
                "从历史经验来看，这个问题通常有多种解决方案...",
                "有趣的是，这个问题与[某领域]有相似之处..."
            ]
            self.buffer.write(f"\n\n{random.choice(diversions)}\n")

        else:  # hard_terminate
            print("检测到严重循环，已终止生成", flush=True)
            self.buffer.write(self.termination_phrase)
            # 提前终止生成
            raise Exception("Loop detection triggered termination")

    def _select_recovery_strategy(self):
        """根据权重选择恢复策略"""
        strategies = list(LOOP_PROTECTION_RECOVERY_STRATEGY.keys())
        weights = list(LOOP_PROTECTION_RECOVERY_STRATEGY.values())
        return random.choices(strategies, weights=weights, k=1)[0]


def load_ollama_llm():
    # 移除预先设置的callbacks，改为在调用时动态传入（避免回调复用导致数据混乱）
    return ChatOllama(
        model=MODEL_NAME,
        temperature=MODEL_TEMPERATURE,
        max_tokens=MODEL_MAX_TOKENS,
        streaming=True,
        keep_alive=-1,
        reasoning=False,
        repeat_last_n=MODEL_REPEAT_LAST_N,
        repeat_penalty=MODEL_REPEAT_PENALTY,
        top_p=MODEL_TOP_P,
        top_k=MODEL_TOP_K
    )


def build_analysis_chain(llm):
    """提示词保持不变"""
    prompt_template = """
仅从以下JavaScript代码中提取并推测路径，不包含任何思考过程、解释，要尽可能多的提取路径，让我们一步步推导：
1.提取对象：
       API路径：所有作为接口访问的路径（不限请求方法，变量拼接需补全，例：/api/v1/user，含中文路径需标注但正常提取）
       JavaScript路径：.js后缀的静态文件路径
       其他静态文件：保留除图片、视频、音频、CSS、字体以外的静态文件路径（含中文名称路径）
2.提取规则：
       路径需合法（符合URL Path规范，允许中文，特殊字符仅允许/._-）
       每条路径用[STR]开头、[END]结尾，单独成行。
3.API端点预测规则（仅对非静态文件的API路径进行）：
       理解操作意图：分析原始API端点的命名，推断其执行的具体操作（如：delete 表示删除，add/create 表示创建，update 表示更新，get/list 表示查询）。
       预测关联操作：基于RESTful设计原则，一个资源的典型操作是成套的（增、删、改、查）。如果原始路径明确指向其中一种操作，可以预测其最直接相关的1-2个其他操作。
       预测方法：
           若原始路径为删除操作（如包含delete, remove, del等），可预测创建操作（如将delete替换为create, add等）。
           若原始路径为创建操作（如包含create, add, new等），可预测删除或查询操作。
           若原始路径为登录（login），可预测登出（logout）和注册（register）。
           避免预测模糊或不相关的操作。
       严格限制：
           不可私自新增路径层数（例如：/api/comment/delete → /api/comment/delete/add 是错误的）。
           每个原始API端点最多预测2个相关端点。
           仅当原路径明确涉及增删改查（CRUD）或类似核心功能时优先预测。对于非CRUD操作适当预测，如登录、登出、注册等。
4.输出规则：
       先输出所有原始提取的路径，每条格式为：[STR]路径[END]。
       再输出所有预测的API端点，格式与原始路径完全相同：[STR]路径[END]。
       如果没有符合条件的原始路径或预测路径，则不输出任何内容。
       输出示例：
           [STR]/api/user[END]
           [STR]/api/user/register[END]
           [STR]/api/user/login[END]
           [STR]/api/user/logout[END]
代码片段如下：
{code}
        """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["code"]
    )
    return prompt | llm


def split_code_into_slices(code_str, lines_per_slice=CODE_SLICE_LINES):
    valid_lines = [line.rstrip() for line in code_str.splitlines() if line.strip()]
    total_lines = len(valid_lines)
    slices = []
    for start_idx in range(0, total_lines, lines_per_slice):
        end_idx = min(start_idx + lines_per_slice - 1, total_lines - 1)
        slice_lines = valid_lines[start_idx:end_idx + 1]
        formatted_slice = [f"{start_idx + 1 + idx}: {line}" for idx, line in enumerate(slice_lines)]
        slices.append("\n".join(formatted_slice))
    return slices


def analyze_single_slice(chain, slice_code):
    """调用链并返回当前切片的模型输出（核心修改：动态传入回调）"""
    # 每次调用创建独立的LoopProtectionCallback实例
    protection_callback = LoopProtectionCallback(
        token_window=LOOP_PROTECTION_TOKEN_WINDOW,
        max_token_repeat=LOOP_PROTECTION_MAX_TOKEN_REPEAT,
        sentence_window=LOOP_PROTECTION_SENTENCE_WINDOW,
        similarity_threshold=LOOP_PROTECTION_SIMILARITY_THRESHOLD,
        check_interval=LOOP_PROTECTION_CHECK_INTERVAL
    )

    try:
        # 调用链时传入循环防护回调
        chain.invoke(
            {"code": slice_code},
            config={"callbacks": [protection_callback]}
        )
        return protection_callback.get_output()
    except Exception as e:
        if "Loop detection triggered termination" in str(e):
            return protection_callback.get_output()  # 返回已生成的部分结果
        raise  # 其他异常正常抛出


def analyze_sliced_code(chain, code_str, lines_per_slice=15):
    slices = split_code_into_slices(code_str, lines_per_slice)
    all_output = []

    for slice_code in slices:
        try:
            slice_output = analyze_single_slice(chain, slice_code)
            if slice_output:
                all_output.append(slice_output)
        except Exception as e:
            logging.error(f"处理切片时出错: {str(e)}")
        time.sleep(0.5)

    return "\n".join(all_output)


def run_analysis(js_code, lines_per_slice=CODE_SLICE_LINES):
    llm = load_ollama_llm()
    analysis_chain = build_analysis_chain(llm)
    # 代码美化与提取
    result_js = format_code(js_code)
    result = extract_relevant_lines(result_js)
    model_full_output = analyze_sliced_code(analysis_chain, result, lines_per_slice=lines_per_slice)
    return model_full_output


def clean_output(output):
    # 去除思考部分<think></think>
    output = re.sub(r'<think>.*?</think>', '', output, flags=re.DOTALL)
    # 1. 提取所有被[STR]和[END]包裹的内容
    paths = re.findall(r'\[STR\](.*?)\[END\]', output, re.DOTALL)
    # 2. 去重
    paths = list(set(paths))
    allowed_pattern = re.compile(
        r'^[a-zA-Z0-9\u4e00-\u9fa5/._-~:?&=+$,#\[\]!*\'()]+$'
    )
    filtered_paths = [path for path in paths if allowed_pattern.match(path)]
    # 4. 处理含http/https且以/开头的行：移除http/https前面的所有/
    processed_paths = []
    http_pattern = re.compile(r'https?://')  # 匹配http://或https://
    example_path_from_prompt = []

    for path in filtered_paths:
        if path.endswith("/"):
            path = path[:-1]

        if path in example_path_from_prompt:
            continue

        if len(path) <= 3:
            continue

        # 检查条件：以/开头 且 包含http/https
        if len(path) > 0 and path[0] == '/' and http_pattern.search(path):
            # 找到http/https的起始位置，截取从该位置开始的内容（去掉前面所有/）
            match = http_pattern.search(path)
            if match:
                processed_path = path[match.start():]
                processed_paths.append(processed_path)
            else:
                processed_paths.append(path)
        else:
            # 不符合条件的行保持原样
            processed_paths.append(path)

    # 5. 处理后可能产生新的重复，再次去重
    return list(set(processed_paths))