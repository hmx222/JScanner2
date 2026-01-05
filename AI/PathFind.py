import logging
import os
import re
import time
from collections import deque
from io import StringIO

import requests

from config.config import LANGCHAIN_LOG_LEVEL, HTTPX_LOG_LEVEL, OLLAMA_MAX_GPU_MEMORY, LOOP_PROTECTION_TOKEN_WINDOW, \
    LOOP_PROTECTION_MAX_TOKEN_REPEAT, LOOP_PROTECTION_SENTENCE_WINDOW, LOOP_PROTECTION_SIMILARITY_THRESHOLD, \
    LOOP_PROTECTION_CHECK_INTERVAL, MODEL_NAME, MODEL_TEMPERATURE, MODEL_MAX_TOKENS, \
    CODE_SLICE_LINES, STOP_WORDS_FOR_MODEL

# try:
#     from sentence_transformers import SentenceTransformer
#     # from sklearn.metrics.pairwise import cosine_similarity
#
#     SEMANTIC_ANALYSIS_AVAILABLE = True
#     _semantic_model = None
# except ImportError:
#     SEMANTIC_ANALYSIS_AVAILABLE = False
#     _semantic_model = None

logging.getLogger("langchain").setLevel(LANGCHAIN_LOG_LEVEL)
logging.getLogger("httpx").setLevel(HTTPX_LOG_LEVEL)
os.environ["OLLAMA_MAX_GPU_MEMORY"] = OLLAMA_MAX_GPU_MEMORY

from langchain_community.chat_models import ChatOllama
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.prompts import PromptTemplate

from AI.beautifyjs import format_code
from AI.split_api_code import extract_relevant_lines



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
        print(token, end="", flush=True)


    def get_output(self) -> str:
        """获取当前生成的输出内容"""
        return self.buffer.getvalue().strip()


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



def load_ollama_llm():
    # 移除预先设置的callbacks，改为在调用时动态传入（避免回调复用导致数据混乱）
    return ChatOllama(
        model=MODEL_NAME,
        temperature=MODEL_TEMPERATURE,
        max_tokens=MODEL_MAX_TOKENS,
        streaming=True,
        keep_alive=-1,
        reasoning=False,
        stop=STOP_WORDS_FOR_MODEL
        # repeat_last_n=MODEL_REPEAT_LAST_N,
        # repeat_penalty=MODEL_REPEAT_PENALTY,
        # top_p=MODEL_TOP_P,
        # top_k=MODEL_TOP_K
    )


def build_analysis_chain(llm):
    """提示词保持不变"""
    prompt_template = """
仅从以下 JavaScript 代码中提取并推测完整路径，不输出任何解释或说明，只输出结果。

【提取对象】
- API 路径
- .js 静态文件路径
- 其他静态文件路径（排除图片/视频/音频/CSS/字体）

【路径拼接规则】
- 需要还原字符串拼接、模板字符串、常量变量参与的路径
- 优先进行确定性拼接（如字符串字面量、常量路径变量）
- 对不确定但可能形成路径的拼接允许进行推测性还原
- 拼接后需尽量形成完整、连续的路径
- 不得仅输出明显的路径残片

【合法性规则】
- 仅允许字符：字母、数字、/ . _ -（允许中文）
- 路径需符合 URL Path 规范

【输出规则】
- 每条路径单独一行
- 每行格式必须为：[STR]路径[END]
- 无符合条件的结果则不输出

代码：
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
    # 提取所有被[STR]和[END]包裹的内容
    paths = re.findall(r'\[STR\](.*?)\[END\]', output, re.DOTALL)

    # 去重
    paths = list(set(paths))
    allowed_pattern = re.compile(
        r'^[a-zA-Z0-9\u4e00-\u9fa5/._-~:?&=+$,#\[\]!*\'()]+$'
    )
    filtered_paths = [path for path in paths if allowed_pattern.match(path)]
    # 处理含http/https且以/开头的行：移除http/https前面的所有/
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

    # 处理后可能产生新的重复，再次去重
    return list(set(processed_paths))

if __name__ == "__main__":
    response = requests.get("https://turbodesk.xfyun.cn/assets/index-6gAHy66a.js")
    js_code = response.text
    model_output = run_analysis(js_code)
    print(model_output)
