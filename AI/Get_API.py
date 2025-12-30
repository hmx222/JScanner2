import logging
import os
import re
import time
import warnings
from io import StringIO

from tqdm import tqdm

# -------------------------- 全局配置变量（用户可根据需求修改） --------------------------
# OLLAMA GPU内存限制，根据本地显卡内存调整
OLLAMA_GPU_MEMORY = "4GB"

# 日志级别设置，ERROR表示只显示错误信息，可改为INFO、DEBUG等
LANGCHAIN_LOG_LEVEL = logging.ERROR
HTTPX_LOG_LEVEL = logging.ERROR

# 调用的OLLAMA模型名称，需确保本地已下载该模型
MODEL_NAME = "qwen2.5:7b-instruct-q3_K_S"

# 模型生成参数：温度值（0-1，越低输出越稳定）
MODEL_TEMPERATURE = 0.4

# 模型生成参数：最大令牌数（控制输出长度）
MODEL_MAX_TOKENS = 900

# 代码切片行数（每次向模型输入的代码行数）
CODE_SLICE_LINES = 25

# -------------------------------------------------------------------------------------

# 屏蔽警告
warnings.filterwarnings("ignore")
logging.getLogger("langchain").setLevel(LANGCHAIN_LOG_LEVEL)
logging.getLogger("httpx").setLevel(HTTPX_LOG_LEVEL)
os.environ["OLLAMA_GPU_MEMORY"] = OLLAMA_GPU_MEMORY

from langchain_community.chat_models import ChatOllama
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.prompts import PromptTemplate

from AI.beautifyjs import format_code
from AI.split_api_code import extract_relevant_lines


# 自定义回调：捕获模型输出（同时打印到控制台）
class CaptureAndPrintCallback(BaseCallbackHandler):
    def __init__(self):
        self.buffer = StringIO()

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        self.buffer.write(token)  # 保存到缓冲区
        print(token, end="", flush=True)  # 同时打印到控制台（保持流式输出体验）

    def get_output(self) -> str:
        return self.buffer.getvalue().strip()


def load_ollama_llm():
    # 移除预先设置的callbacks，改为在调用时动态传入（避免回调复用导致数据混乱）
    return ChatOllama(
        model=MODEL_NAME,
        temperature=MODEL_TEMPERATURE,
        max_tokens=MODEL_MAX_TOKENS,
        streaming=True,
        keep_alive=-1
    )


def build_analysis_chain(llm):
    """提示词保持不变"""
    prompt_template = """
仅从以下JavaScript代码中提取并推测路径，不包含任何思考过程、解释、注释，你可以推理思考，要尽可能多的提取路径：

1. 提取对象：
   - API路径：所有作为接口访问的路径（不限请求方法，变量拼接需补全，例：/api/v1/user，含中文路径需标注但正常提取）
   - JavaScript路径：.js后缀的静态文件路径
   - 其他静态文件：保留除图片（.png/.jpg等）、视频（.mp4等）、音频（.mp3等）、CSS（.css）、字体（.ttf等）以外的静态文件路径（含中文名称路径）

2. 提取规则：
   - 路径需合法（符合URL Path规范，允许中文，特殊字符仅允许/._-）
   - 每条路径用[STR]开头、[END]结尾，单独成行。

3. 输出规则：
   - 无符合条件的内容时，则不输出
   输出示例：
    [STR]/api/v1/user/info[END]
    [STR]/api/v1/user/add[END]
代码片段：
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
    # 每次调用创建独立的回调实例（避免多轮调用数据污染）
    capture_callback = CaptureAndPrintCallback()
    # 调用链时通过config传入回调，确保输出被当前回调捕获
    chain.invoke(
        {"code": slice_code},
        config={"callbacks": [capture_callback]}
    )
    # 直接从当前回调获取输出
    return capture_callback.get_output()


def analyze_sliced_code(chain, code_str, lines_per_slice=15):
    slices = split_code_into_slices(code_str, lines_per_slice)
    all_output = []
    total_slices = len(slices)

    # 创建进度条：总进度为切片数量，描述为"分析代码"
    with tqdm(total=total_slices, desc="分析代码进度", unit="切片") as pbar:
        for slice_code in slices:
            slice_output = analyze_single_slice(chain, slice_code)
            if slice_output:
                all_output.append(slice_output)
            time.sleep(0.5)
            pbar.update(1)

    return "\n".join(all_output)


def run_analysis(js_code, lines_per_slice=CODE_SLICE_LINES):
    print("ollama analysis is start")
    llm = load_ollama_llm()
    analysis_chain = build_analysis_chain(llm)
    # 代码美化与提取
    result_js = format_code(js_code)
    result = extract_relevant_lines(result_js)
    model_full_output = analyze_sliced_code(analysis_chain, result, lines_per_slice=lines_per_slice)
    return model_full_output


def clean_output(output):
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


