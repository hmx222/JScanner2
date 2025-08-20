import os
import time
import requests
import warnings
import logging
import re
from io import StringIO

from tqdm import tqdm

# -------------------------- 全局配置变量（用户可根据需求修改） --------------------------
# OLLAMA GPU内存限制，根据本地显卡内存调整
OLLAMA_GPU_MEMORY = "4GB"

# 日志级别设置，ERROR表示只显示错误信息，可改为INFO、DEBUG等
LANGCHAIN_LOG_LEVEL = logging.ERROR
HTTPX_LOG_LEVEL = logging.ERROR

# 调用的OLLAMA模型名称，需确保本地已下载该模型
MODEL_NAME = "hf-mirror.com/wqerrewetw/DistilQwen2.5-7B-Instruct-GGUF:Q4_K_M"

# 模型生成参数：温度值（0-1，越低输出越稳定）
MODEL_TEMPERATURE = 0.1

# 模型生成参数：最大令牌数（控制输出长度）
MODEL_MAX_TOKENS = 1500

# 代码切片行数（每次向模型输入的代码行数）
CODE_SLICE_LINES = 15

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
from AI.split_code import extract_relevant_lines


# 自定义回调：捕获模型输出（同时打印到控制台）
class CaptureAndPrintCallback(BaseCallbackHandler):
    def __init__(self):
        self.buffer = StringIO()

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        self.buffer.write(token)  # 保存到缓冲区
        # print(token, end="", flush=True)  # 同时打印到控制台（保持流式输出体验）

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
你现在是一个辅助WEB安全渗透测试的路径分析工具，任务是从前端代码中提取并推测对渗透测试有实际价值的API接口路径与静态资源路径

1. 基础规则：
   - 绝对无单引号、双引号、反引号，汉字；
   - 只输出路径内容，无标题、分隔符、解释；
   - 每行仅1条路径，且每条路径必须以[STR]开头、以[END]结尾；
   - 无内容则不输出任何行；
   - 你要保证你输出的路径（非拼接变量）直接拼接在域名后放入浏览器直接可以进行访问；
   - 你要保证你提取的url直接可以在浏览器中进行访问。
   - 静态资源不可包括视频、音频、图片，字体，CSS，应用程序，安装包。

2. 提取路径拆分规则（核心解决合并问题）：
   - 路径以“/”开头，当出现“连续两个及以上独立路径连写”时，必须按功能拆分：
     例1：错误连写 → /api/a/api/b（两个独立路径）
     正确拆分 → 
     [STR]/api/a[END]
     [STR]/api/b[END]
     例2：错误连写 → /api/sparta/message/detail/api/sparta/message/clear（共享前缀但功能不同）
     正确拆分 → 
     [STR]/api/sparta/message/detail[END]
     [STR]/api/sparta/message/clear[END]
   - 含“//”时，从“//”处拆分（如/api/x//api/y → [STR]/api/x[END] 和 [STR]/api/y[END]）。

3. 推测路径规则（必须保留）：
   - 基于提取的路径推测同类路径（同前缀、功能相关），每行1条；
   - 推测需标注“（Speculation from：提取的路径）”，且整体必须以[STR]开头、以[END]结尾，例：
     提取路径 → [STR]/api/user/login[END]
     推测路径 → [STR]/api/user/logout[END]（Speculation from：/api/user/login）
   - 静态资源（例如JavaScript）不可参与推断
4. 输出顺序：
   先输出提取的路径（按拆分后顺序），再输出推测的路径（单独成行）。

5. 完整示例：
   代码中提取到连写路径 → /api/order/list/api/order/detail
   输出结果：
   [STR]/api/order/list[END]
   [STR]/api/order/detail[END]

6. 最后输出结果展示举例（以下举例部分仅为参考，输出不可包含）：
   [STR]/api/order/list[END]
   [STR]/api/order/detail[END]
   [STR]/api/order/add[END]（Speculation from：/api/order/list）
   [STR]/obj/web/static/rc/1.0.0.19/sdk-glue.js[END]
   [STR]/v1/all/sourceMap.js.map[END]
   [STR]/v1/js/user.config[END]

7. 请你严格按照任务要求输出，不允许你输出任何其他的非路径中的汉字，也不允许输出任何解释、标题、注释。
8. 严禁输出汉字，不允许输出任何代码片段，不允许输出Markdown格式的内容，不允许输出任何其他的非路径中的内容。
代码片段（行号已标注）：
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
    # 3. 过滤含汉字或中文标点的行
    chinese_pattern = re.compile(
        r'[\u4e00-\u9fa5\uff0c\uff0e\uff1f\uff01\uff1c\uff1e\u3001\u3002\u201c\u201d\u2018\u2019\uff08\uff09\uff1b\uff1a\u3010\u3011]')
    filtered_paths = [path for path in paths if not chinese_pattern.search(path)]

    # 4. 处理含http/https且以/开头的行：移除http/https前面的所有/
    processed_paths = []
    http_pattern = re.compile(r'https?://')  # 匹配http://或https://
    example_path_from_prompt = ["/api/order/list",
                                "/api/order/detail","/api/order/add",
                                "/obj/web/static/rc/1.0.0.19/sdk-glue.js",
                                "/v1/all/sourceMap.js.map",
                                "/v1/js/user.config",
                                "/api/a",
                                "/api/b",
                                "/api/sparta/message/detail",
                                "/api/sparta/message/clear",
                                "/api/user/login",
                                "/api/user/logout"]

    for path in filtered_paths:
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


