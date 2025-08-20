import os
import time
import requests
import warnings
import logging
import re
from io import StringIO

# 屏蔽警告
warnings.filterwarnings("ignore")
logging.getLogger("langchain").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)
os.environ["OLLAMA_GPU_MEMORY"] = "4GB"

# 优先使用新版langchain-ollama
try:
    from langchain_ollama import ChatOllama
except ImportError:
    from langchain_community.chat_models import ChatOllama

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.prompts import PromptTemplate

# 已有工具函数
from AI.beautifyjs import format_code
from AI.split_code import extract_relevant_lines


# 自定义回调：捕获并打印输出
class CaptureAndPrintCallback(BaseCallbackHandler):
    def __init__(self):
        self.buffer = StringIO()

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        self.buffer.write(token)
        print(token, end="", flush=True)

    def get_output(self) -> str:
        return self.buffer.getvalue().strip()


def load_ollama_llm(model_name):
    return ChatOllama(
        model=model_name,
        temperature=0.0,  # 强制零随机，确保严格遵循规则
        max_tokens=1500,
        streaming=True,
        keep_alive=-1
    )


def build_analysis_chain(llm):
    # 核心优化：用最严苛的规则禁止所有错误类型
    prompt_template = """
你是前端JavaScript敏感信息检测工具，** 输出必须100%符合以下规则，任何违规内容都视为无效 **：

### 一、唯一允许的类型标签（共7种，其他标签绝对禁止）
Token、密钥、加密盐值、手机号、身份证号、邮箱、未知  
→ 禁止使用："类型标签"、"类型"等任何非上述标签。

### 二、绝对排除的内容（出现即不输出）
1. 图片路径：含.png、.jpg、.jpeg、.gif的任何路径（如./level_feed_0.png）；
2. 短内容：长度≤3的字符（如"a"、"i"）；
3. 解释文字："完全静默"、"无信息"等任何说明性文字；
4. 格式错误：孤立的[END]、缺少[STR]或[END]的内容。

### 三、输出格式（必须严格匹配）
每条单独成行，格式为：[STR]允许的标签：内容[END]  
示例：
[STR]未知：x87z2$%kL90pQwer1234[END]
[STR]手机号：13812345678[END]

### 四、错误案例（绝对禁止，出现即零容忍）
- [STR]类型标签：a[END]（使用非法标签+短内容）
- [STR]密钥：./level_feed_0.png[END]（图片路径，即使标签正确）
- 完全静默。（解释文字）
- [END]（孤立的结束标签）

请基于以下代码批次提取，无符合条件的信息时**输出空字符串**（不写任何内容）：
{code_batch}
        """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["code_batch"]
    )
    return prompt | llm


def split_code_into_slices(code_str, lines_per_slice=20):
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
    capture_callback = CaptureAndPrintCallback()
    chain.invoke(
        {"code_batch": slice_code},
        config={"callbacks": [capture_callback]}
    )
    return capture_callback.get_output()


def analyze_sliced_code(chain, code_str, lines_per_slice=15):
    slices = split_code_into_slices(code_str, lines_per_slice)
    all_output = []
    for slice_code in slices:
        slice_output = analyze_single_slice(chain, slice_code)
        if slice_output:
            all_output.append(slice_output)
        time.sleep(0.5)
    return "\n".join(all_output)


def clean_model_output(raw_output):
    """终极过滤：清除所有违规内容"""
    if not raw_output:
        return ""

    # 1. 移除解释文字（如"完全静默"）
    raw_output = re.sub(r"完全静默|无信息|无敏感信息", "", raw_output, flags=re.DOTALL)

    # 2. 移除孤立的[END]
    raw_output = re.sub(r"(?<!\[STR\].*?)\[END\]", "", raw_output)

    # 3. 过滤所有行，仅保留合法内容
    lines = raw_output.splitlines()
    valid_lines = []
    allowed_tags = {"Token", "密钥", "加密盐值", "手机号", "身份证号", "邮箱", "未知"}

    for line in lines:
        line = line.strip()
        if not line:
            continue
        # 检查格式完整性
        if not re.fullmatch(r"\[STR\].*?：.*?\[END\]", line):
            continue
        # 提取标签和内容
        match = re.match(r"\[STR\](.*?)：(.*?)\[END\]", line)
        if not match:
            continue
        tag, content = match.groups()
        # 检查标签合法性
        if tag not in allowed_tags:
            continue
        # 过滤图片路径
        if re.search(r"\.(png|jpg|jpeg|gif)$", content, re.IGNORECASE):
            continue
        # 过滤短内容（长度≤3）
        if len(content) <= 3:
            continue
        valid_lines.append(line)

    return "\n".join(valid_lines)


def run_analysis(js_code, lines_per_slice):
    llm = load_ollama_llm(model_name="hf-mirror.com/wqerrewetw/DistilQwen2.5-7B-Instruct-GGUF:Q4_K_M")
    analysis_chain = build_analysis_chain(llm)
    result_js = format_code(js_code)
    raw_output = analyze_sliced_code(analysis_chain, result_js, lines_per_slice=lines_per_slice)
    return clean_model_output(raw_output)


if __name__ == "__main__":
    urlgettime = time.time()
    response = requests.get(
        url="https://static.nowcoder.com/fe/file/site/www-web/prod/1.0.452/page/terminal/main.entry.js",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"}
    )
    print("请求时间：", time.time() - urlgettime)

    model_full_output = run_analysis(response.text, lines_per_slice=15)
    if model_full_output:
        print("\n最终敏感信息：\n", model_full_output)