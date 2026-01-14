import logging

# OLLAMA GPU内存限制，根据本地显卡内存调整
OLLAMA_MAX_GPU_MEMORY = "4GB"

# 日志级别设置，ERROR表示只显示错误信息，可改为INFO、DEBUG等
LANGCHAIN_LOG_LEVEL = logging.ERROR
HTTPX_LOG_LEVEL = logging.ERROR

DASHSCOPE_API_KEY = "sk-0b4caaf9257d41e89a6884d4793a3050"  # 你的阿里云密钥 sk-xxx

DASHSCOPE_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

BAILIAN_MODEL_NAME = "qwen2.5-coder-14b-instruct"  # 阿里代码模型最优选择

MAX_CANDIDATE_ALL_SIZE = 2000

MAX_ORIGINAL_ALL_SIZE = 1000
# 调用的OLLAMA模型名称，需确保本地已下载该模型
MODEL_NAME = "qwen2.5-coder:14b"
# 模型生成参数：温度值（0-1，越低输出越稳定）
MODEL_TEMPERATURE = 0.8  # 保持不变，确保稳定性
# top_k
MODEL_TOP_K = 50
# top_p
MODEL_TOP_P = 0.9
# repeat_penalty
MODEL_REPEAT_PENALTY = 1.2
# repeat_last_n
MODEL_REPEAT_LAST_N = 40

# 模型生成参数：最大令牌数（控制输出长度）
MODEL_MAX_TOKENS = 900

# 代码切片行数（每次向模型输入的代码行数）
CODE_SLICE_LINES = 30

# L1: 词级检测参数
LOOP_PROTECTION_TOKEN_WINDOW = 30  # 检测重复的token窗口大小
LOOP_PROTECTION_MAX_TOKEN_REPEAT = 4  # 允许相同token序列重复的最大次数

# L2: 句级检测参数
LOOP_PROTECTION_SENTENCE_WINDOW = 5  # 保存的历史句子数量
LOOP_PROTECTION_SIMILARITY_THRESHOLD = 0.70  # 语义相似度阈值
LOOP_PROTECTION_CHECK_INTERVAL = 50  # 每生成N个token检查一次

# L3: 上下文分析参数
LOOP_PROTECTION_TOPIC_STABILITY = 4  # 相同主题持续超过此数量触发

# 恢复策略权重
LOOP_PROTECTION_RECOVERY_STRATEGY = {
    "increase_temperature": 0.4,  # 增加温度策略权重
    "inject_diversity": 0.3,  # 注入多样性提示权重
    "hard_terminate": 0.1  # 硬终止权重
}
STOP_WORDS_FOR_MODEL = ["*","`","，","。"," ","你提","这段","片段"]
