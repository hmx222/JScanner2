import logging

# ==============================================================================
# 1. 全局基础设置
# ==============================================================================
# 日志级别 (ERROR, INFO, DEBUG)
LANGCHAIN_LOG_LEVEL = logging.ERROR
HTTPX_LOG_LEVEL = logging.ERROR

# 飞书 Webhook 通知地址
FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/92159458-e2b8-4722-bb21-35680bee53d8"

# ==============================================================================
# 2. 扫描任务相关限制
# ==============================================================================
MAX_CANDIDATE_ALL_SIZE = 2000  # 最大候选集大小
MAX_ORIGINAL_ALL_SIZE = 1000   # 最大原始集大小
CODE_SLICE_LINES = 30          # 代码切片行数（每次喂给AI的行数）

# ==============================================================================
# 3. LLM 生成参数 (默认值)
#    注意：具体模型的参数(Temperature/Tokens等)优先读取 AIConfig.py 中的配置，
#    这里的参数仅作为代码中未指定时的最后兜底参考。
# ==============================================================================
MODEL_TEMPERATURE = 0.8
MODEL_MAX_TOKENS = 8192
MODEL_TOP_K = 50
MODEL_TOP_P = 0.9
MODEL_REPEAT_PENALTY = 1.2
MODEL_REPEAT_LAST_N = 40

# 本地 Ollama 显存限制
OLLAMA_MAX_GPU_MEMORY = "4GB"

# AI 生成时的停止词列表
STOP_WORDS_FOR_MODEL = ["*", "`", "，", "。", " ", "你提", "这段", "片段"]

# ==============================================================================
# 4. 循环生成保护机制 (Loop Protection)
#    防止 LLM 进入复读机模式
# ==============================================================================

# L1: 词级检测参数
LOOP_PROTECTION_TOKEN_WINDOW = 30       # 检测重复token的窗口大小
LOOP_PROTECTION_MAX_TOKEN_REPEAT = 4    # 允许相同token序列重复的最大次数

# L2: 句级检测参数
LOOP_PROTECTION_SENTENCE_WINDOW = 5     # 保存的历史句子数量
LOOP_PROTECTION_SIMILARITY_THRESHOLD = 0.70 # 语义相似度阈值
LOOP_PROTECTION_CHECK_INTERVAL = 50     # 每生成N个token检查一次

# L3: 上下文分析参数
LOOP_PROTECTION_TOPIC_STABILITY = 4     # 相同主题持续超过此数量触发保护

# 恢复策略权重 (当检测到循环时，如何调整参数以恢复)
LOOP_PROTECTION_RECOVERY_STRATEGY = {
    "increase_temperature": 0.4,  # 增加温度 (使其更发散)
    "inject_diversity": 0.3,      # 注入多样性提示
    "hard_terminate": 0.1         # 强制停止
}
