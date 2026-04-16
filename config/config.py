# 本地/私有化大模型服务地址
BASE_URL = "http://127.0.0.1:3000/v1/"

# API Key（请替换为您自己的密钥）
API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 启用 batch 调用
BATCH_REQ = True

# batch 调用大模型
BATCH_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

# batch 大模型Key
API_KEY_BATCH = "sk-cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx01"

# batch 启用阈值（任务数 >= 此值才使用 Batch API）
MIN_BATCH_THRESHOLD = 5

# batch 单次推荐批量数（平衡效率与稳定性）
RECOMMENDED_BATCH_SIZE = 100

# batch 单次最大批量数（保守设置，远低于阿里云 50,000 限制）
MAX_BATCH_SIZE = 1000

# batch 单文件最大大小限制（阿里云限制 500 MB，我们设置为 80% 即 400 MB）
MAX_BATCH_FILE_SIZE_MB = 400

# batch 单个 JSON 对象最大大小（阿里云限制 6 MB，我们设置为 5 MB）
MAX_SINGLE_REQUEST_SIZE_MB = 5

# batch 文件大小估算安全系数（预留 20-30% 余量）
BATCH_SIZE_SAFETY_FACTOR = 0.75

# 轮询间隔（秒）
POLL_INTERVAL = 40

# 最大等待时间（秒）
MAX_WAIT_TIME = 18000

DEFAULT_CONFIG_PATH = "config/models_config.json"  # 模型配置文件路径

WHITE_SCOPE_PATH = "config/whiteList.txt"   # 白名单路径（仅扫描指定路径）
MEMORY_LIMIT = 80                            # 内存占用阈值（%），超限时会进行内存释放

proxies = {
    "http": "",           # 示例: "http://127.0.0.1:7890"
    "https": "",          # 示例: "http://127.0.0.1:7890"
    "no_proxy": "*"       # 不走代理的域名，* 表示全部走代理
}

# ------------------------------
# 🔔 飞书告警通知
# ------------------------------
FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/1412ed79xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
FEISHU_ALERT_LEVELS = ["ERROR", "CRITICAL"]       # 触发告警的日志级别
FEISHU_RATE_LIMIT_SECONDS = 60                    # 相同告警内容60秒内只发一次

# ------------------------------
# 📁 输出路径配置
# ------------------------------
db_filename = "Result/JScanner_Result.db"         # 扫描结果数据库路径
OVERFLOW_DIR = "Overflow_Queue"                   # 溢出队列暂存目录
LOG_DIR = "logs"                                  # 日志输出目录

# ------------------------------
# 🎯 扫描范围与性能控制
# ------------------------------
GLOBAL_TIMEOUT = 30                          # 单页面最大等待时间（秒）
MAX_REDIRECT_COUNT = 1                       # 最大允许跳转次数

CODE_MAX_LENGTH = 12000  # 单次送入大模型的代码最大长度（避免 token 超限）

# ------------------------------
# 📋 日志系统配置
# ------------------------------
LOG_FILENAME = "scanner.log"
LOG_ERROR_FILENAME = "scanner_error.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 单文件最大10MB
LOG_BACKUP_COUNT = 5              # 保留5个历史日志
CONSOLE_LOG_LEVEL = "INFO"        # 控制台输出级别

# ------------------------------
# 📦 NLTK 数据路径
# ------------------------------
NLTK_DIR = "config/nltk_data"