import re
from typing import Set

# 本地/私有化大模型服务地址（默认本地3000端口）
BASE_URL = "http://127.0.0.1:3000/v1/"

# API Key（请替换为您自己的密钥）
API_KEY = "sk-ERsIPn2b4NxXRiixxxxxxKmWBAM6MAHEccpeUwfCzbMAV"

# 推荐模型列表（按优先级排序，支持自动故障转移）
CONFIG_TEMPLATE = """{
  "models": [
    "MiniMax-M2.5",
    "hunyuan-2.0-instruct-20251111",
    "z-ai/glm4.7"
  ],
  "enabled": true
}"""
DEFAULT_CONFIG_PATH = "config/models_config.json"  # 模型配置文件路径

WHITE_SCOPE_PATH = "config/whiteList.txt"   # 白名单路径（仅扫描指定路径）
MEMORY_LIMIT = 80                            # 内存占用阈值（%），超限时会进行内存释放

proxies = {
    "http": "",           # 示例: "http://127.0.0.1:7890"
    "https": "",          # 示例: "http://127.0.0.1:7890"
    "no_proxy": "*"       # 不走代理的域名，* 表示全部走代理
}

# ------------------------------
# 🔔 飞书告警通知（可选）
# ------------------------------
FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/1412ed79-59f8-4e29-xxxxx-01xxxxx0490"
FEISHU_ALERT_LEVELS = ["ERROR", "CRITICAL"]       # 触发告警的日志级别
FEISHU_RATE_LIMIT_SECONDS = 60                    # 相同告警内容60秒内只发一次

# ------------------------------
# 📁 输出路径配置
# ------------------------------
db_filename = "Result/JScanner_Result.db"         # 扫描结果数据库路径
OVERFLOW_DIR = "Overflow_Queue"                   # 溢出队列暂存目录
LOG_DIR = "logs"                                  # 日志输出目录



# 使用 httpx 直接请求的静态资源后缀（不渲染JS，节省资源）
static_extensions = [
    '.aac', '.apk', '.css', '.csv', '.eot', '.exe', '.gif', '.ico',
    '.jpg', '.jpeg', '.js', '.json', '.m4v', '.map', '.mp3', '.mp4',
    '.otf', '.png', '.svg', '.swf', '.ttf', '.txt', '.wav', '.webp',
    '.woff', '.woff2', '.xls', '.xlsx', '.xml'
]

# 使用 Playwright 渲染的页面后缀（需要执行JS）
html_extensions = ['.html', '.htm', '.xhtml']

# ------------------------------
# 🚫 FastScan 模式过滤规则
# ------------------------------
# response 中包含以下关键词时，自动排除（避免未授权页面污染结果）
unauth_keywords = [
    '未登录', '请先登录', '登录过期', '会话过期', '未授权', '身份验证失败',
    '请登录', '重新登录', '登录失效', '会话已过期', '认证失败',
    'unauthorized', 'unauth', 'not logged in', 'login required',
    'authentication required', 'session expired', 'access denied',
    'please login', 'sign in required', 'token expired', 'invalid token',
    '401', 'login', 'signin', 'jwt expired'
]

# ------------------------------
# 🎯 扫描范围与性能控制
# ------------------------------
GLOBAL_TIMEOUT = 30                          # 单页面最大等待时间（秒）
MAX_REDIRECT_COUNT = 1                       # 最大允许跳转次数

# Playwright 资源拦截（屏蔽非必要资源，提升速度）
BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}


# =============================================================================
# 🤖 第三部分：AI/模型配置
# =============================================================================

# ------------------------------
# 🧠 AI 分析参数
# ------------------------------
CODE_MAX_LENGTH = 12000  # 单次送入大模型的代码最大长度（避免 token 超限）

# ------------------------------
# 🎯 敏感信息分析 Prompt（核心指令）
# ------------------------------
SECRET_PROMPT = """
角色：资深安全研究员 & 渗透测试专家
目标：分析 JavaScript 代码中的硬编码敏感字符串，并提供可执行的测试指导

输入格式：
- value: 硬编码的字符串值
- context: 显示该值如何定义/使用的代码片段
- callers: 调用该值的代码位置列表

分析标准：
1. 这是否是真正的秘密？(许可证密钥、API Token、密码等)
2. 它是什么类型的秘密？
3. 风险等级是什么？(High/Med/Low)
4. 渗透测试人员如何利用它？

输出格式：
为每个候选 ID 返回一个 JSON 对象，结构如下：
{
  "id": {
    "is_secret": 1 或 0,
    "secret_type": "license_key|api_key|token|password|endpoint|other",
    "risk_level": "High|Med|Low",
    "confidence": 0.0-1.0,
    "test_suggestion": "具体的、可执行的渗透测试步骤（中文）"
  }
}

风险等级指南：
- High: 可直接用于未授权访问、认证绕过或数据泄露
- Med: 可能导致信息泄露，或需要额外条件才能利用
- Low: 可能是误报、构建产物或低影响配置

策略：如果不确定，标记为 is_secret=1 (召回率 > 精确率)，但降低 confidence 分数。
"""


# =============================================================================
# 🔍 第四部分：规则引擎配置（敏感信息识别）
# =============================================================================

# ------------------------------
# 🚫 误报排除规则（上下文过滤）
# ------------------------------
EXCLUDE_CONTEXTS = {
    'console.log', 'console.warn', 'console.error', 'console.info', 'console.debug',
    'alert(', 'confirm(', 'prompt(',
    'logger.log', 'logger.debug', 'logger.info', 'logger.warn', 'logger.error',
    'import ', 'require(', 'export ',
    'getElementById', 'querySelector', 'querySelectorAll',
    'getElementsByTagName', 'getElementsByClassName',
    'createElement', 'appendChild', 'innerHTML', 'textContent',
    '.css(', '.html(', '.text(', '.val(', '.attr(',
    '<div', '<span', '<a ', '<img', '<link', '<script', '<style',
    'window.location', 'document.cookie', '_sentryDebugIds'
}

# ------------------------------
# 🚫 误报排除规则（值过滤）
# ------------------------------
EXCLUDE_VALUES = {
    'false', 'undefined', 'delete', 'green', 'white', 'black',
    'gray', 'grey', 'color', 'home', 'index', 'login', 'logout',
    'register', 'signup', 'signin', 'user', 'admin', 'dashboard',
    'header', 'footer', 'sidebar', 'submit', 'reset', 'button',
    'input', 'form', 'https', 'localhost', 'base64', 'unicode',
}

# ------------------------------
# 🔑 敏感关键词字典（命中即候选）
# ------------------------------
SENSITIVE_KEYWORDS = {
    'key', 'secret', 'token', 'auth', 'password', 'pass', 'pwd',
    'credential', 'cert', 'api', 'access', 'private', 'private_key',
    'jwt', 'bearer', 'session', 'cookie', 'csrf', 'xsrf',
    'config', 'setting', 'env', 'environment',
}

# ------------------------------
# 📊 API 风险分级关键词
# ------------------------------
HIGH_RISK_KEYWORDS = [
    "admin", "user", "update", "delete", "remove", "create",
    "password", "email", "role", "permission", "auth", "token",
    "upload", "import", "export", "backup", "restore",
    "payment", "order", "refund", "transfer", "withdraw"
]
MED_RISK_KEYWORDS = [
    "search", "query", "list", "get", "info", "detail",
    "config", "setting", "profile", "account"
]
VALID_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# ------------------------------
# 🧹 代码预处理规则
# ------------------------------
# 忽略前端框架生成的自动前缀（减少误报）
IGNORE_PREFIX_PATTERN = re.compile(
    r'^[\W_]*(chunk-|app-|vendors-|manifest-|data-v-|vue-|bg-|text-|border-|font-|col-|row-|flex-|grid-|btn-|icon-|fa-|el-|mat-)',
    re.IGNORECASE
)
QUOTE_PATTERN = re.compile(r'(["\'])(.*?)\1')              # 提取引号内容
UNICODE_PATTERN = re.compile(r'(\\)+u[0-9a-fA-F]{4}')      # 匹配Unicode转义

# JS 行提取辅助正则
HTML_TAG_PATTERN = re.compile(r'<\s*/?\s*[a-zA-Z][^>]*>')
REGEX_METACHARS = re.compile(r'[*+?^${}()|[\]\\]')
SPLIT_COMMENT_PATTERN = re.compile(r'(?<!:)//')            # 分割行内注释（排除协议头）
QUOTED_CONTENT_PATTERN = re.compile(r'["\'](.*?)["\']')
VALID_SLASH_PATTERN = re.compile(r'[a-zA-Z0-9]/|/[a-zA-Z0-9]')

# 静态资源黑名单（提取JS时跳过）
BLACK_LIST: Set[str] = {
    '.aac', '.apk', '.css', '.eot', '.exe', '.gif', '.ico',
    '.jpg', '.jpeg', '.m4v', '.mp3', '.mp4', '.otf', '.png',
    '.svg', '.swf', '.ttf', '.webp', '.woff', '.woff2'
}


# =============================================================================
# 🗄️ 第五部分：系统底层配置（一般无需修改）
# =============================================================================

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