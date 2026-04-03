# =====================================
# main.py
# =====================================
import re
from typing import Set


LOG_DIR = "logs"
LOG_FILENAME = "scanner.log"
LOG_ERROR_FILENAME = "scanner_error.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5
CONSOLE_LOG_LEVEL = "INFO"

# 触发告警的日志级别
FEISHU_ALERT_LEVELS = ["ERROR", "CRITICAL"]

# 告警频率限制（相同内容在多少秒内只发一次）
FEISHU_RATE_LIMIT_SECONDS = 60

# 飞书 Webhook 通知地址
FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/92159458-e118-4722-1121-35680bee5111"

# 网络代理
proxies = {
    "http": "",
    "https": "",
    "no_proxy": "*"
}

# static_extensions 后缀的使用httpx请求
static_extensions = [
    '.aac', '.apk', '.css', '.csv', '.eot', '.exe', '.gif', '.ico',
    '.jpg', '.jpeg', '.js', '.json', '.m4v', '.map', '.mp3', '.mp4',
    '.otf', '.png', '.svg', '.swf', '.ttf', '.txt', '.wav', '.webp',
    '.woff', '.woff2', '.xls', '.xlsx', '.xml'
]
# html_extensions 后缀的使用playwright请求
html_extensions = ['.html', '.htm', '.xhtml']

# 使用fastscan时，配置需要在response中排除的keywords，response中包括以下内容时，会被默认排除
unauth_keywords = [
    '未登录', '请先登录', '登录过期', '会话过期', '未授权', '身份验证失败',
    '请登录', '重新登录', '登录失效', '会话已过期', '认证失败',
    'unauthorized', 'unauth', 'not logged in', 'login required',
    'authentication required', 'session expired', 'access denied',
    'please login', 'sign in required', 'token expired', 'invalid token',
    '401', 'login', 'signin', 'jwt expired'
]

OVERFLOW_DIR = "Overflow_Queue"  # 溢出队列目录
# 配置请求范围
WHITE_SCOPE_PATH = "config/whiteList.txt"

# 配置内存占用率阈值
MEMORY_LIMIT = 80

# 配置输出结果的路径
db_filename = "Result/JScanner_Result.db"


# =================================
# AISecurityAuditor.py
# =================================
# 配置代码输入AI最大长度
CODE_MAX_LENGTH = 12000

# =================================
# secret_scanner.py
# =================================
NLTK_DIR = "config/nltk_data"

# =================================
# secret_scanner.py
# =================================
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
EXCLUDE_VALUES = {
    'false', 'undefined', 'delete', 'green', 'white', 'black',
    'gray', 'grey', 'color', 'home', 'index', 'login', 'logout',
    'register', 'signup', 'signin', 'user', 'admin', 'dashboard',
    'header', 'footer', 'sidebar', 'submit', 'reset', 'button',
    'input', 'form', 'https', 'localhost', 'base64', 'unicode',
}
SENSITIVE_KEYWORDS = {
    'key', 'secret', 'token', 'auth', 'password', 'pass', 'pwd',
    'credential', 'cert', 'api', 'access', 'private', 'private_key',
    'jwt', 'bearer', 'session', 'cookie', 'csrf', 'xsrf',
    'config', 'setting', 'env', 'environment',
}
IGNORE_PREFIX_PATTERN = re.compile(
    r'^[\W_]*(chunk-|app-|vendors-|manifest-|data-v-|vue-|bg-|text-|border-|font-|col-|row-|flex-|grid-|btn-|icon-|fa-|el-|mat-)',
    re.IGNORECASE
)
QUOTE_PATTERN = re.compile(r'(["\'])(.*?)\1')
UNICODE_PATTERN = re.compile(r'(\\)+u[0-9a-fA-F]{4}')

# ===========================
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

# ===========================
# js_line_extractor
# ===========================
# HTML 标签匹配
HTML_TAG_PATTERN = re.compile(r'<\s*/?\s*[a-zA-Z][^>]*>')

# 正则元字符
REGEX_METACHARS = re.compile(r'[*+?^${}()|[\]\\]')

# 分割行内注释（排除 http:// https:// 等协议头中的双斜杠）
SPLIT_COMMENT_PATTERN = re.compile(r'(?<!:)//')

# 提取单引号或双引号内容
QUOTED_CONTENT_PATTERN = re.compile(r'["\'](.*?)["\']')

# 有效斜杠检测：[a-zA-Z0-9]/ 或 /[a-zA-Z0-9]
VALID_SLASH_PATTERN = re.compile(r'[a-zA-Z0-9]/|/[a-zA-Z0-9]')

# 静态资源黑名单
BLACK_LIST: Set[str] = {
    '.aac', '.apk', '.css', '.eot', '.exe', '.gif', '.ico',
    '.jpg', '.jpeg', '.m4v', '.mp3', '.mp4', '.otf', '.png',
    '.svg', '.swf', '.ttf', '.webp', '.woff', '.woff2'
}

# =========================
# db_manager.py
# =========================
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

# ===========================
# 大模型默认预选
# ===========================
CONFIG_TEMPLATE = """{
  "models": [
    "MiniMax-M2.5",
    "hunyuan-2.0-instruct-20251111",
    "z-ai/glm4.7"
  ],
  "enabled": true
}"""

DEFAULT_CONFIG_PATH = "config/models_config.json"

API_KEY = "sk-ERsIPn2b4NxXRii100dwPIAFKmWBAM6MAHEccpeUwfCzbMAV"
BASE_URL = "http://127.0.0.1:3000/v1/"

# ===============================
# playwright 请求
# ===============================

# 不需要加载的资源类型，节省带宽和内存
BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

# 全局超时设置 (秒)
GLOBAL_TIMEOUT = 30

# 最大允许跳转次数 (0=不允许跳转，1=允许 1 次，2=允许 2 次...)
MAX_REDIRECT_COUNT = 1

