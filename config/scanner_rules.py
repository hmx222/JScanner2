"""
敏感信息检测配置模块

本模块包含敏感信息扫描器所需的各种过滤规则、关键词字典和黑名单配置。
主要用于减少误报、提高检测准确率。
"""

from typing import Set, List

# =============================================================================
# 1. 上下文过滤规则（基于代码上下文排除误报）
# =============================================================================

# 需要排除的代码上下文字段集合
# 当字符串出现在这些上下文中时，通常不是敏感信息（如 DOM 操作、日志输出等）
EXCLUDED_CONTEXT_PATTERNS: Set[str] = {
    # 控制台输出
    'console.log', 'console.warn', 'console.error', 'console.info', 'console.debug',

    # 浏览器弹窗
    'alert(', 'confirm(', 'prompt(',

    # 日志框架
    'logger.log', 'logger.debug', 'logger.info', 'logger.warn', 'logger.error',

    # 模块导入/导出
    'import ', 'require(', 'export ',

    # DOM 查询方法
    'getElementById', 'querySelector', 'querySelectorAll',
    'getElementsByTagName', 'getElementsByClassName',

    # DOM 操作方法
    'createElement', 'appendChild', 'innerHTML', 'textContent',

    # jQuery/前端框架方法
    '.css(', '.html(', '.text(', '.val(', '.attr(',

    # HTML 标签
    '<div', '<span', '<a ', '<img', '<link', '<script', '<style',

    # 浏览器对象属性
    'window.location', 'document.cookie', '_sentryDebugIds'
}

# =============================================================================
# 2. 值过滤规则（基于字符串值本身排除误报）
# =============================================================================

# 需要排除的常见字符串值集合
# 这些值虽然可能出现在代码中，但通常不是敏感信息
EXCLUDED_LITERAL_VALUES: Set[str] = {
    # 布尔值和关键字
    'false', 'undefined', 'delete',

    # 颜色值
    'green', 'white', 'black', 'gray', 'grey', 'color',

    # 路由/页面名称
    'home', 'index', 'login', 'logout',
    'register', 'signup', 'signin',
    'user', 'admin', 'dashboard',

    # UI 组件名称
    'header', 'footer', 'sidebar',
    'submit', 'reset', 'button',
    'input', 'form',

    # 技术术语
    'https', 'localhost', 'base64', 'unicode',
}

# =============================================================================
# 3. 敏感关键词字典（命中则标记为候选）
# =============================================================================

# 敏感信息相关关键词集合
# 如果字符串或所在行包含这些关键词，则提高其作为敏感信息的优先级
SENSITIVE_KEYWORD_SET: Set[str] = {
    # 认证相关
    'key', 'secret', 'token', 'auth', 'password', 'pass', 'pwd',
    'credential', 'cert', 'jwt', 'bearer',

    # 访问控制
    'api', 'access', 'private', 'private_key',

    # 会话管理
    'session', 'cookie', 'csrf', 'xsrf',

    # 配置相关
    'config', 'setting', 'env', 'environment',
}

# =============================================================================
# 4. API 风险分级关键词
# =============================================================================

# 高风险 API 路径关键词
# 包含这些关键词的 API 通常涉及敏感操作（增删改、权限管理等）
HIGH_RISK_API_KEYWORDS: List[str] = [
    # 用户管理
    "admin", "user", "role", "permission",

    # 数据修改操作
    "update", "delete", "remove", "create",

    # 敏感信息
    "password", "email", "auth", "token",

    # 文件操作
    "upload", "import", "export", "backup", "restore",

    # 金融相关
    "payment", "order", "refund", "transfer", "withdraw"
]

# 中风险 API 路径关键词
# 包含这些关键词的 API 通常涉及查询操作，风险相对较低
MEDIUM_RISK_API_KEYWORDS: List[str] = [
    # 查询操作
    "search", "query", "list", "get",

    # 信息展示
    "info", "detail", "profile", "account",

    # 配置读取
    "config", "setting",
]

# 有效的 HTTP 请求方法列表
VALID_HTTP_METHODS: List[str] = [
    "GET", "POST", "PUT", "DELETE",
    "PATCH", "HEAD", "OPTIONS"
]

# =============================================================================
# 5. 静态资源与爬虫配置
# =============================================================================

# 静态资源文件扩展名黑名单
# 扫描 JS 文件时，遇到这些扩展名的引用应跳过
STATIC_RESOURCE_EXTENSIONS: Set[str] = {
    '.aac', '.apk', '.css', '.eot', '.exe', '.gif', '.ico',
    '.jpg', '.jpeg', '.m4v', '.mp3', '.mp4', '.otf', '.png',
    '.svg', '.swf', '.ttf', '.webp', '.woff', '.woff2'
}

# Playwright 浏览器自动化时需要拦截的资源类型
# 拦截这些资源可以显著提升爬取速度
PLAYWRIGHT_BLOCKED_RESOURCES: Set[str] = {
    "image",  # 图片
    "media",  # 媒体文件
    "font",  # 字体文件
    "stylesheet"  # CSS 样式表
}

# 使用 httpx 直接请求的静态资源后缀列表
# 这些资源不需要 JavaScript 渲染，可以直接通过 HTTP 请求获取
HTTPX_STATIC_EXTENSIONS: List[str] = [
    '.aac', '.apk', '.css', '.csv', '.eot', '.exe', '.gif', '.ico',
    '.jpg', '.jpeg', '.js', '.json', '.m4v', '.map', '.mp3', '.mp4',
    '.otf', '.png', '.svg', '.swf', '.ttf', '.txt', '.wav', '.webp',
    '.woff', '.woff2', '.xls', '.xlsx', '.xml'
]

# 需要使用 Playwright 渲染的页面后缀列表
# 这些页面包含 JavaScript 逻辑，需要浏览器环境执行
PLAYWRIGHT_RENDER_EXTENSIONS: List[str] = [
    '.html', '.htm', '.xhtml'
]

# =============================================================================
# 6. FastScan 快速扫描模式过滤规则
# =============================================================================

# 未授权/登录页面的关键词列表
# 如果响应内容包含这些关键词，说明可能是未授权页面，应排除以避免污染结果
UNAUTHORIZED_PAGE_KEYWORDS: List[str] = [
    # 中文提示
    '未登录', '请先登录', '登录过期', '会话过期', '未授权', '身份验证失败',
    '请登录', '重新登录', '登录失效', '会话已过期', '认证失败',

    # 英文提示
    'unauthorized', 'unauth', 'not logged in', 'login required',
    'authentication required', 'session expired', 'access denied',
    'please login', 'sign in required', 'token expired', 'invalid token',

    # HTTP 状态码和相关词汇
    '401', 'login', 'signin', 'jwt expired'
]

# =============================================================================
# 7. 敏感信息检测专用配置
# =============================================================================

# 敏感信息检测的默认黑名单值
# 这些字符串即使符合敏感信息特征，也应直接排除（通常是占位符或测试数据）
SECRET_DETECTION_BLACKLIST: List[str] = [
    "ABCDEFGHIJKLMNOP",  # 字母序列
    "abcdefghijklmnop",  # 小写字母序列
    "0123456789",  # 数字序列
    "0000000000",  # 重复数字
    "&lt;",  # HTML 转义字符
    "I18N"  # 国际化标识
]

# JS/Web 技术词表（用于统计学评分中的 P 特征计算）
# 这些是常见的技术术语，在判断字符串是否为敏感信息时会降低其可疑度
WEB_TECHNICAL_WORDS: Set[str] = {
    'const', 'json', 'facebook', 'webpack', 'redis', 'params',
    'bitbucket', 'django', 'admin', 'github', 'href',
    'gitlab', 'config', 'laravel', "microsoft", "I18N"
}
