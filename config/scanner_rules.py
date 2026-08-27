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
    '.svg', '.swf', '.ttf', '.webp', '.woff', '.woff2','.html','.htm'
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
    '.woff', '.woff2', '.xls', '.xlsx', '.xml','.html','.htm'
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
    "123456789",  # 数字序列
    "0000000000",  # 重复数字
    "&lt;",  # HTML 转义字符
    "I18N",  # 国际化标识
    ".",
    "/"
]

# JS/Web 技术词表（用于统计学评分中的 P 特征计算）
# 这些是常见的技术术语，在判断字符串是否为敏感信息时会降低其可疑度
WEB_TECHNICAL_WORDS: Set[str] = {
    'const', 'json', 'facebook', 'webpack', 'redis', 'params',
    'bitbucket', 'django', 'admin', 'github', 'href',
    'gitlab', 'config', 'laravel', "microsoft", "I18N"
}


# =============================================================================
# 8. HTTP 请求模板与配置
# =============================================================================

# 固定请求头配置（用于 ai_vulns 表的自动化请求验证）
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
    "Referer": "https://cloud.tencent.com",
    "Content-Type": "application/json"
}

# 请求超时时间（秒）
REQUEST_TIMEOUT = 5

# 响应内容摘要长度限制（字符数）
CONTENT_SUMMARY_MAX_LENGTH = 500

# 支持的 HTTP 方法列表（用于请求执行）
SUPPORTED_REQUEST_METHODS = {"GET", "POST"}

# 默认降级方法（当 method 不在支持列表中时使用）
DEFAULT_REQUEST_METHOD = "GET"


# =============================================================================
# 9. API Path 黑名单正则
# =============================================================================
import re


API_PATH_BLACKLIST_PATTERNS: tuple[re.Pattern, ...] = (
    # =========================================================================
    # DELETE / REMOVE / DESTROY
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:delete|remove|destroy|erase|purge|drop)(?:$|[/_.-]|[a-z0-9])'
    ),

    # 例如：
    # deleteUser
    # delete-user
    # user-delete
    # removeAccount
    # account_remove
    re.compile(
        r'(?:^|[/_.-])(?:delete|remove|destroy|erase|purge|drop)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+(?:delete|remove|destroy|erase|purge|drop)[a-z0-9]*$'
    ),


    # =========================================================================
    # CREATE / ADD / INSERT / REGISTER
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:create|insert|register|signup|sign-up|enroll)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:create|insert|register|signup|sign-up|enroll)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:create|insert|register|signup|enroll)[a-z0-9]*$'
    ),

    # add 比较容易误报，因此要求它是独立 segment 或明显 action。
    re.compile(
        r'(?:^|[/_.-])add(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])add[a-z0-9]+$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+add[a-z0-9]*$'
    ),


    # =========================================================================
    # UPDATE / MODIFY / EDIT / ALTER / RENAME
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:update|modify|edit|alter|rename)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:update|modify|edit|alter|rename)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:update|modify|edit|alter|rename)[a-z0-9]*$'
    ),


    # =========================================================================
    # SAVE / SUBMIT / COMMIT / PERSIST
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:save|submit|commit|persist)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:save|submit|commit|persist)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:save|submit|commit|persist)[a-z0-9]*$'
    ),


    # =========================================================================
    # WRITE / OVERWRITE / APPEND
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:write|overwrite|append)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:write|overwrite|append)[a-z0-9]*$'
    ),


    # =========================================================================
    # ENABLE / DISABLE / ACTIVATE / DEACTIVATE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:enable|disable|activate|deactivate)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:enable|disable|activate|deactivate)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:enable|disable|activate|deactivate)[a-z0-9]*$'
    ),


    # =========================================================================
    # SUSPEND / UNSUSPEND / LOCK / UNLOCK / FREEZE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:suspend|unsuspend|freeze|unfreeze|lock|unlock)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:suspend|unsuspend|freeze|unfreeze|lock|unlock)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:suspend|unsuspend|freeze|unfreeze|lock|unlock)[a-z0-9]*$'
    ),


    # =========================================================================
    # RESET / RESTORE / RECOVER
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:reset|restore|recover)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:reset|restore|recover)[a-z0-9]*$'
    ),


    # =========================================================================
    # APPROVE / REJECT / DENY / CONFIRM
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:approve|reject|deny|confirm)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:approve|reject|deny|confirm)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:approve|reject|deny|confirm)[a-z0-9]*$'
    ),


    # =========================================================================
    # CANCEL / ABORT
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:cancel|abort)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:cancel|abort)[a-z0-9]*$'
    ),


    # =========================================================================
    # GRANT / REVOKE / AUTHORIZE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:grant|revoke|authorize|deauthorize)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:grant|revoke|authorize|deauthorize)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:grant|revoke|authorize|deauthorize)[a-z0-9]*$'
    ),


    # =========================================================================
    # ASSIGN / UNASSIGN / BIND / UNBIND
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:assign|unassign|bind|unbind)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:assign|unassign|bind|unbind)[a-z0-9]*$'
    ),


    # =========================================================================
    # TRANSFER / WITHDRAW / DEPOSIT
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:transfer|withdraw|deposit)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:transfer|withdraw|deposit)[a-z0-9]*$'
    ),


    # =========================================================================
    # PAYMENT / REFUND / CHARGE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:payment|pay|refund|charge|checkout)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:payment|pay|refund|charge|checkout)[a-z0-9]*$'
    ),


    # =========================================================================
    # PURCHASE / BUY / SELL
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:purchase|buy|sell)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:purchase|buy|sell)[a-z0-9]*$'
    ),


    # =========================================================================
    # PUBLISH / UNPUBLISH / RELEASE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:publish|unpublish|release)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:publish|unpublish|release)[a-z0-9]*$'
    ),


    # =========================================================================
    # DEPLOY / ROLLBACK
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:deploy|rollback|roll-back)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:deploy|rollback|roll-back)[a-z0-9]*$'
    ),


    # =========================================================================
    # EXECUTE / EXEC / TRIGGER / INVOKE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:execute|exec|trigger|invoke)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:execute|exec|trigger|invoke)[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])[a-z0-9]+'
        r'(?:execute|exec|trigger|invoke)[a-z0-9]*$'
    ),


    # =========================================================================
    # ACTION / COMMAND
    #
    # 这里比 execute 更宽泛，但对于自动执行器来说风险较高。
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:action|command)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:action|command)[a-z0-9]*$'
    ),


    # =========================================================================
    # BATCH / BULK —— 只拦截明确的写操作组合
    #
    # 不直接把 /batchQuery 拦掉。
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])'
        r'(?:batch|bulk)'
        r'(?:delete|remove|destroy|create|insert|update|modify|edit|save|submit)'
        r'[a-z0-9]*$'
    ),

    re.compile(
        r'(?:^|[/_.-])'
        r'(?:delete|remove|destroy|create|insert|update|modify|edit|save|submit)'
        r'(?:batch|bulk)'
        r'[a-z0-9]*$'
    ),


    # =========================================================================
    # UPLOAD / IMPORT / OVERWRITE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:upload|import|overwrite)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:upload|import|overwrite)[a-z0-9]*$'
    ),


    # =========================================================================
    # SEND / DISPATCH / NOTIFY
    #
    # 这些可能触发真实外部副作用。
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:send|dispatch|notify|notification)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:send|dispatch|notify|notification)[a-z0-9]*$'
    ),


    # =========================================================================
    # INVITE / KICK / REMOVE MEMBER
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:invite|kick)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:invite|kick)[a-z0-9]*$'
    ),


    # =========================================================================
    # MOVE / COPY / CLONE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:move|copy|clone)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:move|copy|clone)[a-z0-9]*$'
    ),


    # =========================================================================
    # SYNC / REPLICATE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:sync|replicate)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:sync|replicate)[a-z0-9]*$'
    ),


    # =========================================================================
    # PROVISION / DEPROVISION
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:provision|deprovision)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:provision|deprovision)[a-z0-9]*$'
    ),


    # =========================================================================
    # INITIALIZE / FINALIZE
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:initialize|finalize)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:initialize|finalize)[a-z0-9]*$'
    ),


    # =========================================================================
    # SYSTEM CONTROL
    #
    # restart / reboot / shutdown 明显可能产生服务端副作用。
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:restart|reboot|shutdown)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:restart|reboot|shutdown)[a-z0-9]*$'
    ),


    # =========================================================================
    # CACHE / INDEX 等状态改变
    # =========================================================================

    re.compile(
        r'(?:^|[/_.-])(?:invalidate|reindex|rebuild)'
        r'(?:$|[/_.-]|[a-z0-9])'
    ),

    re.compile(
        r'(?:^|[/_.-])(?:invalidate|reindex|rebuild)[a-z0-9]*$'
    ),
)


def is_api_path_blacklisted(path: str) -> bool:
    if not path or not isinstance(path, str):
        return True
    path_lower = path.lower().split('?')[0]
    return any(p.search(path_lower) for p in API_PATH_BLACKLIST_PATTERNS)


# =============================================================================
# 10. 响应解析配置
# =============================================================================

# 业务层鉴权拒绝的 JSON code 值（HTTP 200 但业务层返回拒绝）
BUSINESS_AUTH_DENIED_CODES: Set = {
    401, 403, -1, -2,
    "401", "403", "-1", "-2",
    "unauthorized", "forbidden", "no_permission",
    "not_login", "need_login", "token_expired", "token_invalid",
}

# 业务层鉴权拒绝的 message 关键词（用于 1.5 层关键词过滤）
BUSINESS_AUTH_DENIED_MESSAGES: List[str] = [
    '未登录', '请先登录', '未授权', '身份验证失败', 'token过期',
    '登录过期', '会话过期', '权限不足', '无权限', '认证失败',
    'unauthorized', 'not logged in', 'login required',
    'token expired', 'invalid token', 'access denied',
    'authentication failed', 'permission denied',
]

# JSON 响应中用于提取业务状态码的常见字段名
JSON_CODE_FIELDS: List[str] = ["code", "status", "errcode", "errno", "ret", "errCode", "statusCode"]

# JSON 响应中用于提取业务消息的常见字段名
JSON_MESSAGE_FIELDS: List[str] = ["msg", "message", "errmsg", "info", "desc", "errMsg", "errorMsg"]

# JSON 响应中用于判断是否有实质业务数据的常见字段名
JSON_DATA_FIELDS: List[str] = ["data", "result", "rows", "list", "items", "records", "content"]

# =============================================================================
# 11. 请求重试与熔断配置
# =============================================================================

# 单个 API 最大重试次数（含 405 切换 + AI 调整），超过后强制停止，输出给人工判断
MAX_RETRY_PER_API = 3

# 405 方法切换映射（只允许互切一次，防止死循环）
METHOD_SWITCH_MAP = {
    "GET": "POST",
    "POST": "GET",
}
