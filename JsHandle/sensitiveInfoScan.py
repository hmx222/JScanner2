import base64
import json

import regex as re


def find_js_map_files_optimized(text: str) -> list:
    """
    ⚡️ 高性能版：从 JS 代码末尾提取 SourceMap 信息
    只检查最后 3 行，避免全文扫描！
    """
    if not isinstance(text, str) or len(text) == 0:
        return []

    # 只取最后 5 行（覆盖 99.9% 的真实场景）
    lines = text.splitlines()
    last_lines = lines[-5:] if len(lines) >= 5 else lines

    # 匹配 sourceMappingURL 注释（支持 // 和 /* */ 风格，新旧语法）
    pattern = r'(?:/\*|//)\s*[@#]\s*sourceMappingURL\s*=\s*([^\s*]+)\s*(?:\*/)?'
    regex = re.compile(pattern, re.IGNORECASE)

    results = []

    for i, line in enumerate(last_lines):
        match = regex.search(line)
        if match:
            url = match.group(1).strip()
            item = {
                "type": "external",
                "url": url,
                "raw_match": match.group(0),
                "line_number": len(lines) - len(last_lines) + i + 1,  # 原始行号
                "position": match.start()
            }

            # 如果是内联 SourceMap (application/json;base64,...)
            if url.startswith('application/json;base64,'):
                try:
                    b64_data = url.split('base64,', 1)[1]
                    json_str = base64.b64decode(b64_data).decode('utf-8')
                    source_map = json.loads(json_str)
                    item.update({
                        "type": "inline",
                        "decoded": source_map,
                        "sources": source_map.get("sources", []),
                        "names": source_map.get("names", [])
                    })
                except Exception:
                    return []

            results.append(item)

    return results

def find_id_cards(text)->list:
    """
    身份证号码提取
    :param text: 待提取的文本
    :return: 身份证号码列表
    """
    # 身份证号码正则表达式
    pattern = r'[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]'
    return re.findall(pattern, text)


def find_comments_sensitive_info(text) -> list:
    """
    提取HTML/JavaScript注释中的敏感信息
    :param text: 待提取的HTML/JavaScript源码
    :return: 包含敏感信息的注释列表
    """
    # 匹配HTML注释 <!-- ... --> 和JS注释 // ... 或 /* ... */
    comment_pattern = r'<!--[\s\S]*?-->|//.*?$|/\*[\s\S]*?\*/'

    # 敏感信息关键词（合并之前的注释关键词）
    sensitive_keywords = [
        'TODO:', 'FIXME:', 'debug', '开发环境', '测试账号', '密码',
        '数据库', 'admin', 'root', '不要删除', '临时解决方案', '未完成',
        'username', 'password', 'secret', 'key', 'token', 'api', 'database',
        'host', 'port', 'url', 'email', 'sql', 'query', 'auth'
    ]

    # 构建敏感信息模式（关键词不区分大小写）
    sensitive_pattern = r'(?i)(' + '|'.join(re.escape(word) for word in sensitive_keywords) + ')'

    # 提取所有注释并筛选包含敏感信息的注释
    comments = re.findall(comment_pattern, text, re.MULTILINE)
    return [comment for comment in comments if re.search(sensitive_pattern, comment)]


def find_phone_numbers(text)->list:
    """
    手机号提取
    :param text: 待提取的文本
    :return: 手机号列表
    """
    # 手机号正则表达式
    pattern = r'/^(13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\d{8}$/'
    return re.findall(pattern, text)


def find_email_addresses(text):
    """
    邮箱地址提取
    :param text: 待提取的文本
    :return: 邮箱地址列表
    """
    # 邮箱地址正则表达式，添加了(?<!png)负向零宽断言确保不以png结尾
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?<!png)\b'
    return re.findall(pattern, text)


def find_access_keys(text)->list:
    """
    密钥提取
    :param text: 待提取的文本
    :return: 密钥列表
    """
    # 密钥正则表达式
    pattern = r'(((access)(|-|_)(key)(|-|_)(id|secret))|(LTAI[a-z0-9]{12,20}))'
    return re.findall(pattern, text)



def find_swagger(text)->list:
    """
    swagger提取
    :param text:
    :return:
    """
    pattern = r'((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))'
    return re.findall(pattern, text)


def find_sensitive_info_1(text: str) -> list:
    OPTIMIZED_REGEX_LIST = [
        # === WPT / WP 聚合 ===
        re.compile(
            r'\bwpt[-_](?:report[-_]api[-_]key|prepare[-_]dir|db[-_](?:user|password))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\bwporg[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bwpjm[-_]phpunit[-_]google[-_]geocode[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
        re.compile(r'\bwordpress[-_]db[-_](?:user|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Wincert / Widget / Watson ===
        re.compile(r'\bwincert[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bwidget[-_]test[-_]server\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bwatson[-_](?:password|device[-_]password|conversation[-_]password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Wakatime / VSCode / Visual Recognition ===
        re.compile(r'\bwakatime[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bvscetoken\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bvisual[-_]recognition[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === VirusTotal / VIP GitHub ===
        re.compile(r'\bvirustotal[-_]apikey\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bvip[-_]github[-_](?:deploy[-_]key(?:[-_]pass)?|build[-_]repo[-_]deploy[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Salesforce (v_sfdc) ===
        re.compile(r'\bv[-_]sfdc[-_](?:password|client[-_]secret)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === User / SSH / AWS ELB ===
        re.compile(
            r'\buser(?:travis|[-_]assets[-_](?:secret[-_]access[-_]key|access[-_]key[-_]id))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\buse[-_]ssh\b\s*[=:]\s*["\']?[\w-]{1,10}["\']?', re.IGNORECASE),  # SSH 通常是布尔值
        re.compile(r'\bus[-_]east[-_]1[-_]elb\.amazonaws\.com\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        # 修复：转义点号

        # === Urban / Unity ===
        re.compile(r'\burban[-_](?:secret|master[-_]secret|key)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bunity[-_](?:serial|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Twitter / Twine / Twilio ===
        re.compile(
            r'\btwitter(?:oauth(?:accesstoken|accesssecret)|[-_]consumer[-_](?:secret|key))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\btwine[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\btwilio[-_](?:token|sid)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
    ]
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "password", "token", "key", "secret", "api", "user", "ssh", "twitter", "twilio"
    ]):
        return []

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result


def find_sensitive_info_2(text: str) -> list:

    OPTIMIZED_REGEX_LIST = [
        # === Twilio 聚合 ===
        re.compile(
            r'\btwilio[-_](?:configuration[-_]sid|chat[-_]account[-_]api[-_]service|api[-_](?:secret|key))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Trex / Travis 聚合 ===
        re.compile(r'\btrex[-_](?:okta[-_]client[-_]token|client[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
        re.compile(
            r'\btravis[-_](?:token|secure[-_]env[-_]vars|pull[-_]request|gh[-_]token|e2e[-_]token|com[-_]token|branch|api[-_]token|access[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Token / Thera / Tester ===
        re.compile(r'\btoken[-_]core[-_]java\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bthera[-_]oss[-_]access[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\btester[-_]keys[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Test / Tesco / SVN / Surge ===
        re.compile(r'\btest[-_]github[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\btesco[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bsvn[-_]pass\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bsurge[-_](?:token|login)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Stripe (修复拼写错误 "strip" → "stripe") ===
        re.compile(
            r'\bstripe[-_](?:public|private|secret[-_]key|publishable[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Stormpath / Starship / Star ===
        re.compile(r'\bstormpath[-_]api[-_]key[-_](?:secret|id)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bstarship[-_](?:auth[-_]token|account[-_]sid)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
        re.compile(
            r'\bstar[-_]test[-_](?:secret[-_]access[-_]key|location|bucket|aws[-_]access[-_]key[-_]id)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Srcclr / Square / SQS ===
        re.compile(r'\bsrcclr[-_]api[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bsquare[-_]reader[-_]sdk[-_]repository[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),
        re.compile(r'\bsqs(?:secret|access)key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Spring / Spotify / Spaces / SoundCloud ===
        re.compile(r'\bspring[-_]mail[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bspotify[-_]api[-_](?:client[-_]secret|access[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
        re.compile(r'\bspaces[-_]access[-_]key[-_](?:secret|id)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bsoundcloud[-_](?:password|client[-_]secret)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),

        # === Sonatype 聚合 ===
        re.compile(r'\bsonatype[-_](?:token[-_](?:user|password)|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),
    ]
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "token", "key", "secret", "password", "api", "twilio", "travis", "stripe", "spotify"
    ]):
        return []

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result


def find_sensitive_info_3(text: str) -> list:
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "secret", "token", "key", "password", "auth", "sentry", "sendgrid",
        "aws", "access", "s3", "sacloud", "salesforce", "sauce", "scrutinizer",
        "sonar", "snyk", "sonatype", "yt_", "zendesk", "zopim"
    ]):
        return []

    OPTIMIZED_REGEX_LIST = [
        # === Sonatype / Sonar / Snyk 聚合 ===
        re.compile(
            r'\b(?:sonatype[-_](?:pass|nexus[-_]password|gpg[-_](?:passphrase|key[-_]name))|sonar[-_](?:token|project[-_]key|organization[-_]key)|snyk[-_](?:token|api[-_]token))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Socrata / Snoowrap / Zopim / Zhuliang / Zendesk ===
        re.compile(
            r'\b(?:socrata[-_](?:password|app[-_]token)|snoowrap[-_](?:refresh[-_]token|password|client[-_]secret)|zopim[-_]account[-_]key|zhuliang[-_]gh[-_]token|zendesk[-_]travis[-_]github)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === YouTube (yt_) 相关聚合 ===
        re.compile(
            r'\byt[-_](?:server[-_]api[-_]key|partner[-_](?:refresh[-_]token|client[-_]secret)|client[-_]secret|api[-_]key|account[-_](?:refresh[-_]token|client[-_]secret))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Yangshun / WPT / Slate / Slash ===
        re.compile(
            r'\b(?:yangshun[-_]gh[-_](?:token|password)|wpt[-_]ssh[-_](?:private[-_]key[-_]base64|connect)|slate[-_]user[-_]email|slash[-_]developer[-_](?:space[-_]key|space))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Signing Key / Set Key ===
        re.compile(
            r'\b(?:signing[-_]key[-_](?:sid|secret|password|id)|set(?:dst)?(?:secret|access)key)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === AWS / SES / S3 / Sandbox 聚合 ===
        re.compile(
            r'\b(?:ses|sandbox[-_]aws|s3|service[-_]account)[-_](?:secret[-_]key|access[-_]key|secret|user[-_]secret|assets|token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\bsandbox[-_]access[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Sentry 聚合 ===
        re.compile(
            r'\bsentry[-_](?:key|secret|endpoint|default[-_]org|auth[-_]token)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === SendGrid / SendWithUs 聚合 ===
        re.compile(
            r'\b(?:send(?:grid|withus))[-_](?:username|user|password|key|api[-_]key)?\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Selion / Segment ===
        re.compile(
            r'\b(?:selion[-_]selenium[-_]host|selion[-_]log[-_]level[-_]dev|segment[-_]api[-_]key)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === SecretID / SecretKey / SecretAccessKey （保留精确匹配）===
        re.compile(
            r'\b(?:secretid|secretkey|secretaccesskey|secret[-_]key[-_]base)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Scrutinizer / Sauce / SDR / Sacloud ===
        re.compile(r'\b(?:scrutinizer|sauce|sdr)[-_]token\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bsauce[-_]access[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bsacloud[-_](?:api|access[-_]token(?:[-_]secret)?)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),

        # === Salesforce ===
        re.compile(
            r'\bsalesforce[-_]bulk[-_]test[-_](?:security[-_]token|password)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

    ]

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result



def find_sensitive_info_4(text: str) -> list:
    OPTIMIZED_REGEX_LIST = [
        # === S3 聚合 ===
        re.compile(
            r'\bs3[-_](?:secret[-_]app[-_]logs|key[-_](?:assets|app[-_]logs|id)?|bucket[-_]name[-_](?:assets|app[-_]logs)|access[-_]key[-_](?:id)?)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\bs3[-_]external[-_]3\.amazonaws\.com\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        # 修复：转义点号

        # === RubyGems / RTD / Route53 ===
        re.compile(r'\brubygems[-_]auth[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\brtd[-_](?:store[-_]pass|key[-_]pass)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\broute53[-_]access[-_]key[-_]id\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Ethereum Testnets (Rinkeby/Ropsten) ===
        re.compile(r'\b(?:rinkeby|ropsten)[-_]private[-_]key\b\s*[=:]\s*["\']?[\w-]{64,66}["\']?', re.IGNORECASE),
        # 限定长度

        # === REST API / RepoToken / Reporting WebDAV ===
        re.compile(r'\brest[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\brepotoken\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\breporting[-_]webdav[-_](?:url|pwd)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Release / Registry / Refresh Token ===
        re.compile(r'\brelease[-_](?:token|gh[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bregistry[-_](?:secure|pass)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\brefresh[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Redis / RabbitMQ / Quip / Qiita ===
        re.compile(r'\bredis(?:cloud[-_]url|[-_]stunnel[-_]urls)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\brandrmusicapiaccesstoken\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\brabbitmq[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\b(?:quip|qiita)[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === PyPI (修复拼写错误 "passowrd" → "password") ===
        re.compile(r'\bpypi[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),  # 修复拼写

        # === Pushover / Publish Keys ===
        re.compile(r'\bpushover[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bpublish[-_](?:secret|key|access)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Production Keys ===
        re.compile(r'\bprod[-_](?:secret[-_]key|password|access[-_]key[-_]id)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),

        # === Private Signing / PostgreSQL ===
        re.compile(r'\bprivate[-_]signing[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bpostgresql[-_](?:pass|db)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bpostgres[-_]env[-_]postgres[-_](?:password|db)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),

        # === Plugin / Plotly / Places API ===
        re.compile(r'\bplugin[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bplotly[-_]apikey\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bplaces[-_]api?[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Percy / PayPal / Parse / PagerDuty ===
        re.compile(r'\bpercy[-_](?:token|project)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bpaypal[-_]client[-_]secret\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bpasswordtravis\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bparse[-_]js[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bpagerduty[-_]apikey\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === PackageCloud / OSSRH (Sonatype) ===
        re.compile(r'\bpackagecloud[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bossrh[-_](?:username|secret|password|pass|jira[-_]password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === OS Auth / OpenWhisk ===
        re.compile(r'\bos[-_](?:password|auth[-_]url)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\b(?:org[-_]project[-_]gradle|org[-_]gradle[-_]project)[-_]sonatype[-_]nexus[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\b(?:openwhisk|open[-_]whisk)[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === OneSignal / Omise ===
        re.compile(r'\bonesignal[-_](?:user[-_]auth[-_]key|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
        re.compile(r'\bomise[-_](?:skey|pubkey|pkey|key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
    ]
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "key", "secret", "password", "token", "api", "s3", "aws", "postgres", "rabbitmq"
    ]):
        return []

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result


def find_sensitive_info_5(text: str) -> list:
    OPTIMIZED_REGEX_LIST = [
        # === Okta / Ofta (可能是 typo) ===
        re.compile(
            r'\bokta[-_](?:oauth2[-_]client(?:secret|[-_]secret)|client[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\bofta[-_](?:secret|region|key)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),  # 保留但加边界

        # === Octest / OC ===
        re.compile(r'\boctest[-_](?:password|app[-_](?:username|password))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),
        re.compile(r'\boc[-_]pass\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Object Storage / OAuth ===
        re.compile(
            r'\bobject[-_](?:store[-_](?:creds|bucket)|storage[-_](?:region[-_]name|password))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\boauth[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Numbers Service / NuGet / NPM ===
        re.compile(r'\bnumbers[-_]service[-_]pass\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bnuget[-_](?:key|api(?:[-_]key)?)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bnpm[-_](?:token|secret[-_]key|password|email|auth[-_]token|api[-_](?:token|key))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Now / Node Pre GYP ===
        re.compile(r'\bnow[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bnode[-_]pre[-_]gyp[-_](?:secretaccesskey|github[-_]token|accesskeyid)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Ngrok ===
        re.compile(r'\bngrok[-_](?:token|auth[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Nexus ===
        re.compile(r'\bnexus(?:password|[-_]password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === New Relic / Netlify ===
        re.compile(r'\bnew[-_]relic[-_]beta[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bnetlify[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === MySQL 聚合 ===
        re.compile(
            r'\bmysql[-_](?:secret|masteruser|username|user|root[-_]password|password|hostname|database)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Multi Workspace/SID 聚合 ===
        re.compile(
            r'\bmulti[-_](?:workspace|workflow|disconnect|connect|bob)[-_]sid\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Minio / Mile Zero / MH ===
        re.compile(r'\bminio[-_](?:secret[-_]key|access[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bmile[-_]zero[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bmh[-_](?:password|apikey)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Mailgun (MG) ===
        re.compile(r'\bmg[-_](?:public[-_]api[-_]key|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Mapbox 聚合 ===
        re.compile(
            r'\bmapbox(?:accesstoken|[-_]aws[-_](?:secret[-_]access[-_]key|access[-_]key[-_]id)|[-_]api[-_]token|[-_]access[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Manifest App Token ===
        re.compile(r'\bmanifest[-_]app[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),  # 保留 token

        # === Mandrill / Management API ===
        re.compile(r'\bmandrill[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bmanagement(?:apiaccesstoken|[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bmanage[-_](?:secret|key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Mailgun 聚合 ===
        re.compile(
            r'\bmailgun[-_](?:secret[-_]api[-_]key|pub[-_](?:key|apikey)|priv[-_]key|password|api(?:[-_]key)?)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Mailer / Mailchimp / Mail ===
        re.compile(r'\bmailer[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bmailchimp[-_](?:key|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bmail[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Magento ===
        re.compile(r'\bmagento[-_](?:password|auth[-_](?:username|password))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),

        # === Lottie 聚合 ===
        re.compile(
            r'\blottie[-_](?:upload[-_]cert[-_]key[-_](?:store[-_]password|password)|s3[-_]secret[-_]key|happo[-_](?:secret[-_]key|api[-_]key))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Looker ===
        re.compile(r'\blooker[-_]test[-_]runner[-_]client[-_]secret\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
    ]
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "key", "secret", "password", "token", "api", "mysql", "mailgun", "npm", "okta"
    ]):
        return []

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result
# 529-418=111


def find_sensitive_info_6(text: str) -> list:
    OPTIMIZED_REGEX_LIST = [
        # === Linux / LinkedIn / Lighthouse ===
        re.compile(r'\blinux[-_]signing[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        # 注意：原正则有语法错误，已拆分修复
        re.compile(r'\blinkedin[-_]client[-_]secret\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\blottie[-_]s3[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\blighthouse[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Lektor / Leanplum ===
        re.compile(r'\blektor[-_]deploy[-_](?:username|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bleanplum[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Kovan / Keystore / Kafka ===
        re.compile(r'\bkovan[-_]private[-_]key\b\s*[=:]\s*["\']?[\w-]{64,66}["\']?', re.IGNORECASE),  # 限定长度
        re.compile(r'\bkeystore[-_]pass\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bkafka[-_](?:rest[-_]url|instance[-_]name|admin[-_]url)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),

        # === JWT / JDBC ===
        re.compile(r'\bjwt[-_]secret\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bjdbc(?:[:]?mysql|[-_](?:host|databaseurl))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Integration Test / IT Test ===
        re.compile(r'\bintegration[-_]test[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bitest[-_]gh[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === iOS / IJ Repo ===
        re.compile(r'\bios[-_]docs[-_]deploy[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bij[-_]repo[-_](?:username|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Hub / Homebrew / HockeyApp ===
        re.compile(r'\bhub[-_]dxia2[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bhomebrew[-_]github[-_]api[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bhockeyapp[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Heroku 聚合 ===
        re.compile(r'\bheroku[-_](?:token|email|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === HB Codesign / GPG ===
        re.compile(r'\bhb[-_]codesign[-_](?:key[-_]pass|gpg[-_]pass)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
                   re.IGNORECASE),
        re.compile(r'\bhabs[-_]auth[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        # 修复 hab → habs? 或保留 hab
        re.compile(
            r'\bgpg[-_](?:secret[-_]keys|private[-_]key|passphrase|ownertrust|key(?:[-_]name)?)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Gradle 聚合 ===
        re.compile(
            r'\bgradle[-_](?:signing[-_](?:password|key[-_]id)|publish[-_](?:secret|key))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Google 聚合 ===
        re.compile(
            r'\bgoogle[-_](?:private[-_]key(?:[-_]id)?|maps[-_]api[-_]key|client[-_](?:secret|id|email)|account[-_]type)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Gogs / GitLab ===
        re.compile(r'\bgogs[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bgitlab[-_]user[-_]email\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === GitHub 聚合（重点优化！）===
        re.compile(
            r'\bgithub[-_](?:tokens?|token|repo|release[-_]token|pwd|password|oauth(?:[-_]token)?|key|hunter[-_](?:username|token)|deployment[-_]token|deploy[-_]hb[-_]doc[-_]pass|client[-_]secret|auth(?:[-_]token)?|api[-_](?:token|key)|access[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Git 聚合（保留 token）===
        re.compile(r'\bgit[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Ghost / GH / GH Unstable ===
        re.compile(r'\bghost[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bghb[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bgh[-_](?:unstable[-_]oauth[-_]client[-_]secret|token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
    ]
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "key", "secret", "password", "token", "api", "github", "google", "jwt", "gpg"
    ]):
        return []

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result
#634-530=104


def find_sensitive_info_7(text: str) -> list:
    OPTIMIZED_REGEX_LIST = [
        # === GitHub (gh_) 聚合 ===
        re.compile(
            r'\bgh[-_](?:repo[-_]token|oauth[-_](?:token|client[-_]secret)|next[-_](?:unstable|oauth)[-_]client[-_](?:secret|id)|email|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === GCP / GCR ===
        re.compile(r'\bgcloud[-_]service[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bgcr[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === FTP 聚合 ===
        re.compile(r'\bftp[-_](?:username|user|pw|password|login)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Flickr / FOSSA ===
        re.compile(r'\bflickr[-_]api[-_](?:secret|key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bfossa[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Flask / Firebase ===
        re.compile(r'\bflask[-_]secret[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bfirebase[-_](?:token|project[-_]develop|key|api[-_](?:token|json))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Elasticsearch / Elastic Cloud ===
        re.compile(r'\belasticsearch[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\belastic[-_]cloud[-_]auth\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Sonar / Droplet / Dropbox ===
        re.compile(r'\bdsonar[-_](?:projectkey|login)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bdroplet[-_]travis[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bdropbox[-_]oauth[-_]bearer\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Doordash / Docker 聚合 ===
        re.compile(r'\bdoordash[-_]auth[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bdocker(?:hub[-_]password|[-_](?:token|postgres[-_]url|password|passwd|pass|key|hub[-_]password))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\bdockerhub(?:password|[-_]password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === DigitalOcean / GPG (修复 dgpg → gpg) ===
        re.compile(
            r'\bdigitalocean[-_](?:ssh[-_]key[-_](?:ids|body)|access[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(r'\b(?:dgpg|gpg)[-_]passphrase\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),  # 兼容 dgpg

        # === Deploy / DDG ===
        re.compile(r'\bdeploy[-_](?:user|token|secure|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bddg[-_]test[-_](?:email[-_]pw|email)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bddgc[-_]github[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === DB / Database 聚合（只保留 password/user）===
        re.compile(r'\bdb[-_](?:username|user|pw|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bdatabase[-_](?:username|user|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Datadog ===
        re.compile(r'\bdatadog[-_](?:app[-_]key|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Danger / Cypress / Coveralls / Coverity ===
        re.compile(r'\bdanger[-_]github[-_]api[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bcypress[-_]record[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bcover(?:alls|ity)[-_](?:scan[-_]token|token|repo[-_]token|api[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === COS / Conversation ===
        re.compile(r'\bcos[-_]secrets\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bconversation[-_](?:username|password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Contentful 聚合 ===
        re.compile(
            r'\bcontentful[-_](?:v2[-_]access[-_]token|test[-_]org[-_]cma[-_]token|php[-_]management[-_]test[-_]token|management[-_]api[-_]access[-_]token(?:[-_]new)?|integration[-_]management[-_]token|cma[-_]test[-_]token|access[-_]token)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Consumer / Conekta / Coding ===
        re.compile(r'\b(?:consumerkey|consumer[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bconekta[-_]apikey\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bcoding[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
    ]
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "key", "secret", "password", "token", "api", "github", "docker", "firebase", "datadog"
    ]):
        return []

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result
# 762-636=126


def find_sensitive_info_8(text: str) -> list:
    OPTIMIZED_REGEX_LIST = [
        # === Cloudflare / Cloudant ===
        re.compile(r'\bcloudflare[-_](?:auth[-_]email|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bcloudant[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Cloud / Clojars / Client Secret ===
        re.compile(r'\bcloud[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bclojars[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bclient[-_]secret\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === CLI / Claimr / CI ===
        re.compile(r'\bcli[-_]e2e[-_]cma[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bclaimr[-_](?:token|superuser)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bci[-_](?:user[-_]token|registry[-_]user|deploy[-_]password)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Chrome / Cheverny / CF ===
        re.compile(r'\bchrome[-_](?:refresh[-_]token|client[-_]secret)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),
        re.compile(r'\bcheverny[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bcf[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === Certificate / Censys / Cattle ===
        re.compile(r'\bcertificate[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
        re.compile(r'\bcensys[-_]secret\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bcattle[-_](?:secret[-_]key|agent[-_]instance[-_]auth|access[-_]key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Cargo / Cache S3 ===
        re.compile(r'\bcargo[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bcache[-_]s3[-_]secret[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === Bundlesize / Built / Bucketeer ===
        re.compile(r'\bbundlesize[-_]github[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bbuilt[-_]branch[-_]deploy[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bbucketeer[-_]aws[-_](?:secret[-_]access[-_]key|access[-_]key[-_]id)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === BrowserStack ===
        re.compile(r'\b(?:browserstack|browser[-_]stack)[-_]access[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),

        # === Brackets / Bluemix ===
        re.compile(r'\bbrackets[-_]repo[-_]oauth[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bbluemix[-_](?:pwd|password|pass(?:[-_]prod)?|auth|api[-_]key)\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === Bintray 聚合 ===
        re.compile(
            r'\bbintray(?:key|[-_](?:token|key|gpg[-_]password|api(?:[-_]key)?))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === B2 App Key ===
        re.compile(r'\bb2[-_]app[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),

        # === AWS 聚合（重点优化！）===
        re.compile(
            r'\b(?:awssecretkey|aws[-_](?:cn[-_])?secret[-_]access[-_]key|aws[-_]ses[-_]secret[-_]access[-_]key|aws[-_]config[-_]secretaccesskey)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(
            r'\b(?:awsaccesskeyid|aws[-_](?:cn[-_])?access[-_]key[-_]id|aws[-_]ses[-_]access[-_]key[-_]id|aws[-_]config[-_]accesskeyid|aws[-_](?:access[-_]key[-_]id|access[-_]key|access))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),
        re.compile(
            r'\baws[-_](?:secrets|secret(?:[-_]key|[-_]access[-_]key|)|key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Author / Auth0 ===
        re.compile(r'\bauthor[-_]npm[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bauth0[-_](?:client[-_]secret|api[-_]clientsecret)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),

        # === Auth / Assistant / Artifacts ===
        re.compile(r'\bauth[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bassistant[-_]iam[-_]apikey\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(
            r'\bartifacts[-_](?:secret|key|bucket|aws[-_](?:secret[-_]access[-_]key|access[-_]key[-_]id))\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
            re.IGNORECASE),

        # === Artifactory / Argos / Apple ===
        re.compile(r'\bartifactory[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bargos[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bapple[-_]id[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),

        # === App 聚合（修复拼写错误 "secrete" → "secret"）===
        re.compile(
            r'\b(?:appclientsecret|app[-_](?:token|secret|report[-_]token[-_]key|bucket[-_]perm))\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?',
            re.IGNORECASE),

        # === API Gateway / Apiary / API Key ===
        re.compile(r'\bapigw[-_]access[-_]token\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bapiary[-_]api[-_]key\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bapi[-_](?:secret|key[-_](?:sid|secret)?|key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?',
                   re.IGNORECASE),

        # === AOS / Ansible ===
        re.compile(r'\baos[-_](?:sec|key)\b\s*[=:]\s*["\']?[\w-]{20,100}["\']?', re.IGNORECASE),
        re.compile(r'\bansible[-_]vault[-_]password\b\s*[=:]\s*["\']?[\w-]{10,100}["\']?', re.IGNORECASE),
    ]
    # === 预过滤：关键词快速跳过 ===
    if not any(kw in text for kw in [
        "key", "secret", "password", "token", "api", "aws", "cloud", "auth", "app"
    ]):
        return []

    result = []
    for regex in OPTIMIZED_REGEX_LIST:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue  # 容错处理
    return result
# 764-899 = 135


import re

def find_sensitive_info_9(text: str) -> list:
    # === 预过滤 ===
    if not any(kw in text for kw in [
        "token", "key", "secret", "password", "access", "auth", "AKIA", "LTAI",
        "AIza", "wx", "ghp", "slack.com", "dingtalk", "feishu", "weixin", "eyJr"
    ]):
        return []

    regex_list = [
        re.compile(r'["\']?codecov[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?codeclimate[-_]?repo[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?codacy[-_]?project[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cocoapods[-_]?trunk[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cocoapods[-_]?trunk[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cn[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cn[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?clu[-_]?ssh[-_]?private[-_]?key[-_]?base64["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?clu[-_]?repo[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudinary[-_]?url[-_]?staging["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudinary[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudflare[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudflare[-_]?auth[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?android[-_]?docs[-_]?deploy[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?anaconda[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?amazon[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?amazon[-_]?bucket[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?alicloud[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?alicloud[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?alias[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?search[-_]?key[-_]?1["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?search[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?search[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?api[-_]?key[-_]?search["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?api[-_]?key[-_]?mcm["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?admin[-_]?key[-_]?mcm["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?admin[-_]?key[-_]?2["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?algolia[-_]?admin[-_]?key[-_]?1["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?air[-_]?table[-_]?api[-_]?key["\']?[=:]["\']?.+["\']', re.IGNORECASE),
        re.compile(r'["\']?adzerk[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?admin[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?account[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?access[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?access[-_]?key[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?account["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'\b[\w-]*password[\w-]*\b\s*[=:]\s*["\']?[\w-]{5,50}["\']?', re.IGNORECASE),
        re.compile(r'\b[\w-]*username[\w-]*\b\s*[=:]\s*["\']?[\w-]{1,100}["\']?', re.IGNORECASE),
        re.compile(r'\b[\w-]*accesskey[\w-]*\b\s*[=:]\s*["\']?[\w-]{1,100}["\']?', re.IGNORECASE),
        re.compile(r'\b[\w-]*secret[\w-]*\b\s*[=:]\s*["\']?[\w-]{1,100}["\']?', re.IGNORECASE),
        re.compile(r'\b[\w-]*bucket[\w-]*\b\s*[=:]\s*["\']?[\w-]{1,100}["\']?', re.IGNORECASE),
        re.compile(r'\b[\w-]*token[\w-]*\b\s*[=:]\s*["\']?[\w-]{1,100}["\']?', re.IGNORECASE),
        re.compile(r'["\']?[-]+BEGIN \w+ PRIVATE KEY[-]+', re.IGNORECASE),
        re.compile(r'["\']?huawei\.oss\.(ak|sk|bucket\.name|endpoint|local\.path)["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?private[-_]?key[-_]?(id)?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?account[-_]?(name|key)?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'LTAI[A-Za-z\d]{12,30}', re.IGNORECASE),
        re.compile(r'AKID[A-Za-z\d]{13,40}', re.IGNORECASE),
        re.compile(r'JDC_[0-9A-Z]{25,40}', re.IGNORECASE),
        re.compile(r'["\']?(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["\']?', re.IGNORECASE),
        re.compile(r'(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}', re.IGNORECASE),
        re.compile(r'AKLT[a-zA-Z0-9-_]{16,28}', re.IGNORECASE),
        re.compile(r'AIza[0-9A-Za-z_\-]{35}', re.IGNORECASE),
        re.compile(r'[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}', re.IGNORECASE),
        re.compile(r'[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}', re.IGNORECASE),
        re.compile(r'["\'\[]*[Aa]uthorization["\'\]]*\s*[:=]\s*[\'"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[\'"]?', re.IGNORECASE),
        re.compile(r'(glpat-[a-zA-Z0-9\-=_]{20,22})', re.IGNORECASE),
        re.compile(r'((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})', re.IGNORECASE),
        re.compile(r'APID[a-zA-Z0-9]{32,42}', re.IGNORECASE),
        re.compile(r'["\'](wx[a-z0-9]{15,18})["\']', re.IGNORECASE),
        re.compile(r'["\'](ww[a-z0-9]{15,18})["\']', re.IGNORECASE),
        re.compile(r'["\'](gh_[a-z0-9]{11,13})["\']', re.IGNORECASE),
        re.compile(r'(?:admin_?pass|password|[a-z]{3,15}_?password|user_?pass|user_?pwd|admin_?pwd)\\?[\'"]*\s*[:=]\s*\\?[\'"][a-z0-9!@#$%&*]{5,20}\\?[\'"]', re.IGNORECASE),
        re.compile(r'https://qyapi.weixin.qq.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}', re.IGNORECASE),
        re.compile(r'https://oapi.dingtalk.com/robot/send\?access_token=[a-z0-9]{50,80}', re.IGNORECASE),
        re.compile(r'https://open.feishu.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}', re.IGNORECASE),
        re.compile(r'https://hooks.slack.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}', re.IGNORECASE),
        re.compile(r'eyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}', re.IGNORECASE),
        re.compile(r'glc_[A-Za-z0-9\-_+/]{32,200}={0,2}', re.IGNORECASE),
        re.compile(r'glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}', re.IGNORECASE)
    ]

    result = []
    for regex in regex_list:
        try:
            matches = regex.findall(text)
            if matches:
                result.extend(matches)
        except Exception:
            continue
    return result
# 976-901=75

def check_available(import_info):
    """
    检查敏感信息是否有效
    1. 检查是否为空列表
    2. 检查是否存在空信息，如果存在则删除
    3. 检查是否存在重复信息，如果存在则删除
    :param import_info:
    :return:
    """

    # 检查是否存在空信息
    if "" in import_info:
        import_info.remove("")

    # 去重
    import_info = list(set(import_info))

    return [item for item in import_info if len(item) <= 500]


def find_all_info_by_rex(text: str):
    """
    高性能敏感信息提取（单线程顺序执行版）

    优势：
    1. 完全避免多进程/多线程问题（尤其Windows兼容性完美）
    2. 预编译正则 + 缓存，避免重复编译开销
    3. 实际性能比多进程更快（无进程创建/通信开销）
    4. 内存使用更高效（无多进程内存复制）

    :param text: 待扫描文本
    :return: 敏感信息列表
    """
    # 顺序执行所有扫描函数（实际比并发更快）
    results = []

    # 1. 基础信息扫描（快速过滤）
    results.extend(find_id_cards(text))
    results.extend(find_phone_numbers(text))
    results.extend(find_email_addresses(text))

    # 2. 中等复杂度扫描
    results.extend(find_access_keys(text))
    results.extend(find_swagger(text))
    results.extend(find_js_map_files_optimized(text))

    # 3. 复杂模式扫描（放在最后，因为最耗时）
    results.extend(find_sensitive_info_1(text))
    results.extend(find_sensitive_info_2(text))
    results.extend(find_sensitive_info_3(text))
    results.extend(find_sensitive_info_4(text))
    results.extend(find_sensitive_info_5(text))
    results.extend(find_sensitive_info_6(text))
    results.extend(find_sensitive_info_7(text))
    results.extend(find_sensitive_info_8(text))
    results.extend(find_sensitive_info_9(text))

    results = [str(item) if not isinstance(item, str) else item for item in results]

    # 返回验证后的结果
    return check_available(results)








