import re


def check_available(import_info):
    """
    检查并清理敏感信息列表

    处理流程：
    1. 过滤空字符串和 None
    2. 统一转为字符串
    3. 去重
    4. 过滤超长数据（超过 500 字符的垃圾数据）

    Args:
        import_info: 原始提取结果列表

    Returns:
        list: 清洗后的有效信息列表
    """
    if not import_info:
        return []

    # 过滤非字符串并转字符串，去空，去重
    cleaned = set()
    for item in import_info:
        if item is None: continue
        s = str(item).strip()
        if s and len(s) <= 500:
            cleaned.add(s)

    return list(cleaned)


def find_all_info_by_rex(text: str) -> list:
    """
    使用正则表达式扫描 JS 代码中的结构化敏感数据

    专注于正则表达式擅长的结构化数据提取，与 AI 扫描形成互补：
    - AI 负责找 Key（逻辑推理）
    - 正则负责找信息（模式匹配）

    扫描类型包括：
    1. 中国大陆手机号（11 位）
    2. 电子邮箱
    3. 内网 IP 地址（10./172./192.168. 段）
    4. JDBC 数据库连接串
    5. 身份证号（18 位）
    6. RSA 私钥头
    7. 硬编码密码（简单匹配）
    8. Webhook URL（钉钉/飞书/Slack/企微）
    9. Swagger/Actuator 敏感路径
    10. JS SourceMap 文件

    Args:
        text: 源代码文本

    Returns:
        list: 发现的结构化敏感信息列表
    """
    # 限制长度防止正则 DoS
    if not text or len(text) > 1000000:
        return []

    results = set()

    # 1. 手机号 (中国大陆 11 位)
    # 使用前后断言排除部分时间戳误报
    phones = re.findall(r'(?<!\d)1[3-9]\d{9}(?!\d)', text)
    if phones: results.update(phones)

    # 2. 电子邮箱
    # 排除示例邮箱和常见误报（图片、JS 文件扩展名）
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    for email in emails:
        lower_email = email.lower()
        if "example.com" not in lower_email and \
                "test.com" not in lower_email and \
                "yourdomain" not in lower_email and \
                not lower_email.endswith((".png", ".jpg", ".js", ".css")):
            results.add(email)

    # 3. 内网 IP 地址（AI 容易忽略的重要信息）
    ips = re.findall(
        r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)',
        text)
    if ips: results.update(ips)

    # 4. JDBC 连接串（数据库泄露实锤）
    jdbcs = re.findall(r'jdbc:[a-z:]+://[^"\s]+', text, re.IGNORECASE)
    if jdbcs: results.update(jdbcs)

    # 5. 身份证号（简单校验 18 位格式）
    id_cards = re.findall(
        r'(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)', text)
    if id_cards: results.update(id_cards)

    # 6. RSA 私钥头（正则极快，明显特征）
    if "-----BEGIN RSA PRIVATE KEY-----" in text:
        results.add("RSA Private Key Found")

    # 7. 硬编码密码兜底
    passwords = re.findall(r'(?:password|passwd|pwd)\s*[:=]\s*[\'\"]([^\'\"]{6,50})[\'\"]', text, re.IGNORECASE)
    for pwd in passwords:
        if pwd.lower() not in ['******', '123456', 'password', 'admin', 'undefined', 'null', 'true', 'false']:
            results.add(f"Potential Password: {pwd}")

    # 8. Webhook URL（钉钉/飞书/Slack/企微）
    webhooks = re.findall(
        r'https://(?:qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=|oapi\.dingtalk\.com/robot/send\?access_token=|open\.feishu\.cn/open-apis/bot/v2/hook/|hooks\.slack\.com/services/)[a-zA-Z0-9\-\_]{20,100}',
        text, re.IGNORECASE)
    if webhooks: results.update(webhooks)

    # 9. Swagger UI / SpringBoot Actuator（敏感接口路径）
    api_paths = re.findall(
        r'[\'"](/[a-zA-Z0-9/_.-]*(?:swagger-ui\.html|v2/api-docs|actuator/heapdump|actuator/env))[\'"]', text,
        re.IGNORECASE)
    if api_paths: results.update(api_paths)

    # 10. JS SourceMap 文件（源码泄露风险）
    tail_content = text[-500:] if len(text) > 500 else text
    js_maps = re.findall(r'sourceMappingURL=([a-zA-Z0-9._-]+\.js\.map)', tail_content)
    if js_maps:
        results.update([f"SourceMap Found: {m}" for m in js_maps])

    return check_available(list(results))