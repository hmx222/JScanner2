import re


def check_available(import_info):
    """
    检查敏感信息是否有效
    1. 过滤空字符串
    2. 去重
    3. 过滤超长垃圾数据
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
    正则扫描：专注于结构化敏感数据（手机号、邮箱、IP、URL、JDBC等）
    互补 AI 扫描的短板。AI 负责找 Key，正则负责找信息。
    """
    if not text or len(text) > 1000000:  # 稍微限制一下长度，防止正则DoS
        return []

    results = set()

    # 1. 手机号 (中国大陆 11 位)
    # 排除前后有数字的情况，避免把时间戳的一部分误认为手机号
    phones = re.findall(r'(?<!\d)1[3-9]\d{9}(?!\d)', text)
    if phones: results.update(phones)

    # 2. 电子邮箱
    # 排除常见的示例邮箱和垃圾邮箱
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    for email in emails:
        lower_email = email.lower()
        if "example.com" not in lower_email and \
                "test.com" not in lower_email and \
                "yourdomain" not in lower_email and \
                not lower_email.endswith((".png", ".jpg", ".js", ".css")):  # 排除类似 name@2x.png 的误报
            results.add(email)

    # 3. 内网 IP 地址 (非常重要，AI 容易忽略)
    ips = re.findall(
        r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)',
        text)
    if ips: results.update(ips)

    # 4. JDBC 连接串 (数据库泄露实锤)
    jdbcs = re.findall(r'jdbc:[a-z:]+://[^"\s]+', text, re.IGNORECASE)
    if jdbcs: results.update(jdbcs)

    # 5. 身份证号 (简单校验 18 位)
    id_cards = re.findall(
        r'(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)', text)
    if id_cards: results.update(id_cards)

    # 6. RSA 私钥头 (虽然 AI 也能认，但这个太明显了，正则极快)
    if "-----BEGIN RSA PRIVATE KEY-----" in text:
        results.add("RSA Private Key Found")

    # 7. 硬编码密码兜底 (简单的 password = 'xxx')
    passwords = re.findall(r'(?:password|passwd|pwd)\s*[:=]\s*[\'\"]([^\'\"]{6,50})[\'\"]', text, re.IGNORECASE)
    for pwd in passwords:
        # 排除常见假密码和占位符
        if pwd.lower() not in ['******', '123456', 'password', 'admin', 'undefined', 'null', 'true', 'false']:
            results.add(f"Potential Password: {pwd}")

    # 8. Webhook (钉钉/飞书/Slack/企微) - 具体的利用路径
    webhooks = re.findall(
        r'https://(?:qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=|oapi\.dingtalk\.com/robot/send\?access_token=|open\.feishu\.cn/open-apis/bot/v2/hook/|hooks\.slack\.com/services/)[a-zA-Z0-9\-\_]{20,100}',
        text, re.IGNORECASE)
    if webhooks: results.update(webhooks)

    # 9. Swagger UI / SpringBoot Actuator (敏感接口路径)
    api_paths = re.findall(
        r'[\'"](/[a-zA-Z0-9/_.-]*(?:swagger-ui\.html|v2/api-docs|actuator/heapdump|actuator/env))[\'"]', text,
        re.IGNORECASE)
    if api_paths: results.update(api_paths)

    # 10. JS Map 文件 (源码泄露)
    tail_content = text[-500:] if len(text) > 500 else text

    # 匹配 sourceMappingURL 注释
    js_maps = re.findall(r'sourceMappingURL=([a-zA-Z0-9._-]+\.js\.map)', tail_content)
    if js_maps:
        results.update([f"SourceMap Found: {m}" for m in js_maps])

    return check_available(list(results))

