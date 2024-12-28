import re

def find_id_cards(text)->list:
    """
    身份证号码提取
    :param text: 待提取的文本
    :return: 身份证号码列表
    """
    # 身份证号码正则表达式
    pattern = r'[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]'
    return re.findall(pattern, text)

def find_phone_numbers(text)->list:
    """
    手机号提取
    :param text: 待提取的文本
    :return: 手机号列表
    """
    # 手机号正则表达式
    pattern = r'1[3456789]\d{9}'
    return re.findall(pattern, text)

def find_email_addresses(text)->list:
    """
    邮箱地址提取
    :param text: 待提取的文本
    :return: 邮箱地址列表
    """
    # 邮箱地址正则表达式
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
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

def find_jdbc(text)->list:
    """
    jdbc提取
    :param text:
    :return:
    """
    pattern = r'jdbc:mysql://[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+'
    return re.findall(pattern, text)

def find_swagger(text)->list:
    """
    swagger提取
    :param text:
    :return:
    """
    pattern = r'((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))'
    return re.findall(pattern, text)

def find_js_map_files(text):
    """寻找所有可能的.js.map文件路径"""
    # 匹配所有以 .js.map 结尾的路径或 URL
    pattern = r'(\S+\.js\.map)'  # 匹配非空白字符后的 .js.map 文件路径
    matches = re.findall(pattern, text)  # 返回所有匹配的结果
    return matches

def find_redis(text)->list:
    """
    redis提取
    :param text:
    :return:
    """
    pattern = r'((redis://)|(redis-cluster://)|(rediss://)|(rediss-cluster://))'
    return re.findall(pattern, text)


def find_sensitive_info(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    pattern = r"(\[?)('?'\"`)?([\w]{0,10})((key|secret|token|config|auth|access|admin|ticket))([\w]{0,10})('?\"`)?(\])?\s*(=|:)\s*['\"`](.*?)['\"`](,?)"
    matches = re.findall(pattern, text)
    return matches

def find_all(text)->list:
    """
    所有敏感信息提取
    :param text:
    :return:
    """
    import_info = []
    import_info.extend(find_id_cards(text))
    import_info.extend(find_phone_numbers(text))
    # import_info.extend(find_email_addresses(text))
    import_info.extend(find_email_addresses(text))
    import_info.extend(find_access_keys(text))
    import_info.extend(find_jdbc(text))
    import_info.extend(find_swagger(text))
    import_info.extend(find_redis(text))
    import_info.extend(find_js_map_files(text))

    import_info.extend(find_sensitive_info(text))
    return import_info
