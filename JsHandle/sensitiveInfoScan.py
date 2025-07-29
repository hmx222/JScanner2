import multiprocessing
import time
import traceback
from multiprocessing import Pool

import regex as re


def find_id_cards(text)->list:
    """
    身份证号码提取
    :param text: 待提取的文本
    :return: 身份证号码列表
    """
    # 身份证号码正则表达式
    pattern = r'[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]'
    return re.findall(pattern, text)


import re


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


def find_js_map_files(text):
    """寻找所有可能的.js.map文件路径"""
    # 匹配所有以 .js.map 结尾的路径或 URL
    pattern = r'(\S+\.js\.map)'  # 匹配非空白字符后的 .js.map 文件路径
    matches = re.findall(pattern, text)  # 返回所有匹配的结果
    return matches


def find_sensitive_info_1(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [

        re.compile(r'["\']?wpt[-_]?report[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wpt[-_]?prepare[-_]?dir["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wpt[-_]?db[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wpt[-_]?db[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wporg[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wpjm[-_]?phpunit[-_]?google[-_]?geocode[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?wordpress[-_]?db[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wordpress[-_]?db[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wincert[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?test[-_]?server["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?fb[-_]?password[-_]?3["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?fb[-_]?password[-_]?2["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?fb[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?basic[-_]?password[-_]?5["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?basic[-_]?password[-_]?4["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?basic[-_]?password[-_]?3["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?basic[-_]?password[-_]?2["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?widget[-_]?basic[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?watson[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?watson[-_]?device[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?watson[-_]?conversation[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wakatime[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?vscetoken["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?visual[-_]?recognition[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?virustotal[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?vip[-_]?github[-_]?deploy[-_]?key[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?vip[-_]?github[-_]?deploy[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?vip[-_]?github[-_]?build[-_]?repo[-_]?deploy[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?v[-_]?sfdc[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?v[-_]?sfdc[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?usertravis["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?user[-_]?assets[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?user[-_]?assets[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?use[-_]?ssh["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?us[-_]?east[-_]?1[-_]?elb[-_]?amazonaws[-_]?com["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?urban[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?urban[-_]?master[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?urban[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?unity[-_]?serial["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?unity[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twitteroauthaccesstoken["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twitteroauthaccesssecret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twitter[-_]?consumer[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twitter[-_]?consumer[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twine[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twilio[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twilio[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
    ]
    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result


def find_sensitive_info_2(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [
        re.compile(r'["\']?twilio[-_]?configuration[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twilio[-_]?chat[-_]?account[-_]?api[-_]?service["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?twilio[-_]?api[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?twilio[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?trex[-_]?okta[-_]?client[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?trex[-_]?client[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?secure[-_]?env[-_]?vars["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?pull[-_]?request["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?gh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?e2e[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?com[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?branch["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?travis[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?token[-_]?core[-_]?java["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?thera[-_]?oss[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?tester[-_]?keys[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?test[-_]?test["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?test[-_]?github[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?tesco[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?svn[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?surge[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?surge[-_]?login["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?stripe[-_]?public["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?stripe[-_]?private["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?strip[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?strip[-_]?publishable[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?stormpath[-_]?api[-_]?key[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?stormpath[-_]?api[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?starship[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?starship[-_]?account[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?star[-_]?test[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?star[-_]?test[-_]?location["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?star[-_]?test[-_]?bucket["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?star[-_]?test[-_]?aws[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?staging[-_]?base[-_]?url[-_]?runscope["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ssmtp[-_]?config["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sshpass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?srcclr[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?square[-_]?reader[-_]?sdk[-_]?repository[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?sqssecretkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sqsaccesskey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?spring[-_]?mail[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?spotify[-_]?api[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?spotify[-_]?api[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?spaces[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?spaces[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?soundcloud[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?soundcloud[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonatypepassword["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonatype[-_]?token[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonatype[-_]?token[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonatype[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),

    ]
    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result


def find_sensitive_info_3(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [
        re.compile(r'["\']?sonatype[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonatype[-_]?nexus[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonatype[-_]?gpg[-_]?passphrase["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonatype[-_]?gpg[-_]?key[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonar[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonar[-_]?project[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sonar[-_]?organization[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?socrata[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?socrata[-_]?app[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?snyk[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?snyk[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?snoowrap[-_]?refresh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?zopim[-_]?account[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?zhuliang[-_]?gh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?zensonatypepassword["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?zendesk[-_]?travis[-_]?github["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yt[-_]?server[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yt[-_]?partner[-_]?refresh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yt[-_]?partner[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yt[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yt[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yt[-_]?account[-_]?refresh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yt[-_]?account[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yangshun[-_]?gh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?yangshun[-_]?gh[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?www[-_]?googleapis[-_]?com["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?wpt[-_]?ssh[-_]?private[-_]?key[-_]?base64["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?wpt[-_]?ssh[-_]?connect["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?snoowrap[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?snoowrap[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?slate[-_]?user[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?slash[-_]?developer[-_]?space[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?slash[-_]?developer[-_]?space["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?signing[-_]?key[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?signing[-_]?key[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?signing[-_]?key[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?signing[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?setsecretkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?setdstsecretkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?setdstaccesskey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ses[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ses[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?service[-_]?account[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sentry[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sentry[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sentry[-_]?endpoint["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sentry[-_]?default[-_]?org["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sentry[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sendwithus[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sendgrid[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sendgrid[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sendgrid[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sendgrid[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sendgrid[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sendgrid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?selion[-_]?selenium[-_]?host["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?selion[-_]?log[-_]?level[-_]?dev["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?segment[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secretid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secretkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secretaccesskey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?key[-_]?base["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?9["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?8["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?7["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?6["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?5["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?4["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?3["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?2["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?11["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?10["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?1["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?secret[-_]?0["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sdr[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?scrutinizer[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sauce[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sandbox[-_]?aws[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?sandbox[-_]?aws[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sandbox[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?salesforce[-_]?bulk[-_]?test[-_]?security[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?salesforce[-_]?bulk[-_]?test[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sacloud[-_]?api["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sacloud[-_]?access[-_]?token[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?sacloud[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?user[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?secret[-_]?assets["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
    ]
    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result
# 311-235


def find_sensitive_info_4(text) -> list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [
        re.compile(r'["\']?s3[-_]?secret[-_]?app[-_]?logs["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?key[-_]?assets["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?key[-_]?app[-_]?logs["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        # 修复重复的正则表达式
        re.compile(r'["\']?s3[-_]?external[-_]?3[-_]?amazonaws[-_]?com["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?bucket[-_]?name[-_]?assets["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?bucket[-_]?name[-_]?app[-_]?logs["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?s3[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?rubygems[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?rtd[-_]?store[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?rtd[-_]?key[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?route53[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?',re.IGNORECASE),
                   re.compile(r'["\']?ropsten[-_]?private[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?rinkeby[-_]?private[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?rest[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?repotoken["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?reporting[-_]?webdav[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?reporting[-_]?webdav[-_]?pwd["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?release[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?release[-_]?gh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?registry[-_]?secure["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?registry[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?refresh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?rediscloud[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?redis[-_]?stunnel[-_]?urls["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?randrmusicapiaccesstoken["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?rabbitmq[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?quip[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?qiita[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?pypi[-_]?passowrd["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?pushover[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?publish[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?publish[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?publish[-_]?access["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?project[-_]?config["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?prod[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?prod[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?prod[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?private[-_]?signing[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                              re.IGNORECASE),
                   re.compile(r'["\']?pring[-_]?mail[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?preferred[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?prebuild[-_]?auth["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?postgresql[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?postgresql[-_]?db["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?postgres[-_]?env[-_]?postgres[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                              re.IGNORECASE),
                   re.compile(r'["\']?postgres[-_]?env[-_]?postgres[-_]?db["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                              re.IGNORECASE),
                   re.compile(r'["\']?plugin[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?plotly[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?places[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?places[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?pg[-_]?host["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?pg[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?personal[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?personal[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?percy[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?percy[-_]?project["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?paypal[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?passwordtravis["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?parse[-_]?js[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?pagerduty[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?packagecloud[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?ossrh[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?ossrh[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?ossrh[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?ossrh[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?ossrh[-_]?jira[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?os[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?os[-_]?auth[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(
                       r'["\']?org[-_]?project[-_]?gradle[-_]?sonatype[-_]?nexus[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?',re.IGNORECASE),
                   re.compile(
                       r'["\']?org[-_]?gradle[-_]?project[-_]?sonatype[-_]?nexus[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                       re.IGNORECASE),
                   re.compile(r'["\']?openwhisk[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?open[-_]?whisk[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?onesignal[-_]?user[-_]?auth[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                              re.IGNORECASE),
                   re.compile(r'["\']?onesignal[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?omise[-_]?skey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?omise[-_]?pubkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?omise[-_]?pkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
                   re.compile(r'["\']?omise[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
    ]

    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result


def find_sensitive_info_5(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [
        re.compile(r'["\']?okta[-_]?oauth2[-_]?clientsecret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?okta[-_]?oauth2[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?okta[-_]?client[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ofta[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ofta[-_]?region["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ofta[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?octest[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?octest[-_]?app[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?octest[-_]?app[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?oc[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?object[-_]?store[-_]?creds["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?object[-_]?store[-_]?bucket["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?object[-_]?storage[-_]?region[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?object[-_]?storage[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?oauth[_-]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?numbers[_-]?service[_-]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?nuget[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?nuget[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?nuget[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?npm[_-]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?npm[_-]?secret[_-]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?npm[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?npm[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?npm[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?npm[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?npm[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?now[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?non[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?node[-_]?pre[-_]?gyp[-_]?secretaccesskey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?node[-_]?pre[-_]?gyp[-_]?github[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?node[-_]?pre[-_]?gyp[-_]?accesskeyid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?node[-_]?env["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ngrok[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ngrok[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?nexuspassword["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?nexus[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?new[-_]?relic[-_]?beta[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?netlify[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?nativeevents["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysqlsecret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysqlmasteruser["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysql[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysql[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysql[-_]?root[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysql[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysql[-_]?hostname["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mysql[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?my[-_]?secret[-_]?env["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?multi[-_]?workspace[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?multi[-_]?workflow[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?multi[-_]?disconnect[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?multi[-_]?connect[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?multi[-_]?bob[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?minio[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?minio[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mile[-_]?zero[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mh[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mh[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mg[-_]?public[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mg[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mapboxaccesstoken["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mapbox[-_]?aws[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?mapbox[-_]?aws[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mapbox[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mapbox[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?manifest[-_]?app[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?manifest[-_]?app[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mandrill[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?managementapiaccesstoken["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?management[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?manage[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?manage[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailgun[-_]?secret[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailgun[-_]?pub[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailgun[-_]?pub[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailgun[-_]?priv[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailgun[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailgun[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailgun[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailer[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailchimp[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mailchimp[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?mail[_-]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?magento[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?magento[-_]?auth[-_]?username ["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?magento[-_]?auth[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?lottie[-_]?upload[-_]?cert[-_]?key[-_]?store[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?lottie[-_]?upload[-_]?cert[-_]?key[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?lottie[-_]?s3[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?lottie[-_]?happo[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?lottie[-_]?happo[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?looker[-_]?test[-_]?runner[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?ll[-_]?shared[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
    ]
    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result
# 529-418=111


def find_sensitive_info_6(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [
        re.compile(r'["\']?ll[-_]?publish[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?linux[-_]?signing[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(
            r'["\']?linkedin[-_]?client[-_]?secretor lottie[-_]?s3[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
            re.IGNORECASE),
        re.compile(r'["\']?lighthouse[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?lektor[-_]?deploy[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?lektor[-_]?deploy[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?leanplum[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?kxoltsn3vogdop92m["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?kubeconfig["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?kubecfg[-_]?s3[-_]?path["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?kovan[-_]?private[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?keystore[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?kafka[-_]?rest[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?kafka[-_]?instance[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?kafka[-_]?admin[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?jwt[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?jdbc:mysql["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?jdbc[-_]?host["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?jdbc[-_]?databaseurl["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?itest[-_]?gh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ios[-_]?docs[-_]?deploy[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?internal[-_]?secrets["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?integration[-_]?test[-_]?appid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?integration[-_]?test[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?index[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ij[-_]?repo[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ij[-_]?repo[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?hub[-_]?dxia2[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?homebrew[-_]?github[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?hockeyapp[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?heroku[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?heroku[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?heroku[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?hb[-_]?codesign[-_]?key[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?hb[-_]?codesign[-_]?gpg[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?hab[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?hab[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?grgit[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gren[-_]?github[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gradle[-_]?signing[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gradle[-_]?signing[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gradle[-_]?publish[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gradle[-_]?publish[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gpg[-_]?secret[-_]?keys["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gpg[-_]?private[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gpg[-_]?passphrase["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gpg[-_]?ownertrust["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gpg[-_]?keyname["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gpg[-_]?key[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?google[-_]?private[-_]?key[-_]?(id)?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?google[-_]?maps[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?google[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?google[-_]?client[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?google[-_]?client[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?google[-_]?account[-_]?type["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gogs[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gitlab[-_]?user[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?tokens["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?repo["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?release[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?pwd["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?oauth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?oauth["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?hunter[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?hunter[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?deployment[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?deploy[-_]?hb[-_]?doc[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?auth["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?github[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?git[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?git[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?git[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?git[-_]?committer[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?git[-_]?committer[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?git[-_]?author[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?git[-_]?author[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ghost[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ghb[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?unstable[-_]?oauth[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
    ]
    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result
#634-530=104


def find_sensitive_info_7(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [
        re.compile(r'["\']?gh[-_]?repo[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?oauth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?oauth[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?next[-_]?unstable[-_]?oauth[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?next[-_]?unstable[-_]?oauth[-_]?client[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?next[-_]?oauth[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gh[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gcs[-_]?bucket["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gcr[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gcloud[-_]?service[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gcloud[-_]?project["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?gcloud[-_]?bucket["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ftp[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ftp[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ftp[-_]?pw["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ftp[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ftp[-_]?login["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ftp[-_]?host["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?fossa[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?flickr[-_]?api[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?flickr[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?flask[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?firefox[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?firebase[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?firebase[-_]?project[-_]?develop["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?firebase[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?firebase[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?firebase[-_]?api[-_]?json["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?file[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?exp[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?eureka[-_]?awssecretkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?env[-_]?sonatype[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?env[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?env[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?env[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?env[-_]?heroku[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?env[-_]?github[-_]?oauth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?end[-_]?user[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?encryption[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?elasticsearch[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?elastic[-_]?cloud[-_]?auth["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?dsonar[-_]?projectkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?dsonar[-_]?login["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?droplet[-_]?travis[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?dropbox[-_]?oauth[-_]?bearer["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?doordash[-_]?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?dockerhubpassword["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?dockerhub[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?docker[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?docker[-_]?postgres[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?docker[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?docker[-_]?passwd["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?docker[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?docker[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?docker[-_]?hub[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?digitalocean[-_]?ssh[-_]?key[-_]?ids["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?digitalocean[-_]?ssh[-_]?key[-_]?body["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?digitalocean[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?dgpg[-_]?passphrase["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?deploy[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?deploy[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?deploy[-_]?secure["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?deploy[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ddgc[-_]?github[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ddg[-_]?test[-_]?email[-_]?pw["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ddg[-_]?test[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?db[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?db[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?db[-_]?pw["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?db[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?db[-_]?host["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?db[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?db[-_]?connection["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?datadog[-_]?app[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?datadog[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?database[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?database[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?database[-_]?port["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?database[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?database[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?database[-_]?host["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?danger[-_]?github[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cypress[-_]?record[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?coverity[-_]?scan[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?coveralls[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?coveralls[-_]?repo[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?coveralls[-_]?api[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cos[-_]?secrets["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?conversation[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?conversation[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?contentful[-_]?v2[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?contentful[-_]?test[-_]?org[-_]?cma[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?contentful[-_]?php[-_]?management[-_]?test[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(
            r'["\']?contentful[-_]?management[-_]?api[-_]?access[-_]?token[-_]?new["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
            re.IGNORECASE),
        re.compile(r'["\']?contentful[-_]?management[-_]?api[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?contentful[-_]?integration[-_]?management[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?contentful[-_]?cma[-_]?test[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?contentful[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?consumerkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?consumer[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?conekta[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?coding[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
    ]
    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result
# 762-636=126


def find_sensitive_info_8(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
    regex_list = [

        re.compile(r'["\']?cloudflare[-_]?auth[-_]?email["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudflare[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?service[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?processed[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?parsed[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?order[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?instance["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?audited[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloudant[-_]?archived[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cloud[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?clojars[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cli[-_]?e2e[-_]?cma[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?claimr[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?claimr[-_]?superuser["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?claimr[-_]?db["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?claimr[-_]?database["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ci[-_]?user[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ci[-_]?server[-_]?name["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ci[-_]?registry[-_]?user["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ci[-_]?project[-_]?url["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ci[-_]?deploy[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?chrome[-_]?refresh[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?chrome[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cheverny[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cf[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?certificate[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?censys[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cattle[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cattle[-_]?agent[-_]?instance[-_]?auth["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cattle[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cargo[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?cache[-_]?s3[-_]?secret[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bx[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bx[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bundlesize[-_]?github[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?built[-_]?branch[-_]?deploy[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bucketeer[-_]?aws[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?bucketeer[-_]?aws[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?browserstack[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?browser[-_]?stack[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?brackets[-_]?repo[-_]?oauth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bluemix[-_]?username["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bluemix[-_]?pwd["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bluemix[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bluemix[-_]?pass[-_]?prod["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bluemix[-_]?pass["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bluemix[-_]?auth["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bluemix[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bintraykey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bintray[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bintray[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bintray[-_]?gpg[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bintray[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?bintray[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?b2[-_]?bucket["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?b2[-_]?app[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?awssecretkey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?awscn[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?awscn[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?awsaccesskeyid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?ses[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?ses[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?secrets["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?secret[_-]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?config[-_]?secretaccesskey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?config[-_]?accesskeyid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?access[_-]?key[_-]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?access[_-]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aws[_-]?access["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?author[-_]?npm[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?author[-_]?email[-_]?addr["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?auth0[-_]?client[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?auth0[-_]?api[-_]?clientsecret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?auth[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?assistant[-_]?iam[-_]?apikey["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?artifacts[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?artifacts[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?artifacts[-_]?bucket["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?artifacts[-_]?aws[-_]?secret[-_]?access[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?artifacts[-_]?aws[-_]?access[-_]?key[-_]?id["\']?\s*[=:]\s*["\']?[\w-]+["\']?',
                   re.IGNORECASE),
        re.compile(r'["\']?artifactory[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?argos[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?apple[-_]?id[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?appclientsecret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?app[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?app[-_]?secrete["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?app[-_]?report[-_]?token[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?app[-_]?bucket[-_]?perm["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?apigw[-_]?access[-_]?token["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?apiary[-_]?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?api[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?api[-_]?key[-_]?sid["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?api[-_]?key[-_]?secret["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?api[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aos[-_]?sec["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?aos[-_]?key["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?ansible[-_]?vault[-_]?password["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
    ]
    result = []
    for regex in regex_list:
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
    return result
# 764-899 = 135


def find_sensitive_info_9(text)->list:
    """
    敏感信息提取
    :param text:
    :return:
    """
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
        re.compile(r'["\']?[\w_-]*?password[\w_-]*?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?[\w_-]*?username[\w_-]*?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?[\w_-]*?accesskey[\w_-]*?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?[\w_-]*?secret[\w_-]*?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?[\w_-]*?bucket[\w_-]*?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
        re.compile(r'["\']?[\w_-]*?token[\w_-]*?["\']?\s*[=:]\s*["\']?[\w-]+["\']?', re.IGNORECASE),
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
        matches = re.findall(regex, text)
        if matches:
            result.extend(matches)
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


# 单个函数执行（纯单进程，无任何并行逻辑）
def run_single_func(func, text):
    try:
        result = func(text)
        return result[:100] if isinstance(result, list) else []
    except Exception as e:
        print(f"函数 {func.__name__} 出错: {str(e)}")
        return []


# 单进程执行所有函数（彻底去掉多进程）
def find_all_info_by_rex(text: str) -> list:
    if not text:
        return []
    text = text.lower()
    if text.startswith("<!doctype html>"):
        return []

    # 定义需要执行的函数列表
    scan_functions = [
        find_id_cards,
        find_comments_sensitive_info,
        find_phone_numbers,
        find_email_addresses,
        find_access_keys,
        find_swagger,
        find_js_map_files,
        find_sensitive_info_1,
        find_sensitive_info_2,
        find_sensitive_info_3,
        find_sensitive_info_4,
        find_sensitive_info_5,
        find_sensitive_info_6,
        find_sensitive_info_7,
        find_sensitive_info_8,
        find_sensitive_info_9
    ]
    total = len(scan_functions)
    print(f"共{total}个函数，开始扫描...")

    results = []
    global_timeout = 20  # 全局超时20秒
    start_time = time.time()

    # 单进程串行执行所有函数
    for func in scan_functions:
        # 检查是否已超时
        if time.time() - start_time > global_timeout:
            print("全局超时！停止后续函数执行")
            break

        # 直接调用函数（无进程池，无异步）
        func_result = run_single_func(func, text)
        results.extend(func_result)

    return check_available(results)


