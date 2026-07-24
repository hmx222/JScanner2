import re

import requests

from config.config import FEISHU_WEBHOOK, proxies


def remove_html_tags(html_text: str) -> str:
    """
    移除 HTML 文本中的标签，保留 <pre> 标签内的内容

    Args:
        html_text: 可能包含 HTML 标签的文本

    Returns:
        str: 去除 HTML 标签后的纯文本
    """
    if not html_text or not isinstance(html_text, str): return ""
    html_text_stripped = html_text.strip()  # 去除首尾空白
    if len(html_text_stripped) == 0: return ""

    has_html_tags = html_text_stripped.startswith('<') and '>' in html_text_stripped[:500]  # 检查前500字符有无标签
    if not has_html_tags: return html_text

    pre_pattern = r'<pre[^>]*>(.*?)</pre>'  # 匹配pre标签的正则
    pre_matches = re.findall(pre_pattern, html_text, re.DOTALL | re.IGNORECASE)  # 提取所有pre内容
    if pre_matches: return '\n'.join(pre_matches).strip()

    return html_text


def send_feishu_notify(title, content=""):
    """
    发送飞书机器人通知消息

    通过飞书 Webhook 发送文本消息通知。静默失败：网络异常或配置为空时不抛出异常。

    Args:
        title: 消息标题
        content: 消息正文内容（可选）
    """
    if not FEISHU_WEBHOOK:
        return
    try:
        requests.post(FEISHU_WEBHOOK,  # 发送飞书通知请求
                      json={"msg_type": "text", "content": {"text": f"{title}\n{content}"}},  # 构造消息体
                      timeout=10,  # 超时10秒
                      proxies=proxies)  # 使用代理配置
    except:  # 捕获所有异常，静默失败
        pass
