import requests

from config.config import FEISHU_WEBHOOK, proxies


def send_feishu_notify(title, content=""):
    if not FEISHU_WEBHOOK:
        return
    try:
        requests.post(FEISHU_WEBHOOK,
                      json={"msg_type": "text", "content": {"text": f"{title}\n{content}"}},
                      timeout=10,
                      proxies=proxies)
    except:
        pass