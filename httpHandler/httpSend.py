import warnings

import requests
warnings.filterwarnings("ignore")

def send_http(url, method, headers)->requests.Response:
    """
    发送HTTP请求的函数
    参数:
    url: 请求的URL
    method: 请求的方法，如GET、POST等
    headers: 请求的头部信息
    param: 请求的参数
    path: 请求的路径信息
    返回:
    响应对象
    """
    try:
        # send request,default timeout is 5s
        response = requests.request(url=url, method=method, headers=headers,verify=False,timeout=5)
    except:
        pass
    else:
        return response




