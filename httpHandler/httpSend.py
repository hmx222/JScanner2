import warnings

import requests
warnings.filterwarnings("ignore")

def send_http(url, method, headers)->requests.Response:

    try:
        # send request,default timeout is 5s
        response = requests.request(url=url, method=method, headers=headers,verify=False,timeout=3)
    except:
        pass
    else:
        return response




