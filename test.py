from DrissionPage import Chromium

tab = Chromium().latest_tab
tab.get('http://DrissionPage.cn',proxies={"http":"127.0.0.1:12334",
                                                "https":"127.0.0.1:12334"})