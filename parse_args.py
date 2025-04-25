import argparse
import ast


def parse_args():
    """user input"""
    parse = argparse.ArgumentParser(description="hi 你好")
    parse.add_argument('-u', '--url',  type=str, help="输入带有http/https的网站URL")
    # parse.add_argument('-r', '--header', type=ast.literal_eval,
    #                    default="{'user-Agent':'Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1'}",
    #                    help="输入user-agent,格式为\"{\'cookie\':\'xxxx\',\'user-Agent\':\'xxxx\',\'xxxx\':\'xxxx\'}\"")
    parse.add_argument('-H', '--height', type=int, default=2, help="查找深度")
    parse.add_argument('-b','--batch',type=str,help="填入文件绝对路径，完成批量扫描，可自动去除空白行")
    parse.add_argument('-e','--excel',type=str,help="输出到excel文件当中")
    parse.add_argument('-t','--thread_num',type=int,default=10,help="线程数")
    parse.add_argument('-p','--proxy',type=str,help="代理网络（127.0.0.1:12335）")
    return parse.parse_args()

