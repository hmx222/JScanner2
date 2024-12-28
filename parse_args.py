import argparse
import ast


def parse_args():
    """用户输入"""
    parse = argparse.ArgumentParser(description="hi 你好")
    parse.add_argument('-u', '--url',  type=str, help="输入带有http/https的网站URL")
    parse.add_argument('-r', '--header', type=ast.literal_eval,
                       default="{'user-Agent':'Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1'}",
                       help="输入user-agent,格式为\"{\'cookie\':\'xxxx\',\'user-Agent\':\'xxxx\',\'xxxx\':\'xxxx\'}\"")
    parse.add_argument('-l', '--level', type=int, default=0, help="输入最大递减数，默认为0表示全递减")
    parse.add_argument('-H', '--height', type=int, default=0, help="查找深度")
    parse.add_argument('-w', '--wait', type=int, default=3, help="网站请求超时等待时间")
    parse.add_argument('-a', '--appoint', type=str, help="读取指定文件")
    parse.add_argument('-T', '--time', type=float, default=0, help="请求间隔延时")
    parse.add_argument('-B', '--blackStatus', type=ast.literal_eval, default=(404, 502, 500),
                       help="输入您不想要获得的状态码,格式：-s \"(xxx,xxx)\"")
    parse.add_argument('-o', '--out', type=str, help="输出为Excel表格")
    parse.add_argument('-p','--proxy',type=str,help="设置代理，格式：-p xxx.xxx.xxx.xxx:端口,如果代理需要认证，格式为：username:password@xxx.xxx.xxx.xxx:xxxx")
    parse.add_argument('-d','--redup',type=str,help="需要配合-o来进行输出，有标题，状态码，返回值长度三者可以选择，选中后会对其进行去重操作，默认会对URL进行去重，不可以多选。")
    parse.add_argument('-b','--batch',type=str,help="填入文件绝对路径，完成批量扫描，可自动去除空白行")
    # parse.add_argument('-f','--findsomething',type=str,help="将findsomething插件当中的IncompletePath与Path放入文本文件，选项后面接路径,当然你也可以与-u一起使用")
    return parse.parse_args()

