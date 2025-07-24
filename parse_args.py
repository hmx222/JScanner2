import argparse
import ast


def parse_args():
    """解析用户输入的命令行参数"""
    parser = argparse.ArgumentParser(description="网站扫描工具 - 支持URL扫描、批量处理及结果导出")

    # 核心目标参数（必选其一）
    parser.add_argument('-u', '--url', type=str, help="输入带有http/https的单个网站URL（如：https://example.com）")
    parser.add_argument('-b', '--batch', type=str, help="批量扫描的URL文件绝对路径（每行一个URL）")

    # 扫描配置参数
    parser.add_argument('-H', '--height', type=int, default=2, help="扫描深度（默认：2）")
    parser.add_argument('-t', '--thread_num', type=int, default=10, help="并发线程数（默认：10）")

    # 网络与浏览器参数
    parser.add_argument('-p', '--proxy', type=str,
                        help="代理服务器（格式：http://127.0.0.1:12335 或 socks5://127.0.0.1:1080）")
    parser.add_argument('-v', '--visible', action='store_true', default=False ,help="显示浏览器窗口（默认：无头模式，不显示窗口）")

    # 结果导出参数
    parser.add_argument('-e', '--excel', type=str, help="导出结果到Excel文件（如：./result.xlsx）")

    # 对于重复的结果，是否使用对title的去重
    parser.add_argument('-d', '--de_duplication_title', action='store_true', default=True,
                        help="对于重复的结果，是否使用对title的去重（默认：True）")

    # 对于重复的结果，是否使用hash的去重
    parser.add_argument('-s', '--de_duplication_hash', type=str, default=0.90,
                        help="对于重复的结果，是否使用对DOM SimHash的去重（默认：0.90）")

    # 对于重复的结果，是否使用返回值长度的去重
    parser.add_argument('-l', '--de_duplication_length', action='store_true', default=True,
                        help="对于重复的结果，是否使用对返回值长度的去重（默认：True）")

    # 对于重复的结果，是否使用对返回值相似度的去重
    parser.add_argument('-f', '--de_duplication_similarity', type=str, default=0.65,
                        help="对于重复的结果，是否使用对返回值相似度的去重（默认：0.65）")

    # 隐藏的header参数
    # parser.add_argument(
    #     '-r', '--header',
    #     type=ast.literal_eval,
    #     default="{'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.0.0 Safari/537.36'}",
    #     help="自定义请求头（格式：\"{'Cookie':'xxx','User-Agent':'xxx'}\"）"
    # )

    # 检查参数合法性（确保url和batch不同时为空）
    args = parser.parse_args()
    if not args.url and not args.batch:
        parser.error("必须指定 -u/--url（单个URL）或 -b/--batch（批量文件）中的一个")

    return args