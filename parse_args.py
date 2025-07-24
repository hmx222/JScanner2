import argparse


def str_to_float(value):
    """将字符串转为浮点数，并验证范围 (0.0-1.0)"""
    try:
        val = float(value)
        if not 0.0 <= val <= 1.0:
            raise argparse.ArgumentTypeError("阈值必须在 0.0 到 1.0 之间")
        return val
    except ValueError:
        raise argparse.ArgumentTypeError("必须输入有效的浮点数")


def parse_args():
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
    parser.add_argument('-v', '--visible', action='store_true', default=False,
                        help="显示浏览器窗口（默认：无头模式，不显示窗口）")

    # 结果导出参数
    parser.add_argument('-e', '--excel', type=str, help="导出结果到Excel文件（如：./result.xlsx）")

    # 去重参数优化方案
    parser.add_argument('-d', '--de_duplication_title', action='store_true', default=False,
                        help="启用标题去重（默认关闭）")

    parser.add_argument('-s', '--de_duplication_hash', type=str_to_float, default=None,  # 关键修改
                        help="启用DOM SimHash去重并设置阈值（默认关闭，启用示例：-s 0.8）")

    parser.add_argument('-l', '--de_duplication_length', action='store_true', default=False,
                        help="启用长度去重（默认关闭）")

    parser.add_argument('-f', '--de_duplication_similarity', type=str_to_float, default=None,  # 关键修改
                        help="启用文本相似度去重并设置阈值（默认关闭，启用示例：-f 0.7）")

    args = parser.parse_args()

    # 动态开启去重功能（当用户指定阈值时启用）
    args.enable_hash_dedup = args.de_duplication_hash is not None
    args.enable_similarity_dedup = args.de_duplication_similarity is not None

    if not args.url and not args.batch:
        parser.error("必须指定 -u/--url（单个URL）或 -b/--batch（批量文件）中的一个")

    return args