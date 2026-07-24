import argparse
import re


def str_to_float(value):
    """
    将字符串转为浮点数，并验证范围在 0.0-1.0 之间

    用于 argparse 的自定义类型转换器。

    Args:
        value: 输入的字符串值

    Returns:
        float: 转换后的浮点数

    Raises:
        argparse.ArgumentTypeError: 值不在有效范围内或无法转换
    """
    try:
        val = float(value)
        # 验证阈值范围
        if not 0.0 <= val <= 1.0:
            raise argparse.ArgumentTypeError("阈值必须在 0.0 到 1.0 之间")
        return val
    except ValueError:
        raise argparse.ArgumentTypeError("必须输入有效的浮点数")


def parse_headers(header_str):
    """
    解析请求头字符串为字典格式

    支持单引号/双引号包裹的键值对，格式如 'key':'value' 或 "key":"value"。

    Args:
        header_str: 请求头字符串

    Returns:
        dict: 解析后的请求头字典
    """
    # 正则匹配引号包裹的键值对
    pattern = r"['\"]([^'\"]+)['\"]:['\"]([^'\"]+)['\"]"
    matches = re.findall(pattern, header_str)

    headers = {}
    for key, value in matches:
        headers[key.strip()] = value.strip()

    return headers


def parse_args():
    """
    解析命令行参数

    定义并解析所有命令行参数，返回解析结果对象。

    Returns:
        argparse.Namespace: 解析后的命令行参数对象，包含以下属性：
            - url: 目标网站 URL
            - height: 扫描深度
            - thread_num: 并发线程数
            - proxy: 代理服务器地址
            - visible: 是否显示浏览器窗口
            - analyzeSensitiveInfoRex: 是否使用正则分析敏感信息
            - findparam: 是否自动解析 API 参数
            - fastscan: 是否启用快速扫描模式
            - analyzeSensitiveInfoAI: 是否使用 AI 分析敏感信息
    """
    parser = argparse.ArgumentParser(description="网站扫描工具 - 支持URL扫描、批量处理及结果导出")

    # 核心目标参数（必选其一）
    parser.add_argument('-u', '--url', type=lambda x: x.strip().rstrip('\r'),
                        help="输入带有http/https的单个网站URL（如：https://example.com）")
    # 扫描配置参数
    parser.add_argument('-H', '--height', type=int, default=2, help="扫描深度（默认：2）")
    parser.add_argument('-t', '--thread_num', type=int, default=10, help="并发线程数（默认：10）")

    # 网络与浏览器参数
    parser.add_argument('-p', '--proxy', type=str,
                        help="代理服务器（格式：http://127.0.0.1:12335 或 socks5://127.0.0.1:1080）")

    parser.add_argument('-v', '--visible', action='store_true', default=False,
                        help="显示浏览器窗口（默认：无头模式，不显示窗口）")

    parser.add_argument('-asir', '--analyzeSensitiveInfoRex', default=False, action='store_true',
                        help="是否利用正则表达式收集JS敏感信息")

    parser.add_argument('-fp', '--findparam', action='store_true', default=False,
                        help="自动解析api参数")

    parser.add_argument('-fs', '--fastscan', action='store_true', default=False, help="是否使用快速扫描模式")

    parser.add_argument('-asia', '--analyzeSensitiveInfoAI', action='store_true', default=False,
                        help="是否使用AI模型分析敏感信息")

    args = parser.parse_args()

    return args