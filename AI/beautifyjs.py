import subprocess
import tempfile
import os

from config import config


def format_code(
        unformatted_code,
        parser="babel"
):
    """
    使用prettier格式化代码，解决Windows下的编码问题

    参数:
        unformatted_code (str): 未格式化的代码字符串
        parser (str): 代码解析器，默认"babel"（适用于JavaScript）
        prettier_path (str): prettier.cmd的绝对路径，若为None则自动查找

    返回:
        str: 格式化后的代码
    """
    prettier_path = config.prettier_path

    # 创建临时文件并以UTF-8编码写入（解决写入时的编码问题）
    with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.js',
            delete=False,
            encoding='utf-8'  # 强制UTF-8编码写入
    ) as temp_file:
        temp_file.write(unformatted_code)
        temp_file_path = temp_file.name

    try:
        # 调用prettier命令行工具，指定UTF-8编码解析输出（解决读取时的编码问题）
        result = subprocess.run(
            [
                prettier_path,
                "--parser", parser,
                "--print-width", "60",  # 每行最大字符数
                "--tab-width", "2",  # 缩进空格数
                "--single-quote", "false",  # 使用双引号
                temp_file_path
            ],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'  # 强制UTF-8编码读取输出
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        # 捕获格式化错误（如代码语法错误）
        raise ValueError(f"代码格式化失败: {e.stderr}") from e

    finally:
        # 确保临时文件被删除
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


# ------------------------------
# 使用示例
# ------------------------------
if __name__ == "__main__":
    # 测试代码（包含多种特殊字符）
    test_code = """
    function helloWorld(){
    console.log("Hello, World! 测试特殊字符：ä è ñ ç 中文 日本語");
    let data = {id:1,name:"test",value:3.14};//131231
    return data;
    }
    """

    try:
        # 替换为你的prettier.cmd实际路径
        formatted_code = format_code(
            test_code,
            prettier_path=r"C:\Users\Cheng\AppData\Roaming\npm\prettier.cmd"
        )
        print("格式化成功：")
        print("-" * 50)
        print(formatted_code)
        print("-" * 50)
    except Exception as e:
        print(f"处理失败：{str(e)}")
