import os
import re

import chardet


def read(file_path):
    """
    读取文件内容，自动检测编码并返回去除空白后的行列表

    Args:
        file_path: 文件路径

    Returns:
        list: 清理后的行列表（每行去除首尾空白和多余空格）
    """
    # 检查文件是否存在
    if not os.path.isfile(file_path):
        return []

    # 读取文件前 1000 字节用于检测编码
    with open(file_path, 'rb') as f:
        raw_data = f.read(1000)
        result = chardet.detect(raw_data)
        encoding = result['encoding']

    # 以检测到的编码重新读取完整文件
    with open(file_path, 'r', encoding=encoding) as f:
        content_list = f.readlines()

    # 清理每行：合并连续空白为单个空格，去除首尾空白
    cleaned_content_list = []
    for line in content_list:
        cleaned_line = re.sub(r'\s+', ' ', line).strip()
        cleaned_content_list.append(cleaned_line)

    return cleaned_content_list
