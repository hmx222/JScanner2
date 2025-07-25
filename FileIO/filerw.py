import os
import re

import chardet
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, Border, Side
from openpyxl.utils import get_column_letter
import json


def read(file_path):
    # 先以二进制模式读取文件一小部分，用于检测编码
    with open(file_path, 'rb') as f:
        raw_data = f.read(1000)  # 读取前1000字节数据
        result = chardet.detect(raw_data)  # 使用chardet库检测编码
        encoding = result['encoding']  # 获取检测到的编码

    # 再以检测到的编码打开文件读取全部内容
    with open(file_path, 'r', encoding=encoding) as f:
        content_list = f.readlines()  # 读取文件内容为列表，每个元素是一行文本

    # 去除每行中的异常空格
    cleaned_content_list = []
    for line in content_list:
        # 使用正则表达式去除多余的空格，包括行首行尾空格以及连续的空格
        cleaned_line = re.sub(r'\s+', ' ', line).strip()
        cleaned_content_list.append(cleaned_line)

    return cleaned_content_list


def write2json(file_path, json_str):
    # 检查文件是否存在，如果不存在则初始化为一个空列表
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        existing_data = []
    else:
        with open(file_path, 'r', encoding='utf-8') as file:
            existing_data = json.load(file)

    new_data = json.loads(json_str)

    if isinstance(existing_data, list):
        existing_data.append(new_data)
    else:
        print(f"写入失败：{json_str}")

    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(existing_data, file, ensure_ascii=False, indent=4)


def clear_or_create_file(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write('')






