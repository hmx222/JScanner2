import os
from random import random
import xlsxwriter as xw

import pandas as pd


def read(filename: str) -> list:
    """文件读取"""
    with open(filename, 'r') as file:
        lines = [line.strip().split(" ")[0] for line in file if line.strip() and line.strip()[0] != "#"]
        lines = [line for line in lines if line] # 过滤空白元素
        return lines


def write_excel(dataList,name):
    # 生成文件名（当前时间戳 + 随机数）
    fileName = name + str(random.randint(1000, 9999))
    # 创建工作簿
    workbook = xw.Workbook(str(fileName) + ".xlsx")
    # 创建子表
    worksheet1 = workbook.add_worksheet("sheet1")
    # 激活表
    worksheet1.activate()
    # 设置表头
    sheet_header = ['URL', '状态码', '返回值长度', '标题']
    # 从A1单元格开始写入表头
    worksheet1.write_row('A1', sheet_header)
    # 设置第一列的宽度为 50
    worksheet1.set_column(0, 0, 50)
    # 遍历数据列表
    for i in range(len(dataList)):
        # 获取当前数据的 URL、状态码、内容长度和标题
        try:
            writeUrl, statusCode, contentLength, url_title = dataList[i]
        except ValueError:
            # 假如不足四个元素就直接忽略
            continue
        else:
            # 在表格中写入 URL、状态码、内容长度和标题
            worksheet1.write(i + 1, 0, writeUrl)
            worksheet1.write(i + 1, 1, statusCode)
            worksheet1.write(i + 1, 2, contentLength)
            worksheet1.write(i + 1, 3, url_title)
    # 关闭工作簿
    workbook.close()

    return fileName

def remove_duplicates(excel_name, column_name,to_name):
    """对指定的列进行去重"""
    # 读取Excel文件
    data = pd.read_excel(excel_name)

    unique_data = data.drop_duplicates(subset=column_name)

    file_name = to_name + str(random.randint(1000, 9999))
    # 将去重后的数据写入新的Excel文件
    unique_data.to_excel(file_name, index=False)
    # 删除源表格
    os.remove(excel_name)