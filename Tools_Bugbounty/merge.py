import pandas as pd
import glob
import os


def merge_excel_files():
    # 1. 设置配置
    # 待合并文件所在的文件夹路径 ('.' 表示当前代码所在文件夹)
    folder_path = '.'
    # 合并后输出的文件名
    output_file = 'merged_result.xlsx'
    # 您指定的目标表头
    target_columns = ['id', 'Domain', 'URL', 'Path', 'sourceURL']

    # 2. 获取所有 .xlsx 文件
    all_files = glob.glob(os.path.join(folder_path, "*.xlsx"))

    # 过滤掉可能存在的临时文件或输出文件本身
    all_files = [f for f in all_files if not os.path.basename(f).startswith('~$')
                 and os.path.basename(f) != output_file]

    if not all_files:
        print("未找到可合并的 Excel (.xlsx) 文件。")
        return

    print(f"找到 {len(all_files)} 个文件，准备开始合并...")

    df_list = []

    for filename in all_files:
        try:
            # 读取 Excel 文件
            df = pd.read_excel(filename)

            # 3. 数据处理：确保列符合要求
            # reindex 会保留存在的列，对于缺失的列会自动填充为空值 (NaN)
            # 这样即使源文件缺少某些列，程序也不会报错，且结果表头统一
            df_processed = df.reindex(columns=target_columns)

            df_list.append(df_processed)
            print(f"已处理: {os.path.basename(filename)}")

        except Exception as e:
            print(f"读取文件 {filename} 时出错: {e}")

    if df_list:
        # 4. 合并数据
        final_df = pd.concat(df_list, ignore_index=True)

        # 5. 保存结果
        final_df.to_excel(output_file, index=False)
        print("-" * 30)
        print(f"合并完成！共合并 {len(final_df)} 行数据。")
        print(f"文件已保存为: {os.path.abspath(output_file)}")
    else:
        print("没有数据被合并。")


if __name__ == "__main__":
    merge_excel_files()