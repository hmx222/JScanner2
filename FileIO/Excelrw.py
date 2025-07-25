from openpyxl.styles import Alignment, Font, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.workbook import Workbook
from openpyxl import load_workbook
import os
import traceback

# 这段代码是AI写的，嘿嘿😁，AI真好用
def sort_paths(data):
    """按路径层级排序，确保相同前缀路径相邻，为合并做准备"""
    return sorted(data, key=lambda x: x['path'].strip('/').split('/'))


class SafePathExcelGenerator:
    def __init__(self, output_file):
        self.output_file = output_file
        self.wb = None  # 工作簿实例
        self.ws = None  # 工作表实例
        self.all_data = []  # 存储所有有效数据
        self.existing_urls = set()  # 去重用的URL集合

        # 样式定义
        self.alignment = Alignment(horizontal="center", vertical="center", wrap_text=False)
        self.header_font = Font(bold=True, name="Arial")
        self.thin_border = Border(
            left=Side(style="thin"),
            right=Side(style="thin"),
            top=Side(style="thin"),
            bottom=Side(style="thin")
        )

        # 初始化文件，确保文件格式正确
        self._init_file_safely()

    def _init_file_safely(self):
        """安全初始化文件，处理旧文件损坏等情况"""
        try:
            if os.path.exists(self.output_file):
                # 尝试加载现有文件，若失败则创建新文件
                self.wb = load_workbook(self.output_file, read_only=False, data_only=False)
                # 确保工作表存在，不存在则创建
                self.ws = self.wb["Paths"] if "Paths" in self.wb.sheetnames else self.wb.create_sheet("Paths")
                # 读取历史数据，做容错处理
                self._load_existing_data_safely()
            else:
                # 创建全新文件
                self.wb = Workbook()
                self.ws = self.wb.active
                self.ws.title = "Paths"
        except Exception as e:
            print(f"初始化文件失败，创建新文件：{str(e)}")
            # 无论加载失败原因，都创建新文件
            self.wb = Workbook()
            self.ws = self.wb.active
            self.ws.title = "Paths"

    def _load_existing_data_safely(self):
        """安全加载历史数据，跳过格式错误的行和单元格"""
        try:
            # 从第2行开始读取（跳过表头）
            for row in range(2, self.ws.max_row + 1):
                # 跳过空行
                if all(self.ws.cell(row=row, column=col).value is None for col in range(1, 4)):
                    continue
                # 读取URL（第3列）用于去重
                url_cell = self.ws.cell(row=row, column=3)
                url = str(url_cell.value).strip() if url_cell.value is not None else ""
                if url:
                    self.existing_urls.add(url)
                # 读取核心数据，容错处理
                self.all_data.append({
                    "domain": str(self.ws.cell(row=row, column=2).value).strip() if self.ws.cell(row=row, column=2).value is not None else "",
                    "url": url,
                    "path": str(self.ws.cell(row=row, column=4).value).strip() if self.ws.cell(row=row, column=4).value is not None else "",
                    "status": str(self.ws.cell(row=row, column=5).value).strip() if self.ws.cell(row=row, column=5).value is not None else "",
                    "length": str(self.ws.cell(row=row, column=6).value).strip() if self.ws.cell(row=row, column=6).value is not None else "",
                    "title": str(self.ws.cell(row=row, column=7).value).strip() if self.ws.cell(row=row, column=7).value is not None else ""
                })
        except Exception as e:
            print(f"⚠️ 加载历史数据时跳过错误行：{str(e)}")

    def save(self):
        """安全保存文件，确保资源释放，避免文件锁定"""
        try:
            if self.wb:
                # 先关闭可能存在的只读模式
                if hasattr(self.wb, 'read_only') and self.wb.read_only:
                    self.wb.read_only = False
                # 保存文件
                self.wb.save(self.output_file)
                print(f"✅ 已成功保存至：{self.output_file}")
                # 保存后重新加载，确保下次操作基于最新文件
                self._init_file_safely()
        except Exception as e:
            print(f"❌ 保存失败：{str(e)}")
            # 尝试创建备份文件
            backup_file = self.output_file.replace(".xlsx", "_backup.xlsx")
            self.wb.save(backup_file)
            print(f"📌 已创建备份文件：{backup_file}")

    def _split_path_levels(self, path):
        """拆分路径，处理空路径等异常情况"""
        if not path or str(path).strip() in ('', '/', 'None'):
            return []
        return str(path).strip('/').split('/')

    def _get_max_depth(self):
        """计算所有路径的最大层级深度"""
        max_depth = 0
        for item in self.all_data:
            try:
                levels = self._split_path_levels(item['path'])
                max_depth = max(max_depth, len(levels))
            except:
                continue
        return max_depth

    def _merge_and_center(self, col_start):
        """合并指定列中连续相同值的单元格，确保合并逻辑正确"""
        if self.ws.max_row < 2:
            return
        start_row = 2
        prev_val = self.ws.cell(row=start_row, column=col_start).value
        for row in range(3, self.ws.max_row + 1):
            current_val = self.ws.cell(row=row, column=col_start).value
            # 处理空值，空值视为相同以便合并（可根据实际需求调整）
            if (prev_val is None and current_val is None) or (prev_val == current_val):
                continue
            else:
                if start_row < row - 1:
                    self.ws.merge_cells(start_row=start_row, start_column=col_start,
                                       end_row=row - 1, end_column=col_start)
                start_row = row
                prev_val = current_val
        # 处理最后一段连续相同值的单元格
        if start_row < self.ws.max_row:
            self.ws.merge_cells(start_row=start_row, start_column=col_start,
                               end_row=self.ws.max_row, end_column=col_start)

    def append_data(self, new_scan_list, auto_save=True):
        """追加数据，包含数据校验、排序、表格重构等逻辑"""
        # 1. 过滤无效数据，确保字段类型正确
        new_data = []
        for item in new_scan_list:
            try:
                if item["is_valid"] == 1:
                    continue
                url = str(item.get("url", "")).strip()
                if not url or url in self.existing_urls:
                    continue
                # 确保所有字段转为字符串
                new_item = {
                    "domain": str(item.get("domain", "")).strip(),
                    "url": url,
                    "path": str(item.get("path", "")).strip(),
                    "status": str(item.get("status", "")).strip(),
                    "length": str(item.get("length", "0")).strip(),
                    "title": str(item.get("title", "")).strip()
                }
                new_data.append(new_item)
                self.existing_urls.add(url)
            except Exception as e:
                print(f"⚠️ 跳过无效数据：{str(e)}")

        if not new_data:
            print("ℹ️ 无新数据可写入")
            return

        # 2. 合并数据并按路径层级排序
        self.all_data.extend(new_data)
        self.all_data = sort_paths(self.all_data)

        # 3. 准备表头
        max_depth = self._get_max_depth()
        base_headers = ["id", "Domain", "url", "path", "Status", "Length", "Title"]
        level_headers = [f"第{i}级路径" for i in range(1, max_depth + 1)]
        all_headers = base_headers + level_headers

        # 4. 清空旧数据，避免格式残留
        try:
            if self.ws.max_row > 0:
                self.ws.delete_rows(1, self.ws.max_row)
        except:
            self.ws = self.wb.create_sheet("Paths")  # 创建新工作表

        # 5. 写入表头并设置样式
        self.ws.append(all_headers)
        for col_idx in range(1, len(all_headers) + 1):
            cell = self.ws.cell(row=1, column=col_idx)
            cell.alignment = self.alignment
            cell.font = self.header_font
            cell.border = self.thin_border

        # 6. 写入数据，确保值为字符串
        for idx, item in enumerate(self.all_data, start=1):
            path_levels = self._split_path_levels(item['path'])
            row_data = [
                str(idx),  # id
                item["domain"],
                item["url"],
                item["path"],
                item["status"],
                item["length"],
                item["title"]
            ]
            # 补充路径层级数据
            for i in range(max_depth):
                row_data.append(path_levels[i] if i < len(path_levels) else "")
            self.ws.append(row_data)

        # 7. 设置单元格样式
        for row_idx in range(2, self.ws.max_row + 1):
            for col_idx in range(1, self.ws.max_column + 1):
                cell = self.ws.cell(row=row_idx, column=col_idx)
                cell.alignment = self.alignment
                cell.border = self.thin_border

        # 8. 执行合并单元格操作，覆盖Domain列和路径层级列
        self._merge_and_center(2)  # 合并Domain列（第2列）
        for i in range(max_depth):
            self._merge_and_center(8 + i)  # 合并路径层级列

        # 9. 调整列宽，限制最大宽度
        for col_idx in range(1, self.ws.max_column + 1):
            try:
                max_length = max(
                    len(str(self.ws.cell(row=row, column=col_idx).value or ""))
                    for row in range(1, self.ws.max_row + 1)
                )
                max_length = min(max_length, 50)  # 限制最大列宽
                self.ws.column_dimensions[get_column_letter(col_idx)].width = max_length + 2
            except:
                continue

        # 10. 自动保存
        if auto_save:
            self.save()

    def __del__(self):
        """对象销毁时关闭工作簿，释放资源"""
        try:
            if self.wb:
                self.wb.close()
        except:
            pass


# 使用示例
if __name__ == "__main__":
    try:
        excel_gen = SafePathExcelGenerator("safe_path_result.xlsx")

        # 模拟数据，包含重复路径前缀的情况
        data1 = [
            {"domain": "test.com", "url": "http://test.com/a/b", "path": "/a/b", "status": 200, "length": 1000, "title": "测试1"},
            {"domain": "test.com", "url": "http://test.com/a/c", "path": "/a/c", "status": 200, "length": 2000, "title": "测试2"},
            {"domain": "test.com", "url": "http://test.com/a/d", "path": "/a/d", "status": 404, "length": 500, "title": "测试3"}
        ]
        excel_gen.append_data(data1)

        # 可继续追加更多数据测试
        # data2 = [{"domain": "test.com", "url": "http://test.com/a/e", "path": "/a/e", "status": 200, "length": 800, "title": "测试4"}]
        # excel_gen.append_data(data2)

        print("🎉 操作完成，表格已生成")
    except Exception as e:
        print(f"❌ 操作失败：{traceback.format_exc()}")