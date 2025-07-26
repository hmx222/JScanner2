from openpyxl.styles import Alignment, Font, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.workbook import Workbook
from openpyxl import load_workbook
from urllib.parse import urlparse, urlunparse
import os
import traceback


# 按域名+URL排序（确保数据有序展示）
def sort_by_domain_and_url(data):
    return sorted(data, key=lambda x: (x['domain'], x['url']))


def normalize_url(url):
    """归一化URL，处理末尾斜杠和协议等差异，增强去重准确性"""
    try:
        parsed = urlparse(url)
        # 统一协议（如果没有协议，默认http）
        scheme = parsed.scheme if parsed.scheme else 'http'
        # 处理空域名情况
        netloc = parsed.netloc if parsed.netloc else parsed.path.split('/')[0] if parsed.path else ''
        # 统一路径结尾（移除末尾斜杠）
        path = parsed.path.rstrip('/') if parsed.path else ''
        # 重组URL（忽略参数、查询和片段）
        normalized = urlunparse((scheme, netloc, path, '', '', ''))
        return normalized.lower()  # 转为小写，大小写不敏感去重
    except:
        return url.strip().lower()


class SafePathExcelGenerator:
    def __init__(self, output_file):
        self.output_file = output_file
        self.wb = None  # 工作簿实例
        self.ws = None  # 工作表实例
        self.all_data = []  # 存储所有有效数据
        self.existing_normalized_urls = set()  # 归一化URL集合，用于去重

        # 样式定义
        self.alignment = Alignment(horizontal="center", vertical="center", wrap_text=False)
        self.header_font = Font(bold=True, name="Arial")
        self.thin_border = Border(
            left=Side(style="thin"),
            right=Side(style="thin"),
            top=Side(style="thin"),
            bottom=Side(style="thin")
        )

        # 初始化文件
        self._init_file_safely()

    def _init_file_safely(self):
        """安全初始化文件，处理旧文件损坏等情况"""
        try:
            if os.path.exists(self.output_file):
                # 尝试加载现有文件，若失败则创建新文件
                self.wb = load_workbook(self.output_file, read_only=False, data_only=False)
                # 确保工作表存在，不存在则创建
                self.ws = self.wb["Paths"] if "Paths" in self.wb.sheetnames else self.wb.create_sheet("Paths")
                # 读取历史数据
                self._load_existing_data_safely()
            else:
                # 创建全新文件
                self.wb = Workbook()
                self.ws = self.wb.active
                self.ws.title = "Paths"
        except Exception as e:
            print(f"初始化文件失败，创建新文件：{str(e)}")
            self.wb = Workbook()
            self.ws = self.wb.active
            self.ws.title = "Paths"

    def _load_existing_data_safely(self):
        """安全加载历史数据，跳过格式错误的行和单元格"""
        try:
            # 从第2行开始读取（跳过表头）
            for row in range(2, self.ws.max_row + 1):
                # 跳过空行
                if all(self.ws.cell(row=row, column=col).value is None for col in range(1, 3)):
                    continue
                # 读取URL（第3列）用于去重
                url_cell = self.ws.cell(row=row, column=3)
                url = str(url_cell.value).strip() if url_cell.value is not None else ""
                if url:
                    normalized = normalize_url(url)
                    self.existing_normalized_urls.add(normalized)
                # 读取核心数据
                self.all_data.append({
                    "domain": str(self.ws.cell(row=row, column=2).value).strip() if self.ws.cell(row=row,
                                                                                                 column=2).value is not None else "",
                    "url": url,
                    "path": str(self.ws.cell(row=row, column=4).value).strip() if self.ws.cell(row=row,
                                                                                               column=4).value is not None else "",
                    "status": str(self.ws.cell(row=row, column=5).value).strip() if self.ws.cell(row=row,
                                                                                                 column=5).value is not None else "",
                    "length": str(self.ws.cell(row=row, column=6).value).strip() if self.ws.cell(row=row,
                                                                                                 column=6).value is not None else "",
                    "title": str(self.ws.cell(row=row, column=7).value).strip() if self.ws.cell(row=row,
                                                                                                column=7).value is not None else ""
                })
        except Exception as e:
            print(f"⚠️ 加载历史数据时跳过错误行：{str(e)}")

    def save(self):
        """安全保存文件"""
        try:
            if self.wb:
                if hasattr(self.wb, 'read_only') and self.wb.read_only:
                    self.wb.read_only = False
                self.wb.save(self.output_file)
                print(f"✅ 已成功保存至：{self.output_file}")
                self._init_file_safely()  # 重新加载最新文件
        except Exception as e:
            print(f"❌ 保存失败：{str(e)}")
            backup_file = self.output_file.replace(".xlsx", "_backup.xlsx")
            self.wb.save(backup_file)
            print(f"📌 已创建备份文件：{backup_file}")

    def append_data(self, new_scan_list, auto_save=True):
        """追加数据，包含数据校验、排序、表格重构等逻辑"""
        # 1. 过滤无效数据
        new_data = []
        for item in new_scan_list:
            try:
                # 跳过无效标记的数据（如果有）
                if item.get("is_valid") == 1:
                    continue
                url = str(item.get("url", "")).strip()
                if not url:
                    continue

                # 归一化URL进行去重检查
                normalized_url = normalize_url(url)
                if normalized_url in self.existing_normalized_urls:
                    continue

                # 构建新数据项
                new_item = {
                    "domain": str(item.get("domain", "")).strip(),
                    "url": url,
                    "path": str(item.get("path", "")).strip(),
                    "status": str(item.get("status", "")).strip(),
                    "length": str(item.get("length", "0")).strip(),
                    "title": str(item.get("title", "")).strip()
                }
                new_data.append(new_item)
                self.existing_normalized_urls.add(normalized_url)
            except Exception as e:
                pass

        if not new_data:
            pass
            return

        # 2. 合并数据并按域名+URL排序
        self.all_data.extend(new_data)
        self.all_data = sort_by_domain_and_url(self.all_data)

        # 3. 准备表头
        all_headers = ["id", "Domain", "URL", "Path", "Status", "Length", "Title"]

        # 4. 清空旧数据
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

        # 6. 写入数据
        for idx, item in enumerate(self.all_data, start=1):
            row_data = [
                str(idx),  # id
                item["domain"],
                item["url"],
                item["path"],
                item["status"],
                item["length"],
                item["title"]
            ]
            self.ws.append(row_data)

        # 7. 设置单元格样式
        for row_idx in range(2, self.ws.max_row + 1):
            for col_idx in range(1, self.ws.max_column + 1):
                cell = self.ws.cell(row=row_idx, column=col_idx)
                cell.alignment = self.alignment
                cell.border = self.thin_border

        # 8. 调整列宽
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

        # 9. 自动保存
        if auto_save:
            self.save()

    def __del__(self):
        """对象销毁时关闭工作簿"""
        try:
            if self.wb:
                self.wb.close()
        except:
            pass


