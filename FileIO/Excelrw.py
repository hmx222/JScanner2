import re

from openpyxl.styles import Alignment, Font, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.workbook import Workbook
from openpyxl import load_workbook
from urllib.parse import urlparse, urlunparse
import os
import traceback
from typing import List, Dict, Any, Iterable, Optional

# 类型别名，提高代码可读性
UrlData = Dict[str, str]
InputData = Iterable[Any]  # 支持 list/set 等可迭代类型

# 啊啊啊啊 ，这文件是ai写的，我也不知道为什么有这些函数😒
def sort_by_domain_and_url(data: List[UrlData]) -> List[UrlData]:
    """按域名 + URL 排序（确保数据有序展示）"""
    return sorted(data, key=lambda x: (x['domain'], x['url']))


def normalize_url(url: str) -> str:
    """归一化 URL，处理末尾斜杠和协议等差异，增强去重准确性"""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme if parsed.scheme else 'http'
        netloc = parsed.netloc if parsed.netloc else (parsed.path.split('/')[0] if parsed.path else '')
        path = parsed.path.rstrip('/') if parsed.path else ''
        normalized = urlunparse((scheme, netloc, path, '', '', ''))
        return normalized.lower()
    except Exception as e:

        return url.strip().lower()


class SafePathExcelGenerator:
    # 类常量：表头和样式配置，集中管理便于修改
    HEADERS = ["id", "Domain", "URL", "Path", "Status", "Length", "Title"]

    def __init__(self, output_file: str):
        self.output_file = output_file
        self.wb: Optional[Workbook] = None
        self.ws = None
        self.all_data: List[UrlData] = []
        # 去重集合：存储（domain, 归一化url, path）的元组
        self.existing_row_signatures: set[tuple[str, str, str]] = set()
        # 兼容旧逻辑的 URL 去重集合（可逐步迁移）
        self.existing_normalized_urls: set[str] = set()

        # 样式定义（一次定义，多次使用）
        self.alignment = Alignment(horizontal="center", vertical="center", wrap_text=False)
        self.header_font = Font(bold=True, name="Arial")
        self.thin_border = Border(
            left=Side(style="thin"),
            right=Side(style="thin"),
            top=Side(style="thin"),
            bottom=Side(style="thin")
        )
        self.del_old_file()
        self._init_file_safely()


    def del_old_file(self) -> None:
        """删除旧文件，创建新文件"""
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    def _init_file_safely(self) -> None:
        """安全初始化文件，处理旧文件损坏等情况"""
        try:
            if os.path.exists(self.output_file):
                self.wb = load_workbook(self.output_file, read_only=False, data_only=False)
                self.ws = self.wb["Paths"] if "Paths" in self.wb.sheetnames else self.wb.create_sheet("Paths")
                self._load_existing_data_safely()
            else:
                self.wb = Workbook()
                self.ws = self.wb.active
                self.ws.title = "Paths"
        except Exception as e:
            print(f"初始化文件失败，创建新文件：{str(e)}")
            self.wb = Workbook()
            self.ws = self.wb.active
            self.ws.title = "Paths"

    def _load_existing_data_safely(self) -> None:
        """安全加载历史数据，同时按完整行特征去重"""
        if not self.ws or self.ws.max_row < 2:
            self.all_data = []
            self.existing_row_signatures = set()
            self.existing_normalized_urls = set()
            return

        try:
            unique_historical_data = []
            existing_signatures = set()
            existing_urls = set()

            for row in range(2, self.ws.max_row + 1):
                # 跳过空行（检查前两列是否都为空）
                if all(self.ws.cell(row=row, column=col).value is None for col in (1, 2)):
                    continue

                # 提取核心字段
                domain = str(self.ws.cell(row=row, column=2).value).strip() if self.ws.cell(row=row,
                                                                                            column=2).value is not None else ""
                url = str(self.ws.cell(row=row, column=3).value).strip() if self.ws.cell(row=row,
                                                                                         column=3).value is not None else ""
                path = str(self.ws.cell(row=row, column=4).value).strip() if self.ws.cell(row=row,
                                                                                          column=4).value is not None else ""

                if not url:
                    continue  # 跳过空 URL 行

                # 构建行特征（domain + 归一化 url + path）
                normalized_url = normalize_url(url)
                row_signature = (domain.lower(), normalized_url, path.lower())

                # 仅保留未重复的历史数据
                if row_signature not in existing_signatures and normalized_url not in existing_urls:
                    existing_signatures.add(row_signature)
                    existing_urls.add(normalized_url)
                    unique_historical_data.append({
                        "domain": domain,
                        "url": url,
                        "path": path,
                        "status": str(self.ws.cell(row=row, column=5).value).strip() if self.ws.cell(row=row,
                                                                                                     column=5).value is not None else "",
                        "length": str(self.ws.cell(row=row, column=6).value).strip() if self.ws.cell(row=row,
                                                                                                     column=6).value is not None else "",
                        "title": str(self.ws.cell(row=row, column=7).value).strip() if self.ws.cell(row=row,
                                                                                                    column=7).value is not None else ""
                    })

            # 更新内存数据
            self.all_data = unique_historical_data
            self.existing_row_signatures = existing_signatures
            self.existing_normalized_urls = existing_urls
            # print(f"✅ 加载历史数据完成，过滤 {self.ws.max_row - 1 - len(unique_historical_data)} 条重复数据")

        except (ValueError, IndexError) as e:
            # print(f"⚠️ 加载历史数据时格式错误：{str(e)}，使用空数据初始化")
            self.all_data = []
            self.existing_row_signatures = set()
            self.existing_normalized_urls = set()
        except Exception as e:
            # print(f"⚠️ 加载历史数据失败：{str(e)}，使用空数据初始化")
            self.all_data = []
            self.existing_row_signatures = set()
            self.existing_normalized_urls = set()

    def save(self) -> None:
        """安全保存文件，增加备份机制"""
        if not self.wb:
            print("❌ 无工作簿实例，保存失败")
            return

        try:
            if hasattr(self.wb, 'read_only') and self.wb.read_only:
                self.wb.read_only = False

            self.wb.save(self.output_file)
            # print(f"✅ 已成功保存至：{self.output_file}")
            self._init_file_safely()  # 重新加载最新文件
        except Exception as e:
            # print(f"❌ 保存失败：{str(e)}")
            backup_file = self.output_file.replace(".xlsx", "_backup.xlsx")
            try:
                self.wb.save(backup_file)
                # print(f"📌 已创建备份文件：{backup_file}")
            except Exception as be:
                pass# print(f"❌ 备份文件创建失败：{str(be)}")

    def _process_input_data(self, input_data: InputData) -> List[UrlData]:
        """
        处理输入数据，统一转换为标准格式
        支持：list/set 的字典或字符串（URL）
        """
        normalized_input: List[UrlData] = []

        # 统一转换为列表处理（支持 set 等可迭代类型）
        input_list = list(input_data) if isinstance(input_data, Iterable) else []

        for item in input_list:
            try:
                if isinstance(item, dict):
                    # 处理完整信息字典
                    normalized_input.append({
                        "domain": str(item.get("domain", "")).strip(),
                        "url": str(item.get("url", "")).strip(),
                        "path": str(item.get("path", "")).strip(),
                        "status": str(item.get("status", "")).strip(),
                        "length": str(item.get("length", "")).strip(),
                        "title": str(item.get("title", "")).strip()
                    })
                elif isinstance(item, str):
                    # 处理纯 URL 字符串
                    url = item.strip()
                    if url:
                        normalized_input.append({
                            "url": url,
                            "domain": self._extract_domain_from_url(url),
                            "path": self._extract_path_from_url(url),
                            "status": "",
                            "length": "",
                            "title": ""
                        })
                else:
                  pass  # print(f"⚠️ 跳过无效数据类型：{type(item)}（值：{item}）")
            except Exception as e:
                pass # print(f"⚠️ 处理数据项失败：{str(item)}，错误：{str(e)}")

        return normalized_input

    def _extract_domain_from_url(self, url: str) -> str:
        """从 URL 中提取域名"""
        try:
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else (parsed.path.split('/')[0] if parsed.path else '')
        except Exception as e:
            # print(f"⚠️ 域名提取失败：{url}，错误：{str(e)}")
            return ''

    def _extract_path_from_url(self, url: str) -> str:
        """从 URL 中提取路径"""
        try:
            parsed = urlparse(url)
            return parsed.path if parsed.path else ''
        except Exception as e:
            # print(f"⚠️ 路径提取失败：{url}，错误：{str(e)}")
            return ''

    def _filter_new_data(self, normalized_input: List[UrlData]) -> List[UrlData]:
        """过滤无效数据和重复数据（按完整行特征去重）"""
        new_data: List[UrlData] = []

        for item in normalized_input:
            try:
                # 跳过无效标记或空 URL
                if item.get("is_valid") == 1:
                    continue
                url = item["url"]
                if not url:
                    # print(f"⚠️ 跳过空 URL 数据")
                    continue

                # 提取核心字段
                domain = item["domain"].strip()
                path = item["path"].strip()
                normalized_url = normalize_url(url)

                # 构建行特征（domain + 归一化 url + path）
                row_signature = (domain.lower(), normalized_url, path.lower())

                # 去重检查（同时检查 URL 和行特征）
                if (row_signature in self.existing_row_signatures
                        or normalized_url in self.existing_normalized_urls):
                    # print(f"⚠️ 跳过重复数据：{item}（URL 或行特征已存在）")
                    continue

                new_data.append(item)
                self.existing_row_signatures.add(row_signature)
                self.existing_normalized_urls.add(normalized_url)
            except Exception as e:
               pass # print(f"⚠️ 过滤数据失败：{str(item)}，错误：{str(e)}")

        return new_data

    def clean_illegal_chars(text):
        if not isinstance(text, str):
            return text
        # 正则表达式，匹配 ASCII 控制字符（除了常见的空白符等可显示的）
        # 这里保留了常见的空白符（如空格、换行等），如果不需要可调整正则
        return re.sub(r'[\x00-\x08\x0b-\x1f]', '', text)

    def _render_excel(self) -> None:
        """渲染 Excel 内容（表头、数据、样式）"""
        if not self.ws or not self.wb:
            print("❌ 工作表未初始化，无法渲染数据")
            return

        # 清空旧数据（保留表头逻辑优化）
        try:
            if self.ws.max_row > 0:
                self.ws.delete_rows(1, self.ws.max_row)
        except Exception as e:
            print(f"⚠️ 清空旧数据失败，创建新工作表：{str(e)}")
            self.ws = self.wb.create_sheet("Paths")

        # 写入表头并设置样式
        self.ws.append(self.HEADERS)
        for col_idx in range(1, len(self.HEADERS) + 1):
            cell = self.ws.cell(row=1, column=col_idx)
            cell.alignment = self.alignment
            cell.font = self.header_font
            cell.border = self.thin_border

        # 写入数据
        for idx, item in enumerate(self.all_data, start=1):
            # 跳过.js与vue的写入
            if ".js" in item["url"]  or ".vue" in item["url"]:
                continue
            row_data = [
                str(idx),
                item["domain"],
                item["url"],
                item["path"],
                item["status"],
                item["length"],
                item["title"]
            ]
            try:
                self.ws.append(row_data)
            except Exception as e:
                print(f"⚠️ 写入数据失败（行{idx}）：{item['url']}")
                continue

        # 设置单元格样式（仅处理数据行）
        for row_idx in range(2, self.ws.max_row + 1):
            for col_idx in range(1, self.ws.max_column + 1):
                cell = self.ws.cell(row=row_idx, column=col_idx)
                cell.alignment = self.alignment
                cell.border = self.thin_border

        # 调整列宽（限制最大宽度避免过宽）
        for col_idx in range(1, self.ws.max_column + 1):
            try:
                max_length = max(
                    len(str(self.ws.cell(row=row, column=col_idx).value or ""))
                    for row in range(1, self.ws.max_row + 1)
                )
                self.ws.column_dimensions[get_column_letter(col_idx)].width = min(max_length, 50) + 2
            except Exception as e:
               pass # print(f"⚠️ 调整列宽失败（列{col_idx}）：{str(e)}")

    def append_data(self, input_data: InputData, auto_save: bool = True) -> None:
        """
        追加数据，支持多种输入格式：
        1. 字典列表：[{"domain": "...", "url": "...", ...}]
        2. URL 列表/集合：["http://example.com", ...] 或 {"http://a.com", ...}
        """
        # 1. 处理输入数据
        normalized_input = self._process_input_data(input_data)
        if not normalized_input:
            # print("ℹ️ 无有效输入数据")
            return

        # 2. 过滤新数据（按完整行特征去重）
        new_data = self._filter_new_data(normalized_input)
        if not new_data:
            # print("ℹ️ 无新数据可写入")
            return

        # 3. 合并并排序数据
        self.all_data.extend(new_data)
        self.all_data = sort_by_domain_and_url(self.all_data)

        # 4. 渲染 Excel
        self._render_excel()

        # 5. 自动保存
        if auto_save:
            self.save()

    def __del__(self) -> None:
        """对象销毁时确保关闭工作簿"""
        try:
            if self.wb:
                self.wb.close()
        except Exception as e:
            pass# print(f"⚠️ 关闭工作簿失败：{str(e)}")


