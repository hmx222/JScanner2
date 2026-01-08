import re

from openpyxl.styles import Alignment, Font, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.workbook import Workbook
from openpyxl import load_workbook
from urllib.parse import urlparse, urlunparse
import os
import traceback
from typing import List, Dict, Any, Iterable, Optional

# 类型别名，匹配你的实际输入格式
UrlData = Dict[str, str]
InputData = List[Dict[str, Any]]  # 实际输入：列表，元素是含next_urls/sourceURL的字典

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
    # 类常量：表头和样式配置
    HEADERS = ["id", "Domain", "URL", "Path", "sourceURL"]

    def __init__(self, output_file: str):
        self.output_file = output_file
        self.wb: Optional[Workbook] = None
        self.ws = None
        self.all_data: List[UrlData] = []
        # 去重集合：存储（domain, 归一化url, path）的元组
        self.existing_row_signatures: set[tuple[str, str, str]] = set()
        self.existing_normalized_urls: set[str] = set()

        # 样式定义
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

                # 提取核心字段（适配新表头）
                domain = str(self.ws.cell(row=row, column=2).value).strip() if self.ws.cell(row=row,
                                                                                            column=2).value is not None else ""
                url = str(self.ws.cell(row=row, column=3).value).strip() if self.ws.cell(row=row,
                                                                                         column=3).value is not None else ""
                path = str(self.ws.cell(row=row, column=4).value).strip() if self.ws.cell(row=row,
                                                                                          column=4).value is not None else ""
                sourceURL = str(self.ws.cell(row=row, column=5).value).strip() if self.ws.cell(row=row,
                                                                                               column=5).value is not None else ""

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
                        "sourceURL": sourceURL
                    })

            # 更新内存数据
            self.all_data = unique_historical_data
            self.existing_row_signatures = existing_signatures
            self.existing_normalized_urls = existing_urls

        except (ValueError, IndexError) as e:
            self.all_data = []
            self.existing_row_signatures = set()
            self.existing_normalized_urls = set()
        except Exception as e:
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
            self._init_file_safely()  # 重新加载最新文件
        except Exception as e:
            backup_file = self.output_file.replace(".xlsx", "_backup.xlsx")
            try:
                self.wb.save(backup_file)
            except Exception as be:
                pass

    def _process_input_data(self, input_data: InputData) -> List[UrlData]:
        """
        完全适配你的实际输入格式：
        input_data = [{"next_urls": 集合/列表, "sourceURL": 字符串}, ...]
        """
        normalized_input: List[UrlData] = []

        # 第一步：校验输入是否为列表
        if not isinstance(input_data, list):
            print("⚠️ 输入数据格式错误，必须是列表：[{'next_urls': 集合/列表, 'sourceURL': 字符串}, ...]")
            return normalized_input

        # 第二步：遍历列表中的每个字典元素
        for item in input_data:
            # 校验每个元素是否是字典，且包含next_urls和sourceURL
            if not isinstance(item, dict) or "next_urls" not in item or "sourceURL" not in item:
                print(f"⚠️ 列表元素格式错误，跳过该元素：{item}，要求：{'next_urls': 集合/列表, 'sourceURL': 字符串}")
                continue

            # 提取当前元素的next_urls（集合/列表）和sourceURL
            next_urls = item.get("next_urls", [])
            sourceURL = str(item.get("sourceURL", "")).strip()

            # 校验next_urls是否为可迭代类型（集合/列表，排除字符串）
            if not isinstance(next_urls, Iterable) or isinstance(next_urls, str):
                print(f"⚠️ next_urls格式错误（必须是集合/列表），跳过该元素：{item}")
                continue

            # 第三步：遍历当前元素的每个next URL，绑定sourceURL
            for url in next_urls:
                # 过滤无效URL（非字符串/空字符串）
                if not isinstance(url, str) or not url.strip():
                    continue
                url_str = url.strip()

                # 构建标准UrlData字典
                normalized_input.append({
                    "url": url_str,
                    "domain": self._extract_domain_from_url(url_str),
                    "path": self._extract_path_from_url(url_str),
                    "sourceURL": sourceURL
                })

        return normalized_input

    def _extract_domain_from_url(self, url: str) -> str:
        """从 URL 中提取域名"""
        try:
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else (parsed.path.split('/')[0] if parsed.path else '')
        except Exception as e:
            return ''

    def _extract_path_from_url(self, url: str) -> str:
        """从 URL 中提取路径"""
        try:
            parsed = urlparse(url)
            return parsed.path if parsed.path else ''
        except Exception as e:
            return ''

    def _filter_new_data(self, normalized_input: List[UrlData]) -> List[UrlData]:
        """过滤无效数据和重复数据（按完整行特征去重）"""
        new_data: List[UrlData] = []

        for item in normalized_input:
            try:
                url = item["url"]
                if not url:
                    continue

                # 提取核心字段
                domain = item["domain"].strip()
                path = item["path"].strip()
                normalized_url = normalize_url(url)

                # 构建行特征（domain + 归一化 url + path）
                row_signature = (domain.lower(), normalized_url, path.lower())

                # 去重检查
                if (row_signature in self.existing_row_signatures
                        or normalized_url in self.existing_normalized_urls):
                    continue

                new_data.append(item)
                self.existing_row_signatures.add(row_signature)
                self.existing_normalized_urls.add(normalized_url)
            except Exception as e:
                pass

        return new_data

    def clean_illegal_chars(self, text):
        if not isinstance(text, str):
            return text
        return re.sub(r'[\x00-\x08\x0b-\x1f]', '', text)

    def _render_excel(self) -> None:
        """渲染 Excel 内容（仅适配新表头和新数据）"""
        if not self.ws or not self.wb:
            print("❌ 工作表未初始化，无法渲染数据")
            return

        # 清空旧数据
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

        # 写入数据（跳过 .js / .vue）
        for idx, item in enumerate(self.all_data, start=1):
            if ".js" in item["url"] or ".vue" in item["url"]:
                continue
            row_data = [
                str(idx),
                item["domain"],
                item["url"],
                item["path"],
                item["sourceURL"]
            ]
            try:
                self.ws.append(row_data)
            except Exception as e:
                print(f"⚠️ 写入数据失败（行{idx}）：{item['url']}，错误：{e}")
                continue

        # 设置数据行样式
        for row_idx in range(2, self.ws.max_row + 1):
            for col_idx in range(1, self.ws.max_column + 1):
                cell = self.ws.cell(row=row_idx, column=col_idx)
                cell.alignment = self.alignment
                cell.border = self.thin_border

        # 优化列宽计算：URL（3列）、sourceURL（5列）
        KEY_COLS = {3, 5}
        DEFAULT_WIDTH = 15
        MAX_SAMPLE_ROWS = 10

        for col_idx in range(1, self.ws.max_column + 1):
            try:
                if col_idx in KEY_COLS and self.ws.max_row > 1:
                    sample_rows = min(MAX_SAMPLE_ROWS, self.ws.max_row)
                    max_length = max(
                        len(str(self.ws.cell(row=row, column=col_idx).value or ""))
                        for row in range(1, sample_rows + 1)
                    )
                    width = min(max_length, 50) + 2
                else:
                    width = DEFAULT_WIDTH

                col_letter = get_column_letter(col_idx)
                self.ws.column_dimensions[col_letter].width = width
            except Exception as e:
                pass

    def append_data(self, input_data: InputData, auto_save: bool = True) -> None:
        """
        追加你的实际格式数据：[{'next_urls': 集合, 'sourceURL': 字符串}, ...]
        """
        # 1. 处理输入数据
        normalized_input = self._process_input_data(input_data)
        if not normalized_input:
            return

        # 2. 过滤新数据
        new_data = self._filter_new_data(normalized_input)
        if not new_data:
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
            pass