import re
import os
import time
from typing import List, Dict, Any, Iterable, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse
from tqdm import tqdm
from openpyxl.workbook import Workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment, Font, Border, Side

# 类型别名
UrlData = Dict[str, str]
InputData = List[Dict[str, Any]]


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
    except Exception:
        return url.strip().lower()


class SafePathExcelGenerator:
    """
    简单可靠的Excel生成器，确保文件正确生成
    - 保持原有功能，只做必要优化
    - 确保文件能正确保存
    - 适中的性能优化
    """
    HEADERS = ["id", "Domain", "URL", "Path", "sourceURL"]

    def __init__(self, output_file: str):
        self.output_file = output_file
        self.wb = Workbook()
        self.ws = self.wb.active
        self.ws.title = "Paths"

        # 写入表头
        self.ws.append(self.HEADERS)

        # 去重集合
        self.existing_signatures: Set[Tuple[str, str, str]] = set()  # (domain, normalized_url, path)
        self.existing_urls: Set[str] = set()  # normalized_urls
        self.row_count = 1  # 表头占1行

        # 样式定义
        self.alignment = Alignment(horizontal="center", vertical="center", wrap_text=False)
        self.header_font = Font(bold=True, name="Arial")
        self.thin_border = Border(
            left=Side(style="thin"),
            right=Side(style="thin"),
            top=Side(style="thin"),
            bottom=Side(style="thin")
        )

        # 设置表头样式
        for col_idx in range(1, len(self.HEADERS) + 1):
            cell = self.ws.cell(row=1, column=col_idx)
            cell.alignment = self.alignment
            cell.font = self.header_font
            cell.border = self.thin_border

        # 预设列宽（避免最后计算）
        self.set_initial_column_widths()

        # 删除旧文件
        self.del_old_file()

    def del_old_file(self) -> None:
        """删除旧文件"""
        if os.path.exists(self.output_file):
            try:
                os.remove(self.output_file)
            except Exception as e:
                print(f"⚠️  删除旧文件失败: {str(e)}")

    def set_initial_column_widths(self) -> None:
        """预设列宽，避免最后计算"""
        column_widths = {
            1: 6,  # id
            2: 20,  # Domain
            3: 50,  # URL
            4: 30,  # Path
            5: 50,  # sourceURL
        }

        for col_idx, width in column_widths.items():
            col_letter = get_column_letter(col_idx)
            self.ws.column_dimensions[col_letter].width = width

    @staticmethod
    def clean_illegal_chars(text: Any) -> Any:
        """清理非法字符，避免Excel写入错误"""
        if not isinstance(text, str):
            return text
        return re.sub(r'[\x00-\x08\x0b-\x1f]', '', text)

    def _extract_domain_from_url(self, url: str) -> str:
        """高效提取域名"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or (parsed.path.split('/')[0] if parsed.path else '')
        except Exception:
            return ''

    def _extract_path_from_url(self, url: str) -> str:
        """高效提取路径"""
        try:
            parsed = urlparse(url)
            return parsed.path or ''
        except Exception:
            return ''

    def _process_input_data(self, input_data: InputData) -> List[UrlData]:
        """处理输入数据，过滤无效项和重复项"""
        result = []

        for item in input_data:
            if not isinstance(item, dict) or "next_urls" not in item or "sourceURL" not in item:
                continue

            next_urls = item.get("next_urls", [])
            source_url = str(item.get("sourceURL", "")).strip()

            if not isinstance(next_urls, (list, set, tuple)) or isinstance(next_urls, str):
                continue

            for url in next_urls:
                if not isinstance(url, str) or not url.strip():
                    continue

                url_str = url.strip()
                domain = self._extract_domain_from_url(url_str)
                path = self._extract_path_from_url(url_str)
                normalized_url = normalize_url(url_str)

                # 去重检查
                signature = (domain.lower(), normalized_url, path.lower())
                if signature in self.existing_signatures or normalized_url in self.existing_urls:
                    continue

                result.append({
                    "url": url_str,
                    "domain": domain,
                    "path": path,
                    "sourceURL": source_url
                })

                # 更新去重集合
                self.existing_signatures.add(signature)
                self.existing_urls.add(normalized_url)

        return result

    def append_data_batch(self, input_data: InputData, batch_size: int = 500, show_progress: bool = True) -> None:
        """
        批量追加数据，每批写入后保存文件
        """
        if not input_data:
            print("[yellow]⚠️  无输入数据，跳过处理[/yellow]")
            return

        # 统计实际URL数量
        total_urls = 0
        for item in input_data:
            if isinstance(item, dict) and "next_urls" in item:
                next_urls = item["next_urls"]
                if isinstance(next_urls, (list, set, tuple)):
                    total_urls += len(next_urls)

        print(f"[bold blue]📊 开始处理批次数据: {len(input_data)} 个批次条目，包含 {total_urls} 个URL[/bold blue]")

        # 1. 处理输入数据（去重、过滤）
        processed_data = self._process_input_data(input_data)
        if not processed_data:
            print("[yellow]⚠️  处理后无有效数据，跳过写入[/yellow]")
            return

        actual_urls = len(processed_data)
        print(f"[green]✅ 数据处理完成: 原始 {total_urls} 个URL → 过滤后 {actual_urls} 个有效URL[/green]")

        # 2. 按域名排序
        sorted_data = sort_by_domain_and_url(processed_data)

        # 3. 分批次写入
        total_batches = (len(sorted_data) + batch_size - 1) // batch_size

        progress = tqdm(total=len(sorted_data), desc="Excel写入", unit="条", ncols=100) if show_progress else None

        for batch_idx in range(0, len(sorted_data), batch_size):
            batch = sorted_data[batch_idx:batch_idx + batch_size]
            current_batch = batch_idx // batch_size + 1

            if show_progress:
                print(f"[cyan]📦 写入Excel批次 {current_batch}/{total_batches} ({len(batch)}条URL数据)...[/cyan]")

            # 写入当前批次
            for item in batch:
                if ".js" in item["url"] or ".vue" in item["url"]:
                    continue

                self.row_count += 1
                row_data = [
                    str(self.row_count),
                    self.clean_illegal_chars(item["domain"]),
                    self.clean_illegal_chars(item["url"]),
                    self.clean_illegal_chars(item["path"]),
                    self.clean_illegal_chars(item["sourceURL"])
                ]
                self.ws.append(row_data)

                # 设置行样式
                for col_idx in range(1, len(row_data) + 1):
                    cell = self.ws.cell(row=self.row_count, column=col_idx)
                    cell.alignment = self.alignment
                    cell.border = self.thin_border

            # 每批写入后保存文件
            self.save()

            if progress:
                progress.update(len(batch))
                progress.set_postfix(batch=f"{current_batch}/{total_batches}")

            if current_batch < total_batches:
                time.sleep(0.1)

        if progress:
            progress.close()

        print(f"[green]✅ 本批次Excel写入完成，新增 {len(sorted_data)} 行数据，总行数: {self.row_count}[/green]")


    def save(self) -> None:
        """保存文件"""
        try:
            start_time = time.time()
            self.wb.save(self.output_file)
            save_time = time.time() - start_time
            print(f"[green]✅ 文件保存成功: {self.output_file}，耗时: {save_time:.2f}秒[/green]")
        except Exception as e:
            print(f"[red]❌ 保存文件失败: {str(e)}[/red]")

    def __del__(self) -> None:
        """确保文件被保存"""
        try:
            self.save()
        except Exception as e:
            pass
