import hashlib
import logging
import math
import mmap
import os
import threading
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class DiskBloomFilter:
    """
    磁盘布隆过滤器（用于内存缓存 + 快速去重）
    注意：这是临时缓存，重启后会清空，持久化靠数据库
    """

    def __init__(self, filepath="Result/global_dedup.bloom", capacity=10_000_000, error_rate=0.001):
        self.filepath = filepath
        self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.hash_count = int((self.size / capacity) * math.log(2))
        self.byte_size = (self.size + 7) // 8

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        if not os.path.exists(filepath):
            with open(filepath, "wb") as f:
                f.write(b'\x00' * self.byte_size)

        self.file = open(filepath, "r+b")
        self.mm = mmap.mmap(self.file.fileno(), 0)

    def _get_hashes(self, item):
        item_encoded = item.encode("utf8")
        md5 = int(hashlib.md5(item_encoded).hexdigest(), 16)
        sha1 = int(hashlib.sha1(item_encoded).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (md5 + i * sha1) % self.size

    def add(self, item):
        if self.contains(item):
            return False
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            self.mm[byte_index] |= (1 << bit_index)
        return True

    def contains(self, item):
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            if not (self.mm[byte_index] & (1 << bit_index)):
                return False
        return True

    def close(self):
        try:
            self.mm.close()
            self.file.close()
        except:
            pass


class DuplicateChecker:
    """
    去重管理器（v2.0 - 支持重启续扫）

    双层去重架构：
    ├── Layer 1: DiskBloomFilter（内存缓存，快速检查）
    └── Layer 2: SQLite 数据库（持久化存储，重启续扫）
    """

    def __init__(self, db_handler=None, initial_root_domain: list = None):
        """
        初始化去重管理器

        :param db_handler: SQLiteStorage 实例（用于持久化）
        :param initial_root_domain: 目标根域名列表（用于 URL 有效性检查）
        """
        # Layer 1: 内存布隆过滤器（临时缓存）
        self.visited_urls = DiskBloomFilter("Result/global_dedup.bloom", capacity=10000000)

        # Layer 2: 数据库持久化（重启续扫核心）
        self.db_handler = db_handler

        # 标题去重缓存
        self.title_map = dict()
        self.target_root = initial_root_domain if initial_root_domain else []
        self.title_lock = threading.Lock()
        self.MAX_TITLE_PER_DOMAIN = 3000
        self.MAX_DOMAIN_CACHE = 200

        # ✅ 从数据库加载历史已访问 URL
        if db_handler:
            self._load_visited_urls_from_db()

        logger.info(f"✅ [Dedup] 去重管理器初始化完成 | 目标域名：{len(self.target_root)} 个")

    def _load_visited_urls_from_db(self):
        """
        从数据库加载历史已访问 URL（重启续扫核心）
        """
        try:
            historical_urls = self.db_handler.get_all_visited_urls()
            count = 0
            for url in historical_urls:
                self.visited_urls.add(url)
                count += 1
            logger.info(f"📚 [Dedup] 从数据库加载 {count} 个历史 URL")
        except Exception as e:
            logger.warning(f"⚠️ [Dedup] 加载历史 URL 失败：{e}")

    def is_valid_url(self, url: str) -> bool:
        """
        [兼容旧接口] 只检查域名范围，不检查是否已访问
        """
        return self.is_within_scope(url)

    def is_within_scope(self, url: str) -> bool:
        """检查 URL 是否在目标域名范围内"""
        if not isinstance(url, str) or len(url.strip()) == 0:
            return False
        try:
            parsed = urlparse(url)
            for root in self.target_root:
                if root in parsed.netloc:
                    return True
            return False
        except Exception as e:
            return False

    def should_scan(self, url: str) -> bool:
        """
        判断 URL 是否应该扫描

        检查顺序：
        1. 是否在目标域名范围内
        2. 是否已访问（内存 + 数据库）
        3. 是否是有效文件类型
        """
        # 1. 检查域名范围
        if not self.is_within_scope(url):
            return False

        # 2. 检查是否已访问（先查内存布隆过滤器）
        if self.visited_urls.contains(url):
            # ✅ 双重检查：布隆过滤器可能有误判，查数据库确认
            if self.db_handler and self.db_handler.is_url_visited(url):
                return False

        # 3. 检查文件类型
        url_lower = url.lower().split('?')[0]
        allowed_extensions = ['.js', '.html', '.htm']

        has_allowed_ext = any(url_lower.endswith(ext) for ext in allowed_extensions)
        no_ext = '.' not in url_lower.split('/')[-1]

        if has_allowed_ext or no_ext:
            return True

        return False

    def mark_url_visited(self, url: str):
        """
        标记 URL 为已访问（同步写入内存 + 数据库）

        :param url: 目标 URL
        """
        if not isinstance(url, str) or len(url.strip()) == 0:
            return

        # Layer 1: 写入内存布隆过滤器
        self.visited_urls.add(url)

        # Layer 2: 写入数据库（持久化）
        if self.db_handler:
            try:
                self.db_handler.mark_url_visited(url)
            except Exception as e:
                logger.warning(f"⚠️ [Dedup] 数据库写入失败：{e}")

    def mark_urls_visited_batch(self, urls: list):
        """
        批量标记 URL 为已访问

        :param urls: URL 列表
        """
        if not urls:
            return

        # Layer 1: 写入内存
        for url in urls:
            self.visited_urls.add(url)

        # Layer 2: 批量写入数据库
        if self.db_handler:
            try:
                self.db_handler.mark_urls_visited_batch(urls)
            except Exception as e:
                logger.warning(f"⚠️ [Dedup] 批量数据库写入失败：{e}")

    def is_url_visited(self, url: str) -> bool:
        """
        检查 URL 是否已访问（内存 + 数据库双重检查）

        :param url: 目标 URL
        :return: 是否已访问
        """
        # 先查内存布隆过滤器（快速）
        if not self.visited_urls.contains(url):
            return False

        # 再查数据库确认（准确）
        if self.db_handler:
            return self.db_handler.is_url_visited(url)

        return True

    def _limit_set_size(self, target_set: set, max_size: int):
        """限制集合大小"""
        if len(target_set) > max_size:
            del_list = list(target_set)[:len(target_set) - max_size]
            for val in del_list:
                target_set.remove(val)

    def _limit_domain_cache(self, target_dict: dict, max_domain: int):
        """限制域名字典大小"""
        if len(target_dict) > max_domain:
            del_domain = list(target_dict.keys())[:len(target_dict) - max_domain]
            for domain in del_domain:
                del target_dict[domain]

    def check_duplicate_by_title(self, title: str, url: str) -> bool:
        """按"域名 + 标题"去重"""
        if not isinstance(title, str):
            return False
        title_norm = title.strip().lower()
        if ".js" in url:
            return False
        if len(title_norm) <= 7:
            return False

        try:
            domain = urlparse(url).netloc
            with self.title_lock:
                if domain not in self.title_map:
                    self.title_map[domain] = set()
                if title_norm in self.title_map[domain]:
                    return True
                self.title_map[domain].add(title_norm)
                self._limit_set_size(self.title_map[domain], self.MAX_TITLE_PER_DOMAIN)
                self._limit_domain_cache(self.title_map, self.MAX_DOMAIN_CACHE)
            return False
        except Exception:
            return False

    def is_page_duplicate(self, url: str, html: str, title: str = "", enable_title_check: bool = True):
        """
        页面去重主入口

        :param url: 页面 URL
        :param html: 页面 HTML 内容
        :param title: 页面标题
        :param enable_title_check: 是否启用标题去重
        :return: 是否重复
        """
        if ".js" in url:
            return False
        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False
        if "jquery" in html.lower():
            return False
        if len(html) > 712000:
            return False

        if enable_title_check and title and len(title.strip()) > 0:
            if self.check_duplicate_by_title(title, url):
                return True
        return False

    def clear_visited_urls(self):
        """
        清空已访问 URL 记录（用于重新开始扫描）
        """
        # 清空内存布隆过滤器（重新创建）
        self.visited_urls.close()
        if os.path.exists(self.visited_urls.filepath):
            os.remove(self.visited_urls.filepath)
        self.visited_urls = DiskBloomFilter("Result/global_dedup.bloom", capacity=10000000)

        # 清空数据库记录
        if self.db_handler:
            try:
                self.db_handler.clear_visited_urls()
            except Exception as e:
                logger.warning(f"⚠️ [Dedup] 清空数据库记录失败：{e}")

        logger.info("🗑️ [Dedup] 已清空所有已访问 URL 记录")

    def get_visited_count(self) -> int:
        """
        获取已访问 URL 数量

        :return: 已访问 URL 数量
        """
        if self.db_handler:
            try:
                stats = self.db_handler.get_stats()
                return stats.get("visited_urls", {}).get("total", 0)
            except:
                pass
        return 0

    def close(self):
        """关闭资源"""
        try:
            self.visited_urls.close()
        except:
            pass
        logger.info("🔒 [Dedup] 去重管理器已关闭")