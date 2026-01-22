import gc
import threading
from urllib.parse import urlparse
import time
import mmap
import hashlib
import math
import os


class DiskBloomFilter:
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
    def __init__(self, initial_root_domain: list):
        """
        初始化去重管理器（持久化版）
        :param initial_root_domain: 目标根域名（用于URL有效性检查）
        """
        self.visited_urls = DiskBloomFilter("Result/global_dedup.bloom", capacity=10000000)

        self.title_map = dict()
        self.target_root = initial_root_domain
        self.title_lock = threading.Lock()
        self.MAX_TITLE_PER_DOMAIN = 3000
        self.MAX_DOMAIN_CACHE = 200

    def is_valid_url(self, url: str) -> bool:
        """
        [兼容旧接口] 默认行为改为：只检查域名范围，不检查是否已访问。
        防止 process_scan_result 误杀当前正在跑的 URL。
        """
        return self.is_within_scope(url)

    def is_within_scope(self, url: str) -> bool:
        if not isinstance(url, str) or len(url.strip()) == 0:
            return False
        try:
            parsed = urlparse(url)
            for root in self.target_root:
                if root in parsed.netloc:
                    return True
            return False
        except Exception as e:
            # print(f"URL校验异常: {url}")
            return False

    def should_scan(self, url: str) -> bool:
        # 1. 先看是不是自家域名
        if not self.is_within_scope(url):
            return False

        # 2. 再看以前扫过没 (DiskBloomFilter)
        if self.visited_urls.contains(url):
            return False

        return True

    def mark_url_visited(self, url: str):
        """标记URL为已访问"""
        if not isinstance(url, str) or len(url.strip()) == 0:
            return
        self.visited_urls.add(url)

    def _limit_set_size(self, target_set: set, max_size: int):
        if len(target_set) > max_size:
            del_list = list(target_set)[:len(target_set) - max_size]
            for val in del_list:
                target_set.remove(val)

    def _limit_domain_cache(self, target_dict: dict, max_domain: int):
        if len(target_dict) > max_domain:
            del_domain = list(target_dict.keys())[:len(target_dict) - max_domain]
            for domain in del_domain:
                del target_dict[domain]

    def check_duplicate_by_title(self, title: str, url: str) -> bool:
        """按“域名+标题”去重"""
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
        finally:
            pass

    def is_page_duplicate(self, url: str, html: str, title: str = "", enable_title_check: bool = True):
        """极简主入口"""
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
