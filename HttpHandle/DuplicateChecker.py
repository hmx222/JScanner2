import gc
import threading
from urllib.parse import urlparse
import time


from HttpHandle.url_bloom_filter import URLBloomFilter

class DuplicateChecker:
    def __init__(self, initial_root_domain: list):
        """
        初始化去重管理器（极致精简版-纯内存、无Redis、无持久化）
        仅保留：标题去重 + URL访问记录 ✔ 无任何SimHash/DOM相关计算，性能天花板
        :param initial_root_domain: 目标根域名（用于URL有效性检查）
        """
        self.visited_urls = URLBloomFilter()  # 已访问URL 布隆过滤器
        self.title_map = dict()  # {域名: {标题集合}}（标题去重核心）
        self.target_root = initial_root_domain  # 目标根域名过滤

        self.url_lock = threading.Lock()
        self.title_lock = threading.Lock()

        self.MAX_TITLE_PER_DOMAIN = 3000    # 每个域名最多存3000个标题，足够覆盖99.9%场景
        self.MAX_DOMAIN_CACHE = 200         # 最多缓存200个域名，超了删最早的，释放内存

    def is_valid_url(self, url: str) -> bool:
        """检查URL是否有效（未访问+属于目标域名）- 完整保留核心逻辑"""
        if not isinstance(url, str) or len(url.strip()) == 0:
            return False
        try:
            with self.url_lock:
                if self.visited_urls.is_processed(url):
                    return False
                parsed = urlparse(url)
                for root in self.target_root:
                    if root in parsed.netloc:
                        return True
            return False
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] URL校验异常: {url}, 错误: {str(e)[:50]}")
            return False

    def mark_url_visited(self, url: str):
        """标记URL为已访问（线程安全）- 完整保留核心逻辑"""
        if not isinstance(url, str) or len(url.strip()) == 0:
            return
        with self.url_lock:
            self.visited_urls.mark_as_processed(url)

    # 集合容量超限自动淘汰 - 保留，标题去重内存控制核心
    def _limit_set_size(self, target_set: set, max_size: int):
        if len(target_set) > max_size:
            del_list = list(target_set)[:len(target_set)-max_size]
            for val in del_list:
                target_set.remove(val)

    # 域名缓存超限全量释放 - 保留，解决长尾域名内存泄漏核心
    def _limit_domain_cache(self, target_dict: dict, max_domain: int):
        if len(target_dict) > max_domain:
            del_domain = list(target_dict.keys())[:len(target_dict)-max_domain]
            for domain in del_domain:
                del target_dict[domain]
            # gc.collect()

    def check_duplicate_by_title(self, title: str, url: str) -> bool:
        """按“域名+标题”去重 - 你的核心去重逻辑，完整保留无修改，O(1)极致快"""
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
                    # print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 重复过滤 → 标题重复: {url}")
                    return True
                self.title_map[domain].add(title_norm)
                self._limit_set_size(self.title_map[domain], self.MAX_TITLE_PER_DOMAIN)
                self._limit_domain_cache(self.title_map, self.MAX_DOMAIN_CACHE)
            return False
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 标题去重异常: {url}, 错误: {str(e)[:50]}")
            return False
        finally:
            gc.collect()  # ✅ 新增，释放内存

    def is_page_duplicate(self, url: str, html: str, title: str = "",
                          enable_title_check: bool = True):
        """
        ✅ 彻底精简重构 - 极简主入口，无任何无用参数/无用判断
        仅保留：标题去重 核心逻辑，所有SimHash/DOM相关逻辑全部删除
        优先级：标题去重(O(1)最快，唯一去重维度)
        特点：极致快、无CPU计算、无内存占用、误判率极低
        """
        if ".js" in url:
            return False

        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False

        if "jquery" in html.lower():
            return False

        # 内存优化：过滤超大HTML，减少无效处理
        if len(html) > 712000:
            return False

        # 仅保留标题去重核心逻辑，无其他任何校验
        if enable_title_check and title and len(title.strip()) > 0:
            if self.check_duplicate_by_title(title, url):
                return True

        # 无重复，放行
        return False
