import threading
from urllib.parse import urlparse

from infra.bloom import DiskBloomFilter
from logger import get_logger

logger = get_logger(__name__)  # 获取模块日志器


class DuplicateChecker:
    """
    去重管理器（v2.0 - 支持重启续扫）

    三层去重架构：
    ├── Layer 1: Set 缓存（最快，O(1) 查询）
    ├── Layer 2: DiskBloomFilter（内存映射磁盘，快速存在性检查）
    └── Layer 3: SQLite 数据库（持久化存储，重启续扫核心）
    """

    def __init__(self, db_handler=None, initial_root_domain: list = None):
        """
        初始化去重管理器

        从数据库加载历史记录恢复缓存，支持进程重启后续扫。

        Args:
            db_handler: SQLiteStorage 实例（用于持久化）
            initial_root_domain: 目标根域名列表（用于 URL 有效性检查）
        """
        # Layer 1: 内存 Set 缓存（最快，O(1) 查询）
        self.api_path_cache = set()  # 内存Set缓存

        # Layer 2: 磁盘布隆过滤器（快速，低内存）
        self.visited_urls = DiskBloomFilter("Result/global_dedup.bloom", capacity=10000000)  # 全局URL布隆过滤器
        self.visited_api_paths = DiskBloomFilter("Result/api_path_dedup.bloom", capacity=1000000)  # API路径布隆过滤器

        # Layer 3: 数据库持久化（重启续扫核心）
        self.db_handler = db_handler  # 数据库处理器引用

        # 标题去重缓存
        self.title_map = dict()  # 标题去重字典
        self.target_root = initial_root_domain if initial_root_domain else []  # 目标根域名列表
        self.title_lock = threading.Lock()  # 标题去重锁
        self.MAX_TITLE_PER_DOMAIN = 3000  # 每个域名最大标题数
        self.MAX_DOMAIN_CACHE = 200       # 最大域名缓存数

        # 从数据库加载历史记录到缓存
        if db_handler:
            self._load_visited_urls_from_db()
            self._load_processed_api_paths_from_db()

        logger.info(f"✅ [Dedup] 去重管理器初始化完成 | 目标域名：{len(self.target_root)} 个")

    def _load_visited_urls_from_db(self):
        """
        从数据库加载历史已访问 URL（重启续扫核心）

        将数据库中的历史 URL 加载到内存布隆过滤器，实现进程重启后继续扫描。
        """
        try:
            historical_urls = self.db_handler.get_all_visited_urls()  # 获取历史URL列表
            count = 0  # 已加载计数器
            for url in historical_urls:  # 遍历历史URL
                self.visited_urls.add(url)
                count += 1  # 累加已加载数
            logger.info(f"📚 [Dedup] 从数据库加载 {count} 个历史 URL")
        except Exception as e:  # 加载异常处理
            logger.error(f"⚠️ [Dedup] 加载历史 URL 失败：{e}")

    def _load_processed_api_paths_from_db(self):
        """
        从数据库加载历史已处理 API paths（重启续扫核心）

        同时加载到 Set 缓存和布隆过滤器，实现双重加速。
        """
        try:
            historical_paths = self.db_handler.get_all_processed_api_paths()  # 获取历史API路径
            count = 0  # 已加载计数器
            for path in historical_paths:  # 遍历历史API路径
                # 同时加载到 Set 和 Bloom Filter
                self.api_path_cache.add(path)
                self.visited_api_paths.add(path)
                count += 1  # 累加已加载数
            logger.info(f"📚 [Dedup] 从数据库加载 {count} 个历史 API path 到缓存")
        except Exception as e:  # 加载异常处理
            logger.error(f"⚠️ [Dedup] 加载历史 API path 失败：{e}")

    def is_within_scope(self, url: str) -> bool:
        """
        检查 URL 是否在目标域名范围内

        Args:
            url: 目标 URL

        Returns:
            bool: 是否在允许的域名范围内
        """
        if not isinstance(url, str) or len(url.strip()) == 0:
            return False
        try:
            parsed = urlparse(url)  # 解析URL各组件
            for root in self.target_root:  # 遍历目标域名列表
                if root in parsed.netloc:
                    return True
            return False
        except Exception as e:  # URL解析异常
            return False

    def should_scan(self, url: str) -> bool:
        """
        判断 URL 是否应该被扫描

        三层检查：
        1. 是否在目标域名范围内
        2. 是否已访问（内存布隆过滤器 + 数据库双重确认）
        3. 文件类型是否有效（仅扫描 .js, .html, .htm 或无扩展名的 URL）

        Args:
            url: 目标 URL

        Returns:
            bool: True 表示应该扫描
        """
        # 1. 检查域名范围
        if not self.is_within_scope(url):
            return False

        # 2. 检查是否已访问（先查内存布隆过滤器）
        if self.visited_urls.contains(url):
            if self.db_handler and self.db_handler.is_url_visited(url):
                return False

        # 3. 检查文件类型
        url_lower = url.lower().split('?')[0]  # 取URL小写无参部分
        allowed_extensions = ['.js', '.html', '.htm']  # 允许的文件扩展名

        has_allowed_ext = any(url_lower.endswith(ext) for ext in allowed_extensions)  # 是否允许的扩展名
        no_ext = '.' not in url_lower.split('/')[-1]  # 无扩展名

        if has_allowed_ext or no_ext:
            return True

        return False

    def mark_url_visited(self, url: str):
        """
        标记 URL 为已访问（同步写入内存 + 数据库）

        Args:
            url: 目标 URL
        """
        if not isinstance(url, str) or len(url.strip()) == 0:
            return

        # Layer 1: 写入内存布隆过滤器
        self.visited_urls.add(url)

        # Layer 2: 写入数据库（持久化）
        if self.db_handler:
            try:
                self.db_handler.mark_url_visited(url)
            except Exception as e:  # 写入异常处理
                logger.error(f"⚠️ [Dedup] 数据库写入失败：{e}")

    def mark_urls_visited_batch(self, urls: list):
        """
        批量标记 URL 为已访问

        Args:
            urls: URL 列表
        """
        if not urls:
            return

        # Layer 1: 写入内存
        for url in urls:  # 遍历URL列表批量标记
            self.visited_urls.add(url)

        # Layer 2: 批量写入数据库
        if self.db_handler:
            try:
                self.db_handler.mark_urls_visited_batch(urls)
            except Exception as e:  # 批量写入异常
                logger.error(f"⚠️ [Dedup] 批量数据库写入失败：{e}")

    def is_url_visited(self, url: str) -> bool:
        """
        检查 URL 是否已访问（内存 + 数据库双重检查）

        先查内存布隆过滤器（快速），再查数据库确认（准确）。
        布隆过滤器有假阳性可能，所以需要数据库二次确认。

        Args:
            url: 目标 URL

        Returns:
            bool: 是否已访问
        """
        # 先查内存布隆过滤器（快速）
        if not self.visited_urls.contains(url):
            return False

        # 再查数据库确认（准确）
        if self.db_handler:
            return self.db_handler.is_url_visited(url)

        return True

    def _limit_set_size(self, target_set: set, max_size: int):
        """
        限制集合大小，超出时移除最早添加的元素

        Args:
            target_set: 目标集合
            max_size: 最大容量
        """
        if len(target_set) > max_size:
            del_list = list(target_set)[:len(target_set) - max_size]  # 计算待删除元素
            for val in del_list:  # 遍历移除多余元素
                target_set.remove(val)

    def _limit_domain_cache(self, target_dict: dict, max_domain: int):
        """
        限制域名字典大小，超出时移除最早添加的域名

        Args:
            target_dict: 目标字典
            max_domain: 最大域名数量
        """
        if len(target_dict) > max_domain:
            del_domain = list(target_dict.keys())[:len(target_dict) - max_domain]  # 计算待删除域名
            for domain in del_domain:  # 遍历移除多余域名
                del target_dict[domain]

    def check_duplicate_by_title(self, title: str, url: str) -> bool:
        """
        按"域名 + 标题"去重

        Args:
            title: 页面标题
            url: 页面 URL

        Returns:
            bool: 是否重复
        """
        if not isinstance(title, str):
            return False
        title_norm = title.strip().lower()  # 标题标准化处理
        # JS 文件跳过标题去重（标题通常无用）
        if ".js" in url:
            return False
        # 过短的标题跳过（无意义）
        if len(title_norm) <= 7:
            return False

        try:
            domain = urlparse(url).netloc  # 提取URL域名
            with self.title_lock:
                if domain not in self.title_map:
                    self.title_map[domain] = set()  # 初始化该域名标题集合
                if title_norm in self.title_map[domain]:
                    return True
                self.title_map[domain].add(title_norm)
                # 限制缓存大小
                self._limit_set_size(self.title_map[domain], self.MAX_TITLE_PER_DOMAIN)
                self._limit_domain_cache(self.title_map, self.MAX_DOMAIN_CACHE)
            return False
        except Exception:
            return False

    def is_page_duplicate(self, url: str, html: str, title: str = "", enable_title_check: bool = True):
        """
        页面去重主入口

        多重去重策略：
        1. JS 文件不做去重（所有 JS 都需要分析）
        2. 非 HTML 文档跳过
        3. 包含 jQuery 的页面可能包含动态内容，跳过
        4. 过大的页面跳过
        5. 标题去重（可选）

        Args:
            url: 页面 URL
            html: 页面 HTML 内容
            title: 页面标题
            enable_title_check: 是否启用标题去重

        Returns:
            bool: 是否重复
        """
        # JS 文件不做去重
        if ".js" in url:
            return False
        # 只对 HTML 文档进行去重
        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False
        # jQuery 页面跳过（内容可能动态变化）
        if "jquery" in html.lower():
            return False
        # 过大的页面跳过
        if len(html) > 712000:
            return False

        # 标题去重
        if enable_title_check and title and len(title.strip()) > 0:
            if self.check_duplicate_by_title(title, url):
                return True
        return False

    def close(self):
        """关闭资源（布隆过滤器文件句柄）"""
        try:
            self.visited_urls.close()
            self.visited_api_paths.close()
        except:
            pass
        logger.info("🔒 [Dedup] 去重管理器已关闭")

    def is_api_path_processed(self, api_path: str) -> bool:
        """
        检查 API path 是否已处理（三层缓存查询）

        查询链路（从快到慢）：
        1. Set 缓存（O(1) 最快）
        2. Bloom Filter（快速，有假阳性可能）
        3. 数据库（准确，相对较慢）

        Args:
            api_path: API 路径

        Returns:
            bool: 是否已处理
        """
        if not isinstance(api_path, str) or len(api_path.strip()) == 0:
            return True

        # Layer 1: Set 缓存（最快，O(1)）
        if api_path in self.api_path_cache:
            return True

        # Layer 2: Bloom Filter（快速，可能有假阳性）
        if not self.visited_api_paths.contains(api_path):
            return False

        # Layer 3: 数据库（准确，但慢）
        if self.db_handler:
            if self.db_handler.is_api_path_processed(api_path):
                # 同步更新缓存
                self.api_path_cache.add(api_path)
                return True

        return False

    def mark_api_paths_processed_batch(self, paths_data: list):
        """
        批量标记 API paths 为已处理

        Args:
            paths_data: [(api_path, js_url), ...] 元组列表
        """
        if not paths_data:
            return

        # Layer 1: 写入 Set 缓存
        for api_path, _ in paths_data:  # 遍历API路径列表
            self.api_path_cache.add(api_path)

        # Layer 2: 写入 Bloom Filter
        for api_path, _ in paths_data:  # 遍历API路径列表
            self.visited_api_paths.add(api_path)

        # Layer 3: 批量写入数据库
        if self.db_handler:
            try:
                self.db_handler.mark_api_paths_processed_batch(paths_data)
            except Exception as e:  # 批量API路径异常
                logger.error(f"⚠️ [Dedup] 批量 API path 数据库写入失败：{e}")

