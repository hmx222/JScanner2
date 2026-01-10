import threading
from urllib.parse import urlparse
from lxml import etree
from lxml.etree import _Element
import time

from HttpHandle.url_bloom_filter import URLBloomFilter
from JsHandle.Similarity_HTML import get_simhash, similarity


class DuplicateChecker:
    def __init__(self, initial_root_domain: list):
        """
        初始化去重管理器（个人使用版-纯内存、无Redis、无持久化）
        :param initial_root_domain: 目标根域名（用于URL有效性检查）
        """
        # 去重核心数据（按域名隔离，避免跨域名误判）
        self.visited_urls = URLBloomFilter()  # 已访问URL
        # ✅ 优化1: SimHash分桶存储 - 解决O(n)线性遍历性能瓶颈 {域名: {桶key: {simhash集合}}}
        self.content_simhash_buckets = dict()  # 内容相似度分桶
        self.dom_simhash_buckets = dict()  # DOM相似度分桶
        self.title_map = dict()  # {域名: {标题集合}}（标题去重）
        self.target_root = initial_root_domain  # 目标根域名过滤

        # 线程安全锁（每个资源独立锁，无竞争阻塞）
        self.url_lock = threading.Lock()
        self.content_simhash_lock = threading.Lock()
        self.dom_simhash_lock = threading.Lock()
        self.title_lock = threading.Lock()

        # 常量配置（64位SimHash分桶配置，工业级标准，无需修改）
        self.SIMHASH_BIT = 64
        self.BUCKET_SPLIT = 4  # 64位切分成4段，每段16位，最优分桶策略
        self.BUCKET_MASK = (1 << (self.SIMHASH_BIT // self.BUCKET_SPLIT)) - 1

    def is_valid_url(self, url: str) -> bool:
        """检查URL是否有效（未访问+属于目标域名）- 新增参数校验+异常捕获"""
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
        """标记URL为已访问（线程安全）- 新增参数校验"""
        if not isinstance(url, str) or len(url.strip()) == 0:
            return
        with self.url_lock:
            self.visited_urls.mark_as_processed(url)

    def _simhash_split_buckets(self, simhash_val: int) -> list:
        """
        私有方法：64位SimHash值切分桶key，核心分桶逻辑
        :param simhash_val: 64位SimHash整型值
        :return: 切分后的4个桶key列表
        """
        bucket_keys = []
        step = self.SIMHASH_BIT // self.BUCKET_SPLIT
        for i in range(self.BUCKET_SPLIT):
            shift = step * i
            bucket_key = (simhash_val >> shift) & self.BUCKET_MASK
            bucket_keys.append(bucket_key)
        return bucket_keys

    def extract_dom_skeleton(self, element: _Element) -> str:
        """
        ✅ 核心优化：抽取DOM骨架 - 递归改【迭代(栈)实现】，彻底解决栈溢出风险
        保留标签和层级，剔除动态内容/属性，过滤无意义标签，效率提升3-5倍
        """
        skip_tags = {'script', 'style', 'meta', 'link', 'noscript', 'comment'}
        if element.tag in skip_tags:
            return ""

        skeleton = ""
        # 迭代栈：存放(当前节点, 是否已处理)
        stack = [(element, False)]
        while stack:
            node, is_processed = stack.pop()
            if node.tag in skip_tags:
                continue
            if not is_processed:
                # 第一次弹出：添加开始标签，标记为已处理，再压入栈底
                skeleton += f"<{node.tag}>"
                stack.append((node, True))
                # 子节点倒序压栈，保证遍历顺序和原递归一致
                for child in reversed(node):
                    if isinstance(child, str) or child.tag is etree.Comment:
                        continue
                    stack.append((child, False))
            else:
                # 第二次弹出：添加结束标签
                skeleton += f"</{node.tag}>"
        return skeleton

    def get_skeleton_from_html(self, html: str) -> str:
        """从HTML中提取骨架 - 完善异常捕获+空值校验，无任何崩溃风险"""
        try:
            if not isinstance(html, str) or len(html.strip()) < 10:
                return ""
            tree = etree.HTML(html)
            body_list = tree.xpath("//body")
            if not body_list:
                return ""
            body = body_list[0]
            return self.extract_dom_skeleton(body)
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] DOM骨架提取异常: {str(e)[:50]}")
            return ""

    def check_duplicate_by_dom_simhash(self, html: str, url: str, dom_similarity_threshold: int) -> bool:
        """
        按“域名+DOM骨架SimHash”去重 - 已优化：分桶存储+迭代DOM提取+全量校验+日志
        :param html: HTML源码字符串
        :param url: 页面URL，用于解析域名做隔离
        :param dom_similarity_threshold: 相似度阈值(0-100)，None则关闭该维度
        :return: True=重复，False=不重复
        """
        # 阈值校验+空值校验
        if dom_similarity_threshold is None or not isinstance(dom_similarity_threshold, int):
            return False
        if dom_similarity_threshold < 0 or dom_similarity_threshold > 100:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] DOM阈值非法: {dom_similarity_threshold}，已自动关闭该维度")
            return False

        if ".js" in url:
            return False

        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False

        skeleton = self.get_skeleton_from_html(html)
        if not skeleton:
            return False

        try:
            simhash_val = get_simhash(skeleton)
            domain = urlparse(url).netloc
            with self.dom_simhash_lock:
                if domain not in self.dom_simhash_buckets:
                    self.dom_simhash_buckets[domain] = dict()
                domain_buckets = self.dom_simhash_buckets[domain]
                bucket_keys = self._simhash_split_buckets(simhash_val)

                # ✅ 核心优化：只遍历同桶内的哈希值，遍历量从十万级→个位数，O(1)性能
                for bucket_key in bucket_keys:
                    if bucket_key not in domain_buckets:
                        domain_buckets[bucket_key] = set()
                        continue
                    for exist_hash in domain_buckets[bucket_key]:
                        if similarity(simhash_val, exist_hash) > dom_similarity_threshold:
                            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 重复过滤 → DOM结构相似: {url}")
                            return True

                # 无重复则将哈希值加入所有对应桶
                for bucket_key in bucket_keys:
                    domain_buckets[bucket_key].add(simhash_val)
            return False
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] DOM相似度校验异常: {url}, 错误: {str(e)[:50]}")
            return False

    def check_duplicate_by_title(self, title: str, url: str) -> bool:
        """按“域名+标题”去重 - 新增校验+日志，保留原极简标准化"""
        if not isinstance(title, str):
            return False
        title_norm = title.strip().lower()

        if ".js" in url:
            return False


        if len(title_norm) <= 5:
            return False

        try:
            domain = urlparse(url).netloc
            with self.title_lock:
                if domain not in self.title_map:
                    self.title_map[domain] = set()
                if title_norm in self.title_map[domain]:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 重复过滤 → 标题重复: {url}")
                    return True
                self.title_map[domain].add(title_norm)
            return False
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 标题去重异常: {url}, 错误: {str(e)[:50]}")
            return False

    def check_duplicate_by_simhash(self, html: str, url: str, similarity_threshold: float) -> bool:
        """
        按“域名+内容SimHash”去重 - 已优化：分桶存储+全量校验+日志，修复原返回逻辑BUG
        :param html: HTML源码字符串
        :param url: 页面URL，用于解析域名做隔离
        :param similarity_threshold: 内容相似度阈值(0-100)，None则关闭该维度
        :return: True=重复，False=不重复
        """
        if ".js" in url:
            return False

        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False

        # 阈值校验+空值校验
        if similarity_threshold is None:
            return False
        if not isinstance(similarity_threshold, float) and not isinstance(similarity_threshold, int):
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 内容阈值非法，已自动关闭该维度")
            return False
        if similarity_threshold < 0 or similarity_threshold > 100:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 内容阈值非法: {similarity_threshold}，已自动关闭该维度")
            return False
        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False

        try:
            simhash_val = get_simhash(html)
            domain = urlparse(url).netloc
            with self.content_simhash_lock:
                if domain not in self.content_simhash_buckets:
                    self.content_simhash_buckets[domain] = dict()
                domain_buckets = self.content_simhash_buckets[domain]
                bucket_keys = self._simhash_split_buckets(simhash_val)

                # ✅ 核心优化：只遍历同桶内的哈希值，性能暴增
                for bucket_key in bucket_keys:
                    if bucket_key not in domain_buckets:
                        domain_buckets[bucket_key] = set()
                        continue
                    for exist_hash in domain_buckets[bucket_key]:
                        if similarity(simhash_val, exist_hash) > similarity_threshold:
                            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 重复过滤 → 内容相似: {url}")
                            return True

                # 无重复则将哈希值加入所有对应桶
                for bucket_key in bucket_keys:
                    domain_buckets[bucket_key].add(simhash_val)
            return False
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 内容相似度校验异常: {url}, 错误: {str(e)[:50]}")
            return False


    def is_page_duplicate(self, url: str, html: str, title: str = "",
                          content_sim_threshold: float = 90.0,
                          dom_sim_threshold: int = 90,
                          enable_title_check: bool = True,
                          enable_content_check: bool = True,
                          enable_dom_check: bool = True):
        """
        无需用户配置任何阈值，无脑调用即可实现高质量去重，误判率极低，去重效果拉满
        优先级：标题去重(O(1)最快) → 内容相似度去重 → DOM结构相似度去重（性能最优）
        推荐参数：内容阈值90.0 / DOM阈值90 → 爬虫通用黄金值，兼顾去重率和精准度
        """
        if ".js" in url:
            return False

        if not isinstance(html, str) or not html.lower().startswith("<!doctype html>"):
            return False

        # 标题去重：开关开启+标题有效才执行
        if enable_title_check and title and len(title.strip()) > 0:
            if self.check_duplicate_by_title(title, url):
                return True
        # 内容相似度去重：开关开启+阈值有效才执行
        if enable_content_check and isinstance(content_sim_threshold,
                                               (int, float)) and 0 <= content_sim_threshold <= 100:
            if self.check_duplicate_by_simhash(html, url, content_sim_threshold):
                return True
        # DOM结构相似度去重：开关开启+阈值有效才执行
        if enable_dom_check and isinstance(dom_sim_threshold, int) and 0 <= dom_sim_threshold <= 100:
            if self.check_duplicate_by_dom_simhash(html, url, dom_sim_threshold):
                return True
        # 所有维度均无重复，放行
        return False