import threading
from hashlib import md5
from urllib.parse import urlparse

import zss
from bs4 import BeautifulSoup
from lxml import etree
from lxml.etree import _Element

from JsHandle.Similarity_HTML import get_simhash, similarity


class DuplicateChecker:
    def __init__(self, initial_root_domain: list):
        """
        初始化去重管理器
        :param initial_root_domain: 目标根域名（用于URL有效性检查）
        """
        # 去重核心数据（按域名隔离，避免跨域名误判）
        self.visited_urls = set()  # 已访问URL
        self.simhash_map = dict()  # {域名: {simhash集合}}（内容相似度去重）
        self.title_map = dict()  # {域名: {标题集合}}（标题去重）
        self.length_map = dict()  # {域名: {长度集合}}（长度去重）
        self.target_root = initial_root_domain  # 目标根域名（用于URL过滤）
        self.DOM_simhash_map = dict()  # {域名: {DOM骨架集合}}（DOM结构去重）

        # 线程安全锁（每个资源独立锁，避免竞争）
        self.url_lock = threading.Lock()
        self.hash_lock = threading.Lock()
        self.simhash_lock = threading.Lock()
        self.title_lock = threading.Lock()
        self.length_lock = threading.Lock()

    def is_valid_url(self, url: str) -> bool:
        """检查URL是否有效（未访问+属于目标域名）"""
        with self.url_lock:
            # 已访问过的URL直接过滤
            if url in self.visited_urls:
                return False
            # 检查是否属于目标域名
            parsed = urlparse(url)
            for root in self.target_root:
                if root in parsed.netloc:
                    return True
            return False

    def mark_url_visited(self, url: str):
        """标记URL为已访问（线程安全）"""
        with self.url_lock:
            self.visited_urls.add(url)

    def extract_dom_skeleton(self, element: _Element) -> str:
        """抽取DOM骨架（保留标签和层级，剔除动态内容）"""
        # 只保留标签名，剔除所有属性值
        skeleton = f"<{element.tag}>"

        for child in element:
            # 跳过文本节点
            if child.tag is etree.Comment:
                continue
            if isinstance(child, str):
                continue
            skeleton += self.extract_dom_skeleton(child)

        skeleton += f"</{element.tag}>"
        return skeleton

    # 示例：从HTML中提取骨架
    def get_skeleton_from_html(self, html: str) -> str:
        try:
            tree = etree.HTML(html)
            # 以<body>为根节点
            body = tree.xpath("//body")[0]
            return self.extract_dom_skeleton(body)
        except Exception:
            return ""

    def check_duplicate_by_DOM_simhash(self, source: str, threshold:str) -> bool:
        if threshold is None:
            return True
        if not source.lower().startswith("<!doctype html>"):
            return False  # 仅对HTML页面进行DOM去重
        # 提取DOM骨架
        skeleton = self.get_skeleton_from_html(source)
        if not skeleton:
            return False
        simhash = get_simhash(skeleton)
        domain = urlparse(source).netloc
        with self.simhash_lock:
            if domain not in self.DOM_simhash_map:
                self.DOM_simhash_map[domain] = set()
            if any(similarity(simhash, existing) > int(threshold)
                   for existing in self.DOM_simhash_map[domain]):
                return True  # 重复
            self.DOM_simhash_map[domain].add(simhash)
        return False  # 不重复


    def check_duplicate_by_title(self, title: str, url: str) -> bool:
        """按“域名+标题”去重（同域名标题相同视为重复）"""
        if not title or title.strip() in ("", " "):
            return False  # 空标题不参与去重

        domain = urlparse(url).netloc
        with self.title_lock:
            if domain not in self.title_map:
                self.title_map[domain] = set()
            if title in self.title_map[domain]:
                return True  # 重复
            self.title_map[domain].add(title)
        return False  # 不重复

    def check_duplicate_by_length(self, length: int, url: str) -> bool:
        """按“域名+长度”去重（同域名长度相同视为重复）"""
        if length < 300:
            return False

        domain = urlparse(url).netloc
        with self.length_lock:
            if domain not in self.length_map:
                self.length_map[domain] = set()
            if length in self.length_map[domain]:
                return True  # 重复
            self.length_map[domain].add(length)
        return False  # 不重复

    def check_duplicate_by_simhash(self, source: str, url: str, similarity_threshold: float) -> bool:
        """按“域名+SimHash”去重（内容相似度超过阈值视为重复）"""
        if similarity_threshold is None:
            return True
        # 只对HTML页面做SimHash去重
        if not source.lower().startswith("<!doctype html>"):
            return False

        domain = urlparse(url).netloc
        simhash = get_simhash(source)  # 复用原有SimHash计算
        with self.simhash_lock:
            if domain not in self.simhash_map:
                self.simhash_map[domain] = set()
            if any(similarity(simhash, existing) > similarity_threshold
                   for existing in self.simhash_map[domain]):
                return True  # 重复
            self.simhash_map[domain].add(simhash)
        return False  # 不重复