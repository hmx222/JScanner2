"""
数据库存储层 - SQLiteStorage 组合类

SQLiteStorage 继承自三个 Mixin 类：
- SchemaMixin: 表结构、初始化、工具方法（storage.schema）
- CRUDMixin: 写入操作（storage.crud）
- QueryMixin: 查询和导出（storage.query）

外部通过 `from storage.db import SQLiteStorage` 导入，接口保持不变。
"""

from storage.schema import SchemaMixin
from storage.crud import CRUDMixin
from storage.query import QueryMixin


class SQLiteStorage(SchemaMixin, CRUDMixin, QueryMixin):
    """
    SQLite 数据库存储层

    管理所有数据表的创建、读写、查询和导出操作。
    包含 6 张核心表：
    - scan_results: 基础爬虫扫描结果
    - ai_vulns: AI 发现的渗透建议/漏洞
    - sensitive_info: 敏感信息硬编码
    - visited_urls: 已访问 URL 记录（支持重启续扫）
    - processed_api_paths: 已处理 API 路径记录（防止重复分析）
    - js_source_maps: JS SourceMap 暴露检测结果
    """
    pass
