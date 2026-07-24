"""数据库表结构和初始化模块"""

import os
from typing import Optional

from logger import get_logger

logger = get_logger(__name__)


class SchemaMixin:
    """数据库表结构管理 Mixin"""

    def __init__(self, db_path: str):
        """
        初始化数据库

        Args:
            db_path: 数据库文件路径
        """
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.db_path = db_path
        self.conn: Optional["sqlite3.Connection"] = None
        self._init_db()

    def _init_db(self):
        """
        初始化数据库：创建表结构和索引

        使用 WAL 模式获得极速写入性能，优化并发读写。
        """
        import sqlite3
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()

            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA temp_store=MEMORY;")
            cursor.execute("PRAGMA cache_size=-64000;")

            # 1. 基础爬虫结果表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                domain TEXT,
                path TEXT,
                source_url TEXT,
                scan_depth INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scan_results(domain);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_depth ON scan_results(scan_depth);")

            # 2. AI 渗透建议表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                js_url TEXT NOT NULL,
                api_endpoint TEXT NOT NULL,
                http_method TEXT DEFAULT 'UNKNOWN',
                risk_level TEXT NOT NULL DEFAULT 'Low',
                path TEXT,
                params JSON,
                request_status TEXT,
                response_code INTEGER,
                response_length INTEGER,
                response_body_preview TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(js_url, api_endpoint)
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk ON ai_vulns(risk_level);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoint ON ai_vulns(api_endpoint);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_js_url ON ai_vulns(js_url);")

            # 3. 敏感信息硬编码表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sensitive_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                js_url TEXT NOT NULL,
                sensitive_value TEXT NOT NULL,
                context_code TEXT,
                caller_codes JSON,
                risk_level TEXT DEFAULT 'Low',
                secret_type TEXT,
                test_suggestion TEXT,
                ai_raw_analysis JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(js_url, sensitive_value)
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_risk ON sensitive_info(risk_level);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_js ON sensitive_info(js_url);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_type ON sensitive_info(secret_type);")

            # 4. 已访问 URL 记录表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS visited_urls (
                url TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_visited_url ON visited_urls(url);")

            # 5. 已处理 API Path 记录表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_api_paths (
                api_path TEXT PRIMARY KEY,
                js_url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_path ON processed_api_paths(api_path);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_js ON processed_api_paths(js_url);")

            # 6. JS SourceMap 结果表
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS js_source_maps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                js_url TEXT NOT NULL UNIQUE,
                is_sourceMap TEXT NOT NULL DEFAULT 'N',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sourcemap_js ON js_source_maps(js_url);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sourcemap_flag ON js_source_maps(is_sourceMap);")

            # 迁移：为已有 ai_vulns 表添加缺失字段
            for column in ['request_status', 'response_code', 'response_length', 'response_body_preview']:
                try:
                    cursor.execute(f"ALTER TABLE ai_vulns ADD COLUMN {column} TEXT")
                except Exception:
                    pass

            self.conn.commit()
            logger.info(f"✅ [DB] 数据库初始化成功：{self.db_path}")

        except Exception as e:
            logger.error(f"❌ [DB] 数据库初始化失败：{e}")
            raise

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            try:
                self.conn.close()
            except Exception as e:
                logger.warning(f"⚠️ [DB] 关闭连接时出错：{e}")

    def __enter__(self):
        """上下文管理器入口"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出时自动关闭连接"""
        self.close()

    # ==================== 工具方法 ====================

    def _extract_domain(self, url: str) -> str:
        """从 URL 中提取域名"""
        from urllib.parse import urlparse
        try:
            return urlparse(url).netloc
        except Exception:
            return ""

    def _extract_path(self, url: str) -> str:
        """从 URL 中提取路径"""
        from urllib.parse import urlparse
        try:
            return urlparse(url).path
        except Exception:
            return ""

    def _normalize_method(self, method: str) -> str:
        """标准化 HTTP 方法名"""
        from config.scanner_rules import VALID_HTTP_METHODS
        if not method:
            return "UNKNOWN"
        method = method.upper().strip()
        if method in VALID_HTTP_METHODS:
            return method
        return "UNKNOWN"

    def _parse_params(self, params_str: str) -> dict:
        """解析参数列表字符串为字典"""
        if not params_str:
            return {}
        try:
            params_str = params_str.strip()
            if params_str.startswith("[") and params_str.endswith("]"):
                params_str = params_str[1:-1]
            if not params_str:
                return {}
            params = {}
            for item in params_str.split(","):
                item = item.strip()
                if not item:
                    continue
                if "=" in item:
                    key, value = item.split("=", 1)
                    params[key.strip()] = value.strip()
                else:
                    params[item] = ""
            return params
        except Exception as e:
            logger.warning(f"⚠️ [DB] params 解析失败：{e}")
            return {}

    def _calculate_risk_level(self, path: str, params: dict, method: str) -> str:
        """根据路径、参数和方法计算风险等级"""
        from config.scanner_rules import HIGH_RISK_API_KEYWORDS, MEDIUM_RISK_API_KEYWORDS
        all_text = f"{path} {method} "
        for k, v in params.items():
            all_text += f"{k}={v} "
        all_text_lower = all_text.lower()
        for keyword in HIGH_RISK_API_KEYWORDS:
            if keyword.lower() in all_text_lower:
                return "High"
        for keyword in MEDIUM_RISK_API_KEYWORDS:
            if keyword.lower() in all_text_lower:
                return "Med"
        return "Low"

    def _is_static_resource(self, url: str) -> bool:
        """判断 URL 是否为静态资源"""
        static_extensions = [
            ".js", ".vue", ".css", ".ts", ".jsx", ".tsx",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".woff", ".woff2", ".ttf", ".eot",
            ".mp4", ".mp3", ".wav", ".webm"
        ]
        url_lower = url.lower()
        url_without_query = url_lower.split("?")[0]
        for ext in static_extensions:
            if url_without_query.endswith(ext):
                return True
        return False

    def _deserialize_json_fields(self, record: dict, fields: list) -> dict:
        """反序列化记录中的 JSON 字段"""
        import json
        for field in fields:
            if record.get(field):
                try:
                    record[field] = json.loads(record[field])
                except json.JSONDecodeError:
                    pass
        return record
