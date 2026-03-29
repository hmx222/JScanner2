import sqlite3
import logging
import os
import json
import re
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class SQLiteStorage:
    """
    高性能 SQLite 存储管理器 (v6.3 - 适配 Level 2/3 极简结构)
    支持：
    1. 基础爬虫数据存储 (scan_results)
    2. AI 渗透建议存储 (ai_vulns) - path/method/params 结构
    3. 敏感信息硬编码存储 (sensitive_info)
    """

    # 风险等级关键词映射（基于 path 和 params 内容）
    HIGH_RISK_KEYWORDS = [
        "admin", "user", "update", "delete", "remove", "create",
        "password", "email", "role", "permission", "auth", "token",
        "upload", "import", "export", "backup", "restore",
        "payment", "order", "refund", "transfer", "withdraw"
    ]
    MED_RISK_KEYWORDS = [
        "search", "query", "list", "get", "info", "detail",
        "config", "setting", "profile", "account"
    ]
    VALID_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    def __init__(self, db_path: str):
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        """初始化数据库：开启 WAL 模式以获得极速写入性能"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()

            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA temp_store=MEMORY;")
            cursor.execute("PRAGMA cache_size=-64000;")

            # 1. 基础爬虫结果表
            create_scan_table_sql = """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                domain TEXT,
                path TEXT,
                source_url TEXT,
                scan_depth INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            cursor.execute(create_scan_table_sql)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scan_results(domain);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_depth ON scan_results(scan_depth);")

            # 2. AI 渗透建议表 (v6.3 - 极简结构)
            # 只保留 path/method/params，移除 vuln_focus/expert_advice
            create_ai_table_sql = """
            CREATE TABLE IF NOT EXISTS ai_vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                js_url TEXT NOT NULL,
                api_endpoint TEXT NOT NULL,
                http_method TEXT DEFAULT 'UNKNOWN',
                risk_level TEXT NOT NULL DEFAULT 'Low',
                path TEXT,
                params JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(js_url, api_endpoint)
            );
            """
            cursor.execute(create_ai_table_sql)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk ON ai_vulns(risk_level);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoint ON ai_vulns(api_endpoint);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_js_url ON ai_vulns(js_url);")

            # 3. 敏感信息硬编码表
            create_sensitive_table_sql = """
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
            """
            cursor.execute(create_sensitive_table_sql)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_risk ON sensitive_info(risk_level);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_js ON sensitive_info(js_url);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sensitive_type ON sensitive_info(secret_type);")

            self.conn.commit()
            logger.info(f"✅ [DB] 数据库初始化成功：{self.db_path}")

        except Exception as e:
            logger.error(f"❌ [DB] 数据库初始化失败：{e}")
            raise

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception as e:
                logger.warning(f"⚠️ [DB] 关闭连接时出错：{e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ==================== 工具方法 ====================

    def _extract_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc
        except Exception:
            return ""

    def _extract_path(self, url: str) -> str:
        try:
            return urlparse(url).path
        except Exception:
            return ""

    def _normalize_method(self, method: str) -> str:
        if not method:
            return "UNKNOWN"
        method = method.upper().strip()
        if method in self.VALID_HTTP_METHODS:
            return method
        return "UNKNOWN"

    def _parse_params(self, params_str: str) -> Dict[str, str]:
        """
        解析 params 字符串（支持 key=value / key / =value 三种格式）
        
        输入示例：
        - "id=1,email=test@example.com" → {"id":"1","email":"test@example.com"}
        - "userid,token" → {"userid":"","token":""}  # 只有 key
        - "=admin,role=user" → {"":"admin","role":"user"}  # 混合情况
        """
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
                if not item:  # 跳过空项
                    continue
                    
                if "=" in item:
                    key, value = item.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    # 允许空 key 或空 value（保留原始信息）
                    params[key] = value
                else:
                    # 只有 key，没有 value（说明参数存在但值未知）
                    params[item] = ""
                    
            return params
        except Exception as e:
            logger.warning(f"⚠️ [DB] params 解析失败：{e}")
            return {}

    def _calculate_risk_level(self, path: str, params: Dict[str, str], method: str) -> str:
        """
        根据 path、params 和 method 动态计算风险等级
        """
        all_text = f"{path} {method} "
        for k, v in params.items():
            # 即使 value 为空，key 本身也可能包含敏感信息（如 admin_token）
            all_text += f"{k}={v} "

        all_text_lower = all_text.lower()

        # 高危关键词：管理操作、敏感数据
        for keyword in self.HIGH_RISK_KEYWORDS:
            if keyword.lower() in all_text_lower:
                return "High"

        # 中危关键词：查询、信息获取
        for keyword in self.MED_RISK_KEYWORDS:
            if keyword.lower() in all_text_lower:
                return "Med"

        return "Low"

    def append_data_batch(self, input_data: list, depth: int = 0, show_progress: bool = False) -> None:
        if not input_data:
            return

        rows_to_insert = []
        for item in input_data:
            if not isinstance(item, dict):
                continue
            source_url = str(item.get("sourceURL", "")).strip()
            next_urls = item.get("next_urls", [])
            if not next_urls:
                continue

            for url in next_urls:
                if not isinstance(url, str) or not url.strip():
                    continue
                url_str = url.strip()
                if self._is_static_resource(url_str):
                    continue
                domain = self._extract_domain(url_str)
                path = self._extract_path(url_str)
                rows_to_insert.append((url_str, domain, path, source_url, depth))

        if not rows_to_insert:
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            sql = """
                INSERT OR IGNORE INTO scan_results
                (url, domain, path, source_url, scan_depth)
                VALUES (?, ?, ?, ?, ?)
            """
            cursor.executemany(sql, rows_to_insert)
            self.conn.commit()
            if show_progress:
                print(f"💾 [DB] 基础数据写入：{len(rows_to_insert)} 条")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 基础数据写入异常：{e}")
            raise

    def _is_static_resource(self, url: str) -> bool:
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

    # ==================== AI 漏洞建议写入方法 (v6.3 更新) ====================

    def save_ai_result(self, js_url: str, api_endpoint: str, advisory_report: Dict[str, Any]):
        """
        保存 AI 的渗透测试建议（v6.3 极简结构）

        advisory_report 结构：
        {
            "path": "/admin/user/update",
            "method": "PUT",
            "params": "id=1,email=test@example.com,role"
        }
        """
        if not advisory_report or not isinstance(advisory_report, dict):
            logger.warning("⚠️ [DB] advisory_report 为空或格式错误")
            return

        if not js_url or not api_endpoint:
            logger.warning("⚠️ [DB] js_url 或 api_endpoint 为空")
            return

        try:
            cursor = self.conn.cursor()

            # 1. 提取 method
            raw_method = advisory_report.get("method", "")
            http_method = self._normalize_method(raw_method)

            # 2. 提取 path
            path = advisory_report.get("path", "")

            # 3. 提取并解析 params
            params_raw = advisory_report.get("params", "")
            params_parsed = self._parse_params(params_raw)
            params_json = json.dumps(params_parsed, ensure_ascii=False) if params_parsed else None

            # 4. 计算风险等级
            risk_level = self._calculate_risk_level(path, params_parsed, http_method)

            # 5. 执行写入（极简结构）
            sql = """
                INSERT OR REPLACE INTO ai_vulns
                (js_url, api_endpoint, http_method, risk_level, path, params)
                VALUES (?, ?, ?, ?, ?, ?)
            """

            cursor.execute(sql, (
                js_url,
                api_endpoint,
                http_method,
                risk_level,
                path,
                params_json
            ))

            self.conn.commit()

            # 6. 记录日志
            if risk_level == "High":
                logger.info(f"🔥 [DB] 发现高价值攻击目标：{http_method} {api_endpoint}")
                if params_parsed:
                    logger.info(f"   🔑 关键参数：{params_parsed}")
            else:
                logger.info(f"💾 [DB] 渗透建议已存档：{http_method} {api_endpoint} [{risk_level}]")

        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] AI 渗透建议写入失败：{e}")
            raise

    # ==================== 敏感信息写入方法 ====================

    def save_sensitive_info(self, js_url: str, sensitive_items: List[Dict[str, Any]]):
        if not js_url:
            logger.warning("⚠️ [DB] js_url 为空")
            return
        if not sensitive_items or not isinstance(sensitive_items, list):
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")

            sql = """
                INSERT OR REPLACE INTO sensitive_info
                (js_url, sensitive_value, context_code, caller_codes, risk_level,
                 secret_type, test_suggestion, ai_raw_analysis)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """

            inserted_count = 0
            high_risk_count = 0

            for item in sensitive_items:
                if not isinstance(item, dict):
                    continue
                value = item.get("value", "")
                if not value:
                    continue

                context = item.get("context", "")
                callers = item.get("callers", [])
                risk_level = item.get("risk_level", "Low")
                secret_type = item.get("secret_type", "unknown")
                test_suggestion = item.get("test_suggestion", "")
                ai_raw = item.get("ai_raw_analysis", {})

                callers_json = json.dumps(callers, ensure_ascii=False)
                ai_raw_json = json.dumps(ai_raw, ensure_ascii=False)

                cursor.execute(sql, (
                    js_url, value, context, callers_json,
                    risk_level, secret_type, test_suggestion, ai_raw_json
                ))

                inserted_count += 1
                if risk_level == "High":
                    high_risk_count += 1

            self.conn.commit()

            if high_risk_count > 0:
                logger.info(f"🔥 [DB] 敏感信息写入：{inserted_count} 条 (高危：{high_risk_count})")
            else:
                logger.info(f"💾 [DB] 敏感信息写入：{inserted_count} 条")

        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 敏感信息写入失败：{e}")
            raise

    # ==================== 敏感信息读取方法 ====================

    def get_sensitive_by_js(self, js_url: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE js_url = ? ORDER BY created_at DESC"
            cursor.execute(sql, (js_url,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按 JS URL 读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_risk(self, risk_level: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE risk_level = ? ORDER BY created_at DESC"
            cursor.execute(sql, (risk_level,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按风险等级读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_type(self, secret_type: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE secret_type = ? ORDER BY created_at DESC"
            cursor.execute(sql, (secret_type,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按秘密类型读取敏感信息失败：{e}")
            return []

    def get_all_sensitive(self) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info ORDER BY created_at DESC"
            cursor.execute(sql)
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ["caller_codes", "ai_raw_analysis"]:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 读取所有敏感信息失败：{e}")
            return []

    # ==================== 关联查询方法 ====================

    def get_linked_report(self, js_url: str) -> Dict[str, Any]:
        try:
            ai_vulns = self.get_vulns_by_js(js_url)
            sensitive_info = self.get_sensitive_by_js(js_url)
            high_risk_vulns = sum(1 for v in ai_vulns if v.get("risk_level") == "High")
            high_risk_sensitive = sum(1 for s in sensitive_info if s.get("risk_level") == "High")

            return {
                "js_url": js_url,
                "ai_vulns": {
                    "total": len(ai_vulns),
                    "high_risk": high_risk_vulns,
                    "items": ai_vulns
                },
                "sensitive_info": {
                    "total": len(sensitive_info),
                    "high_risk": high_risk_sensitive,
                    "items": sensitive_info
                },
                "summary": {
                    "total_findings": len(ai_vulns) + len(sensitive_info),
                    "total_high_risk": high_risk_vulns + high_risk_sensitive
                }
            }
        except Exception as e:
            logger.error(f"❌ [DB] 获取关联报告失败：{e}")
            return {}

    # ==================== 漏洞记录读取方法 ====================

    def get_all_vulns(self, risk_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            if risk_filter:
                sql = "SELECT * FROM ai_vulns WHERE risk_level = ? ORDER BY created_at DESC"
                cursor.execute(sql, (risk_filter,))
            else:
                sql = "SELECT * FROM ai_vulns ORDER BY created_at DESC"
                cursor.execute(sql)

            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                # 只解析 params 字段
                if record.get("params"):
                    try:
                        record["params"] = json.loads(record["params"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 读取漏洞记录失败：{e}")
            return []

    def get_vulns_by_js(self, js_url: str) -> List[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM ai_vulns WHERE js_url = ? ORDER BY created_at DESC"
            cursor.execute(sql, (js_url,))
            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                if record.get("params"):
                    try:
                        record["params"] = json.loads(record["params"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按 JS URL 读取失败：{e}")
            return []

    def get_vuln_by_endpoint(self, api_endpoint: str) -> Optional[Dict[str, Any]]:
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM ai_vulns WHERE api_endpoint = ? LIMIT 1"
            cursor.execute(sql, (api_endpoint,))
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                record = dict(zip(columns, row))
                if record.get("params"):
                    try:
                        record["params"] = json.loads(record["params"])
                    except json.JSONDecodeError:
                        pass
                return record
            return None
        except Exception as e:
            logger.error(f"❌ [DB] 按端点读取失败：{e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        try:
            cursor = self.conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM ai_vulns")
            total_vulns = cursor.fetchone()[0]

            cursor.execute("SELECT risk_level, COUNT(*) FROM ai_vulns GROUP BY risk_level")
            risk_distribution_vulns = dict(cursor.fetchall())

            cursor.execute("SELECT COUNT(*) FROM sensitive_info")
            total_sensitive = cursor.fetchone()[0]

            cursor.execute("SELECT risk_level, COUNT(*) FROM sensitive_info GROUP BY risk_level")
            risk_distribution_sensitive = dict(cursor.fetchall())

            cursor.execute("SELECT secret_type, COUNT(*) FROM sensitive_info GROUP BY secret_type")
            type_distribution = dict(cursor.fetchall())

            cursor.execute("SELECT COUNT(*) FROM scan_results")
            total_urls = cursor.fetchone()[0]

            return {
                "ai_vulns": {
                    "total": total_vulns,
                    "by_risk": risk_distribution_vulns
                },
                "sensitive_info": {
                    "total": total_sensitive,
                    "by_risk": risk_distribution_sensitive,
                    "by_type": type_distribution
                },
                "scan_results": {
                    "total_urls": total_urls
                }
            }
        except Exception as e:
            logger.error(f"❌ [DB] 获取统计信息失败：{e}")
            return {}

    def export_high_risk(self) -> List[Dict[str, Any]]:
        return self.get_all_vulns(risk_filter="High")

    def export_high_risk_sensitive(self) -> List[Dict[str, Any]]:
        return self.get_sensitive_by_risk("High")

    def export_for_burp(self, output_path: str) -> bool:
        """导出高危漏洞为 Burp Suite 可导入的 CSV 格式（v6.3 极简结构）"""
        try:
            high_risks = self.export_high_risk()
            if not high_risks:
                logger.warning("⚠️ [DB] 没有高危漏洞可导出")
                return False

            with open(output_path, "w", encoding="utf-8") as f:
                f.write("URL,Method,Risk Level,Path,Params\n")

                for vuln in high_risks:
                    url = vuln.get("api_endpoint", "")
                    method = vuln.get("http_method", "UNKNOWN")
                    risk = vuln.get("risk_level", "Low")

                    # path
                    path = vuln.get("path", "")
                    path = path.replace(",", ";").replace("\n", " ") if path else ""

                    # params
                    params = vuln.get("params", {})
                    if isinstance(params, dict):
                        params_str = ",".join(f"{k}={v}" for k, v in params.items())
                    else:
                        params_str = str(params)
                    params_str = params_str.replace(",", ";") if params_str else ""

                    f.write(f'"{url}","{method}","{risk}","{path}","{params_str}"\n')

            logger.info(f"✅ [DB] 已导出 {len(high_risks)} 条高危漏洞到：{output_path}")
            return True
        except Exception as e:
            logger.error(f"❌ [DB] 导出 Burp 格式失败：{e}")
            return False