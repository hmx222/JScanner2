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
    高性能 SQLite 存储管理器 (v6.1 params 整合版)
    支持：
    1. 基础爬虫数据存储 (scan_results)
    2. AI 专家审计建议存储 (ai_vulns) - 新增 params 字段
    3. 敏感信息硬编码存储 (sensitive_info)
    """

    # 风险等级关键词映射（基于 vuln_focus 和 actionable_test 内容）
    HIGH_RISK_KEYWORDS = [
        "注入", "Injection", "RCE", "绕过", "Bypass",
        "越权", "IDOR", "未授权", "Unauthorized",
        "劫持", "Hijack", "溢出", "Overflow"
    ]
    MED_RISK_KEYWORDS = [
        "枚举", "Enumeration", "污染", "Pollution",
        "重定向", "Redirect", "泄露", "Leak",
        "伪造", "Spoofing", "竞争", "Race"
    ]
    VALID_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    def __init__(self, db_path: str):
        # 确保目录存在
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

            # 开启高性能模式
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA temp_store=MEMORY;")
            cursor.execute("PRAGMA cache_size=-64000;")  # 64MB 缓存

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

            # 2. AI 渗透建议表 (v6.1 新增 params 字段)
            create_ai_table_sql = """
            CREATE TABLE IF NOT EXISTS ai_vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                js_url TEXT NOT NULL,
                api_endpoint TEXT NOT NULL,
                http_method TEXT DEFAULT 'UNKNOWN',
                risk_level TEXT NOT NULL DEFAULT 'Low',
                vuln_focus TEXT,
                expert_advice JSON,
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
        """关闭数据库连接"""
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
        """从 URL 提取域名"""
        try:
            return urlparse(url).netloc
        except Exception:
            return ""

    def _extract_path(self, url: str) -> str:
        """从 URL 提取路径"""
        try:
            return urlparse(url).path
        except Exception:
            return ""

    def _normalize_method(self, method: str) -> str:
        """标准化 HTTP 方法名"""
        if not method:
            return "UNKNOWN"

        method = method.upper().strip()
        if method in self.VALID_HTTP_METHODS:
            return method
        return "UNKNOWN"

    def _parse_params(self, params_str: str) -> Dict[str, str]:
        """
        解析 params 字符串为字典

        输入："[id=1,isadmin=true]"
        输出：{"id": "1", "isadmin": "true"}

        Args:
            params_str: params 字符串

        Returns:
            参数字典
        """
        if not params_str or not isinstance(params_str, str):
            return {}

        try:
            # 去除首尾空格
            params_str = params_str.strip()

            # 去除方括号
            if params_str.startswith("[") and params_str.endswith("]"):
                params_str = params_str[1:-1]

            # 空字符串处理
            if not params_str:
                return {}

            # 按逗号分割并解析键值对
            params = {}
            for item in params_str.split(","):
                item = item.strip()
                if "=" in item:
                    key, value = item.split("=", 1)
                    params[key.strip()] = value.strip()

            return params

        except Exception as e:
            logger.warning(f"⚠️ [DB] params 解析失败：{e}")
            return {}

    def _calculate_risk_level(self, vuln_focus: str, expert_advice: List[Dict[str, Any]]) -> str:
        """
        根据 vuln_focus 和 expert_advice 内容动态计算风险等级
        """
        all_text = vuln_focus or ""

        if expert_advice and isinstance(expert_advice, list):
            for advice in expert_advice:
                if isinstance(advice, dict):
                    test_content = advice.get("actionable_test", "")
                    if test_content:
                        all_text += " " + test_content

        all_text_upper = all_text.upper()

        for keyword in self.HIGH_RISK_KEYWORDS:
            if keyword.upper() in all_text_upper:
                return "High"

        for keyword in self.MED_RISK_KEYWORDS:
            if keyword.upper() in all_text_upper:
                return "Med"

        return "Low"

    # ==================== 爬虫数据写入方法 ====================

    def append_data_batch(self, input_data: list, depth: int = 0, show_progress: bool = False) -> None:
        """
        批量写入爬虫抓取到的 URL 数据
        """
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
        """判断是否为静态资源文件"""
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

    # ==================== AI 漏洞建议写入方法 (v6.1 更新) ====================

    def save_ai_result(self, js_url: str, api_endpoint: str, advisory_report: Dict[str, Any]):
        """
        保存 AI 的渗透测试建议

        advisory_report 结构：
        {
            "method": "GET",
            "vuln_focus": "...",
            "expert_advice": [...],
            "params": "[id=1,isadmin=true]"  ← 新增
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

            # 2. 提取 vuln_focus
            vuln_focus = advisory_report.get("vuln_focus", "")

            # 3. 提取 expert_advice
            expert_advice = advisory_report.get("expert_advice", [])
            expert_advice_json = json.dumps(expert_advice, ensure_ascii=False)

            # 4. 【新增】提取并解析 params
            params_raw = advisory_report.get("params", "")
            params_parsed = self._parse_params(params_raw)
            params_json = json.dumps(params_parsed, ensure_ascii=False) if params_parsed else None

            # 5. 计算风险等级
            risk_level = self._calculate_risk_level(vuln_focus, expert_advice)

            # 6. 执行写入 (params 字段新增)
            sql = """
                INSERT OR REPLACE INTO ai_vulns
                (js_url, api_endpoint, http_method, risk_level, vuln_focus, expert_advice, params)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """

            cursor.execute(sql, (
                js_url,
                api_endpoint,
                http_method,
                risk_level,
                vuln_focus,
                expert_advice_json,
                params_json
            ))

            self.conn.commit()

            # 7. 记录日志
            if risk_level == "High":
                logger.info(f"🔥 [DB] 发现高价值攻击目标：{http_method} {api_endpoint}")
                focus_preview = vuln_focus[:80] + "..." if len(vuln_focus) > 80 else vuln_focus
                logger.info(f"   📋 漏洞焦点：{focus_preview}")
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
        """
        保存敏感信息到数据库

        Args:
            js_url: 来源 JS 文件 URL
            sensitive_items: 敏感信息列表，每项结构：
                {
                    "value": "P644E3B2D92EF81",
                    "context": "...",
                    "callers": [...],
                    "risk_level": "High",
                    "secret_type": "license_key",
                    "test_suggestion": "...",
                    "ai_raw_analysis": {...}
                }
        """
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
                    js_url,
                    value,
                    context,
                    callers_json,
                    risk_level,
                    secret_type,
                    test_suggestion,
                    ai_raw_json
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
        """根据 JS 文件 URL 获取敏感信息记录"""
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE js_url = ? ORDER BY created_at DESC"
            cursor.execute(sql, (js_url,))

            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                if record.get("caller_codes"):
                    try:
                        record["caller_codes"] = json.loads(record["caller_codes"])
                    except json.JSONDecodeError:
                        pass
                if record.get("ai_raw_analysis"):
                    try:
                        record["ai_raw_analysis"] = json.loads(record["ai_raw_analysis"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)

            return results

        except Exception as e:
            logger.error(f"❌ [DB] 按 JS URL 读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_risk(self, risk_level: str) -> List[Dict[str, Any]]:
        """根据风险等级获取敏感信息记录"""
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE risk_level = ? ORDER BY created_at DESC"
            cursor.execute(sql, (risk_level,))

            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                if record.get("caller_codes"):
                    try:
                        record["caller_codes"] = json.loads(record["caller_codes"])
                    except json.JSONDecodeError:
                        pass
                if record.get("ai_raw_analysis"):
                    try:
                        record["ai_raw_analysis"] = json.loads(record["ai_raw_analysis"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)

            return results

        except Exception as e:
            logger.error(f"❌ [DB] 按风险等级读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_type(self, secret_type: str) -> List[Dict[str, Any]]:
        """根据秘密类型获取敏感信息记录"""
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info WHERE secret_type = ? ORDER BY created_at DESC"
            cursor.execute(sql, (secret_type,))

            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                if record.get("caller_codes"):
                    try:
                        record["caller_codes"] = json.loads(record["caller_codes"])
                    except json.JSONDecodeError:
                        pass
                if record.get("ai_raw_analysis"):
                    try:
                        record["ai_raw_analysis"] = json.loads(record["ai_raw_analysis"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)

            return results

        except Exception as e:
            logger.error(f"❌ [DB] 按秘密类型读取敏感信息失败：{e}")
            return []

    def get_all_sensitive(self) -> List[Dict[str, Any]]:
        """获取所有敏感信息记录"""
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM sensitive_info ORDER BY created_at DESC"
            cursor.execute(sql)

            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                if record.get("caller_codes"):
                    try:
                        record["caller_codes"] = json.loads(record["caller_codes"])
                    except json.JSONDecodeError:
                        pass
                if record.get("ai_raw_analysis"):
                    try:
                        record["ai_raw_analysis"] = json.loads(record["ai_raw_analysis"])
                    except json.JSONDecodeError:
                        pass
                results.append(record)

            return results

        except Exception as e:
            logger.error(f"❌ [DB] 读取所有敏感信息失败：{e}")
            return []

    # ==================== 关联查询方法 ====================

    def get_linked_report(self, js_url: str) -> Dict[str, Any]:
        """
        获取 JS 文件关联的完整报告 (ai_vulns + sensitive_info)

        Args:
            js_url: JS 文件 URL

        Returns:
            完整报告字典
        """
        try:
            # 获取 AI 漏洞建议
            ai_vulns = self.get_vulns_by_js(js_url)

            # 获取敏感信息
            sensitive_info = self.get_sensitive_by_js(js_url)

            # 统计
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
        """获取所有漏洞记录"""
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
                # 反序列化 JSON 字段 (包括新增的 params)
                for field in ['expert_advice', 'params']:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)

            return results

        except Exception as e:
            logger.error(f"❌ [DB] 读取漏洞记录失败：{e}")
            return []

    def get_vulns_by_js(self, js_url: str) -> List[Dict[str, Any]]:
        """根据 JS 文件 URL 获取相关漏洞记录"""
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM ai_vulns WHERE js_url = ? ORDER BY created_at DESC"
            cursor.execute(sql, (js_url,))

            columns = [desc[0] for desc in cursor.description]
            results = []

            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                for field in ['expert_advice', 'params']:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)

            return results

        except Exception as e:
            logger.error(f"❌ [DB] 按 JS URL 读取失败：{e}")
            return []

    def get_vuln_by_endpoint(self, api_endpoint: str) -> Optional[Dict[str, Any]]:
        """根据 API 端点获取单条漏洞记录"""
        try:
            cursor = self.conn.cursor()
            sql = "SELECT * FROM ai_vulns WHERE api_endpoint = ? LIMIT 1"
            cursor.execute(sql, (api_endpoint,))

            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                record = dict(zip(columns, row))
                for field in ['expert_advice', 'params']:
                    if record.get(field):
                        try:
                            record[field] = json.loads(record[field])
                        except json.JSONDecodeError:
                            pass
                return record

            return None

        except Exception as e:
            logger.error(f"❌ [DB] 按端点读取失败：{e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """获取数据库统计信息"""
        try:
            cursor = self.conn.cursor()

            # 漏洞统计
            cursor.execute("SELECT COUNT(*) FROM ai_vulns")
            total_vulns = cursor.fetchone()[0]

            cursor.execute("SELECT risk_level, COUNT(*) FROM ai_vulns GROUP BY risk_level")
            risk_distribution_vulns = dict(cursor.fetchall())

            # 敏感信息统计
            cursor.execute("SELECT COUNT(*) FROM sensitive_info")
            total_sensitive = cursor.fetchone()[0]

            cursor.execute("SELECT risk_level, COUNT(*) FROM sensitive_info GROUP BY risk_level")
            risk_distribution_sensitive = dict(cursor.fetchall())

            cursor.execute("SELECT secret_type, COUNT(*) FROM sensitive_info GROUP BY secret_type")
            type_distribution = dict(cursor.fetchall())

            # 爬虫数据统计
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
        """导出所有高危漏洞记录"""
        return self.get_all_vulns(risk_filter="High")

    def export_high_risk_sensitive(self) -> List[Dict[str, Any]]:
        """导出所有高危敏感信息记录"""
        return self.get_sensitive_by_risk("High")

    def export_for_burp(self, output_path: str) -> bool:
        """导出高危漏洞为 Burp Suite 可导入的 CSV 格式"""
        try:
            high_risks = self.export_high_risk()

            if not high_risks:
                logger.warning("⚠️ [DB] 没有高危漏洞可导出")
                return False

            with open(output_path, "w", encoding="utf-8") as f:
                f.write("URL,Method,Risk Level,Vuln Focus,Params,Test Steps\n")

                for vuln in high_risks:
                    url = vuln.get("api_endpoint", "")
                    method = vuln.get("http_method", "UNKNOWN")
                    risk = vuln.get("risk_level", "Low")
                    focus = vuln.get("vuln_focus", "").replace(",", ";").replace("\n", " ")

                    # 新增：导出 params
                    params = vuln.get("params", {})
                    params_str = ",".join(f"{k}={v}" for k, v in params.items()) if params else ""
                    params_str = params_str.replace(",", ";") if params_str else ""

                    test_steps = ""
                    expert_advice = vuln.get("expert_advice", [])
                    if expert_advice and isinstance(expert_advice, list):
                        steps = [item.get("actionable_test", "") for item in expert_advice if isinstance(item, dict)]
                        test_steps = " | ".join(steps).replace(",", ";").replace("\n", " ")

                    f.write(f'"{url}","{method}","{risk}","{focus}","{params_str}","{test_steps}"\n')

            logger.info(f"✅ [DB] 已导出 {len(high_risks)} 条高危漏洞到：{output_path}")
            return True

        except Exception as e:
            logger.error(f"❌ [DB] 导出 Burp 格式失败：{e}")
            return False