"""数据库查询和导出模块"""

import json

from logger import get_logger

logger = get_logger(__name__)


class QueryMixin:
    """数据库查询和导出操作 Mixin"""

    # ==================== 已访问 URL 查询 ====================

    def get_all_visited_urls(self) -> list:
        """获取所有已访问的 URL（用于重启后续扫）"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT url FROM visited_urls")
            urls = [row[0] for row in cursor.fetchall()]
            logger.info(f"📚 [DB] 从数据库加载 {len(urls)} 个历史 URL")
            return urls
        except Exception as e:
            logger.warning(f"⚠️ [DB] 获取已访问 URL 失败：{e}")
            return []

    def is_url_visited(self, url: str) -> bool:
        """检查 URL 是否已访问"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM visited_urls WHERE url = ? LIMIT 1", (url,))
            return cursor.fetchone() is not None
        except Exception as e:
            logger.warning(f"⚠️ [DB] 检查 URL 状态失败：{e}")
            return False

    # ==================== API Path 查询 ====================

    def is_api_path_processed(self, api_path: str) -> bool:
        """检查 API path 是否已被处理过"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM processed_api_paths WHERE api_path = ? LIMIT 1", (api_path,))
            return cursor.fetchone() is not None
        except Exception as e:
            logger.warning(f"⚠️ [DB] 检查 API path 状态失败：{e}")
            return False

    def get_all_processed_api_paths(self) -> list:
        """获取所有已处理的 API paths"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT api_path FROM processed_api_paths")
            paths = [row[0] for row in cursor.fetchall()]
            logger.info(f"📚 [DB] 从数据库加载 {len(paths)} 个历史 API path")
            return paths
        except Exception as e:
            logger.warning(f"⚠️ [DB] 获取已处理 API path 失败：{e}")
            return []

    # ==================== 敏感信息查询 ====================

    def get_sensitive_by_js(self, js_url: str) -> list:
        """按 JS URL 查询敏感信息"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM sensitive_info WHERE js_url = ? ORDER BY created_at DESC", (js_url,))
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                record = self._deserialize_json_fields(record, ["caller_codes", "ai_raw_analysis"])
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按 JS URL 读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_risk(self, risk_level: str) -> list:
        """按风险等级查询敏感信息"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM sensitive_info WHERE risk_level = ? ORDER BY created_at DESC", (risk_level,))
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                record = self._deserialize_json_fields(record, ["caller_codes", "ai_raw_analysis"])
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按风险等级读取敏感信息失败：{e}")
            return []

    def get_sensitive_by_type(self, secret_type: str) -> list:
        """按秘密类型查询敏感信息"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM sensitive_info WHERE secret_type = ? ORDER BY created_at DESC", (secret_type,))
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                record = self._deserialize_json_fields(record, ["caller_codes", "ai_raw_analysis"])
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 按秘密类型读取敏感信息失败：{e}")
            return []

    def get_all_sensitive(self) -> list:
        """获取所有敏感信息记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM sensitive_info ORDER BY created_at DESC")
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                record = dict(zip(columns, row))
                record = self._deserialize_json_fields(record, ["caller_codes", "ai_raw_analysis"])
                results.append(record)
            return results
        except Exception as e:
            logger.error(f"❌ [DB] 读取所有敏感信息失败：{e}")
            return []

    # ==================== 漏洞查询 ====================

    def get_all_vulns(self, risk_filter: str = None) -> list:
        """获取所有漏洞记录（可按风险等级过滤）"""
        try:
            cursor = self.conn.cursor()
            if risk_filter:
                cursor.execute("SELECT * FROM ai_vulns WHERE risk_level = ? ORDER BY created_at DESC", (risk_filter,))
            else:
                cursor.execute("SELECT * FROM ai_vulns ORDER BY created_at DESC")
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
            logger.error(f"❌ [DB] 读取漏洞记录失败：{e}")
            return []

    def get_vulns_by_js(self, js_url: str) -> list:
        """按 JS URL 查询漏洞记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM ai_vulns WHERE js_url = ? ORDER BY created_at DESC", (js_url,))
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

    def get_vuln_by_endpoint(self, api_endpoint: str):
        """按 API 端点查询漏洞记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM ai_vulns WHERE api_endpoint = ? LIMIT 1", (api_endpoint,))
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

    # ==================== 关联报告 ====================

    def get_linked_report(self, js_url: str) -> dict:
        """获取指定 JS URL 的关联报告（AI 漏洞 + 敏感信息）"""
        try:
            ai_vulns = self.get_vulns_by_js(js_url)
            sensitive_info = self.get_sensitive_by_js(js_url)
            high_risk_vulns = sum(1 for v in ai_vulns if v.get("risk_level") == "High")
            high_risk_sensitive = sum(1 for s in sensitive_info if s.get("risk_level") == "High")
            return {
                "js_url": js_url,
                "ai_vulns": {"total": len(ai_vulns), "high_risk": high_risk_vulns, "items": ai_vulns},
                "sensitive_info": {"total": len(sensitive_info), "high_risk": high_risk_sensitive, "items": sensitive_info},
                "summary": {"total_findings": len(ai_vulns) + len(sensitive_info),
                            "total_high_risk": high_risk_vulns + high_risk_sensitive}
            }
        except Exception as e:
            logger.error(f"❌ [DB] 获取关联报告失败：{e}")
            return {}

    # ==================== 统计 ====================

    # ==================== 导出 ====================

    def export_high_risk(self) -> list:
        """导出所有高危漏洞"""
        return self.get_all_vulns(risk_filter="High")

    def export_high_risk_sensitive(self) -> list:
        """导出所有高危敏感信息"""
        return self.get_sensitive_by_risk("High")

    def export_for_burp(self, output_path: str) -> bool:
        """导出高危漏洞为 Burp Suite 可导入的 CSV 格式"""
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
                    path = vuln.get("path", "").replace(",", ";").replace("\n", " ") if vuln.get("path") else ""
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

    # ==================== SourceMap 查询 ====================

    def get_source_map_results(self) -> list:
        """获取所有 SourceMap 检测结果"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM js_source_maps ORDER BY created_at DESC")
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"❌ [DB] 读取 SourceMap 结果失败：{e}")
            return []
