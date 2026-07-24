"""数据库写入操作模块"""

import json

from logger import get_logger

logger = get_logger(__name__)


class CRUDMixin:
    """数据库 CRUD 写入操作 Mixin"""

    # ==================== 已访问 URL 管理 ====================

    def mark_url_visited(self, url: str) -> bool:
        """标记 URL 为已访问"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO visited_urls (url) VALUES (?)", (url,))
            self.conn.commit()
            return True
        except Exception as e:
            logger.warning(f"⚠️ [DB] 标记 URL 失败：{e}")
            return False

    def mark_urls_visited_batch(self, urls: list) -> int:
        """批量标记 URL 为已访问"""
        if not urls:
            return 0
        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            data = [(url,) for url in urls if url and isinstance(url, str)]
            cursor.executemany("INSERT OR IGNORE INTO visited_urls (url) VALUES (?)", data)
            self.conn.commit()
            logger.debug(f"📝 [DB] 批量标记 {len(data)} 个 URL 为已访问")
            return len(data)
        except Exception as e:
            self.conn.rollback()
            logger.warning(f"⚠️ [DB] 批量标记 URL 失败：{e}")
            return 0

    # ==================== API Path 管理 ====================

    def mark_api_paths_processed_batch(self, paths_data: list) -> int:
        """批量标记 API paths 为已处理"""
        if not paths_data:
            return 0
        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            cursor.executemany(
                "INSERT OR IGNORE INTO processed_api_paths (api_path, js_url) VALUES (?, ?)",
                paths_data
            )
            self.conn.commit()
            logger.debug(f"📝 [DB] 批量标记 {len(paths_data)} 个 API path 为已处理")
            return len(paths_data)
        except Exception as e:
            self.conn.rollback()
            logger.warning(f"⚠️ [DB] 批量标记 API path 失败：{e}")
            return 0

    # ==================== 基础数据写入 ====================

    def append_data_batch(self, input_data: list, depth: int = 0, show_progress: bool = False):
        """批量写入扫描结果数据"""
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
            cursor.executemany("""
                INSERT OR IGNORE INTO scan_results
                (url, domain, path, source_url, scan_depth)
                VALUES (?, ?, ?, ?, ?)
            """, rows_to_insert)

            visited_urls = [(row[0],) for row in rows_to_insert]
            cursor.executemany(
                "INSERT OR IGNORE INTO visited_urls (url) VALUES (?)",
                visited_urls
            )

            self.conn.commit()
            if show_progress:
                print(f"💾 [DB] 基础数据写入：{len(rows_to_insert)} 条")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 基础数据写入异常：{e}")
            raise

    # ==================== AI 结果保存 ====================

    def save_ai_result(self, js_url: str, api_endpoint: str, advisory_report: dict):
        """保存 AI 渗透建议结果（旧接口，不返回 ID）"""
        if not advisory_report or not isinstance(advisory_report, dict):
            logger.warning("⚠️ [DB] advisory_report 为空或格式错误")
            return
        if not js_url or not api_endpoint:
            logger.warning("⚠️ [DB] js_url 或 api_endpoint 为空")
            return

        try:
            cursor = self.conn.cursor()
            raw_method = advisory_report.get("method", "")
            http_method = self._normalize_method(raw_method)
            path = advisory_report.get("path", "")
            params_raw = advisory_report.get("params", "")
            params_parsed = self._parse_params(params_raw)
            params_json = json.dumps(params_parsed, ensure_ascii=False) if params_parsed else None
            risk_level = self._calculate_risk_level(path, params_parsed, http_method)

            cursor.execute("""
                INSERT OR REPLACE INTO ai_vulns
                (js_url, api_endpoint, http_method, risk_level, path, params)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (js_url, api_endpoint, http_method, risk_level, path, params_json))
            self.conn.commit()

            if risk_level == "High":
                logger.info(f"🔥 [DB] 发现高价值攻击目标：{http_method} {api_endpoint}")
            else:
                logger.info(f"💾 [DB] 渗透建议已存档：{http_method} {api_endpoint} [{risk_level}]")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] AI 渗透建议写入失败：{e}")
            raise

    def save_ai_result_with_id(self, js_url: str, full_url: str, advisory_report: dict):
        """保存 AI 分析结果并返回记录 ID"""
        if not advisory_report or not isinstance(advisory_report, dict):
            logger.warning("⚠️ [DB] advisory_report 为空或格式错误")
            return None
        if not js_url or not full_url:
            logger.warning("⚠️ [DB] js_url 或 full_url 为空")
            return None

        try:
            cursor = self.conn.cursor()
            raw_method = advisory_report.get("method", "")
            http_method = self._normalize_method(raw_method)
            path = advisory_report.get("path", "")
            params_raw = advisory_report.get("params", "")
            params_parsed = self._parse_params(params_raw)
            params_json = json.dumps(params_parsed, ensure_ascii=False) if params_parsed else None
            risk_level = self._calculate_risk_level(path, params_parsed, http_method)

            cursor.execute("""
                INSERT OR REPLACE INTO ai_vulns
                (js_url, api_endpoint, http_method, risk_level, path, params)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (js_url, full_url, http_method, risk_level, path, params_json))
            self.conn.commit()

            record_id = cursor.lastrowid

            if risk_level == "High":
                logger.info(f"🔥 [DB] 发现高价值攻击目标：{http_method} {full_url}")
            else:
                logger.info(f"💾 [DB] 渗透建议已存档：{http_method} {full_url} [{risk_level}]")

            return record_id
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] AI 渗透建议写入失败：{e}")
            return None

    def batch_update_ai_vuln_request_results(self, request_results: list) -> int:
        """批量更新 AI 漏洞记录的请求验证结果"""
        if not request_results:
            return 0
        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            updated_count = 0
            for result in request_results:
                record_id = result.get("id")
                if not record_id:
                    continue
                status_code = result.get("status_code", -1)
                content_summary = result.get("content_summary", "")
                request_status = "success" if status_code > 0 else "failed"
                response_length = len(content_summary) if content_summary else 0
                cursor.execute("""
                    UPDATE ai_vulns
                    SET request_status = ?, response_code = ?, response_length = ?, response_body_preview = ?
                    WHERE id = ?
                """, (request_status, status_code, response_length, content_summary, record_id))
                updated_count += 1
            self.conn.commit()
            logger.info(f"💾 [DB] 批量更新请求验证结果：{updated_count} 条")
            return updated_count
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] 批量更新请求结果失败：{e}")
            return 0

    # ==================== 敏感信息存储 ====================

    def save_sensitive_info(self, js_url: str, sensitive_items: list):
        """保存敏感信息检测结果"""
        if not js_url:
            logger.warning("⚠️ [DB] js_url 为空")
            return
        if not sensitive_items or not isinstance(sensitive_items, list):
            return

        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
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

                cursor.execute("""
                    INSERT OR REPLACE INTO sensitive_info
                    (js_url, sensitive_value, context_code, caller_codes, risk_level,
                     secret_type, test_suggestion, ai_raw_analysis)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    js_url, value, context, json.dumps(callers, ensure_ascii=False),
                    risk_level, secret_type, test_suggestion, json.dumps(ai_raw, ensure_ascii=False)
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

    # ==================== SourceMap 保存 ====================

    def save_source_map_result(self, js_url: str, is_source_map: str) -> bool:
        """保存单个 SourceMap 检测结果"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO js_source_maps (js_url, is_sourceMap)
                VALUES (?, ?)
            """, (js_url, is_source_map))
            self.conn.commit()
            return True
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] SourceMap 结果写入失败：{e}")
            return False

    def batch_save_source_map_results(self, results: list) -> int:
        """批量保存 SourceMap 检测结果"""
        if not results:
            return 0
        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN TRANSACTION;")
            cursor.executemany("""
                INSERT OR REPLACE INTO js_source_maps (js_url, is_sourceMap)
                VALUES (?, ?)
            """, results)
            self.conn.commit()
            logger.info(f"💾 [DB] SourceMap 检测结果写入：{len(results)} 条")
            return len(results)
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ [DB] SourceMap 批量写入失败：{e}")
            return 0
