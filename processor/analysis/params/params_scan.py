import re
import time
from traceback import print_exc
from typing import Any, Dict, Optional, List
import json_repair

from infra.ai_client import client
from logger import get_logger
from processor.analysis.prompts import SYSTEM_PROMPT_ADVISORY, SYSTEM_PROMPT_JUDGE
from processor.js.context.context_extractor import extract_multiple_apis_from_raw_code

try:
    from main import proxies
except ImportError:
    proxies = None

logger = get_logger(__name__)


class AISecurityAuditor:
    # 代码最大长度阈值
    CODE_MAX_LENGTH = 12000

    def __init__(self):
        pass

    def _clean_json_response(self, content: str) -> str:
        """强壮的 JSON 剥壳器（用于 Level 2 和 Level 3）"""
        if not content:
            return ""
        content = content.strip()
        if content.startswith('{') or content.startswith('['):
            if content.endswith('```'):
                content = content[:-3].strip()
            return content
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", content, flags=re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        start_idx = content.find('{')
        end_idx = content.rfind('}')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            return content[start_idx: end_idx + 1].strip()
        return ""

    def _parse_level2_result(self, content: str) -> Dict[str, Any]:
        """
        解析 Level 2 的 JSON 输出

        解析策略：
        - 解析 JSON 获取 has_value 和 param_keys
        - 解析失败时默认 has_value=1, param_keys=[]（宁可多测，不可漏测）
        """
        if not content:
            return {"has_value": 1, "param_keys": []}

        content = content.strip()

        try:
            parsed = json_repair.loads(content)
            has_value = parsed.get("has_value", 1)
            param_keys = parsed.get("param_keys", [])

            # 过滤单字母参数名
            param_keys = [k for k in param_keys if len(k) > 1 or k.lower() in ['id', 'ip', 'os']]

            return {
                "has_value": has_value,
                "param_keys": param_keys
            }

        except Exception as e:
            print_exc()
            time.sleep(100)
            logger.warning(f"⚠️ Level 2 JSON 解析失败：{e}，默认 has_value=1")
            return {"has_value": 1, "param_keys": []}

    def _aggressive_minify(self, code: str, max_chars: int = None) -> str:
        """纯代码级压缩（删除对安全分析无用的代码）"""
        if not code:
            return ""


        original_length = len(code)

        # ========== 删除低价值代码 ==========
        code = re.sub(r'["\']image/[a-zA-Z]*;base64,[^"\']*["\']', '"[IMG]"', code)
        code = re.sub(r'["\'][^"\']*[\.#][a-zA-Z0-9_-]+\s*\{[^}]*:[^}]*\}[^"\']*["\']', '"[CSS]"', code)
        code = re.sub(r'["\'][^"\']*<[a-z][^>]*>[^"\']*["\']', '"[HTML]"', code)
        code = re.sub(r'\[(\s*["\'][a-zA-Z0-9]{2,}["\']\s*,?){50,}\]', '"[ARRAY]"', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        code = re.sub(r'\s+', ' ', code)
        code = re.sub(r'console\.[a-zA-Z]+\([^)]*\)', '', code)
        code = re.sub(r'logger\.[a-zA-Z]+\([^)]*\)', '', code)

        # ========== 统计 ==========
        compressed_length = len(code)
        total_saved = original_length - compressed_length
        compression_rate = (total_saved / original_length) * 100 if original_length > 0 else 0

        logger.info(
            f"[Minify] 压缩：{original_length} → {compressed_length} 字符 (节省：{total_saved} 字符，{compression_rate:.1f}%)")

        return code

    def _compress_code_loop(self, code: str, max_chars: int) -> str:
        """代码压缩（仅规则压缩 + 结构截断）"""
        original_length = len(code)
        current_code = self._aggressive_minify(code, max_chars)

        if len(current_code) <= max_chars:
            logger.info(f"[Compress] Rule-based sufficient: {original_length} → {len(current_code)}")
            return current_code

        logger.warning(
            f"[Compress] Rule-based not enough ({len(current_code)} > {max_chars}), using structural truncate")
        current_code = self._structural_truncate(current_code, max_chars)
        logger.info(f"[Compress] Final: {original_length} → {len(current_code)}")
        return current_code

    def _structural_truncate(self, code: str, max_chars: int) -> str:
        """结构截断：在 function 边界处截断"""
        if len(code) <= max_chars:
            return code

        function_pattern = r'(?:function\s+\w+|\w+\s*=\s*(?:async\s+)?function|\w+\s*:\s*(?:async\s+)?function)'
        function_matches = list(re.finditer(function_pattern, code))

        if not function_matches:
            return code[:max_chars] + "\n\n/*...[代码截断]...*/\n\n"

        protected_keywords = [
            'params', 'data', 'body', 'payload', 'query',
            'fetch', 'axios', 'request', 'http', 'post', 'get',
            'token', 'sign', 'auth', 'permission', 'key', 'secret'
        ]

        protected_functions = []
        for i, match in enumerate(function_matches):
            start = match.start()
            end = function_matches[i + 1].start() if i + 1 < len(function_matches) else len(code)
            function_code = code[start:end]

            if any(kw in function_code for kw in protected_keywords):
                protected_functions.append((start, end))

        result_parts = []
        current_pos = 0
        total_length = 0

        for start, end in protected_functions:
            if total_length + (end - start) > max_chars * 0.8:
                break
            result_parts.append(code[current_pos:start])
            result_parts.append(code[start:end])
            total_length += (end - current_pos)
            current_pos = end

        if total_length < max_chars and current_pos < len(code):
            remaining = max_chars - total_length
            result_parts.append(code[current_pos:current_pos + remaining])
            total_length += remaining

        result = ''.join(result_parts)

        if len(result) < len(code):
            result += "\n\n/*...[代码截断 - 保留关键函数]...*/\n\n"

        return result[:max_chars + 100]

    def _analyze_multiple_api_values(self, api_candidates: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Level 2: 参数名提取 (输出 param_keys)
        """
        strategy_results = {}
        if not api_candidates:
            return strategy_results

        for index, info in enumerate(api_candidates):
            api_path = info['api_path']
            context_data = info['context_data']

            logger.info(f" 正在审计：{api_path}")

            raw_wrapper = context_data.get('wrapper_code', '')
            caller_codes = context_data.get('caller_codes', [])

            wrapper_code = self._compress_code_loop(raw_wrapper, self.CODE_MAX_LENGTH // 2)
            processed_callers = [self._compress_code_loop(c, self.CODE_MAX_LENGTH // 6) for c in caller_codes[:3]]
            callers_str = "\n\n".join([f"--- 业务调用点 {i + 1} ---\n{c}" for i, c in enumerate(processed_callers)])

            full_desc = f"目标 API: {api_path}\n\n[JS 底层发包函数]:\n{wrapper_code}\n\n[JS 业务调用点]:\n{callers_str}"

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT_JUDGE},
                {"role": "user", "content": f"请对该单一 API 的全量源码进行审查，提取 HTTP 参数名：\n\n{full_desc}"}
            ]

            result = client.chat(messages=messages, max_tokens=500, temperature=0.1)

            try:
                # 解析 Level 2 JSON 输出
                level2_result = self._parse_level2_result(result)

                strategy_results[api_path] = {
                    "decision": level2_result["has_value"],
                    "param_keys": level2_result["param_keys"]
                }

                logger.debug(f"[{api_path}] Has value: {level2_result['has_value']}, Keys: {level2_result['param_keys']}")

            except Exception as e:
                logger.error(f"[-] Level 2 单点 ({api_path}) 解析异常：{e}，默认 has_value=1")
                strategy_results[api_path] = {
                    "decision": 1,
                    "param_keys": []
                }

        return strategy_results

    def analyze(self, context_data: Dict[str, Any], param_keys: List[str] = None) -> Optional[Dict[str, Any]]:
        """
        Level 3: 参数值补充 + 请求构建
        """
        if not context_data or not context_data.get("found"):
            return None

        try:
            raw_wrapper = context_data.get('wrapper_code', '')
            caller_codes = context_data.get('caller_codes', [])

            wrapper_code = self._compress_code_loop(raw_wrapper, self.CODE_MAX_LENGTH // 2)
            processed_callers = [self._compress_code_loop(c, self.CODE_MAX_LENGTH // 6) for c in caller_codes[:3]]
            callers_str = "\n\n".join([f"--- 业务调用点 {i + 1} ---\n{c}" for i, c in enumerate(processed_callers)])

            full_code = f"[底层发包函数 (Wrapper)]\n{wrapper_code}\n\n[高层业务调用点 (Callers)]\n{callers_str}"

        except Exception as e:
            logger.error(f"[-] 构建上下文数据失败：{e}")
            return None

        api_url = context_data.get('api_url', '')

        # 构建 Level 2 参数名线索提示
        param_keys_hint = ""
        if param_keys and len(param_keys) > 0:
            param_keys_hint = f"Level 2 检测到的参数名线索：{param_keys}\n（仅供参考，以代码实际内容为准）\n\n"

        user_prompt = f"""
{param_keys_hint}=== 【前端 JS 代码证据】 ===
{full_code}

目标 API: {api_url}

请严格按照 Prompt 要求提取请求信息。
"""

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_ADVISORY},
            {"role": "user", "content": user_prompt}
        ]

        result = client.chat(messages=messages, max_tokens=2000, temperature=0.2)

        cleaned_content = self._clean_json_response(result)
        if not cleaned_content:
            return None

        try:
            parsed = json_repair.loads(cleaned_content)

            # 只补充 path，其他保持 AI 输出原样
            if not parsed.get('path') and api_url:
                parsed['path'] = api_url

            return parsed

        except Exception as e:
            logger.error(f"[-] AI JSON 解析失败：{e}")
            return None

    def scan_multiple_apis(self, js_code: str, api_paths: list, target_url: str) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        主流程漏斗：API 提取 → Level 2 过滤 → Level 3 分析
        """
        results = {}

        # ========== Step 1: 提取 API 上下文 ==========
        try:
            all_contexts = extract_multiple_apis_from_raw_code(js_code, api_paths)
        except Exception as e:
            logger.error(f"[-] 批量提取上下文数据失败：{e}")
            return {api: None for api in api_paths}

        # ========== Step 2: 初步筛选候选 API ==========
        level_2_candidates = []

        for api_path, context_data in all_contexts.items():
            if not context_data or not context_data.get("found"):
                continue

            has_wrapper = bool(context_data.get('wrapper_code'))
            has_callers = bool(context_data.get('caller_codes'))

            if (has_wrapper or has_callers) or '?' in api_path:
                level_2_candidates.append({
                    "api_path": api_path,
                    "context_data": context_data
                })
            else:
                results[api_path] = None

        logger.info(f"📋 候选 API: {len(level_2_candidates)} / {len(all_contexts)}")

        # ========== Step 3: Level 2 参数名提取 ==========
        if level_2_candidates:
            ai_judgements = self._analyze_multiple_api_values(level_2_candidates)
        else:
            ai_judgements = {}
            logger.info("⚠️ 无候选 API，跳过 Level 2")

        # ========== Step 4: 过滤 + Level 3 分析 ==========
        for candidate in level_2_candidates:
            api_path = candidate['api_path']
            context_data = candidate['context_data']

            # 获取 Level 2 结果
            judgement = ai_judgements.get(api_path)

            # 如果 Level 2 没返回结果，说明出错了
            if not judgement:
                logger.warning(f"⚠️ [{api_path}] Level 2 无结果，跳过")
                results[api_path] = None
                continue

            # 单一过滤条件：AI 信号
            if judgement.get("decision", 1) == 0:
                logger.debug(f"[{api_path}] Skipped (has_value=0)")
                results[api_path] = None
                continue

            logger.info(f"✅ [{api_path}] 进入 Level 3")

            context_data['target_host'] = target_url
            context_data['api_url'] = api_path

            # 传递 Level 2 的 param_keys 给 Level 3
            param_keys = judgement.get("param_keys", [])

            analysis_result = self.analyze(
                context_data=context_data,
                param_keys=param_keys
            )
            results[api_path] = analysis_result

        # ========== Step 5: 统计输出 ==========
        total = len(results)
        success = sum(1 for r in results.values() if r is not None)
        logger.info(f"📈 扫描完成：{success} / {total} API 有数据")

        return results