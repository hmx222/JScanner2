import re
import traceback
from traceback import print_exc
from typing import Any, Dict, Optional, List

import json_repair

from logger import get_logger
from config.prompts import SYSTEM_PROMPT_ADVISORY, SYSTEM_PROMPT_JUDGE
from processor.js.context.context_extractor import extract_multiple_apis_from_raw_code

from config.config import proxies

logger = get_logger(__name__)  # 获取模块日志器


class AISecurityAuditor:
    """
    AI 安全审计器

    三级分析流水线：
    - Level 1: 从原始 JS 代码中提取 API 路径上下文（使用 AST 分析）
    - Level 2 (Judge): 判断每个 API 是否有参数值，提取参数名
    - Level 3 (Advisor): 基于代码证据构建完整的 HTTP 请求信息

    属性:
        CODE_MAX_LENGTH: 单次送入大模型的代码最大长度（避免 token 超限）
    """

    CODE_MAX_LENGTH = 12000

    def __init__(self, client=None):
        """
        初始化 AI 安全审计器

        Args:
            client: AI 客户端实例（通过 DI 注入，与 SensitiveInfoScanner 风格一致）
        """
        if client is None:
            from infra.ai_client import client as _client
            self.client = _client  # 注入默认客户端
        else:
            self.client = client  # 使用传入客户端

    def _clean_json_response(self, content: str) -> str:
        """
        强壮的 JSON 剥壳器（用于 Level 2 和 Level 3）

        处理 AI 返回的各种 JSON 格式变体：
        - 纯 JSON 字符串
        - ```json ... ``` 代码块包裹的 JSON
        - 文章中嵌入的 JSON

        Args:
            content: AI 原始返回内容

        Returns:
            str: 清理后的 JSON 字符串
        """
        if not content:
            return ""
        content = content.strip()  # 去除首尾空白
        # 已经是 JSON 格式（以 { 或 [ 开头）
        if content.startswith('{') or content.startswith('['):
            if content.endswith('```'):
                content = content[:-3].strip()  # 移除结尾反引号
            return content
        # 尝试匹配代码块
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", content, flags=re.DOTALL | re.IGNORECASE)  # 匹配JSON代码块
        if match:
            return match.group(1).strip()
        # 回退：查找第一个 { 到最后一个 }
        start_idx = content.find('{')  # 查找左花括号位置
        end_idx = content.rfind('}')  # 查找右花括号位置
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            return content[start_idx: end_idx + 1].strip()
        return ""

    def _parse_level2_result(self, content: str) -> Dict[str, Any]:
        """
        解析 Level 2 的 JSON 输出

        解析策略：宁可多测，不可漏测。
        - 解析成功时获取 has_value 和 param_keys
        - 解析失败时默认 has_value=1（认为有参数），param_keys=[]

        Args:
            content: Level 2 的原始返回内容

        Returns:
            dict: 包含 has_value（1=有参数，0=无参数）和 param_keys（参数名列表）
        """
        if not content:
            return {"has_value": 1, "param_keys": []}

        # 如果 content 已经是字典，直接使用
        if isinstance(content, dict):
            has_value = content.get("has_value", 1)  # 获取是否有参数值
            param_keys = content.get("param_keys", [])  # 获取参数名列表
            # 过滤单字母无意义参数名（保留常见有意义的单字母参数）
            param_keys = [k for k in param_keys if len(k) > 1 or k.lower() in ['id', 'ip', 'os']]  # 过滤无效参数名
            return {"has_value": has_value, "param_keys": param_keys}

        # 如果 content 是列表，说明 AI 返回格式错误，使用默认值
        if isinstance(content, list):
            logger.warning(f"⚠️ Level 2 返回了列表而非字典：{content}，默认 has_value=1")
            return {"has_value": 1, "param_keys": []}

        content = content.strip()  # 去除首尾空白

        try:
            parsed = json_repair.loads(content)  # 尝试修复并解析JSON

            if isinstance(parsed, list):
                logger.warning(f"⚠️ Level 2 JSON 解析后为列表：{parsed}，默认 has_value=1")
                return {"has_value": 1, "param_keys": []}

            if isinstance(parsed, dict):
                has_value = parsed.get("has_value", 1)  # 获取是否有参数值
                param_keys = parsed.get("param_keys", [])  # 获取参数名列表
                # 过滤单字母无意义参数名
                param_keys = [k for k in param_keys if len(k) > 1 or k.lower() in ['id', 'ip', 'os']]  # 过滤无效参数名
                return {"has_value": has_value, "param_keys": param_keys}

            logger.warning(f"⚠️ Level 2 JSON 解析后为未知类型：{type(parsed)}，默认 has_value=1")
            return {"has_value": 1, "param_keys": []}

        except Exception as e:  # JSON解析异常处理
            logger.warning(f"⚠️ Level 2 JSON 解析失败：{e}，默认 has_value=1")
            return {"has_value": 1, "param_keys": []}

    def _aggressive_minify(self, code: str, max_chars: int = None) -> str:
        """
        纯代码级压缩（删除对安全分析无用的代码）

        压缩策略：
        - 替换 base64 图片数据为占位符
        - 替换 CSS 字符串为占位符
        - 替换 HTML 字符串为占位符
        - 替换大数组为占位符
        - 删除多行注释和单行注释
        - 合并空白字符
        - 删除 console.log 和 logger 调用

        Args:
            code: 原始 JS 代码
            max_chars: 目标最大字符数（可选）

        Returns:
            str: 压缩后的代码
        """
        if not code:
            return ""

        original_length = len(code)  # 记录原始长度

        # 替换 base64 图片数据
        code = re.sub(r'["\']image/[a-zA-Z]*;base64,[^"\']*["\']', '"[IMG]"', code)  # 替换base64图片
        # 替换 CSS 字符串
        code = re.sub(r'["\'][^"\']*[\.#][a-zA-Z0-9_-]+\s*\{[^}]*:[^}]*\}[^"\']*["\']', '"[CSS]"', code)  # 替换CSS字符串
        # 替换 HTML 字符串
        code = re.sub(r'["\'][^"\']*<[a-z][^>]*>[^"\']*["\']', '"[HTML]"', code)  # 替换HTML字符串
        # 替换大数组
        code = re.sub(r'\[(\s*["\'][a-zA-Z0-9]{2,}["\']\s*,?){50,}\]', '"[ARRAY]"', code)  # 替换大数组
        # 删除多行注释
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # 删除多行注释
        # 删除单行注释
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)  # 删除单行注释
        # 合并空白字符
        code = re.sub(r'\s+', ' ', code)  # 合并空白字符
        # 删除 console 调用
        code = re.sub(r'console\.[a-zA-Z]+\([^)]*\)', '', code)  # 删除console调用
        # 删除 logger 调用
        code = re.sub(r'logger\.[a-zA-Z]+\([^)]*\)', '', code)  # 删除logger调用

        compressed_length = len(code)  # 获取压缩后长度
        total_saved = original_length - compressed_length  # 计算节省字符数
        compression_rate = (total_saved / original_length) * 100 if original_length > 0 else 0  # 计算压缩率

        logger.info(f"[Minify] 压缩：{original_length} → {compressed_length} 字符 (节省：{total_saved} 字符，{compression_rate:.1f}%)")

        return code

    def _compress_code_loop(self, code: str, max_chars: int) -> str:
        """
        代码压缩（规则压缩 + 结构截断）

        先使用规则压缩（_aggressive_minify），如果仍然超过限制，
        则使用结构截断（_structural_truncate）在函数边界处截断。

        Args:
            code: 原始代码
            max_chars: 最大字符数

        Returns:
            str: 压缩后的代码
        """
        original_length = len(code)  # 记录原始长度
        # 先尝试规则压缩
        current_code = self._aggressive_minify(code, max_chars)  # 执行规则压缩

        if len(current_code) <= max_chars:
            logger.info(f"[Compress] Rule-based sufficient: {original_length} → {len(current_code)}")
            return current_code

        # 规则压缩不够，使用结构截断
        logger.warning(f"[Compress] Rule-based not enough ({len(current_code)} > {max_chars}), using structural truncate")
        current_code = self._structural_truncate(current_code, max_chars)  # 执行结构截断
        logger.info(f"[Compress] Final: {original_length} → {len(current_code)}")
        return current_code

    def _structural_truncate(self, code: str, max_chars: int) -> str:
        """
        结构截断：在函数边界处智能截断

        保留包含关键安全关键词的函数（如 params, fetch, token, auth 等），
        其余部分的代码在边界处截断。

        Args:
            code: 待截断的代码
            max_chars: 最大字符数

        Returns:
            str: 截断后的代码
        """
        if len(code) <= max_chars:
            return code

        # 匹配函数定义（多种格式）
        function_pattern = r'(?:function\s+\w+|\w+\s*=\s*(?:async\s+)?function|\w+\s*:\s*(?:async\s+)?function)'
        function_matches = list(re.finditer(function_pattern, code))  # 查找所有函数定义

        if not function_matches:
            return code[:max_chars] + "\n\n/*...[代码截断]...*/\n\n"

        # 需要保护的关键词列表
        protected_keywords = [  # 需保护的关键词列表
            'params', 'data', 'body', 'payload', 'query',
            'fetch', 'axios', 'request', 'http', 'post', 'get',
            'token', 'sign', 'auth', 'permission', 'key', 'secret'
        ]

        # 筛选需要保护的函数
        protected_functions = []  # 需保护的函数列表
        for i, match in enumerate(function_matches):  # 遍历函数匹配结果
            start = match.start()  # 获取函数起始位置
            end = function_matches[i + 1].start() if i + 1 < len(function_matches) else len(code)  # 获取函数结束位置
            function_code = code[start:end]  # 提取函数代码片段

            if any(kw in function_code for kw in protected_keywords):
                protected_functions.append((start, end))  # 记录保护函数位置

        # 拼接保护函数和部分其他代码
        result_parts = []  # 结果片段列表
        current_pos = 0  # 当前处理位置
        total_length = 0  # 累计长度

        for start, end in protected_functions:  # 遍历保护函数
            if total_length + (end - start) > max_chars * 0.8:
                break
            result_parts.append(code[current_pos:start])
            result_parts.append(code[start:end])
            total_length += (end - current_pos)  # 更新累计长度
            current_pos = end  # 更新当前位置

        # 填充剩余空间
        if total_length < max_chars and current_pos < len(code):
            remaining = max_chars - total_length  # 计算剩余空间
            result_parts.append(code[current_pos:current_pos + remaining])
            total_length += remaining  # 更新累计长度

        result = ''.join(result_parts)  # 拼接结果字符串

        if len(result) < len(code):
            result += "\n\n/*...[代码截断 - 保留关键函数]...*/\n\n"  # 添加截断标记

        return result[:max_chars + 100]

    def _analyze_multiple_api_values(self, candidates: List[Dict[str, Any]]) -> Dict[str, Dict]:
        """
        Level 2: 逐个判断多个 API 是否有参数值

        对每个候选 API，将包含上下文的代码片段送入 LLM Judge 模型，
        判断该 API 是否有参数值，并提取参数名。

        Args:
            candidates: 候选 API 列表，每个包含 api_path 和 context_data

        Returns:
            dict: {api_path: {"decision": 1/0, "param_keys": [...]}}
        """
        strategy_results = {}  # 记录所有API判断结果

        for candidate in candidates:  # 遍历候选API列表
            api_path = candidate['api_path']  # 获取API路径
            context_data = candidate['context_data']  # 获取上下文数据

            raw_wrapper = context_data.get('wrapper_code', '')  # 获取底层发包函数代码
            caller_codes = context_data.get('caller_codes', [])  # 获取业务调用点代码

            # 压缩代码到适合 LLM 的大小
            wrapper_code = self._compress_code_loop(raw_wrapper, self.CODE_MAX_LENGTH // 2)  # 压缩包装代码
            processed_callers = [self._compress_code_loop(c, self.CODE_MAX_LENGTH // 6) for c in caller_codes[:3]]  # 压缩调用点代码
            callers_str = "\n\n".join([f"--- 业务调用点 {i + 1} ---\n{c}" for i, c in enumerate(processed_callers)])  # 格式化调用点字符串

            full_desc = f"目标 API: {api_path}\n\n[JS 底层发包函数]:\n{wrapper_code}\n\n[JS 业务调用点]:\n{callers_str}"  # 构建完整描述

            messages = [  # 构建LLM消息
                {"role": "system", "content": SYSTEM_PROMPT_JUDGE},
                {"role": "user", "content": f"请对该单一 API 的全量源码进行审查，提取 HTTP 参数名：\n\n{full_desc}"}
            ]

            result = self.client.chat(  # 调用LLM进行判断
                messages=messages,
                max_tokens=1000,
                require_json=True
            )
            try:
                level2_result = self._parse_level2_result(result)  # 解析LLM返回结果

                strategy_results[api_path] = {  # 记录该API判断结果
                    "decision": level2_result["has_value"],
                    "param_keys": level2_result["param_keys"]
                }

                logger.debug(f"[{api_path}] Has value: {level2_result['has_value']}, Keys: {level2_result['param_keys']}")

            except Exception as e:  # 解析异常处理
                exc = traceback.format_exc()  # 获取异常堆栈
                logger.error(f"[-] Level 2 单点 ({api_path}) 解析异常：{exc}，默认 has_value=1")
                strategy_results[api_path] = {  # 异常时使用默认值
                    "decision": 1,
                    "param_keys": []
                }

        return strategy_results

    def analyze(self, context_data: Dict[str, Any], param_keys: List[str] = None) -> Optional[Dict[str, Any]]:
        """
        Level 3: 参数值补充 + 请求构建

        将 JS 代码证据（底层发包函数 + 高层调用点）送入 LLM Advisor 模型，
        提取完整的请求信息（路径、方法、参数）。

        Args:
            context_data: 上下文数据，包含 wrapper_code, caller_codes, api_url 等
            param_keys: Level 2 检测到的参数名列表（可选，作为线索）

        Returns:
            Optional[Dict]: 包含 path, method, params 的字典，失败返回 None
        """
        if not context_data or not context_data.get("found"):
            return None

        try:
            raw_wrapper = context_data.get('wrapper_code', '')  # 获取底层发包函数代码
            caller_codes = context_data.get('caller_codes', [])  # 获取业务调用点代码

            # 压缩代码到适合 LLM 的大小
            wrapper_code = self._compress_code_loop(raw_wrapper, self.CODE_MAX_LENGTH // 2)  # 压缩包装代码
            processed_callers = [self._compress_code_loop(c, self.CODE_MAX_LENGTH // 6) for c in caller_codes[:3]]  # 压缩调用点代码
            callers_str = "\n\n".join([f"--- 业务调用点 {i + 1} ---\n{c}" for i, c in enumerate(processed_callers)])  # 格式化调用点

            full_code = f"[底层发包函数 (Wrapper)]\n{wrapper_code}\n\n[高层业务调用点 (Callers)]\n{callers_str}"  # 构建完整代码块

        except Exception as e:  # 构建上下文异常处理
            logger.error(f"[-] 构建上下文数据失败：{e}")
            return None

        api_url = context_data.get('api_url', '')  # 获取API路径

        # 构建 Level 2 参数名线索提示
        param_keys_hint = ""  # 参数名提示字符串
        if param_keys and len(param_keys) > 0:
            param_keys_hint = f"Level 2 检测到的参数名线索：{param_keys}\n（仅供参考，以代码实际内容为准）\n\n"  # 构建参数线索提示

        user_prompt = f"""  # 构建用户提示词
{param_keys_hint}=== 【前端 JS 代码证据】 ===
{full_code}

目标 API: {api_url}

请严格按照 Prompt 要求提取请求信息。
"""

        messages = [  # 构建LLM消息
            {"role": "system", "content": SYSTEM_PROMPT_ADVISORY},
            {"role": "user", "content": user_prompt}
        ]

        result = self.client.chat(messages=messages, max_tokens=2000, temperature=0.2)  # 调用LLM进行分析

        cleaned_content = self._clean_json_response(result)  # 清理JSON响应
        if not cleaned_content:
            return None

        try:
            parsed = json_repair.loads(cleaned_content)  # 解析清理后的JSON

            # 只补充 path，其他保持 AI 输出原样
            if not parsed.get('path') and api_url:
                parsed['path'] = api_url  # 补充缺失的路径

            return parsed

        except Exception as e:  # JSON解析异常处理
            logger.error(f"[-] AI JSON 解析失败：{e}")
            return None

    def scan_multiple_apis(self, js_code: str, api_paths: list, target_url: str) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        主流程漏斗：批量分析多个 API

        处理流程：
        1. 使用 AST 提取每个 API 路径的上下文数据
        2. Level 2 过滤：判断 API 是否有参数值
        3. Level 3 分析：构建完整的 HTTP 请求信息

        Args:
            js_code: JS 源代码
            api_paths: API 路径列表
            target_url: 目标网站 URL

        Returns:
            dict: {api_path: advisory_report_or_None}
                advisory_report 包含 path, method, params 等字段
        """
        results = {}  # 存储所有API分析结果

        try:
            # 第一步：从原始 JS 代码中提取所有 API 路径的上下文
            all_contexts = extract_multiple_apis_from_raw_code(js_code, api_paths)  # 提取所有API上下文
        except Exception as e:  # 提取上下文异常处理
            logger.error(f"[-] 批量提取上下文数据失败：{e}")
            return {api: None for api in api_paths}

        # 第二步：收集需要 Level 2 分析的候选
        level_2_candidates = []  # 待Level2分析的候选API列表

        for api_path, context_data in all_contexts.items():  # 遍历所有API上下文
            if not context_data or not context_data.get("found"):
                continue

            has_wrapper = bool(context_data.get('wrapper_code'))  # 是否包含包装代码
            has_callers = bool(context_data.get('caller_codes'))  # 是否包含调用点代码

            # 有上下文 或 路径中包含参数标记（问号）则进入 Level 2
            if (has_wrapper or has_callers) or '?' in api_path:
                level_2_candidates.append({
                    "api_path": api_path,
                    "context_data": context_data
                })
            else:
                results[api_path] = None  # 无上下文直接标记为无结果

        logger.info(f"📋 候选 API: {len(level_2_candidates)} / {len(all_contexts)}")

        # 第三步：Level 2 分析（参数名提取）
        if level_2_candidates:
            ai_judgements = self._analyze_multiple_api_values(level_2_candidates)  # 执行Level2分析
        else:
            ai_judgements = {}  # 无候选用空字典
            logger.info("⚠️ 无候选 API，跳过 Level 2")

        # 第四步：Level 3 分析（请求信息构建）
        for candidate in level_2_candidates:  # 遍历候选API进行Level3分析
            api_path = candidate['api_path']  # 获取API路径
            context_data = candidate['context_data']  # 获取上下文数据

            judgement = ai_judgements.get(api_path)  # 获取Level2判断结果

            if not judgement:
                logger.warning(f"⚠️ [{api_path}] Level 2 无结果，跳过")
                results[api_path] = None  # 无结果标记为空
                continue

            if judgement.get("decision", 1) == 0:
                logger.debug(f"[{api_path}] Skipped (has_value=0)")
                results[api_path] = None  # 无参数值标记为空
                continue

            logger.info(f"✅ [{api_path}] 进入 Level 3")

            context_data['target_host'] = target_url  # 设置目标主机
            context_data['api_url'] = api_path  # 设置API路径

            param_keys = judgement.get("param_keys", [])  # 获取参数名列表

            analysis_result = self.analyze(  # 执行Level3分析
                context_data=context_data,
                param_keys=param_keys
            )
            results[api_path] = analysis_result  # 记录分析结果

        # 第五步：统计输出
        total = len(results)  # 总API数量
        success = sum(1 for r in results.values() if r is not None)  # 成功分析的API数量
        logger.info(f"📈 扫描完成：{success} / {total} API 有数据")

        return results
