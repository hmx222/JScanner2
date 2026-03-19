import logging
import re
from typing import Any, Dict, Optional, List

import json_repair

from HttpHandle.AI_Req import client
from ai_security_scanner.analysis.context_extractor import extract_multiple_apis_from_raw_code

try:
    from main import proxies
except ImportError:
    proxies = None

logger = logging.getLogger(__name__)


class AISecurityAuditor:
    """
    AI 安全审计顾问 (v5.0 逐级独立全量会诊版)：
    - L1: 提取过滤
    - L2 (_analyze_multiple_api_values): 独立会诊每个 API 的全量代码，识别参数组合，生成【战略方向】。
    - L3 (analyze): 接收 L2 方向，基于 HackTricks 方法论，针对单 API 输出深度【渗透测试作战指南】。
    """

    # =========================================================================
    # Level 2: 独立战略预判与方向指导 Prompt (针对单一 API)
    # =========================================================================
    _SYSTEM_PROMPT_JUDGE = """角色：顶级 SRC 漏洞挖掘专家与架构师。
任务：审查单一【API 路径】与它的【全量 JS 源码切片】，进行高价值漏洞预判，并为下级执行者提供精确的战略指导。

【核心准则 - 必须严格遵守】
1. 真实参数提取：仔细阅读代码，提取真实的传参。如果代码中确实没有参数，请如实记录（空列表），切勿凭空捏造参数去硬猜。
2. 拒绝无脑测试与低危漏洞：
   - 绝对禁止建议 SQL 注入测试（默认后端使用强类型 ORM）。
   - 绝对禁止建议无脑的泛型 XSS 测试（除非你在 JS 中明确看到了直接将参数写入 DOM 的危险汇聚点，如 innerHTML/v-html）。
   - 忽略所有低危漏洞（如 CORS、版本泄露、无敏感信息的路径）。
3. 聚焦中高危与组合逻辑：重点寻找 业务状态机绕过、参数组合逻辑缺陷（如参数A配合参数B绕过验证）、支付精度溢出、SSRF。
4. 无参数场景：如果未发现参数，重点思考 HTTP Method 替换、未授权访问探测、或 Header 伪造。

【输出格式要求】
必须返回单一的纯 JSON 对象，严禁 Markdown 标记。JSON 结构：
{
  "api": "string",
  "has_value": boolean,              // 仅存在中高危逻辑或风险时给 true，低危垃圾接口给 false
  "params_found": ["param1", "param2"], // 如果未发现参数，请给出 []，且strategic_directions必须直接输出空列表！
  "strategic_directions": [
    // 给下级渗透专家的战略指导。必须具备深度和针对性，例如：
    // "该接口未发现参数，建议专注于未授权访问与 HTTP Method 替换测试。"
    // "参数 uid 与 target_id 存在明显的组合越权可能，请重点挖掘 BOLA 漏洞，拒绝单一参数独立测试。"
    // "未发现 DOM 渲染汇聚点，完全忽略 XSS，聚焦 amount 字段的负数与精度边界击穿。"
  ]
}
"""

    # =========================================================================
    # Level 3: 深度渗透测试指南 Prompt (HackTricks Methodology)
    # =========================================================================
    _SYSTEM_PROMPT_ADVISORY = """角色：资深 SRC 漏洞挖掘实战专家。
任务：基于上级的【战略指导】和【JS 全量源码证据】，参考 HackTricks 渗透方法论，编写极其专业的【深度渗透测试指南】。

【极度严苛的专业性要求】
1. 深度思考，拒绝模板化：绝不要对每个参数输出千篇一律的测试建议。必须根据参数在代码中的具体作用（语义）给出特定的攻击手法。
2. 参数关联与组合利用：如果存在多个参数，深度分析它们之间的依赖关系。思考如何通过组合变异（如保留业务参数、删除校验参数，或类型混淆）来打穿逻辑。
3. 无参数接口处理：如果上级指出无参数，指南应聚焦：目录遍历探测、绕过认证的直连访问、或强行注入预期外的特定 Header 引发错误。
4. 严格禁区：
   - 绝对禁止提及 SQL 注入。
   - 除非战略指导明确提示存在前端 DOM 汇聚点，否则禁止提及任何 XSS。

【输出格式要求】
必须返回纯 JSON 对象，严禁 Markdown 标记。JSON 结构：
{
  "vuln_focus": "一句话精准总结该接口的中高危测试焦点",
  "method":"从JS代码提取的请求方式，没有则输出空",
  "params":"从JS提取的可能的请求参数与值, 如果未发现值，则直接保留参数即可（例如：id=1,isadmin=true,secret）",
  "expert_advice": [
    {
      "actionable_test": "详细的具体操作建议 (300字以上，例如: '针对 amount，尝试传入极大浮点数 0.000000001；同时删除 sign 签名参数观察放行情况')"
    }
  ]
}
"""

    def __init__(self):
        pass

    def _clean_json_response(self, content: str) -> str:
        """强壮的 JSON 剥壳器"""
        if not content: return ""
        content = content.strip()
        if content.startswith('{') or content.startswith('['):
            if content.endswith('```'): content = content[:-3].strip()
            return content
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", content, flags=re.DOTALL | re.IGNORECASE)
        if match: return match.group(1).strip()
        start_idx = content.find('{')
        end_idx = content.rfind('}')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            return content[start_idx: end_idx + 1].strip()
        return content

    def _aggressive_minify(self, code: str, max_chars: int) -> str:
        """轻量级去噪，保留核心业务逻辑，大幅放宽截断限制以提供全量代码"""
        if not code: return ""
        # 仅暴力剔除必定无用的巨大 Base64 和混淆大数组
        code = re.sub(r'["\']data:image/[a-zA-Z]*;base64,[^"\']*["\']', '"[IMG_REMOVED]"', code)
        code = re.sub(r'\[(\s*["\'][a-zA-Z0-9+/-]{50,}["\']\s*,?)+\]', '"[ARRAY_REMOVED]"', code)

        # 截断限制放宽，保障全量逻辑可见
        if len(code) > max_chars:
            half = max(int(max_chars / 2) - 100, 100)
            return code[:half] + f"\n\n/*...[极长逻辑安全截断]...*/\n\n" + code[-half:]
        return code

    def _analyze_multiple_api_values(self, api_candidates: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Level 2: AI 独立判决与战略方向生成 (重构为逐个 API 提供全量代码会诊)
        """
        strategy_results = {}
        if not api_candidates:
            return strategy_results

        logger.info(f"🤖 [Level 2] 启动一对一专家会诊，共 {len(api_candidates)} 个 API...")

        for index, info in enumerate(api_candidates):
            api_path = info['api_path']
            context_data = info['context_data']

            logger.info(f"   -> 会诊进度: [{index + 1}/{len(api_candidates)}] 正在审计: {api_path}")

            # 提取充沛的全量代码供 L2 分析 (3000字符底层 + 每个调用1000字符)
            raw_wrapper = context_data.get('wrapper_code', '')
            caller_codes = context_data.get('caller_codes', [])
            wrapper_code = self._aggressive_minify(raw_wrapper, 3000)
            processed_callers = [self._aggressive_minify(c, 1000) for c in caller_codes[:3]]
            callers_str = "\n\n".join([f"--- 业务调用点 {i + 1} ---\n{c}" for i, c in enumerate(processed_callers)])

            full_desc = f"目标 API: {api_path}\n\n[JS 底层发包函数]:\n{wrapper_code}\n\n[JS 业务调用点]:\n{callers_str}"

            messages = [
                {"role": "system", "content": self._SYSTEM_PROMPT_JUDGE},
                {"role": "user", "content": f"请对该单一 API 的全量源码进行深度审查并提供战略指导：\n\n{full_desc}"}
            ]

            # 针对单个 API 请求 AI
            result = client.chat(messages=messages, max_tokens=4096, temperature=0.1)
            content = self._clean_json_response(result)

            try:
                parsed = json_repair.loads(content)
                params = parsed.get("params_found", [])

                # 如果源码中没发现参数，直接设定 has_value 为 False，终止后续 L3 流程
                if not params:
                    has_value = False
                    directions = []
                else:
                    # 只有有参数时，才保留 AI 返回的判决和方向
                    has_value = parsed.get("has_value", True)
                    directions = parsed.get("strategic_directions", [])

                strategy_results[api_path] = {
                    "decision": has_value,
                    "directions": directions
                }

            except Exception as e:
                logger.error(f"[-] Level 2 单点 ({api_path}) 战略解析异常: {e}")
                strategy_results[api_path] = {"decision": True, "directions": []}

        return strategy_results

    def analyze(self, context_data: Dict[str, Any], strategic_directions: List[str] = None) -> Optional[Dict[str, Any]]:
        """
        Level 3: 核心分析函数 -> 接收战略指令，输出 HackTricks 级渗透作战指南
        """
        if not context_data or not context_data.get("found"):
            return None

        try:
            # 再次提取充沛的全量代码，与 L2 看到的内容保持一致
            raw_wrapper = context_data.get('wrapper_code', '')
            caller_codes = context_data.get('caller_codes', [])

            wrapper_code = self._aggressive_minify(raw_wrapper, 3000)
            processed_callers = [self._aggressive_minify(c, 1000) for c in caller_codes[:3]]
            callers_str = "\n\n".join([f"--- 业务调用点 {i + 1} ---\n{c}" for i, c in enumerate(processed_callers)])

        except Exception as e:
            logger.error(f"[-] 构建上下文数据失败：{e}")
            return None


        # =================================================================
        #  Level 2
        # =================================================================
        dynamic_directions_block = ""
        if strategic_directions and len(strategic_directions) > 0:
            directions_text = "\n".join([f"- {d}" for d in strategic_directions])
            dynamic_directions_block = f"""
=== 【Level 2 架构师战略指导】(绝对最高优先级) ===
{directions_text}
⚠️ 强制服从指令：你编写的指南必须严格围绕上述方向展开。如果上级告诉你没有参数或没有 DOM 汇聚点，你绝对不能自行捏造参数或建议无脑盲测！请进行深度的组合关联分析！
===================================================
"""

        user_prompt = f"""
=== 【前端 JS 全量代码切片证据】 ===
[底层发包函数 (Wrapper)]
{wrapper_code if wrapper_code else "无"}

[高层业务调用点 (Callers)]
{callers_str if callers_str else "无"}

{dynamic_directions_block}

Task:
作为资深 SRC 渗透专家，请基于真实的 JS 逻辑和上级绝对战略指导，为该接口制定一份极具深度的【人工渗透作战指南】。
拒绝单参数傻瓜式遍历，必须具备业务逻辑组合视角的思考！
"""

        messages = [
            {"role": "system", "content": self._SYSTEM_PROMPT_ADVISORY},
            {"role": "user", "content": user_prompt}
        ]

        result = client.chat(messages=messages, max_tokens=4096, temperature=0.2)

        cleaned_content = self._clean_json_response(result)
        if not cleaned_content: return None

        try:
            return json_repair.loads(cleaned_content)
        except Exception as e:
            logger.error(f"[-] AI 深度指南 JSON 解析失败：{e}")
            return None

    def scan_multiple_apis(self, js_code: str, api_paths: list, target_url: str) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        主流程漏斗 (保持原有流转架构，但在 L2 传入完整的 context_data 用于独立评估)
        """
        results = {}

        try:
            all_contexts = extract_multiple_apis_from_raw_code(js_code, api_paths)
        except Exception as e:
            logger.error(f"[-] 批量提取上下文数据失败：{e}")
            return {api: None for api in api_paths}

        # ==============================================================
        # 第一阶段：Level 1 提取代码上下文
        # ==============================================================
        level_2_candidates = []

        for api_path, context_data in all_contexts.items():
            if not context_data or not context_data.get("found"):
                results[api_path] = None
                continue

            has_wrapper = bool(context_data.get('wrapper_code'))
            has_callers = bool(context_data.get('caller_codes'))

            if not ((has_wrapper or has_callers) or '?' in api_path):
                results[api_path] = None
                continue

            # 将原始的 context_data 完整传给 L2 供其进行独立全量分析
            level_2_candidates.append({
                "api_path": api_path,
                "context_data": context_data
            })

        # ==============================================================
        # 第二阶段：Level 2 AI 独立判决与战略下发
        # ==============================================================
        if level_2_candidates:
            ai_judgements = self._analyze_multiple_api_values(level_2_candidates)
        else:
            ai_judgements = {}

        # ==============================================================
        # 第三阶段：Level 3 接收指导，生成具体作战计划
        # ==============================================================
        for candidate in level_2_candidates:
            api_path = candidate['api_path']
            context_data = candidate['context_data']

            judgement = ai_judgements.get(api_path, {"decision": True, "directions": []})

            if not judgement.get("decision", True):
                results[api_path] = None
                continue

            # 获取 L2 给出的战略建议
            strategic_directions = judgement.get("directions", [])
            context_data['target_host'] = target_url
            context_data['api_url'] = api_path

            # 将 strategic_directions 传入 analyze 方法
            analysis_result = self.analyze(
                context_data=context_data,
                strategic_directions=strategic_directions
            )
            results[api_path] = analysis_result

        return results
