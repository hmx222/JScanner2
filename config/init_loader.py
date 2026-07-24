"""
初始化加载器 - 集中管理所有初始化逻辑

将去重器创建、AI 审计器创建等初始化逻辑从 Scanner 中剥离，
统一放在此处供 main.py 调用，使核心扫描逻辑保持干净。
"""
from infra.dedup import DuplicateChecker


def create_duplicate_checker(db_handler, initial_urls: list) -> DuplicateChecker:
    """
    创建去重管理器（含布隆过滤器）

    Args:
        db_handler: 数据库处理器
        initial_urls: 白名单域名列表

    Returns:
        DuplicateChecker: 去重管理器实例
    """
    return DuplicateChecker(
        db_handler=db_handler,
        initial_root_domain=initial_urls
    )


def create_ai_auditor(client=None):
    """
    创建 AI 安全审计器

    Args:
        client: AI 客户端实例（注入，保持与 SensitiveInfoScanner 一致的 DI 风格）

    Returns:
        AISecurityAuditor or None: 创建失败时返回 None
    """
    try:
        from processor.analysis import AISecurityAuditor
        return AISecurityAuditor(client=client)
    except Exception as e:
        print(f"[AI] AI 安全审计器初始化失败：{e}")
        return None


def create_sensitive_scanner(client, db_handler, max_ast_analysis=50, max_llm=80):
    """
    创建敏感信息扫描器

    Args:
        client: AI 客户端实例
        db_handler: 数据库处理器
        max_ast_analysis: AST 分析的最大候选数
        max_llm: LLM 验证的最大候选数

    Returns:
        SensitiveInfoScanner or None: 创建失败时返回 None
    """
    try:
        from processor.analysis.secret.secret_scanner import SensitiveInfoScanner
        return SensitiveInfoScanner(
            client=client,
            db=db_handler,
            max_ast_analysis=max_ast_analysis,
            max_llm=max_llm
        )
    except Exception as e:
        print(f"[Scanner] 敏感信息扫描器初始化失败：{e}")
        return None
