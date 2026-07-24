import asyncio
import os
import time
from traceback import print_exc

from colorama import init

from config.config import db_filename
from config.init_loader import create_duplicate_checker, create_ai_auditor, create_sensitive_scanner
from processor.analysis.api.api_scan import get_root_domain
from core.scanner import Scanner
from infra.ai_client import client
from infra.utils import send_feishu_notify
from config.arg_parser import parse_args
from processor.analysis.secret.secret_scanner import SQLiteStorage


# ==================== 程序入口 ====================

if __name__ == '__main__':
    init(autoreset=True)  # 初始化 colorama（自动重置颜色）
    args = parse_args()  # 解析命令行参数
    start_time = time.time()  # 记录开始时间
    os.makedirs("Result", exist_ok=True)
    target_url = args.url.strip() if args.url else "unknown"  # 目标URL
    print(f"📂 扫描结果将存入数据库：{db_filename}")

    # ========== 初始化所有依赖 ==========
    db_handler = SQLiteStorage(db_filename)                          # 数据库
    # 从种子 URL 提取根域名（域名范围过滤的唯一输入）
    seed_domains = [get_root_domain(args.url.strip())] if args.url and args.url.strip() else []  # 种子域名列表
    args.initial_urls = seed_domains                                 # 注入 args
    checker = create_duplicate_checker(db_handler, seed_domains)     # 去重管理器（含布隆过滤器）
    ai_auditor = create_ai_auditor(client) if args.findparam else None     # AI 安全审计器
    sensitive_scanner = create_sensitive_scanner(client, db_handler) if args.analyzeSensitiveInfoAI else None  # 敏感信息扫描器

    scanner = Scanner(
        args=args,
        db_handler=db_handler,
        checker=checker,
        ai_auditor=ai_auditor,
        sensitive_scanner=sensitive_scanner
    )  # 创建扫描器实例

    try:
        # 运行异步扫描主流程
        asyncio.run(scanner.run())
        run_time = round(time.time() - start_time, 2)  # 计算运行耗时
        print(f"本次扫描耗时：{run_time}s")
    except Exception as e:  # 捕获异常
        run_time = round(time.time() - start_time, 2)  # 计算异常耗时
        error_content = f"❌ 错误：{str(e)}\n⏱️ 耗时：{run_time}s"  # 异常信息内容
        # 发送飞书告警通知
        send_feishu_notify("【扫描任务报警】", error_content)
        print_exc()
    finally:
        # 清理资源
        scanner._cleanup_resources()