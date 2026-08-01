import asyncio
import logging
import os
import time
import warnings
from traceback import print_exc

from colorama import init

from config.config import db_filename
from infra.ai_client import client
from infra.feishu import send_feishu_notify
from parse_args import parse_args
from processor.analysis import AISecurityAuditor
from processor.analysis.secret.secret_scanner import SQLiteStorage, SensitiveInfoScanner
from Scanner import Scanner, load_initial_urls, create_duplicate_checker

warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    init(autoreset=True)
    args = parse_args()
    start_time = time.time()
    os.makedirs("Result", exist_ok=True)
    print(f"📂 扫描结果将存入数据库：{db_filename}")
    db_handler = SQLiteStorage(db_filename)

    initial_urls = load_initial_urls(args.url)
    checker = create_duplicate_checker(db_handler, initial_urls)

    ai_auditor = None
    if args.findparam:
        try:
            ai_auditor = AISecurityAuditor()
        except Exception as e:
            print(f"[AI] AI 安全审计器初始化失败：{e}")
            ai_auditor = None

    sensitive_scanner = None
    if args.analyzeSensitiveInfoAI:
        try:
            sensitive_scanner = SensitiveInfoScanner(
                client=client,
                db=db_handler,
                max_ast_analysis=50,
                max_llm=80
            )
        except Exception as e:
            print(f"[Scanner] 敏感信息扫描器初始化失败：{e}")
            sensitive_scanner = None
    args.initial_urls = initial_urls

    scanner = Scanner(args, db_handler,
                      checker=checker,
                      initial_urls=initial_urls,
                      ai_auditor=ai_auditor,
                      sensitive_scanner=sensitive_scanner)

    try:
        asyncio.run(scanner.run())
        run_time = round(time.time() - start_time, 2)
        print(f"本次扫描耗时：{run_time}s")
    except Exception as e:
        run_time = round(time.time() - start_time, 2)
        error_content = f"❌ 错误：{str(e)}\n⏱️ 耗时：{run_time}s"
        send_feishu_notify("【扫描任务报警】", error_content)
        print_exc()
    finally:
        scanner._cleanup_resources()
