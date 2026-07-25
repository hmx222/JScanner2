import asyncio
import logging
import os
import time
import warnings
from traceback import print_exc

from colorama import init

from config.config import db_filename
from infra.feishu import send_feishu_notify
from parse_args import parse_args
from processor.analysis.secret.secret_scanner import SQLiteStorage
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
    scanner = Scanner(args, db_handler, checker=checker, initial_urls=initial_urls)

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
