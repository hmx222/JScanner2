#!/bin/bash
# -*- coding: utf-8 -*-
# clean_scan.sh - JScanner2 专用状态重置脚本
# 作用：清理所有进度记录、去重记录、中间队列、AI缓存、日志文件，并删除结果文件。

# 颜色定义
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
RESET='\033[0m'

# 定义要清理的路径
LOG_DIR="./logs"
LOGGER_LOG_DIR="./logger/logs"
OVERFLOW_DIR="./Overflow_Queue"
RESULT_DIR="./Result"

echo -e "${YELLOW}🧹 正在执行清理操作...${RESET}"

# 1. 清理 Shell 脚本的进度记录 (scan_done_urls.txt 等)
if [ -d "${LOG_DIR}" ]; then
    rm -rf "${LOG_DIR}"
    echo -e "${GREEN}✅ 已删除日志目录 (logs) - 清除所有运行日志${RESET}"
fi

# 1.1 清理 logger 模块的日志目录
if [ -d "${LOGGER_LOG_DIR}" ]; then
    rm -rf "${LOGGER_LOG_DIR}"
    echo -e "${GREEN}✅ 已删除 logger 日志目录 (logger/logs) - 清除模块日志${RESET}"
fi

# 2. 清理 Result 目录下的所有内容（包括 .bloom、.db、.xlsx、.json 等）
if [ -d "${RESULT_DIR}" ]; then
    # 统计清理前的文件数量
    file_count=$(find "${RESULT_DIR}" -type f 2>/dev/null | wc -l)

    if [ "$file_count" -gt 0 ]; then
        # 删除 Result 目录下所有文件和子目录
        find "${RESULT_DIR}" -mindepth 1 -delete
        echo -e "${GREEN}✅ 已清空结果目录 (Result) - 共删除 ${file_count} 个文件${RESET}"
        echo -e "${GREEN}   包含: 数据库(.db)、Excel(.xlsx)、JSON(.json)、布隆过滤器(.bloom)等${RESET}"
    else
        echo -e "${YELLOW}⚠️ 结果目录为空，无需清理${RESET}"
    fi
else
    echo -e "${YELLOW}⚠️ 结果目录不存在: ${RESULT_DIR}${RESET}"
fi

# 3. 清理内存熔断产生的临时队列
if [ -d "${OVERFLOW_DIR}" ]; then
    rm -rf "${OVERFLOW_DIR}"
    echo -e "${GREEN}✅ 已删除溢出队列 (Overflow_Queue) - 清除未完成的接力任务${RESET}"
fi

# 重新创建必要的空目录
mkdir -p "${LOG_DIR}" "${LOGGER_LOG_DIR}" "${OVERFLOW_DIR}" "${RESULT_DIR}"

echo -e "${YELLOW}----------------------------------------${RESET}"
echo -e "${GREEN}✨ 清理完成！所有状态已重置 (含日志、结果、AI缓存、数据库)，可以运行 ./run_scan.sh 开始新任务。${RESET}"
