#!/bin/bash
# -*- coding: utf-8 -*-
# clean_scan.sh - JScanner2 专用状态重置脚本
# 作用：清理所有进度记录、去重记录、中间队列、AI缓存，并删除结果文件。

# 颜色定义
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
RESET='\033[0m'

# 定义要清理的路径
LOG_DIR="./Log_Data"
OVERFLOW_DIR="./Overflow_Queue"
RESULT_DIR="./Result"

# 定义所有需要清理的 .bloom 文件 (包含主程序去重 + SenInfo AI去重)
BLOOM_FILES=(
    "${RESULT_DIR}/global_dedup.bloom"
    "${RESULT_DIR}/ai_candidates.bloom"
    "${RESULT_DIR}/output_lines.bloom"
    "${RESULT_DIR}/word_analysis.bloom"
)

echo -e "${YELLOW}🧹 正在执行清理操作...${RESET}"

# 1. 清理 Shell 脚本的进度记录 (scan_done_urls.txt 等)
if [ -d "${LOG_DIR}" ]; then
    rm -rf "${LOG_DIR}"
    echo -e "${GREEN}✅ 已删除日志目录 (Log_Data) - 解除 Shell 脚本的'跳过'限制${RESET}"
fi

# 2. 清理所有持久化布隆过滤器
for bloom_file in "${BLOOM_FILES[@]}"; do
    if [ -f "${bloom_file}" ]; then
        rm -f "${bloom_file}"
        echo -e "${GREEN}✅ 已删除去重记录: $(basename "${bloom_file}")${RESET}"
    fi
done

# 3. 清理内存熔断产生的临时队列
if [ -d "${OVERFLOW_DIR}" ]; then
    rm -rf "${OVERFLOW_DIR}"
    echo -e "${GREEN}✅ 已删除溢出队列 (Overflow_Queue) - 清除未完成的接力任务${RESET}"
fi

# 4. 删除所有 Excel 结果文件 和 JSON 结果
if [ -d "${RESULT_DIR}" ]; then
    # 删除 Excel
    if ls ${RESULT_DIR}/*.xlsx 1> /dev/null 2>&1; then
        rm -f "${RESULT_DIR}"/*.xlsx
        echo -e "${GREEN}✅ 已删除所有 Excel 结果文件${RESET}"
    fi
    # 删除 敏感信息 JSON
    if [ -f "${RESULT_DIR}/sensitiveInfo.json" ]; then
        rm -f "${RESULT_DIR}/sensitiveInfo.json"
        echo -e "${GREEN}✅ 已删除敏感信息 JSON 文件${RESET}"
    fi
else
    echo -e "${YELLOW}⚠️ 结果目录不存在: ${RESULT_DIR}${RESET}"
fi

# 重新创建必要的空目录
mkdir -p "${LOG_DIR}" "${OVERFLOW_DIR}" "${RESULT_DIR}"

echo -e "${YELLOW}----------------------------------------${RESET}"
echo -e "${GREEN}✨ 清理完成！所有状态已重置 (含AI缓存)，可以运行 ./run_scan.sh 开始新任务。${RESET}"
