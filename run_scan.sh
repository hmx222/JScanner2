#!/bin/bash
# -*- coding: utf-8 -*-

PYTHON_CMD="main.py"
PYTHON_ARGS="-H 5 -o -q -x"
LOG_FILE="./scan_run_log.log"       # Shell脚本执行日志
PYTHON_LOG_DIR="./python_url_logs"  # Python每个URL的详细日志(含进度条)
DONE_URL_FILE="./scan_done_urls.txt"# 断点续跑-已执行URL记录
FAIL_URL_FILE="./scan_fail_urls.txt"# 执行失败的URL记录

# 初始化文件+文件夹
mkdir -p ${PYTHON_LOG_DIR}
touch ${LOG_FILE} ${DONE_URL_FILE} ${FAIL_URL_FILE}
echo -e "===== 扫描开始时间: $(date '+%Y-%m-%d %H:%M:%S') =====" >> ${LOG_FILE}

# ===================== 处理【管道输入】+【参数输入】 =====================
URL_FILE=""
if [ -p /dev/stdin ]; then
    read -r URL_FILE
elif [ $# -eq 1 ]; then
    URL_FILE=$1
else
    echo -e "\033[31m❌ 错误：请使用管道传参或直接传参！\033[0m"
    echo -e "\033[32m✅ 使用方式1(管道): echo url_list.txt | $0\033[0m"
    echo -e "\033[32m✅ 使用方式2(传参): $0 url_list.txt\033[0m"
    exit 1
fi

if [ ! -f "${URL_FILE}" ]; then
    echo -e "\033[31m❌ 错误：URL文件 ${URL_FILE} 不存在！\033[0m"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: URL文件 ${URL_FILE} 不存在" >> ${LOG_FILE}
    exit 1
fi

# ===================== 跨系统兼容处理 =====================
if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "win32"* ]]; then
    PYTHON_EXE="python"
else
    PYTHON_EXE="python3"
fi

if ! command -v ${PYTHON_EXE} &> /dev/null; then
    echo -e "\033[31m❌ 错误：未找到Python，请先安装Python并配置环境变量！\033[0m"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Python未安装或未配置环境变量" >> ${LOG_FILE}
    exit 1
fi

# ===================== 读取URL并执行核心逻辑【解决冲突核心修改处】 =====================
ALL_URLS=($(grep -v "^#" ${URL_FILE} | sed '/^[[:space:]]*$/d' | awk '{$1=$1};1' | sort -u))
TOTAL_URL=${#ALL_URLS[@]}
CURRENT_NUM=0

echo -e "\033[32m✅ 扫描开始！共读取到 ${TOTAL_URL} 个有效URL \033[0m"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: 共读取到 ${TOTAL_URL} 个有效URL" >> ${LOG_FILE}

for TARGET_URL in "${ALL_URLS[@]}"; do
    CURRENT_NUM=$((CURRENT_NUM + 1))
    if grep -qx "${TARGET_URL}" ${DONE_URL_FILE}; then
        echo -e "\033[33m⏩ [${CURRENT_NUM}/${TOTAL_URL}] 已执行过，跳过: ${TARGET_URL}\033[0m"
        continue
    fi

    # 生成当前URL的独立日志文件名(兼容特殊字符)
    URL_LOG_NAME=$(echo ${TARGET_URL} | sed 's/[^a-zA-Z0-9]/_/g').log
    URL_LOG_FILE=${PYTHON_LOG_DIR}/${URL_LOG_NAME}

    echo -e "\033[36m=====================================================\033[0m"
    echo -e "\033[32m▶️  [${CURRENT_NUM}/${TOTAL_URL}] 开始扫描: ${TARGET_URL}\033[0m"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: 开始执行 [${CURRENT_NUM}/${TOTAL_URL}] ${TARGET_URL}" >> ${LOG_FILE}

    # ===================== 核心解决冲突 ↓↓↓↓↓↓ =====================
    # Python所有输出(进度条+日志+报错)重定向到独立日志文件，控制台无任何Python输出
    ${PYTHON_EXE} ${PYTHON_CMD} -u "${TARGET_URL}" ${PYTHON_ARGS} > ${URL_LOG_FILE} 2>&1
    # ===================== 核心解决冲突 ↑↑↑↑↑↑ =====================

    # 判断执行结果
    if [ $? -eq 0 ]; then
        echo -e "\033[32m✅ [${CURRENT_NUM}/${TOTAL_URL}] 扫描成功: ${TARGET_URL}\033[0m"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: ${TARGET_URL}" >> ${LOG_FILE}
        echo "${TARGET_URL}" >> ${DONE_URL_FILE}
    else
        echo -e "\033[31m❌ [${CURRENT_NUM}/${TOTAL_URL}] 扫描失败: ${TARGET_URL}\033[0m"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED: ${TARGET_URL}" >> ${LOG_FILE}
        echo "${TARGET_URL}" >> ${FAIL_URL_FILE}
    fi
done

# ===================== 执行完成汇总 =====================
echo -e "\033[36m=====================================================\033[0m"
echo -e "\033[32m🎉 所有URL扫描完成！\033[0m"
echo -e "\033[32m📊 统计：总=${TOTAL_URL} | 成功=$(wc -l < ${DONE_URL_FILE}) | 失败=$(wc -l < ${FAIL_URL_FILE})\033[0m"
echo -e "\033[32m📝 Shell日志: ${LOG_FILE}\033[0m"
echo -e "\033[32m🐍 Python进度条日志: ${PYTHON_LOG_DIR}\033[0m"
echo -e "\033[32m✅ 已执行URL: ${DONE_URL_FILE}\033[0m"
echo -e "\033[31m❌ 失败URL: ${FAIL_URL_FILE}\033[0m"
echo -e "===== 扫描结束时间: $(date '+%Y-%m-%d %H:%M:%S') =====" >> ${LOG_FILE}