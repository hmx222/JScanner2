#!/bin/bash

set -e

# ---------- 🔑 大模型 API ----------
API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
BASE_URL="http://127.0.0.1:3000/v1/"

# ---------- 🤖 模型列表 (空格分隔) ----------
MODELS="glm-4.7-flash qwen3.5-flash"

# ---------- 🔔 飞书 Webhook ----------
FEISHU_WEBHOOK="https://open.feishu.cn/open-apis/bot/v2/hook/1412ed79xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# ---------- 🌐 代理 (留空表示不用代理) ----------
HTTP_PROXY=""
HTTPS_PROXY=""
NO_PROXY="*"

# ---------- 🌐 白名单域名 (空格分隔，留空则不限制) ----------
WHITELIST_DOMAINS=""

# ---------- ⚙️ 可选参数 (一般不用改) ----------
MEMORY_LIMIT=80
CODE_MAX_LENGTH=12000
GLOBAL_TIMEOUT=30
MAX_REDIRECT_COUNT=1

# ===================== 配置区结束 =====================


echo -e "\033[36m🔧 JScanner2 一键配置开始...\033[0m"

# ------------------------------------------------------------------
# 1. 生成 config/config.py
# ------------------------------------------------------------------
echo -e "  📄 正在生成 config/config.py ..."

cat > config/config.py << PYEOF
# ===== 此文件由 setup.sh 自动生成，如需自定义请直接编辑此文件 =====

# 本地/私有化大模型服务地址
BASE_URL = "${BASE_URL}"

# API Key（请替换为您自己的密钥）
API_KEY = "${API_KEY}"

# 🔧 提示词缓存配置（阿里云 DashScope）
ENABLE_PROMPT_CACHE = True  # 是否启用提示词缓存
CACHE_CONTROL_TYPE = "ephemeral"  # 缓存类型：ephemeral（临时缓存，5分钟有效期）
MIN_CACHE_TOKENS = 1024  # 最小缓存 token 数（约等于字符数）
MAX_CACHE_MARKERS = 4  # 单次请求最多缓存标记数

DEFAULT_CONFIG_PATH = "config/models_config.json"  # 模型配置文件路径

WHITE_SCOPE_PATH = "config/whiteList.txt"   # 白名单路径（仅扫描指定路径）
MEMORY_LIMIT = ${MEMORY_LIMIT}                            # 内存占用阈值（%），超限时会进行内存释放

proxies = {
    "http": "${HTTP_PROXY}",           # 示例: "http://127.0.0.1:7890"
    "https": "${HTTPS_PROXY}",          # 示例: "http://127.0.0.1:7890"
    "no_proxy": "${NO_PROXY}"       # 不走代理的域名，* 表示全部走代理
}

# ------------------------------
# 🔔 飞书告警通知
# ------------------------------
FEISHU_WEBHOOK = "${FEISHU_WEBHOOK}"
FEISHU_ALERT_LEVELS = ["ERROR", "CRITICAL"]       # 触发告警的日志级别
FEISHU_RATE_LIMIT_SECONDS = 60                    # 相同告警内容60秒内只发一次

# ------------------------------
# 📁 输出路径配置
# ------------------------------
db_filename = "Result/JScanner_Result.db"         # 扫描结果数据库路径
OVERFLOW_DIR = "Overflow_Queue"                   # 溢出队列暂存目录
LOG_DIR = "logs"                                  # 日志输出目录

# ------------------------------
# 🎯 扫描范围与性能控制
# ------------------------------
GLOBAL_TIMEOUT = ${GLOBAL_TIMEOUT}                          # 单页面最大等待时间（秒）
MAX_REDIRECT_COUNT = ${MAX_REDIRECT_COUNT}                       # 最大允许跳转次数

CODE_MAX_LENGTH = ${CODE_MAX_LENGTH}  # 单次送入大模型的代码最大长度（避免 token 超限）

# ------------------------------
# 📋 日志系统配置
# ------------------------------
LOG_FILENAME = "scanner.log"
LOG_ERROR_FILENAME = "scanner_error.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 单文件最大10MB
LOG_BACKUP_COUNT = 5              # 保留5个历史日志
CONSOLE_LOG_LEVEL = "INFO"        # 控制台输出级别

# ------------------------------
# 📦 NLTK 数据路径
# ------------------------------
NLTK_DIR = "config/nltk_data"
PYEOF

echo -e "  \033[32m✅ config/config.py 已生成\033[0m"


# ------------------------------------------------------------------
# 2. 生成 config/models_config.json
# ------------------------------------------------------------------
echo -e "  📄 正在生成 config/models_config.json ..."

# 将空格分隔的模型列表转为 JSON 数组
MODEL_JSON='{\n  "models": [\n'
FIRST=true
for MODEL in ${MODELS}; do
    if [ "${FIRST}" = true ]; then
        MODEL_JSON="${MODEL_JSON}    \"${MODEL}\""
        FIRST=false
    else
        MODEL_JSON="${MODEL_JSON},\n    \"${MODEL}\""
    fi
done
MODEL_JSON="${MODEL_JSON}\n  ]\n}"

printf "${MODEL_JSON}" > config/models_config.json

echo -e "  \033[32m✅ config/models_config.json 已生成 ($(echo ${MODELS} | wc -w) 个模型)\033[0m"


# ------------------------------------------------------------------
# 3. 替换 run_scan.sh 中的飞书 Webhook
# ------------------------------------------------------------------
echo -e "  📄 正在更新 run_scan.sh 中的飞书通知地址 ..."

tmp=$(mktemp)
sed "s|^FEISHU_URL=.*|FEISHU_URL=\"${FEISHU_WEBHOOK}\"|" run_scan.sh > "$tmp" && cat "$tmp" > run_scan.sh && rm "$tmp"

echo -e "  \033[32m✅ run_scan.sh 已更新\033[0m"


# ------------------------------------------------------------------
# 4. 汇总
# ------------------------------------------------------------------
echo ""
echo -e "\033[36m=====================================================\033[0m"
echo -e "\033[32m🎉 配置完成！汇总如下：\033[0m"
echo -e "   API Key:     ${API_KEY:0:10}...（已隐藏）"
echo -e "   Base URL:    ${BASE_URL}"
echo -e "   模型数量:    $(echo ${MODELS} | wc -w) 个"
echo -e "   飞书告警:    ${FEISHU_WEBHOOK:0:50}..."
echo -e "   代理:        HTTP=${HTTP_PROXY:-无} | HTTPS=${HTTPS_PROXY:-无}"
echo -e "\033[36m=====================================================\033[0m"
echo ""
echo -e "\033[32m▶️  现在可以运行扫描了：\033[0m"
echo -e "   \033[33mdocker compose run --rm scanner run_scan.sh urls.txt\033[0m"
echo -e ""
echo -e "   \033[33m💡 如需配置白名单，请手动编辑: vim config/whiteList.txt\033[0m"
echo ""
