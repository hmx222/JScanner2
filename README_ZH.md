# JScanner2

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

**JScanner2** 是一款专为**大规模资产测绘**设计的 JavaScript 敏感信息挖掘工具，它可以帮助您高效的发现隐藏接口与JS硬编码信息。

------

## 🚀 核心特性

- **🛡️ 内存熔断保护**
- **🧠 双模 AI 引擎**
- **💾 持久化去重**
- **🔍 智能清洗**

------

## 🛠️ 快速开始

### 1. 安装

```bash
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 安装 Python 依赖
pip install -r requirements.txt

# 安装 Playwright 浏览器
playwright install-deps
playwright install

# (可选) 拉取本地 AI 模型 - 仅在使用本地模式时需要
ollama pull qwen2.5-coder:14b
```

### 2. 配置 (`config/config.py`)

所有运行参数均在 `config/config.py` 中管理，程序会根据配置自动判断运行模式：

#### 🤖 AI 模型配置 (二选一)

- **模式 A：阿里云百炼/其他平台 (推荐，速度快精度高)**

  - 在 `config.py` 中填入您的 `DASHSCOPE_API_KEY`。
  - 程序会自动检测 Key 并优先使用云端模型 (`qwen2.5-coder-14b-instruct`)。

  ```python
  DASHSCOPE_API_KEY = "sk-xxxxxxxxxxxxxxxx" 
  ```

- **模式 B：本地 Ollama (隐私性强，需显存)**

  - 保持 `DASHSCOPE_API_KEY` 为空字符串 `""`。
  - 程序将自动降级使用本地 Ollama 服务。
  - 根据显卡调整 `OLLAMA_MAX_GPU_MEMORY` (默认 "4GB")。

#### 📨 通知配置

- **飞书通知**：

  - 配置 `FEISHU_WEBHOOK`，工具将在 **发生报错** 或 **任务全部完成** 时发送通知。

  ```python
  FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/..."
  ```

### 3. 运行 (生产环境推荐)

**不要直接运行 `python main.py`**。请使用我们封装好的 Shell 脚本来激活自动熔断与接力功能：

```bash
# 方式一：管道输入 (推荐)
echo urls.txt | ./run_scan.sh

# 方式二：文件参数
./run_scan.sh urls.txt
```

> **提示**：程序会自动监控内存，处理溢出任务，并自动合并最终的 Excel 结果，无需人工干预。

### 4. 重置任务

如果需要换一批目标重新扫描，请**务必**执行清理脚本以重置去重记录，否则新任务会被视为“已扫描”而跳过：

```bash
./clean_scan.sh
```

------

## 📂 结果输出

结果文件会自动按**日期**归档至 `Result/` 目录：

- **Excel 报告**：`Result/Result_域名_2023xxxx.xlsx` (包含所有发现的 URL 和层级关系，支持断点续写)
- **敏感信息**：`Result/sensitiveInfo.json` (AI 审计出的 Key/Token/Secret)
- **运行日志**：`Log_Data/scan_run_log.log`

------

## ⚙️ 核心参数 (调试用)

如果你需要手动调试核心脚本（不启用熔断保护）：

```bash
python3 main.py -u https://example.com [选项]
```

- `-o` / `--ollama`: 启用 AI 代码审计
- `-q`: 使用 Qwen 模型提取敏感信息
- `-x`: 开启智能去重 (默认开启)
- `-H 5`: 爬取深度 (默认 5)
- `-t 10`: 线程数 (默认 10)

------

## ⚠️ 免责声明

本工具仅供安全研究与授权测试使用。严禁用于未授权的渗透测试或非法攻击。使用者需自行承担一切法律后果。
