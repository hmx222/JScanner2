# JScanner2 - 大模型驱动的 JavaScript 敏感信息智能识别工具

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

## 🛠️ 安装指南

### 环境要求

- Python 3.9+

### 快速安装

```bash
# 克隆仓库
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 安装 Python 依赖
pip install -r requirements.txt

# 安装 Playwright 依赖
playwright install-deps
playwright install

# 安装 prettier（用于代码格式化）
npm install prettier
```

## ⚙️ 使用前配置检查

> ⚠️ **重要**：在使用 JScanner2 之前，请务必完成以下配置步骤：

| 步骤 | 文件/目录 | 配置目的 | 是否必需 |
|------|----------|---------|----------|
| 1️⃣ | `run_scan.sh` | 配置飞书 Webhook、扫描参数、目标列表（脚本模式专用） | ✅ 使用 `bash run_scan.sh` 时必需 |
| 2️⃣ | `config/` 目录 | 配置大模型接口地址、API Key、代理等核心参数 | ✅ 始终必需 |

### 快速配置指引

```bash
# 1. 编辑核心配置
vim config/config.py
# → 修改项：BASE_URL, API_KEY, proxies, FEISHU_WEBHOOK

# 2. 编辑脚本配置（如使用脚本模式）
vim run_scan.sh
# → 修改项：FEISHU_WEBHOOK, SCAN_DEPTH, TARGET_LIST 等

# 3. （可选）准备目标列表
echo "https://target.com" > config/targets.txt
```

> 💡 **建议**：`API_KEY` 等敏感配置建议通过环境变量管理，或避免提交至版本仓库。

---

## 📋 使用指南

### 两种运行模式

JScanner2 支持两种运行方式，适配不同使用场景：

| 模式 | 命令 | 适用场景 | 多目标支持 | 飞书通知 |
|------|------|----------|-----------|----------|
| 🔹 命令行模式 | `python main.py [参数]` | 调试 / 单目标快速测试 | ❌ | ❌ |
| 🔹 脚本模式 | `bash run_scan.sh` | 批量扫描 / 自动化任务 | ✅ | ✅ |

> 💡 **提示**：`run_scan.sh` 模式支持在脚本内部自定义扫描参数、深度及飞书机器人配置。

### 核心 AI 参数说明

| 参数 | 全称 | 功能说明 |
|------|------|----------|
| -asir | --analyzeSensitiveInfoRex | 通过正则表达式识别敏感信息 |
| -asia | --analyzeSensitiveInfoAI | 使用 AI 自动分析敏感信息 |
| -fp | --findparam | 自动解析 API 参数 |
| -fs | --fastscan | 启用快速扫描模式 |

### 基础扫描参数说明

| 参数 | 全称 | 功能说明 |
|------|------|----------|
| -u | --url | 输入单个网站 URL，需包含 http/https（如 https://example.com）。参数会自动去除首尾空格及末尾回车符 (\r)，类型为 string。 |
| -H | --height | 扫描深度（默认值：2），类型为 integer。 |
| -t | --thread_num | 并发线程数（默认值：10），类型为 integer。 |
| -p | --proxy | 代理服务器（格式要求：http://127.0.0.1:12335 或 socks5://127.0.0.1:1080），类型为 string。 |
| -v | --visible | 显示浏览器窗口（默认：无头模式，不显示窗口）。布尔开关参数（添加即启用，无需赋值）。 |

### 使用示例

```bash
# 命令行模式：基础扫描
python main.py -u https://example.com

# 命令行模式：启用 AI 分析 + 深度扫描
python main.py -u https://example.com -asia -fp -H 6 

# 脚本模式：执行预设自动化任务
echo urls.txt | ./run_scan.sh
```

---

## ⚠️ 免责声明

**重要**：本工具仅限合法授权的安全评估使用，禁止用于未授权扫描。用户需对自身行为承担法律责任，开发者不承担任何连带责任。

使用本工具前，请确保：

- 已获得目标网站的明确书面授权

- 遵守相关法律法规及网站服务条款

- 仅用于安全研究与漏洞修复目的

- 不将分析结果用于非法用途

---

## 🤝 致谢与参考

- **基础框架**：[Playwright](https://playwright.dev) - 浏览器自动化

- **代码分析**：[LinkFinder](https://github.com/GerbenJavado/LinkFinder)

- **自然语言处理**：[NLTK](https://www.nltk.org)

---

## 📧 反馈与支持

如在使用过程中遇到问题，欢迎提交 Issue：

https://github.com/hmx222/JScanner2/issues
