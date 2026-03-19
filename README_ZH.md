# JScanner2 - 基于大模型的JavaScript敏感信息智能识别工具

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

**JScanner2** 是一款革命性的JavaScript安全分析工具，核心突破在于**集成大模型智能识别敏感信息**。相比传统正则匹配的工具，本工具通过AI深度理解代码语义，实现前所未有的敏感信息识别准确率和召回率，是安全研究人员的AI助手。

## 🚀 核心设计亮点：大模型驱动的敏感信息识别

### 🤖 **AI敏感信息智能分析引擎**
- **语义级理解**：超越传统正则匹配，大模型理解代码上下文语义，精准识别隐藏的敏感信息
- **多维度风险评估**：自动评估敏感信息的风险等级（高/中/低），提供处置建议
- **动态适应能力**：面对混淆、加密、动态生成的敏感信息依然保持高识别率



## 🛠️ 安装指南

### 环境要求
- Python 3.9+
- NVIDIA GPU（4GB+显存，用于AI分析）
- 16GB+ 系统内存

### 快速安装
```bash
# 克隆仓库
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 安装Python依赖
pip install -r requirements.txt

# 安装Playwright依赖
playwright install-deps
playwright install

# 安装prettier（用于代码格式化）
npm install prettier
```

## 📋 使用指南

### 核心AI参数说明
| 参数      | 全称                          | 说明            |
|---------|-----------------------------|---------------|
| `-asir` | `--analyzeSensitiveInfoRex` | 通过正则表达式识别敏感信息 |
| `-acp`  | `--autoConstructPoc`        | 输出渗透测试建议      |
| `-asia` | `--analyzeSensitiveInfoAI`  | 自动分析敏感信息          |

### 基础扫描参数
| 参数 | 全称           | 功能                                                         |
| :--- | :------------- | :----------------------------------------------------------- |
| `-u` | `--url`        | 输入带有http/https的单个网站URL（如：https://example.com），参数会自动去除首尾空格及末尾的回车符（`\r`），参数类型为字符串 |
| `-H` | `--height`     | 扫描深度（默认值：2），参数类型为整数                        |
| `-t` | `--thread_num` | 并发线程数（默认值：10），参数类型为整数                     |
| `-p` | `--proxy`      | 代理服务器（格式要求：http://127.0.0.1:12335 或 socks5://[127.0.0.1:1080](127.0.0.1:1080)），参数类型为字符串 |
| `-v` | `--visible`    | 显示浏览器窗口（默认：无头模式，不显示窗口），为布尔型开关参数（只需添加该参数即启用，无需赋值） |

## ⚠️ 免责声明

**重要**：本工具仅限合法授权的安全评估使用，禁止未授权扫描。使用者需自行承担法律责任，开发者不承担任何连带责任。

使用本工具前请确保：
- 已获得目标网站的明确书面授权
- 遵守相关法律法规和网站使用条款
- 仅用于安全研究和漏洞修复目的
- 不将分析结果用于非法用途

## 🤝 致谢与参考
- **基础框架**：[Playwright](https://playwright.dev) - 浏览器自动化
- **代码分析**：[LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- **自然语言处理**：[NLTK](https://www.nltk.org)

## 📧 问题反馈

使用过程中遇到任何问题，欢迎提交issue：
https://github.com/hmx222/JScanner2/issues

