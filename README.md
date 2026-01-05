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

# 安装Ollama和AI模型（核心步骤）
# 务必安装Ollama后执行：
ollama pull qwen2.5-coder:14b
```

## 📋 使用指南

### 核心AI参数说明
| 参数 | 全称                  | 说明                                                  |
| ---- | --------------------- | ----------------------------------------------------- |
| `-o` | `--ollama`            | 启用Ollama大模型分析JavaScript代码（核心功能）        |
| `-q` | `--sensitiveInfoQwen` | 使用Qwen2.5模型专门抽取敏感信息（推荐与`-g`配合使用） |
| `-g` | `--sensitiveInfo`     | 启用敏感信息扫描模式（基础模式，可单独使用）          |

### 基础扫描参数
| 参数 | 全称           | 说明                                                         |
| ---- | -------------- | ------------------------------------------------------------ |
| `-u` | `--url`        | 单个网站URL（需带http/https，例如：`https://example.com`）与`-b`参数必选其一 |
| `-b` | `--batch`      | 批量扫描的URL文件绝对路径（文件内需每行一个URL）             |
| `-H` | `--height`     | 扫描深度（默认值：2，AI分析时建议保持默认）                  |
| `-t` | `--thread_num` | 并发线程数（默认值：10，AI分析时建议降低至5-8）              |
| `-m` | `--time`       | 请求间隔时间（默认：0.1秒，避免触发风控）                    |
| `-a` | `--api`        | 对API进行全量扫描（与AI分析配合效果最佳）                    |

### 智能去重参数（配合AI使用）
| 参数 | 全称                      | 说明                           |
| ---- | ------------------------- | ------------------------------ |
| `-d` | `--de_duplication_title`  | 标题去重（提升AI分析效率）     |
| `-s` | `--de_duplication_hash`   | DOM SimHash去重（推荐阈值0.8） |
| `-l` | `--de_duplication_length` | 内容长度去重（减少重复分析）   |

### 最佳实践命令

```bash
# 【推荐】标准AI敏感信息扫描（平衡速度与精度）
python main.py -u "https://target.com" -H 2 -o -q -g -s 0.8 -l

# 【高精度】深度AI分析（适合关键目标）
python main.py -u "https://target.com" -H 2 -o -q -g -a -s 0.85 -d -l -t 5

# 【批量扫描】多URL AI分析（生产环境推荐）
python main.py -b targets.txt -H 2 -o -q -g -s 0.8 -l -t 8

# 【快速扫描】仅基础敏感信息识别（无AI，速度快）
python main.py -u "https://target.com" -g -s 0.8 -l
```

## 🤖 AI模型性能与配置

### 模型性能对比
| 模型配置                     | 准确率 | 速度(页/分钟) | 显存占用 | 适用场景                |
| ---------------------------- | ------ | ------------- | -------- | ----------------------- |
| Qwen2.5-7B Q4_K_M (默认推荐) | 96.2%  | 15-20         | 4GB      | **推荐** 平衡性能与精度 |
| Qwen2.5-7B 原始版            | 98.1%  | 8-12          | 14GB     | 高精度需求，服务器环境  |
| Qwen2.5-3B Q4                | 92.5%  | 25-30         | 2GB      | 低配设备，速度优先      |
| 无AI模式                     | 73.8%  | 40-50         | -        | 快速初步扫描            |

## ⚠️ 免责声明

**重要**：本工具仅限合法授权的安全评估使用，禁止未授权扫描。使用者需自行承担法律责任，开发者不承担任何连带责任。

使用本工具前请确保：
- 已获得目标网站的明确书面授权
- 遵守相关法律法规和网站使用条款
- 仅用于安全研究和漏洞修复目的
- 不将分析结果用于非法用途

## 🤝 致谢与参考

- **AI模型**：[Qwen](https://github.com/QwenLM) - 阿里巴巴通义千问
- **基础框架**：[Playwright](https://playwright.dev) - 浏览器自动化
- **代码分析**：[LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- **自然语言处理**：[NLTK](https://www.nltk.org) 
- **规则库**：[findsomething](https://github.com/momosecurity/FindSomething)
- **腾讯云Cloud Studio**：[Cloud Studio](https://ide.cloud.tencent.com/)

## 📧 问题反馈

使用过程中遇到任何问题，欢迎提交issue：
https://github.com/hmx222/JScanner2/issues

---

**JScanner2** - 让AI成为您的安全研究员，智能识别每一个潜在风险。  
**下一代安全工具，不止于扫描，更在于理解。**
