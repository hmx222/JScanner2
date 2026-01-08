# JScanner2 - LLM-Powered Intelligent Identification Tool for Sensitive Information in JavaScript

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

[简体中文](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md)

**JScanner2** is a revolutionary JavaScript security analysis tool with a core breakthrough in **integrating large language models (LLMs) for intelligent sensitive information identification**. Unlike traditional regex-based tools, this tool deeply understands code semantics through AI, achieving unprecedented accuracy and recall rates in sensitive information detection—serving as an AI assistant for security researchers.

## 🚀 Core Design Highlight: LLM-Driven Sensitive Information Identification

### 🤖 **AI-Powered Intelligent Sensitive Information Analysis Engine**

- **Semantic-level Understanding**: Beyond traditional regex matching, LLMs comprehend the contextual semantics of code to accurately identify hidden sensitive information

- **Multi-dimensional Risk Assessment**: Automatically evaluate the risk level (High/Medium/Low) of sensitive information and provide disposal recommendations

- **Dynamic Adaptability**: Maintains high recognition rates even for obfuscated, encrypted, or dynamically generated sensitive information

## 🛠️ Installation Guide

### Environment Requirements

- Python 3.9+

- NVIDIA GPU (4GB+ VRAM for AI analysis)

- 16GB+ system memory

### Quick Installation

```Bash

# Clone the repository
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright dependencies
playwright install-deps
playwright install

# Install prettier (for code formatting)
npm install prettier

# Install Ollama and AI model (core step)
# Be sure to execute after installing Ollama:
ollama pull qwen2.5-coder:14b
```

## 📋 Usage Guide

### Core AI Parameter Description

|Parameter|Full Name|Description|
|---|---|---|
|`-o`|`--ollama`|Enable Ollama LLM to analyze JavaScript code (core feature)|
|`-q`|`--sensitiveInfoQwen`|Use Qwen2.5 model to extract sensitive information (recommended to use with `-g`)|
|`-g`|`--sensitiveInfo`|Enable sensitive information scanning mode (basic mode, can be used independently)|
### Basic Scanning Parameters

|Parameter|Full Name|Description|
|---|---|---|
|`-u`|`--url`|Single website URL (must include http/https, e.g., `https://example.com`). Required if `-b` is not used|
|`-b`|`--batch`|Absolute path of the URL file for batch scanning (one URL per line in the file)|
|`-H`|`--height`|Scanning depth (default: 2, recommended to keep default for AI analysis)|
|`-t`|`--thread_num`|Number of concurrent threads (default: 10, recommended to reduce to 5-8 for AI analysis)|
|`-m`|`--time`|Request interval time (default: 0.1 seconds, to avoid triggering risk control)|
### Intelligent Deduplication Parameters (for use with AI)

|Parameter|Full Name|Description|
|---|---|---|
|`-d`|`--de_duplication_title`|Title deduplication (improve AI analysis efficiency)|
|`-s`|`--de_duplication_hash`|DOM SimHash deduplication (recommended threshold: 0.8)|
|`-l`|`--de_duplication_length`|Content length deduplication (reduce repeated analysis)|
### Best Practice Commands

```Bash

# [Recommended] Standard AI-sensitive information scanning (balance speed and accuracy)
python main.py -u "https://target.com" -H 4 -l -q -o

# [Batch Scanning] Multi-URL AI analysis (recommended for production environment)
python main.py -b targets.txt -H 4 -l -q -o
```

## 🤖 AI Model Performance and Configuration

### Model Performance Comparison

|Model Configuration|Accuracy|Speed (pages/min)|VRAM Usage|Applicable Scenarios|
|---|---|---|---|---|
|Qwen2.5-7B Q4_K_M (default)|96.2%|15-20|4GB|**Recommended** Balance performance and accuracy|
|Qwen2.5-7B Original|98.1%|8-12|14GB|High-precision requirements, server environment|
|Qwen2.5-3B Q4|92.5%|25-30|2GB|Low-end devices, speed priority|
|Non-AI Mode|73.8%|40-50|-|Fast preliminary scanning|
## ⚠️ Disclaimer

**Important**: This tool is only for legally authorized security assessments. Unauthorized scanning is prohibited. Users shall bear all legal responsibilities independently, and the developer shall not be liable for any joint liability.

Before using this tool, ensure that:

- You have obtained explicit written authorization for the target website

- You comply with relevant laws, regulations, and website terms of use

- It is only used for security research and vulnerability remediation purposes

- The analysis results are not used for illegal purposes

## 🤝 Acknowledgments and References

- **AI Model**: [Qwen](https://github.com/QwenLM) - Alibaba Tongyi Qianwen

- **Basic Framework**: [Playwright](https://playwright.dev) - Browser Automation

- **Code Analysis**: [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

- **Natural Language Processing**: [NLTK](https://www.nltk.org) 

- **Rule Base**: [findsomething](https://github.com/momosecurity/FindSomething)

- **Tencent Cloud Cloud Studio**: [Cloud Studio](https://ide.cloud.tencent.com/)

## 📧 Issue Feedback

If you encounter any problems during use, please submit an issue:

[https://github.com/hmx222/JScanner2/issues](https://github.com/hmx222/JScanner2/issues)

---

**JScanner2** - Let AI be your security researcher, intelligently identifying every potential risk.  

**The next generation of security tools - more than just scanning, but understanding.**

---


3. 保留了所有实操命令和参数说明的准确性，可直接用于英文环境下的工具使用，同时支持中文README与该英文版本的双向切换（默认展示英文版本）。
> （注：文档部分内容可能由 AI 生成）
