# JScanner2 - Large Model-Based JavaScript Sensitive Information Intelligent Recognition Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

## 🛠️ Installation Guide

### Environment Requirements

- Python 3.9+

### Quick Installation

```bash
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
```

## 📋 User Guide

### Core AI Parameter Description

|Parameter|Full Name|Description|
|---|---|---|
|-asir|--analyzeSensitiveInfoRex|Identify sensitive information through regular expressions|
|-acp|--autoConstructPoc|Output penetration testing recommendations|
|-asia|--analyzeSensitiveInfoAI|Automatically analyze sensitive information|
### Basic Scanning Parameters

|Parameter|Full Name|Function|
|---|---|---|
|-u|--url|Enter a single website URL with http/https (e.g., https://example.com). The parameter will automatically remove leading/trailing spaces and trailing carriage returns (\r), and the parameter type is string.|
|-H|--height|Scanning depth (default value: 2), parameter type is integer.|
|-t|--thread_num|Number of concurrent threads (default value: 10), parameter type is integer.|
|-p|--proxy|Proxy server (format requirement: http://127.0.0.1:12335 or socks5://[127.0.0.1:1080](127.0.0.1:1080)), parameter type is string.|
|-v|--visible|Show browser window (default: headless mode, no window displayed). It is a boolean switch parameter (just add the parameter to enable it, no need to assign a value).|
## ⚠️ Disclaimer

**Important**: This tool is only for legally authorized security assessments; unauthorized scanning is prohibited. Users shall bear legal responsibility for their own actions, and the developer shall not bear any joint liability.

Before using this tool, please ensure that:

- You have obtained explicit written authorization for the target website

- You comply with relevant laws, regulations and website terms of service

- It is only used for security research and vulnerability repair purposes

- The analysis results are not used for illegal purposes

## 🤝 Acknowledgements and References

- **Basic Framework**: [Playwright](https://playwright.dev) - Browser Automation

- **Code Analysis**: [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

- **Natural Language Processing**: [NLTK](https://www.nltk.org)

## 📧 Feedback

If you encounter any problems during use, please feel free to submit an issue:

https://github.com/hmx222/JScanner2/issues