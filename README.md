# JScanner2 - AI-Powered JavaScript Security Analysis Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

[中文版](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md) | [English](https://github.com/hmx222/JScanner2/blob/master/README.md)

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- AI Model API access (Recommended: **Qwen 3.5-flash**)
- Recommended specs: **4 CPU cores + 4GB RAM**

### Installation & Usage

```bash
# 1. Clone the repository
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 2. Configure and initialize
vim setup.sh  # Configure your AI API keys etc
docker compose run --rm scanner /app/setup.sh

# 3. Prepare target URLs
# Required: Add URLs to scan in urls.txt

# 4. Add WhiteList
# Optional: Add whitelist domains in config/whiteList.txt

# 5. Start scanning
docker compose run --rm scanner /app/run_scan.sh urls.txt
```

---

## 📖 Overview

**JScanner2** is an intelligent JavaScript security scanning tool that combines **AST (Abstract Syntax Tree) parsing** with **AI large language models** to discover sensitive information and unauthorized access vulnerabilities in JavaScript files.

Unlike traditional regex-based tools, JScanner2 understands code semantics, extracts API parameters automatically, and provides AI-powered exploit guidance.

### ✨ Key Features

- 🔍 **Intelligent Parameter Discovery** - AST-based extraction of API endpoints AND parameters
- 🤖 **AI-Driven Analysis** - Context-aware hardcoded secret detection with exploit suggestions  
- 🔄 **Resumable Scanning** - Support for pause/resume operations

---

## 💡 Why JScanner2

### ❌ Limitations of Traditional Tools

Traditional JavaScript scanning tools (findsomething, JSFinder, etc.) rely on **regex matching** and suffer from:

1. **API Paths Only** - Cannot extract parameters needed to trigger vulnerabilities
2. **High False Positives** - Regex cannot understand context (e.g., `s=qcfvg28@4a`)
3. **Manual Analysis Required** - Every finding needs human verification
4. **No Business Logic** - Cannot distinguish between safe and exploitable secrets

---

## 📊 Results Analysis

Scan results are stored as SQLite databases in the `Result/` directory.

## 📈 Real-World Results

Tested against **29 domestic SRCs** (Security Response Centers) with the following findings:

| Severity     | Count |
| ------------ | ----- |
| 🔴 **High**   | 10    |
| 🟡 **Medium** | 4     |
| 🟢 **Low**    | 1     |

**Notes:**
- ✅ Deduplicated (no repeated vulnerabilities)
- ✅ Low WAF detection rate (no attack payloads)
- ✅ Suitable for red team/blue team exercises
- ✅ Includes only independent SRCs (not public bug bounty platforms)

---

## 💰 Cost & Performance

### Token Consumption

- **~100 million tokens** for scanning 1,600-2,000 websites (URLs in urls.txt only)
- Recursive JS file discovery included in count

### Scan Duration

- 2,000 websites: Several hours (depends on JS file count)
- Recommended: Run on server with screen/tmux

### Recommended Configuration

| Resource    | Minimum           | Recommended        |
| ----------- | ----------------- | ------------------ |
| **CPU**     | 2 cores           | 4+ cores           |
| **RAM**     | 2GB               | 4GB+               |
| **Network** | Stable connection | High bandwidth     |
| **Storage** | 1GB               | 5GB+ (for results) |

---

## 🔧 Advanced Usage

### Whitelist Configuration

Prevent scanning of specific domains:

```bash
# config/whiteList.txt
google.com
facebook.com
analytics.example.com
```

---

## 🤝 Acknowledgments

Built with:
- [Playwright](https://playwright.dev/) - Browser automation
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP probing
- [NLTK](https://www.nltk.org/) - Natural language processing
- [阿里云](https://www.aliyun.com/) - AI model services

---

## 📧 Support & Feedback

- **Issues**: [GitHub Issues](https://github.com/hmx222/JScanner2/issues)
- **Technical Details**: [Article (Chinese)](https://xz.aliyun.com/news/91962)
- **Discussions**: [GitHub Discussions](https://github.com/hmx222/JScanner2/discussions)

---

**Made with ❤️ for the security community**
