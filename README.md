# JScanner2 - AI-Powered JavaScript Security Analysis Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)


[中文版](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md)
[English](https://github.com/hmx222/JScanner2/blob/master/README.md)


* Input: [https://example.com](https://example.com)
* Output:

  * Sensitive API detected
  * Parameters auto-identified
  * AI risk analysis (e.g. HARD-CODED TOKEN → exploitable)




## 🚀 Why JScanner2

Traditional JavaScript security scanning tools have clear limitations:

* ❌ Only extract API paths (no parameter awareness)
* ❌ Require manual fuzzing to find vulnerabilities
* ❌ Cannot understand business logic
* ❌ Hardcoded secrets lack exploit context

### ✅ What JScanner2 Solves

JScanner2 combines **AST parsing + AI analysis** to enable real-world vulnerability discovery:

#### 1️⃣ Intelligent Parameter Discovery

* Parse JS using AST
* Extract API endpoints AND parameters
* AI infers parameter structure and meaning

👉 No more blind fuzzing

#### 2️⃣ AI-Based Hardcoded Secret Analysis

* Detect tokens, keys, credentials
* AI explains **how to exploit them**

👉 Not just detection, but exploitation guidance

#### 3️⃣ Real Attack Scenarios

In real-world SRC testing:

* APIs alone may seem safe
* BUT become vulnerable when combined with valid parameters

👉 JScanner2 bridges this gap



# ⚡ Usage Overview

## ⚡ Start 

```bash
# 1. 克隆项目
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 2. 初始化配置
vim setup.sh
docker compose run --rm scanner /app/setup.sh

# 3. 准备目标URL列表
# 将您需要扫描的url，放入urls.txt（必须）
# 将您的白名单域，放入config/whiteList.txt（可选）

# 4. 开始扫描
docker compose run --rm scanner /app/run_scan.sh urls.txt
```



## 📊 Output

* API endpoints
* Parameters (auto-generated)
* Sensitive data findings
* Exploit suggestions (AI)

👉 Results are stored for analysis



## ⚠️ Disclaimer

For authorized security testing only.

* Obtain permission
* Follow laws
* No illegal usage



## 🤝 Acknowledgements

* Playwright
* LinkFinder
* NLTK
* 阿里云


## 📧 Feedback

[https://github.com/hmx222/JScanner2/issues](https://github.com/hmx222/JScanner2/issues)
