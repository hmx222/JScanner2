# JScanner2 - AI-Powered JavaScript Security Analysis Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

---
[中文版](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md)
[English](https://github.com/hmx222/JScanner2/blob/master/README.md)


* Input: [https://example.com](https://example.com)
* Output:

  * Sensitive API detected
  * Parameters auto-identified
  * AI risk analysis (e.g. HARD-CODED TOKEN → exploitable)

---


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
git clone https://github.com/hmx222/JScanner2.git

# [Optional] Edit `run_scan.sh` to configure the `FEISHU_WEBHOOK`. 
# Replace the default URL with your own Feishu (Lark) bot webhook.
vim run_scan.sh

# [REQUIRED] You must configure the LLM API Key in this file. 
# You can also configure the Feishu bot token here (optional). 
# Note: If the Feishu token is not set, error messages and task completion notifications 
# will not be pushed to Feishu. You won't receive timely alerts or know when the task finishes.
vim config/config.py

# [REQUIRED] Strictly configure the model parameters in this JSON file.
vim config/models_config.json

# [Optional] You can customize the scanner rules according to your own needs.
vim config/scanner_rules.py

# [Optional] Configure the whitelist. Add the specific domains that are allowed to be crawled by the spider.
vim config/whiteList.txt

docker compose run --rm scanner run_scan.sh urls.txt
```



## 📊 Output

* API endpoints
* Parameters (auto-generated)
* Sensitive data findings
* Exploit suggestions (AI)

👉 Results are stored for analysis

---

## ⚠️ Disclaimer

For authorized security testing only.

* Obtain permission
* Follow laws
* No illegal usage

---

## 🤝 Acknowledgements

* Playwright
* LinkFinder
* NLTK
* 阿里云
---

## 📧 Feedback

[https://github.com/hmx222/JScanner2/issues](https://github.com/hmx222/JScanner2/issues)
