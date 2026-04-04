# JScanner2 - AI-Powered JavaScript Security Analysis Tool

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

---

## 🎬 Demo

![B0CIOkQJ_converted](https://github.com/user-attachments/assets/d9034311-8343-4c08-b298-6403b09b012f)


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

---

# ⚡ Usage Overview

> 🎯 Three usage levels depending on your needs:

* **Quick Scan** → No config, fast results
* **AI Scan (Recommended)** → Full capability
* **Automation Mode** → Batch + notification

---

## ⚡ Quick Start (No Configuration)

Run a basic scan without any configuration:

```bash
python main.py -u https://example.com -H 6
```

### Features:

* ✅ No API key required
* ✅ No Playwright required
* ✅ Fast execution

> 💡 Uses regex-based detection only (no AI)

---

## 🚀 AI-Powered Scan (Recommended)

Enable full functionality:

```bash
# install dependencies
pip install -r requirements.txt
playwright install
playwright install-deps
npm install prettier

# configure
vim config/config.py
# set: BASE_URL, API_KEY

# run(Recommended)
python main.py -u https://example.com -asia -fp -H 6
```

### Features:

* Intelligent parameter identification
* AI-based sensitive info detection
* Exploit suggestions

> 🔥 Recommended for real vulnerability discovery

---

## 🤖 Automation Mode (Batch + Notification)

Run large-scale scans with notification:

```bash
vim run_scan.sh
# configure FEISHU_WEBHOOK

echo urls.txt | ./run_scan.sh
```

### Features:

* Batch scanning
* Background execution (server)
* Feishu notification

> 💡 Ideal for VPS / long-running tasks

---

## 🛠️ Installation

### Requirements

* Python 3.9+

### Full Installation

```bash
pip install -r requirements.txt
playwright install-deps
playwright install
npm install prettier
```

---

## ⚙️ Configuration

Edit:

```bash
config/config.py
```

Modify:

* BASE_URL
* API_KEY
* Proxy (optional)
* FEISHU_WEBHOOK (optional)

---

## 🧠 Core Parameters

| Parameter | Description           |
| --------- | --------------------- |
| -asia     | AI-based analysis     |
| -asir     | Regex-based detection |
| -fp       | Parameter discovery   |
| -fs       | Fast scan             |
| -H        | Scan depth            |

---

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
* 讯飞星辰

---

## 📧 Feedback

[https://github.com/hmx222/JScanner2/issues](https://github.com/hmx222/JScanner2/issues)
