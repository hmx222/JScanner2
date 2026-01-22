
# JScanner2

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

**JScanner2** is a JavaScript sensitive information mining tool designed exclusively for **large-scale asset mapping**.

---

## 🚀 Core Features

- **🛡️ Memory Meltdown Protection**

- **🧠 Dual-Mode AI Engine**

- **💾 Persistent Deduplication**

- **🔍 Intelligent Data Cleansing**

---

## 🛠️ Quick Start

### 1. Installation

```Bash

git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install-deps
playwright install

# (Optional) Pull local AI model - Required only for local mode
ollama pull qwen2.5-coder:14b
```

### 2. Configuration (`config/config.py`)

All runtime parameters are managed in `config/config.py`, and the program automatically determines the running mode based on the configuration:

#### 🤖 AI Model Configuration (Choose One)

- **Mode A: Alibaba Cloud DashScope/Other Platforms (Recommended, Fast & High Precision)**

    - Fill in your `DASHSCOPE_API_KEY` in `config.py`.

    - The program will automatically detect the key and prioritize the cloud model (`qwen2.5-coder-14b-instruct`).

```Python

DASHSCOPE_API_KEY = "sk-xxxxxxxxxxxxxxxx" 
```

- **Mode B: Local Ollama (High Privacy, VRAM Required)**

    - Keep `DASHSCOPE_API_KEY` as an empty string `""`.

    - The program will automatically fall back to the local Ollama service.

    - Adjust `OLLAMA_MAX_GPU_MEMORY` according to your graphics card (default: "4GB").

#### 📨 Notification Configuration

- **Lark Notification**:

    - Configure `FEISHU_WEBHOOK`, and the tool will send notifications when **errors occur** or **all tasks are completed**.

```Python

FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/..."
```

### 3. Run (Recommended for Production)

**Do not run ** **`python main.py`** ** directly**. Use our encapsulated Shell script to activate the automatic meltdown and task relay features:

```Bash

# Method 1: Pipe input (Recommended)
echo urls.txt | ./run_scan.sh

# Method 2: File parameter
./run_scan.sh urls.txt
```

**Tip**: The program automatically monitors memory, processes overflow tasks, and merges the final Excel results without manual intervention.

### 4. Reset Tasks

If you need to scan a new batch of targets, **be sure to** execute the cleanup script to reset the deduplication records; otherwise, new tasks will be marked as "scanned" and skipped:

```Bash

./clean_scan.sh
```

---

## 📂 Result Output

Result files are automatically archived by **date** in the `Result/` directory:

- **Excel Report**: `Result/Result_Domain_2023xxxx.xlsx` (Contains all discovered URLs and hierarchical relationships, supports breakpoint resumption)

- **Sensitive Information**: `Result/sensitiveInfo.json` (Keys/Tokens/Secrets identified by AI auditing)

- **Runtime Logs**: `Log_Data/scan_run_log.log`

---

## ⚙️ Core Parameters (For Debugging)

If you need to debug the core script manually (without meltdown protection):

```Bash

python3 main.py -u https://example.com [options]
```

- `-o` / `--ollama`: Enable AI code auditing

- `-q`: Use Qwen model to extract sensitive information

- `-x`: Enable intelligent deduplication (Enabled by default)

- `-H 5`: Crawling depth (Default: 5)

- `-t 10`: Number of threads (Default: 10)

---

## ⚠️ Disclaimer

This tool is for **security research and authorized testing only**. Unauthorized penetration testing or illegal attacks are strictly prohibited. Users shall bear all legal consequences arising from the use of this tool.
