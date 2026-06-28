
# JScanner2 - AI 驱动的 JavaScript 安全分析工具

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

---
[中文版](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md)
[English](https://github.com/hmx222/JScanner2/blob/master/README.md)


* 输入: [https://example.com](https://example.com)
* 输出:

  * 检测到敏感 API
  * 自动识别参数
  * AI 风险分析（例如：硬编码 Token → 可利用）

---


## 🚀 为什么选择 JScanner2

传统的 JavaScript 安全扫描工具存在明显的局限性：

* ❌ 只能提取 API 路径（缺乏参数感知能力）
* ❌ 需要手动 Fuzzing 才能发现漏洞
* ❌ 无法理解业务逻辑
* ❌ 硬编码的敏感信息缺乏利用上下文

### ✅ JScanner2 解决了什么问题

JScanner2 结合了 **AST（抽象语法树）解析 + AI 分析**，以实现真实环境下的漏洞发现：

#### 1️⃣ 智能参数发现

* 使用 AST 解析 JS 代码
* 提取 API 端点**和**参数
* AI 推断参数结构和含义

👉 告别盲目 Fuzzing

#### 2️⃣ 基于 AI 的硬编码敏感信息分析

* 检测 Token、密钥、凭证
* AI 解释**如何利用它们**

👉 不仅仅是检测，更提供利用指导

#### 3️⃣ 真实攻击场景

在真实的 SRC（安全响应中心）测试中：

* 单独的 API 看起来可能很安全
* **但是**当结合有效的参数时，就会暴露出漏洞

👉 JScanner2 弥补了这一鸿沟

---

# ⚡ 使用概览

---

## ⚡ 快速开始 

```bash
git clone https://github.com/hmx222/JScanner2.git

# [可选] 编辑 `run_scan.sh` 以配置 `FEISHU_WEBHOOK`。
# 将默认 URL 替换为您自己的飞书机器人 Webhook 地址。
vim run_scan.sh

# [必填] 必须在此文件中配置大模型的 API Key。
# 您也可以在此处配置飞书机器人 Token（可选）。
# 注意：如果不配置飞书 Token，报错信息和任务完成通知将无法回传到飞书，
# 导致您无法及时看到报错，也无法在任务结束后收到通知。
vim config/config.py

# [必填] 必须严格配置此 JSON 文件中的模型参数。
vim config/models_config.json

# [可选] 可根据自身需求自行配置扫描规则。
vim config/scanner_rules.py

# [可选] 配置白名单，设置哪些域名允许被爬虫抓取。
vim config/whiteList.txt

docker compose run --rm scanner run_scan.sh urls.txt
```



## 📊 输出结果

* API 端点
* 参数（自动生成）
* 敏感数据发现
* 利用建议（AI 生成）

👉 结果会被保存以供后续分析

---

## ⚠️ 免责声明

仅限授权的安全测试使用。

* 获取授权许可
* 遵守法律法规
* 严禁非法使用

---

## 🤝 致谢

* Playwright
* LinkFinder
* NLTK
* 阿里云

---

## 📧 问题反馈

[https://github.com/hmx222/JScanner2/issues](https://github.com/hmx222/JScanner2/issues)
```
