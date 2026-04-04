# JScanner2 - AI 驱动的 JavaScript 安全分析工具

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)

---

## 🎬 效果演示

![B0CIOkQJ_converted](https://github.com/user-attachments/assets/d9034311-8343-4c08-b298-6403b09b012f)

* 输入：[https://example.com](https://example.com)
* 输出：
  * 敏感 API 自动检测
  * 参数智能识别
  * AI 风险分析（例如：硬编码 Token → 可利用）

---

## 🚀 为什么选择 JScanner2

传统 JavaScript 安全扫描工具存在明显局限：

* ❌ 仅提取 API 路径（无参数感知能力）
* ❌ 需手动模糊测试才能发现漏洞
* ❌ 无法理解业务逻辑
* ❌ 硬编码敏感信息缺乏利用上下文

### ✅ JScanner2 的解决方案

JScanner2 融合 **AST 解析 + AI 语义分析**，实现真实场景下的漏洞挖掘：

#### 1️⃣ 智能参数发现

* 基于 AST 解析 JS 代码
* 同时提取 API 端点 **与** 参数
* AI 推理参数结构与业务含义

👉 告别盲测，精准打击

#### 2️⃣ AI 驱动的硬编码敏感信息分析

* 检测 Token、密钥、凭证等硬编码内容
* AI 自动分析 **如何利用这些敏感信息**

👉 不仅是发现，更是利用指引

#### 3️⃣ 贴合真实攻击场景

在实际 SRC 测试中：

* 单独看 API 可能看似安全
* 但 **结合有效参数后** 可能形成高危漏洞

👉 JScanner2 正是为弥合这一差距而生

---

# ⚡ 使用概览

> 🎯 按需求选择三种使用层级：

* **快速扫描** → 无需配置，快速出结果
* **AI 扫描（推荐）** → 启用全部能力
* **自动化模式** → 批量任务 + 通知

---

## ⚡ 快速开始（无需配置）

无需任何配置，直接运行基础扫描：

```bash
python main.py -u https://example.com -H 6
```

### 功能特点：

* ✅ 无需 API Key
* ✅ 执行速度快

> 💡 仅使用正则匹配检测（不调用 AI）

---

## 🚀 AI 智能扫描（推荐）

启用完整功能进行深度分析：

```bash
# 安装依赖
pip install -r requirements.txt
playwright install
playwright install-deps
npm install prettier

# 配置核心参数
vim config/config.py
# 设置：BASE_URL, API_KEY

# 运行扫描（推荐）
python main.py -u https://example.com -asia -fp -H 6
```

### 功能特点：

* 智能参数识别与结构推断
* AI 分析硬编码敏感信息
* 自动生成漏洞利用建议

> 🔥 推荐用于真实漏洞挖掘场景

---

## 🤖 自动化模式（批量扫描 + 通知）

执行大规模扫描并接收结果通知：

```bash
# 配置脚本
vim run_scan.sh
# 设置 FEISHU_WEBHOOK

# 执行批量任务
echo urls.txt | ./run_scan.sh
```

### 功能特点：

* 支持批量目标扫描
* 后台运行（适合服务器部署）
* 飞书机器人实时通知

> 💡 适合 VPS 长期任务或自动化巡检

---

## 🛠️ 安装指南

### 环境要求

* Python 3.9+

### 完整安装

```bash
pip install -r requirements.txt
playwright install-deps
playwright install
npm install prettier
```

---

## ⚙️ 配置说明

编辑配置文件：

```bash
config/config.py
```

修改以下关键项：

* `BASE_URL`：大模型服务地址
* `API_KEY`：API 认证密钥
* `Proxy`：代理配置（可选）
* `FEISHU_WEBHOOK`：飞书通知地址（可选）

---

## 🧠 核心参数速查

| 参数 | 功能说明 |
|------|----------|
| -asia | 启用 AI 智能分析 |
| -asir | 启用正则匹配检测 |
| -fp | 自动解析 API 参数 |
| -fs | 启用快速扫描模式 |
| -H | 设置扫描深度 |

---

## 📊 输出结果

* 提取的 API 端点列表
* 自动推断的参数结构
* 硬编码敏感信息发现
* AI 生成的漏洞利用建议

👉 所有结果自动入库，支持后续分析与复现

---

## ⚠️ 免责声明

本工具仅限授权的安全测试使用。

* 使用前请获得明确书面授权
* 遵守相关法律法规及目标网站服务条款
* 禁止将分析结果用于非法用途

---

## 🤝 致谢

* [Playwright](https://playwright.dev) - 浏览器自动化框架
* [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - JS 链路分析
* [NLTK](https://www.nltk.org) - 自然语言处理
* 讯飞星辰 - 大模型支持

---

## 📧 反馈与支持

如遇问题或有任何建议，欢迎提交 Issue：

[https://github.com/hmx222/JScanner2/issues](https://github.com/hmx222/JScanner2/issues)
