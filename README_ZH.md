# JScanner2 - AI驱动的JavaScript安全分析工具

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0-brightgreen)
![AI-Powered](https://img.shields.io/badge/AI-Powered-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

[中文版](https://github.com/hmx222/JScanner2/blob/master/README_ZH.md) | [English](https://github.com/hmx222/JScanner2/blob/master/README.md)

---

## 🚀 快速开始

### 环境要求

- Docker & Docker Compose
- AI模型API访问权限（推荐：**Qwen 3.5-flash**）
- 推荐配置：**4核CPU + 4GB内存**

### 安装与使用

```bash
# 1. 克隆项目
git clone https://github.com/hmx222/JScanner2.git
cd JScanner2

# 2. 初始化配置
vim setup.sh  # 配置AI API密钥等
docker compose run --rm scanner /app/setup.sh

# 3. 准备目标URL列表
# 必需：将需要扫描的URL添加到urls.txt中

# 4. 添加白名单
# 可选：将白名单域名添加到config/whiteList.txt中

# 5. 开始扫描
docker compose run --rm scanner /app/run_scan.sh urls.txt
```

---

##  概述

**JScanner2** 是一款结合 **AST（抽象语法树）解析** 与 **AI大语言模型** 的智能化JavaScript安全扫描工具，用于发现JavaScript文件中的敏感信息和未授权访问漏洞。

与传统的基于正则表达式的工具不同，JScanner2能够理解代码语义，自动提取API参数，并提供AI驱动的漏洞利用指导。

### ✨ 核心特性

- 🔍 **智能参数发现** - 基于AST提取API端点及参数
- 🤖 **AI驱动分析** - 上下文感知的硬编码密钥检测，附带利用建议
- 🔄 **断点续扫** - 支持暂停/恢复扫描任务

---

## 💡 为什么选择JScanner2

###  传统工具的局限性

传统的JavaScript扫描工具（findsomething、JSFinder等）依赖 **正则表达式匹配**，存在以下问题：

1. **仅能获取API路径** - 无法提取触发漏洞所需的参数
2. **误报率高** - 正则无法理解上下文（例如：`s=qcfvg28@4a`）
3. **需要大量人工分析** - 每个发现都需要人工验证
4. **缺乏业务逻辑理解** - 无法区分安全和可 exploited 的密钥

---

## 📊 结果分析

扫描结果以SQLite数据库形式存储在 `Result/` 目录中。

## 📈 实战成果

对 **29个国内SRC**（安全应急响应中心）的部分网站进行测试，成果如下：

| 漏洞等级 | 数量 |
| -------- | ---- |
| 🔴 **高危** | 10   |
|  **中危** | 4    |
| 🟢 **低危** | 1    |

**说明：**
- ✅ 已去重（不包含重复漏洞）
- ✅ WAF检测率低（不发起攻击性payload）
- ✅ 适合攻防演练场景使用
- ✅ 仅包含独立运营的SRC（不包括公益SRC）

---

## 💰 成本与性能

### Token消耗

- 扫描 **1,600-2,000个网站** 约需 **1亿tokens**（仅指urls.txt中的URL数量）
- 包含递归JS文件发现

### 扫描时长

- 2,000个网站：数小时（取决于JS文件数量）
- 建议使用服务器配合screen/tmux运行

### 推荐配置

| 资源 | 最低配置 | 推荐配置 |
| ---- | -------- | -------- |
| **CPU** | 2核 | 4核及以上 |
| **内存** | 2GB | 4GB及以上 |
| **网络** | 稳定连接 | 高带宽 |
| **存储** | 1GB | 5GB及以上（用于存储结果） |

---

##  高级用法

### 白名单配置

防止扫描特定域名：

```bash
# config/whiteList.txt
google.com
facebook.com
analytics.example.com
```

---

## 🤝 致谢

本项目使用以下技术构建：
- [Playwright](https://playwright.dev/) - 浏览器自动化
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP探测
- [NLTK](https://www.nltk.org/) - 自然语言处理
- [阿里云](https://www.aliyun.com/) - AI模型服务

---

##  支持与反馈

- **问题反馈**: [GitHub Issues](https://github.com/hmx222/JScanner2/issues)
- **技术文章**: [中文技术文章](https://xz.aliyun.com/news/91962)
- **讨论区**: [GitHub Discussions](https://github.com/hmx222/JScanner2/discussions)

---

**为安全社区用心制作 ❤️**
