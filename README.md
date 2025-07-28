# 🛡️ JScanner2 - 递归式敏感信息扫描工具

> **升级重点**：新增扩散式扫描引擎、智能去重系统与动态加载支持

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-green)]()
[![Release](https://img.shields.io/badge/Release-Beta-orange)]()

## 📜 目录
- 核心功能  
- 新增特性  
- 安装指南  
- 使用指南  
- 智能去重系统  
- 最佳实践  
- 免责声明  
- 开发路线



## 🌟 核心功能
1. **递归路径探测**  
   - 自动解析网页源码发现JS文件 
   - 深度提取JS中的隐藏路径与接口（支持自定义状态码过滤）

2. **多维度扫描控制**  

   - 目录递减访问（`-l`参数控制遍历深度）
   - 可调扫描深度（`-H`参数，建议≤2）
   - 多URL批量扫描（`-b`文件输入）

3. **多种页面相似度检测**  

   - 使用SimHash配合DOM骨架去重
   - 使用SimHash配合jieba去重
   - 使用title，length去重

4. **页面重点信息标记**

   - 多维度评估页面可用点
   - 助力漏洞挖掘

---

## 🚀 新增特性
### 1. 智能去重系统
| 去重方式                | 适用场景                          | 参数开关          |
|-------------------------|---------------------------------|-------------------|
| DOM骨架SimHash (推荐)   | 同模板页面（如电商列表页）        | `-s <阈值>`       |
| 标题去重                | 同标题不同参数页                  | `-d`              |
| 返回值长度去重          | 静态资源重复                      | `-l`              |
| 文本相似度去重          | 内容农场文章                      | `-f <阈值>`       |

### 2. 采用PlayWright作为爬虫框架

- 弃用了DrissionPage，采用PlayWright异步请求
- 后续会合并master分支为Playwright版本

---

## ⚙️ 安装指南
```bash
# 克隆仓库（含beta/stable分支）
git clone https://github.com/hmx222/JScanner2.git 

# 安装依赖
cd JScanner2
pip install -r requirements.txt
```

> **环境要求**：Python 3.8+，Chromium内核浏览器

---

## 🔧 使用指南
### 命令行参数
| 参数 | 全称 | 说明 |
|------|------|------|
| `-u` | `--url` | 单个网站URL（需带http/https，例如：`https://example.com`）<br>*与`-b`参数必选其一* |
| `-b` | `--batch` | 批量扫描的URL文件绝对路径（文件内需每行一个URL）<br>*与`-u`参数必选其一* |
| `-H` | `--height` | 扫描深度（默认值：2，数值越大扫描范围越广，耗时越长） |
| `-t` | `--thread_num` | 并发线程数（默认值：10，可根据网络环境调整） |
| `-p` | `--proxy` | 代理服务器设置（格式：`http://127.0.0.1:12335` 或 `socks5://127.0.0.1:1080`） |
| `-v` | `--visible` | 显示浏览器窗口（默认：无头模式，不显示窗口；启用后可观察浏览器操作过程） |
| `-c` | `--headers` | 自定义请求头（格式示例：`'cookie':'session=123';'Referer':'https://example.com'`）<br>*注：User-Agent已默认随机生成，无需额外指定* |
| `-e` | `--excel` | 导出结果到Excel文件（需指定路径，例如：`./result.xlsx`） |
| `-d` | `--de_duplication_title` | 启用标题去重（默认关闭；启用后会过滤标题完全相同的页面） |
| `-s` | `--de_duplication_hash` | 启用DOM SimHash去重并设置阈值（格式：`-s 0.8`，默认关闭；阈值范围0.0-1.0，数值越小去重越严格） |
| `-l` | `--de_duplication_length` | 启用长度去重（默认关闭；启用后会过滤HTML长度完全相同的页面） |
| `-f` | `--de_duplication_similarity` | 启用文本相似度去重并设置阈值（格式：`-f 0.7`，默认关闭；阈值范围0.0-1.0，数值越小去重越严格） |
| `-g` | `--sensitiveInfo` | 主动寻找Javascript中的敏感信息 |


---

## 🧠 智能去重系统
### DOM骨架SimHash技术
```python
def extract_dom_skeleton(element):
    """ 提取标签层级结构（剔除动态内容） """
    skeleton = f"<{element.tag}>"
    for child in element:
        if not isinstance(child, str): 
            skeleton += extract_dom_skeleton(child)
    skeleton += f"</{element.tag}>"
    return skeleton
```
**处理效果**：  
```
https://help.aliyun.com/zh/rds/apsaradb-rds-for-mysql/?spm=a2c4g.11186623.nav-v2-dropdown-menu-3.d_main_0_7.e0f45630AW7XNc&scm=20140722.M_10247527._.V_1
与
https://market.aliyun.com/xinxuan/application/miniapps?spm=a2c4g.11186623.nav-v2-dropdown-menu-6.d_main_0_1.4c47293as877sK&scm=20140722.M_10215511._.V_1
→ 76%相似度 → 标记为重复页面 
```


### 多维度去重策略
1. **标题去重**：同域名下标题完全一致则去重
2. **长度去重**：响应体长度差值<5%视为重复
3. **文本相似度**：Jieba分词+SimHash计算（适合文章类）

---

## ⚡ 最佳实践

   ```bash
    # 不推荐
    python main.py -u "https://xxxxx.com" -H 3
   ```
   ```bash
   # 使用title与length去重
   python main.py -u "https://target.com" -H 3 -d -l
   ```
   ```bash
   # 平衡去重与效率（最最最推荐）
   python main.py -u "https://xxxx.com" -H 3 -d -s 0.8 -l -s -g 
   ```
   ```bash
   # 效率最慢（次之）
   python main.py -u "https://xxxx.com" -H 3 -d -s 0.8 -l -f 0.65 
   ```
   ```bash
   # 多URL扫描，建议在config/whiteList 添加白名单，让扫描更充分
   python main.py -b xxxx.txt -H 3 -d -s 0.8 -l -g
   ```

---

## ⚠️ 免责声明
> **重要**：本工具仅限**合法授权**的安全评估使用，禁止未授权扫描。使用者需自行承担法律责任，开发者不承担任何连带责任。

---

## 🛣️ 开发路线
- [ ] AI辅助页面价值分析（引入BERT辅助检测）
- [ ] jsmap自动下载
- [ ] 优化代码，减少性能开支
- [ ] Docker容器化部署支持 

---

## 📚 参考资源
1. 正则表达式库：https://github.com/GerbenJavado/LinkFinder 
2. 敏感信息规则：https://github.com/momosecurity/FindSomething
3. 使用问题反馈：https://github.com/hmx222/JScanner2/issues

---
