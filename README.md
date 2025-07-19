# JScanner2

JScanner2 是敏感信息扫描工具 JScanner 的升级版本，支持扩散式扫描、动态加载、批量扫描等功能。它能够通过正则表达式从网页源码和 JavaScript 文件中提取敏感信息，如身份证号、手机号、邮箱地址等，并可将结果输出到 Excel 文件中。


## 工具特性

- **扩散式扫描**：能够从初始 URL 开始，递归地扫描相关页面，扩大扫描范围。

- **动态加载**：支持动态加载内容，确保能够扫描到通过 JavaScript 动态生成的页面元素。

- **批量扫描**：可以同时对多个目标 URL 进行扫描，提高扫描效率。

- **自定义深度查找**：用户可以根据需要设置扫描的深度，控制扫描的范围。

- **白名单支持**：通过配置白名单文件，可以排除不需要扫描的 URL。

- **多线程处理**：采用多线程技术，加速扫描过程。

- **Excel 输出**：扫描结果可以方便地导出到 Excel 文件中，便于查看和分析。

- **灵活的参数配置**：支持代理设置、浏览器窗口显示控制、结果去重等多种参数配置，满足不同场景需求。

## 安装方法

1. 克隆项目仓库：

```
git clone https://github.com/hmx222/JScanner2.git
```

1. 注意此工具有 beta 版本与 stable 版本。克隆完成后，进入项目目录：

```
cd JScanner2
```

1. 安装依赖：

```
pip install -r requirements.txt
```

## 使用方法

### 命令行参数说明

| 参数 | 全称                        | 说明                                                         |
| ---- | --------------------------- | ------------------------------------------------------------ |
| -u   | --url                       | 输入带有 http/https 的单个网站 URL（如：https://example.com），与-b参数必选其一 |
| -b   | --batch                     | 批量扫描的 URL 文件绝对路径（每行一个 URL），与-u参数必选其一 |
| -H   | --height                    | 扫描深度（默认：2）                                          |
| -t   | --thread_num                | 并发线程数（默认：10）                                       |
| -p   | --proxy                     | 代理服务器（格式：[http://127.0.0.1](http://127.0.0.1:12335)[:1233](http://127.0.0.1:12335)[5](http://127.0.0.1:12335) 或 socks5://127.0.0.1:1080） |
| -v   | --visible                   | 显示浏览器窗口（默认：无头模式，不显示窗口）                 |
| -e   | --excel                     | 导出结果到 Excel 文件（如：./result.xlsx）                   |
| -d   | --de_duplication_title      | 对于重复的结果，是否使用对 title 的去重（默认：True）        |
| -l   | --de_duplication_length     | 对于重复的结果，是否使用对 length 的去重（默认：True）       |
| -f   | --de_duplication_similarity | 对于重复的结果，使用文本相似度去重的阈值（默认：0.65）       |
| -s   | --de_duplication_hash       | 对于重复的结果，是否使用对 普通hash 的去重（默认：True）     |



### 示例

#### 常用的方法

对于单文件：

```
python main.py -u "http://example.com" -H 3 -t 10 -p 127.0.0.1:12334 -d -l -s
```

对于多文件：

```
python main.py -b "./" -H 3 -t 5 -p 127.0.0.1:12334 -d -l -s
```

对于需要高价值的页面：

```
python main.py -u "http://example.com" -H 3 -t 10 -p 127.0.0.1:12334 -d -l -f 0.7 -s
```

最后只需要查看**result目录下的两个json**即可。
结果预览：

<img width="1770" height="1281" alt="1752678149504" src="https://github.com/user-attachments/assets/cca2e742-a084-4f56-b077-54ea2b6641f1" />


#### 单 URL 扫描

```
python main.py -u "http://example.com" -H 3
```

该命令表示对http://example.com这个 URL 进行扫描，扫描深度设置为 3。

#### 批量扫描

```
python main.py -b "urls.txt" -t 15
```

此命令会批量扫描urls.txt文件中的所有 URL，并发线程数设置为 15。

#### 带代理扫描并导出结果

```
python main.py -u "https://example.com" -p "http://127.0.0.1:12335" -e "output.xlsx"
```

该命令以http://127.0.0.1:12335作为代理服务器，对https://example.com进行扫描，并将结果导出到output.xlsx文件中。

#### 显示浏览器窗口扫描

```
python main.py -u "http://example.com" -v
```

执行该命令会在扫描时显示浏览器窗口，默认情况下为无头模式不显示窗口。

#### 去重

为什么要进行去重？

相似的页面太多，对于SRC挖掘来说，以下的两个页面几乎相似：

- https://www.aliyun.com/benefit?scm=20140722.M_10776205._.V_1
- https://www.aliyun.com/activity/superproducts/discount?scm=20140722.M_10798717._.V_1

对于漏洞挖掘来将，实在是没有必要进行两个页面都进行分析，对于代码来将，识别页面有没有用便是难题，一个页面到底有没有价值去进行细致的测试，倘若我们逐个查看，便是特别大的工作量，特别是资产量特别大的时候，便更加消耗时间，于是我采用了下面的几种方法来进行去重，可以自行选择.

##### Hash去重

取出每个前端代码的前400位数，计算hash。

##### 标题去重

防止重复标题的出现，检查并添加标题，且标题一样的前提是域名一样

##### 返回值长度去重

按照返回值长度进行去重。

##### 文本相似度检测

使用bs4去除标签与simhash计算求汉明距离



## 配置说明

- **白名单文件**：config/whiteList 文件中放置的请求的范围，防止误伤其他网站。（此处最好是直接使用测绘引擎等导出excel表格后，可以将子域名列信息填入）

- **输出目录**：所有的输出信息都位于 output 目录下，扫描结果会以 JSON 和 Excel 文件的形式保存。

- **下载文件目录**：download_files 目录下存放下载的文件。

## 注意事项

- 请确保在合法合规的前提下使用本工具，避免对未经授权的网站进行扫描。

- 扫描过程可能会消耗较多的系统资源和网络带宽，请根据实际情况合理设置扫描参数。

- 使用代理时，需确保代理服务器可用，否则可能导致扫描失败。

- 批量扫描时，URL 文件需保证每行一个 URL，且格式正确。

## 后续计划

- 有价值页面的tag标记
- 网页截图后，让ai进行判断


## 敏感信息正则来源

- 敏感信息的正则表达式部分来自于： https://github.com/momosecurity/FindSomething。

- 部分正则表达式来自于：https://github.com/GerbenJavado/LinkFinder

## 写于

2024.12.28
