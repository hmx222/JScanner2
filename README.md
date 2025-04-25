### JScanner2

敏感信息的正则表达式来自于 **findsomething**
部分正则表达式来自于：https://github.com/GerbenJavado/LinkFinder
是上一代工具的升级版本：https://github.com/hmx222/JScanner

#### 安装方法

```
git clone https://github.com/hmx222/JScanner2.git
```
（注意：此工具有beta版本与stable版本）
然后打开目录
```
pip install -r requirements.txt
```

#### 这款这款工具能够干什么？

- 支持扩散式扫描
- 支持动态加载
- 支持批量扫描
- 支持自定义深度查找
- 支持白名单
- 支持多线程
- 可以输出内容到excel当中

#### 注意：
whiteList是白名单文件，里面存放的是需要排除的url，位于config目录下。
所有的输出信息都位于output目录下。
download_files目录下存放的是下载的文件。


##### 推荐用法1
```shell
python main.py -u "http://example.com" -H 3 
```
##### 推荐用法2
批量扫描
```shell
python main.py -u "http://example.com" -H 3 -b files.txt
```
##### 推荐用法3
输出到excel文件
```shell
python main.py -u "https://example.com -H 3 -e "output.xlsx"
```

输出到表格的形式
![image](https://github.com/user-attachments/assets/71aa32c2-6deb-433d-b8fb-817ec1c5e0f3)
可以按照对每个端点进行排除，方便进行统计分析，方便构造更多的api。

#### Coming
- Web2Vec 实现API预测
- 更加精美的报告输出

#### TODO
- docker版本
- 支持代理网络
- 尝试融入参数爆破

该工具时Jscanner的升级版本，后续新的功能会在此进行发布

写于2024.12.28
