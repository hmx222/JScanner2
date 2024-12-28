### JScanner2

#### 为什么要写这款工具？

在2022年，我测试了无数网站，但是某些网站无论如何都不能搞定它，看了好多别人的实战思路，我总结出来了一点，那些大佬们总是会在前期在js文件当中收集信息，收集到别人在fofa还是鹰图上面探测不到了信息。于是我便想写一款工具来帮助自己在前期更好的探测。

部分正则表达式来自于：https://github.com/GerbenJavado/LinkFinder

#### 这款这款工具能够干什么？

- 探测网页源代码，发现js文件
- 探测js文件，发现路径
- 支持自定义状态码
- 支持多URL请求
- 支持深度查找
- 支持对标题与返回值长度的输出
- 支持多URL的查找
- 敏感信息的查找

##### 推荐用法
```shell
python main.py -u "http://example.com" -H 5 
```
##### 推荐用法2
批量扫描
```shell
python main.py -u "http://example.com" -H 5 -b files.txt
```

#### 这款工具怎么使用？

```shell
python main.py -h
```

你可以看到具体的帮助文档

##### 默认情况下：

```shell
python main.py -u "https://example.com/xxxxx"
```

##### 设置header请求头

```shell
python main.py -u "https://example.com/xxxxx" -r "{'cookie':'xxxx','user-Agent':'xxxx','xxxx':'xxxx'}"
```
若不设置则会使用默认的请求头

##### 设置查找深度

```shell
python main.py -u "https://example.com/xxxxx" -H 2
```


##### 设置您不想要的状态码

```shell
python main.py -u "https://example.com/xxxxx" -B "(404,502)"
```
##### 输出为Excel表格的形式
```shell
python main.py -u "https://example.com/xxxxx" -o excel
```

.........

该工具时Jscanner的升级版本，后续新的功能会在此进行发布

写于2024.12.28
