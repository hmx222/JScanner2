import re

import jieba
from bs4 import BeautifulSoup
from simhash import Simhash


def extract_text(html_content):
    """提取HTML中的纯文本"""
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.get_text(separator=' ')


def extract_features(text):
    """提取中英文混合文本的特征词"""
    features = []
    pattern = re.compile(r'[\u4e00-\u9fa5]+|[a-zA-Z0-9]+')

    for match in pattern.finditer(text):
        word = match.group(0)
        if all('\u4e00' <= char <= '\u9fa5' for char in word):
            features.extend(jieba.cut(word))
        else:
            features.append(word.lower())

    # 过滤短词和停用词
    stopwords = {'的', '了', '在', '是', '我', '有', '和', '就', '不', '人', '都', '一', '一个', '上', '也', '很', '到',
                 '说', '要', '去', '你', '会', '着', '没有', '看', '好', '自己', '这'}
    return [word for word in features if len(word) > 1 and word not in stopwords]


def get_simhash(text):
    """生成文本的SimHash指纹"""
    features = extract_features(text)
    return Simhash(features).value


def similarity(simhash1, simhash2):
    """计算两个SimHash的相似度（0-1之间）"""
    x = (simhash1 ^ simhash2) & ((1 << 64) - 1)
    ans = 0
    while x:
        ans += 1
        x &= x - 1
    return 1 - ans / 64


def compare_html_similarity(html1, html2):
    """比较两个HTML页面的相似度"""
    text1 = extract_text(html1)
    text2 = extract_text(html2)

    simhash1 = get_simhash(text1)
    simhash2 = get_simhash(text2)

    return simhash1, simhash2

if __name__ == '__main__':
    html1 = """
    <html>
    <body>
        <h1>Welcome to Example Site</h1>
        <p>这是一个测试页面，用于演示文本相似度计算。</p>
        <div class="content">
            <p>The main content includes web parsing, feature extraction, and similarity comparison.</p>
        </div>
    </body>
    </html>
    """

    html2 = """
    <html>
    <body>
        <header><h1>欢迎访问示例网站</h1></header>
        <div class="main">
            <p>This is a test page to demonstrate text similarity calculation.</p>
            <section>
                <p>核心内容有网页解析、特征提取以及相似度比较。</p>
            </section>
        </div>
    </body>
    </html>
    """
    simhash1, simhash2 = compare_html_similarity(html1, html2)
    print(f"SimHash1: {simhash1.value}")
    print(f"SimHash2: {simhash2.value}")
    print(f"相似度: {similarity(simhash1, simhash2)}")
    print(simhash2.distance(simhash1))
