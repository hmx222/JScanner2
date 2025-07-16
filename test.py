import re
import jieba
import requests
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
    return Simhash(features)


def similarity(simhash1, simhash2):
    """计算两个SimHash的相似度（0-1之间）"""
    distance = simhash1.distance(simhash2)
    return (64 - distance) / 64


def compare_html_similarity(html1, html2):
    """比较两个HTML页面的相似度"""
    text1 = extract_text(html1)
    text2 = extract_text(html2)

    simhash1 = get_simhash(text1)
    simhash2 = get_simhash(text2)

    sim = similarity(simhash1, simhash2)
    return {
        'text1_length': len(text1),
        'text2_length': len(text2),
        'similarity': sim,
        'is_similar': sim > 0.6  # 中英文混合文本的阈值建议
    }



if __name__ == '__main__':
    h1 = requests.get("https://www.xiaohongshu.com/explore?language=zh-CN",proxies={"http":"127.0.0.1:12334","https":"127.0.0.1:12334"}).text
    h2 = requests.get("https://www.xiaohongshu.com/explore?channel_id=homefeed.fashion_v3",proxies={"http":"127.0.0.1:12334","https":"127.0.0.1:12334"}).text

    # print("直接计算",html_similarity(h1,h2))
    # print("dom:",dom_similarity(h1,h2))
    # print("jaccard:",jaccard_similarity(h1,h2))
    # hash1 = Simhash(h1)
    # hash2 = Simhash(h2)
    # distance = hash1.distance(hash2)  # 距离越小越相似
    # print("simhash:",1 - distance / 64)

    # similarity = html_similarity(h1, h2)
    # print("相似度:", similarity)

    # 测试
    # text1 = "苹果是一种水果，富含维生素C"
    # text2 = "苹果公司生产iPhone，是一种科技产品"
    # hash1 = simhash(h1)
    #hash2 = simhash(h2)
    #
    # dist = sum(1 for a, b in zip(hash1, hash2) if a != b)
    # print(f"文本1指纹: {hash1}\n文本2指纹: {hash2}")
    # print(f"汉明距离: {dist}, 相似度: {1 - dist / 64:.2f}")

    # 模拟中英文混合的HTML页面
    result = compare_html_similarity(h1, h2)
    print(f"相似度: {result['similarity']:.2%}")
    print(f"是否相似: {result['is_similar']}")