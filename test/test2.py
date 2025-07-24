import requests
from lxml import etree
from lxml.etree import _Element
from simhash import Simhash


def extract_dom_skeleton(element: _Element) -> str:
    """抽取DOM骨架（保留标签和层级，剔除动态内容）"""
    # 1. 处理当前节点：只保留标签名，剔除所有属性值
    skeleton = f"<{element.tag}>"  # 如 <div>（剔除class、id等属性）

    # 2. 递归处理子节点（保留层级关系）
    for child in element:
        # 跳过文本节点（动态内容，如商品描述、用户评论）
        if child.tag is etree.Comment:  # 跳过注释
            continue
        if isinstance(child, str):  # 跳过文本
            continue
        # 递归生成子节点骨架
        skeleton += extract_dom_skeleton(child)

    # 3. 闭合标签（保持层级完整性）
    skeleton += f"</{element.tag}>"
    return skeleton


# 示例：从HTML中提取骨架
def get_skeleton_from_html(html: str) -> str:
    try:
        print("length: ", len(html))
        tree = etree.HTML(html)
        # 以<body>为根节点（忽略<head>中可能的动态脚本）
        body = tree.xpath("//body")[0]
        return extract_dom_skeleton(body)
    except Exception:
        print("出错了")


def get_simhash(text):
    """生成文本的SimHash指纹"""
    return Simhash(text)

def similarity(simhash1, simhash2):
    """计算两个SimHash的相似度（0-1之间）"""
    distance = simhash1.distance(simhash2)
    return (64 - distance) / 64

if __name__ == "__main__":
    html = requests.get("https://market.aliyun.com/xinxuan/application/miniapps?spm=a2c4g.11186623.nav-v2-dropdown-menu-6.d_main_0_1.4c47293as877sK&scm=20140722.M_10215511._.V_1").text
    html2 = requests.get("https://help.aliyun.com/zh/rds/apsaradb-rds-for-mysql/?spm=a2c4g.11186623.nav-v2-dropdown-menu-3.d_main_0_7.e0f45630AW7XNc&scm=20140722.M_10247527._.V_1").text
    s1 = get_skeleton_from_html(html)
    s2 = get_skeleton_from_html(html2)
    g1 = get_simhash(s1)
    g2 = get_simhash(s2)
    print(similarity(g1, g2))
    # print(s1)
    #print(html2)
