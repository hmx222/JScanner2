import tldextract
from urllib.parse import urlparse

def get_root_domain(url):
    """
    get root domain
    """

    parsed_url = urlparse(url)
    full_domain = parsed_url.netloc
    extracted = tldextract.extract(full_domain)
    root_domain = f"{extracted.domain}.{extracted.suffix}"
    return root_domain

# 1. 读取并处理URL列表（去重）
with open("../config/urllists", "r") as f:
    # 读取后去除换行符，再去重（避免因换行符导致的重复URL）
    urls = [url.strip() for url in f.readlines() if url.strip()]
    unique_urls = list(set(urls))  # 对URL去重

# 2. 读取已存在的根域名（避免与历史内容重复）
existing_domains = set()
try:
    with open("../config/root_domains", "r") as f:
        # 读取已有域名并去重（strip()避免空行和空格问题）
        existing_domains = {line.strip() for line in f if line.strip()}
except FileNotFoundError:
    # 如果文件不存在，初始化空集合
    pass

# 3. 提取新的根域名并合并去重
for url in unique_urls:
    try:
        root_domain = get_root_domain(url)
        if root_domain:  # 确保提取到有效域名
            existing_domains.add(root_domain)
    except Exception as e:
        print(f"处理URL {url} 时出错: {e}")  # 捕获异常，避免单个URL处理失败中断整体流程

# 4. 将去重后的所有根域名写入文件（覆盖原文件，确保无重复）
with open("../config/root_domains", "w") as f:
    # 按字母排序后写入（可选，方便查看）
    for domain in sorted(existing_domains):
        f.write(domain + "\n")

print(f"处理完成，共写入 {len(existing_domains)} 个不重复的根域名")

