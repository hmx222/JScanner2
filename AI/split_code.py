import re


def has_valid_slash(content):
    """判断内容中是否存在至少一个/，其左侧或右侧有数字/字母"""
    for i, char in enumerate(content):
        if char == '/':
            # 检查左侧是否有数字/字母（i > 0表示不是第一个字符）
            left_valid = i > 0 and content[i - 1].isalnum()
            # 检查右侧是否有数字/字母（i < len-1表示不是最后一个字符）
            right_valid = i < len(content) - 1 and content[i + 1].isalnum()
            if left_valid or right_valid:
                return True
    return False


def extract_relevant_lines(input_str):
    BLACK_LIST = ('.png', '.css', '.jpeg', '.mp4', '.mp3', '.gif', '.ico',
                  '.ttf', '.svg', '.m4v', '.aac', '.woff', '.woff2',
                  '.eot', '.otf', '.apk', '.exe')

    # 正则元字符排除（过滤正则模式）
    REGEX_METACHARS = re.compile(r'[*+?^${}()|[\]\\]')

    relevant_lines = []
    for line in input_str.splitlines():
        line_trimmed = line.strip()
        if not line_trimmed or line_trimmed.startswith('//'):
            continue

        # 去除行内注释
        line_no_comment = re.split(r'(?<!:)//', line, 1)[0].rstrip()
        if not line_no_comment:
            continue

        # 过滤长行
        if len(line_no_comment) > 150:
            continue

        # 提取所有引号内容
        quoted_contents = re.findall(r'["\'](.*?)["\']', line_no_comment)
        if not quoted_contents:
            continue

        # 检查是否有符合条件的内容：
        # 1. 包含有效/（至少一个/的左或右有数字/字母）
        # 2. 不含正则元字符
        # 3. 不在黑名单
        valid = False
        for content in quoted_contents:
            if (
                    has_valid_slash(content)  # 核心判断：是否有有效/
                    and not REGEX_METACHARS.search(content)
                    and not content.lower().endswith(BLACK_LIST)
            ):
                valid = True
                break

        if valid:
            relevant_lines.append(' '.join(line_no_comment.split()))

    return "\n".join(relevant_lines)


if __name__ == "__main__":
    sample_js = """function test() {
    // 需要保留的行（/左右有字母）
    Yt = Vt.post("/u/msg/add-common-words", { needUrlEncoded: !0 });
    a.A.post("/discuss/hidden");
    var valid2 = '../data.json';
    var valid3 = 'abc/def';

    // 需要排除的行（/左右无数字/字母）
    t("div", { staticClass: "tag-item tw-truncate" }, [e._v(e._s(e.job.jobCityList.join("/")))]);
    var invalid = "a//b";  // 中间//的左右无字母
}"""

    result = extract_relevant_lines(sample_js)
    print("==== 提取结果 ====")
    print(result)
