import re


def check_valid_page(source):
    """
    检查页面是否有高价值的利用点，仅返回匹配到的风险标签
    """
    # 定义关键词分类字典
    keyword_categories = {
        '疑似可登录': [
            "登录", "login", "账号登录", "密码登录", "手机登录", "邮箱登录",
            "验证码登录", "扫码登录", "第三方登录", "微信登录", "QQ登录", "微博登录",
            "记住我", "记住登录状态", "自动登录", "保持登录", "切换账号", "退出登录",
            "请先登录", "未登录", "登录失效", "登录超时", "会话过期", "重新登录"
        ],
        '疑似可注册': [
            "注册", "新用户注册", "账号注册", "创建账号", "申请账号", "注册账号",
            "同意协议", "用户协议", "隐私政策", "手机号注册", "邮箱注册", "邀请注册",
            "注册成功", "注册失败", "账号已存在", "手机号已注册", "邮箱已被使用"
        ],
        '疑似存在短信验证码': [
            "验证码", "短信验证码", "获取验证码", "发送验证码",
            "语音验证码",  "重新获取", "验证码过期", "验证码错误", "输入验证码",
            "验证手机", "验证邮箱", "身份验证", "安全验证", "二次验证"
        ],
        '疑似可重置密码': [
            "忘记密码", "找回密码", "重置密码", "密码重置", "修改密码", "更换密码",
            "通过手机找回", "通过邮箱找回", "安全问题", "找回链接", "重置链接",
            "旧密码", "新密码", "确认密码", "密码强度", "密码格式", "密码要求"
        ],
        # '疑似存在超管权限': [
        #     "管理员", "admin", "后台", "后台登录", "管理中心", "权限管理", "角色管理",
        #     "超级管理员", "普通用户", "权限不足", "无访问权限",
        #     "批量操作", "导入", "导出", "备份", "恢复",
        #     "上传", "上传文件", "上传图片", "仅自己可见"
        # ],
        # '疑似存在流程越权': [
        #     "下一步", "上一步", "完成", "返回", "确认提交",
        #     "提交订单", "确认订单", "取消订单", "支付", "退款",
        #     "优惠券", "折扣", "积分", "余额",
        #     "操作成功", "操作失败", "提交成功", "提交失败", "请填写", "输入错误"
        # ], AI 写的关键词太水了趴
        '可以利用的HTML tag:': [
            "<form", "</form>"
            "<input","<textarea",
            "<select", "<option", "<button",
        ]
    }

    # 编译正则表达式
    compiled_patterns = {}
    for category, keywords in keyword_categories.items():
        pattern = r'(?i)(' + '|'.join(re.escape(kw) for kw in keywords) + ')'
        compiled_patterns[category] = re.compile(pattern)

    # 收集匹配到的风险标签（去重）
    risk_tags = set()

    # 检查每个类别
    for category, pattern in compiled_patterns.items():
        if pattern.search(source):
            risk_tags.add(category)

    # 检查表单详情（如果有表单标签）
    if 'html_form' in risk_tags:
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        if form_pattern.search(source):
            risk_tags.add('html_form_detail')

    # 转换为列表并返回
    return list(risk_tags)
