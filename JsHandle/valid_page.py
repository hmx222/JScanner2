import re


def check_valid_page(url, source):
    """
    检查页面是否有高价值的利用点
    :param url: 页面URL
    :param source: 页面源代码
    :return: 匹配结果列表，每个结果包含类别、匹配关键词、位置和匹配文本
    """
    # 定义关键词分类字典（保留原有分类）
    keyword_categories = {
        'auth_login': [
            "登录", "login", "账号登录", "密码登录", "手机登录", "邮箱登录",
            "验证码登录", "扫码登录", "第三方登录", "微信登录", "QQ登录", "微博登录",
            "记住我", "记住登录状态", "自动登录", "保持登录", "切换账号", "退出登录",
            "请先登录", "未登录", "登录失效", "登录超时", "会话过期", "重新登录"
        ],
        'register': [
            "注册", "新用户注册", "账号注册", "创建账号", "申请账号", "注册账号",
            "同意协议", "用户协议", "隐私政策", "手机号注册", "邮箱注册", "邀请注册",
            "注册成功", "注册失败", "账号已存在", "手机号已注册", "邮箱已被使用"
        ],
        'verification': [
            "验证码", "短信验证码", "获取验证码", "发送验证码", "图形验证码",
            "语音验证码", "滑块验证", "拼图验证", "人机验证", "点击验证",
            "刷新验证码", "重新获取", "验证码过期", "验证码错误", "输入验证码",
            "验证手机", "验证邮箱", "身份验证", "安全验证", "二次验证"
        ],
        'password_reset': [
            "忘记密码", "找回密码", "重置密码", "密码重置", "修改密码", "更换密码",
            "通过手机找回", "通过邮箱找回", "安全问题", "找回链接", "重置链接",
            "旧密码", "新密码", "确认密码", "密码强度", "密码格式", "密码要求"
        ],
        'user_info': [
            "个人中心", "我的资料", "用户信息", "基本信息", "个人资料", "账号信息",
            "修改资料", "编辑资料", "绑定手机", "更换手机", "解绑手机", "绑定邮箱",
            "实名认证", "身份信息", "性别", "生日", "地址", "联系方式",
            "个人信息未完善", "请完成实名认证", "信息已保存", "信息修改成功"
        ],
        'sensitive_operation': [
            "管理员", "admin", "后台", "后台登录", "管理中心", "权限管理", "角色管理",
            "超级管理员", "普通用户", "用户组", "权限不足", "无访问权限",
            "删除", "删除账号", "删除信息", "编辑", "修改", "新增", "添加", "提交",
            "确认", "取消", "批量操作", "导入", "导出", "备份", "恢复",
            "查看", "详情", "预览", "下载", "上传", "上传文件", "上传图片", "仅自己可见"
        ],
        'business_flow': [
            "下一步", "上一步", "完成", "返回", "确认提交", "步骤1", "步骤2", "流程",
            "提交订单", "确认订单", "取消订单", "支付", "退款", "金额", "数量",
            "优惠券", "折扣", "积分", "余额",
            "操作成功", "操作失败", "提交成功", "提交失败", "请填写", "输入错误"
        ],
        'api_interaction': [
            "API", "接口", "接口调用", "数据接口", "后端接口",
            "加载数据", "刷新数据", "提交数据", "异步加载", "同步数据", "加载更多",
            "搜索", "查询", "筛选", "排序", "分页", "更新数据", "数据提交"
        ],
        'html_form': [
            "<form", "</form>", "form action=", "form method=", "form-data",
            "<input", "type=", "name=", "value=", "placeholder=",
            "hidden", "password", "text", "email", "tel", "number", "file",
            "<textarea", "<select", "<option", "<button",
            "required", "disabled", "readonly", "autocomplete", "enctype"
        ]
    }

    # 为每个类别分配权重（可根据需求调整）
    category_weights = {
        'auth_login': 8,  # 登录相关页面通常价值高
        'register': 7,  # 注册页面可能存在注入点
        'verification': 7,  # 验证码逻辑可能有漏洞
        'password_reset': 8,  # 密码重置流程风险高
        'user_info': 6,  # 个人信息页面可能有越权
        'sensitive_operation': 9,  # 敏感操作直接关联漏洞
        'business_flow': 7,  # 业务流程可能存在逻辑漏洞
        'api_interaction': 7,  # API接口可能未授权访问
        'html_form': 6  # 表单是注入攻击的主要入口
    }

    # 预编译正则表达式（提高匹配效率）
    compiled_patterns = {}
    for category, keywords in keyword_categories.items():
        # 使用非贪婪匹配并捕获关键词
        pattern = r'(?i)(' + '|'.join(re.escape(kw) for kw in keywords) + ')'
        compiled_patterns[category] = re.compile(pattern)

    # 存储匹配结果
    matches = []

    # 对每个类别进行匹配
    for category, pattern in compiled_patterns.items():
        for match in pattern.finditer(source):
            keyword = match.group(0)
            start_pos = match.start()
            end_pos = match.end()

            # 获取匹配文本上下文（前后各50个字符）
            context_start = max(0, start_pos - 50)
            context_end = min(len(source), end_pos + 50)
            context = source[context_start:context_end]

            matches.append({
                'category': category,
                'keyword': keyword,
                'position': (start_pos, end_pos),
                'context': context,
                'weight': category_weights[category]
            })

    # 按权重和位置排序（高权重在前，相同权重按出现位置排序）
    matches.sort(key=lambda x: (-x['weight'], x['position'][0]))

    # 提取表单字段信息（增强对html_form类别的分析）
    if any(m['category'] == 'html_form' for m in matches):
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)

        for form_match in form_pattern.finditer(source):
            form_content = form_match.group(0)
            form_action = re.search(r'action=["\'](.*?)["\']', form_content, re.IGNORECASE)
            form_method = re.search(r'method=["\'](.*?)["\']', form_content, re.IGNORECASE)

            form_info = {
                'category': 'html_form_detail',
                'action': form_action.group(1) if form_action else 'unknown',
                'method': form_method.group(1).upper() if form_method else 'GET',
                'inputs': []
            }

            # 提取表单中的输入字段
            for input_match in input_pattern.finditer(form_content):
                input_tag = input_match.group(0)
                input_type = re.search(r'type=["\'](.*?)["\']', input_tag, re.IGNORECASE)
                input_name = re.search(r'name=["\'](.*?)["\']', input_tag, re.IGNORECASE)
                input_value = re.search(r'value=["\'](.*?)["\']', input_tag, re.IGNORECASE)

                input_info = {
                    'type': input_type.group(1) if input_type else 'text',
                    'name': input_name.group(1) if input_name else 'unknown',
                    'value': input_value.group(1) if input_value else '',
                    'tag': input_tag
                }

                form_info['inputs'].append(input_info)

            # 仅保留有意义的表单（至少有一个输入字段）
            if form_info['inputs']:
                matches.append(form_info)

    return matches