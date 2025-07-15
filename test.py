import re
import esprima  # 主要依赖：pip install esprima
import uuid


def extract_js_api_params(js_code):
    """
    从JavaScript代码中提取所有可能向后端发送参数的点
    返回格式: {端点URL: [参数变量名称或对象]}
    """
    results = {}

    # 1. 正则表达式匹配基础传参模式
    patterns = [
        # 匹配Fetch API
        (r"fetch\(['\"]([^'\"]+)['\"][^)]*body:\s*([\w$]+)", "FETCH"),
        # 匹配XMLHttpRequest
        (r"\.send\(([\w$]+)\)", "XHR"),
        # 匹配jQuery AJAX
        (r"\.ajax\({[^{}]*url:\s*['\"]([^'\"]+)['\"][^{}]*data:\s*([\w$\[]+)", "AJAX"),
        (r"\.(?:post|get)\(['\"]([^'\"]+)['\"],\s*([\w$]+)", "AJAX"),
        # 匹配Axios
        (r"axios\.(?:post|get)\(['\"]([^'\"]+)['\"][^)]*params:\s*{([^}]+)}", "AXIOS"),
        # 匹配表单提交
        (r"document\.(?:getElementById|querySelector)\(['\"]([^'\"]+)['\"]\)\.submit\(\)", "FORM"),
        (r"\.submit\(\);?\s*\/\/\s*Form:\s*(\w+)", "FORM"),
        # 匹配WebSocket
        (r"new\s+WebSocket\(['\"]([^'\"]+)['\"]\)", "WEBSOCKET")
    ]

    # 执行正则匹配
    for pattern, method in patterns:
        for match in re.finditer(pattern, js_code, re.DOTALL):
            # 提取URL和参数
            groups = [g for g in match.groups() if g]
            if len(groups) >= 2:
                url, param = groups[0], groups[1]
                if url not in results:
                    results[url] = set()
                results[url].add(param)

    # 2. AST解析获取深层调用 (当esprima可用时)
    try:
        ast = esprima.parseScript(js_code, {'jsx': True})

        # 递归遍历AST节点
        def traverse(node):
            # 处理Fetch调用
            if (node.type == 'CallExpression' and
                    node.callee.name == 'fetch' and
                    node.arguments):
                url = node.arguments[0].value if node.arguments[0].type == 'Literal' else '动态URL'
                if len(node.arguments) > 1 and node.arguments[1].type == 'ObjectExpression':
                    for prop in node.arguments[1].properties:
                        if prop.key.name == 'body' and prop.value.type == 'Identifier':
                            results.setdefault(url, set()).add(prop.value.name)

            # 处理jQuery AJAX
            elif (node.type == 'CallExpression' and
                  node.callee.property and
                  node.callee.property.name in ('ajax', 'post', 'get') and
                  node.arguments and node.arguments[0].type == 'ObjectExpression'):

                url = None
                param = None
                for prop in node.arguments[0].properties:
                    if prop.key.name == 'url' and prop.value.type == 'Literal':
                        url = prop.value.value
                    elif prop.key.name == 'data' and prop.value.type == 'Identifier':
                        param = prop.value.name

                if url and param:
                    results.setdefault(url, set()).add(param)

            # 继续遍历子节点
            for child in node.__dict__.values():
                if isinstance(child, list):
                    for item in child:
                        if hasattr(item, 'type'):
                            traverse(item)
                elif hasattr(child, 'type'):
                    traverse(child)

        traverse(ast)

    except Exception as e:
        pass

    # 转换为标准字典格式
    return {url: list(params) for url, params in results.items()}


# 测试代码 - 包含所有检测场景
if __name__ == "__main__":
    test_js = """
    // Fetch API示例
    fetch("/api/data", {
        method: 'POST',
        body: formData
    });

    // XMLHttpRequest示例
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/submit", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(requestPayload);

    // jQuery AJAX示例
    $.ajax({
        url: "/save",
        data: userProfile,
        type: "POST"
    });

    // 表单提交示例
    document.getElementById("loginForm").submit();
    """

    results = extract_js_api_params(test_js)

    # 打印结果用于模糊测试
    print("提取的API端点与参数:")
    for url, params in results.items():
        print(f"URL: {url}")
        print(f"参数: {', '.join(params)}")
        print(f"模糊测试Payload示例: {url}?{params[0]}=FUZZ")
        print("-" * 50)
