import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse


class FrontendAnalyzer:
    def __init__(self, html_content, js_content=None):
        self.html_content = html_content
        self.js_content = js_content
        self.soup = BeautifulSoup(html_content, 'html.parser')
        self.results = {
            'forms': [],
            'input_fields': [],
            'file_uploads': [],
            'url_jumps': [],
            'event_listeners': [],
            'potential_vulnerabilities': []
        }

    def analyze(self):
        """执行全面分析"""
        self._analyze_forms()
        self._analyze_input_fields()
        self._analyze_file_uploads()
        self._analyze_url_jumps()

        if self.js_content:
            self._analyze_js_vulnerabilities()
            self._analyze_js_url_jumps()
            self._analyze_event_listeners()

        return self.results

    def _analyze_forms(self):
        """分析HTML表单"""
        for form in self.soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', '').upper(),
                'has_password_field': any(input.get('type') == 'password' for input in form.find_all('input')),
                'has_file_upload': any(input.get('type') == 'file' for input in form.find_all('input')),
                'inputs': []
            }

            for input_field in form.find_all(['input', 'textarea']):
                input_info = {
                    'name': input_field.get('name'),
                    'type': input_field.get('type'),
                    'id': input_field.get('id'),
                    'class': input_field.get('class'),
                    'placeholder': input_field.get('placeholder'),
                    'autocomplete': input_field.get('autocomplete')
                }
                form_info['inputs'].append(input_info)

            self.results['forms'].append(form_info)

    def _analyze_input_fields(self):
        """分析所有输入字段"""
        for input_field in self.soup.find_all(['input', 'textarea']):
            self.results['input_fields'].append({
                'name': input_field.get('name'),
                'type': input_field.get('type'),
                'id': input_field.get('id'),
                'class': input_field.get('class'),
                'placeholder': input_field.get('placeholder'),
                'autocomplete': input_field.get('autocomplete'),
                'form': input_field.get('form')
            })

    def _analyze_file_uploads(self):
        """分析文件上传控件"""
        for file_input in self.soup.find_all('input', type='file'):
            self.results['file_uploads'].append({
                'name': file_input.get('name'),
                'id': file_input.get('id'),
                'multiple': file_input.get('multiple') is not None,
                'accept': file_input.get('accept'),
                'form': file_input.get('form')
            })

    def _analyze_url_jumps(self):
        """分析HTML中的URL跳转(a标签)"""
        for link in self.soup.find_all('a', href=True):
            href = link.get('href')
            self.results['url_jumps'].append({
                'href': href,
                'text': link.get_text(strip=True),
                'target': link.get('target'),
                'rel': link.get('rel'),
                'is_external': self._is_external_url(href)
            })

    def _analyze_js_url_jumps(self):
        """分析JavaScript中的URL跳转"""
        # 匹配window.location.href = '...' 或 window.location.assign('...')
        location_pattern = re.compile(
            r'window\.location\s*=\s*[\'"`]([^`"\']+)[`"\']|window\.location\.(href|assign|replace)\s*\(\s*[\'"`]([^`"\']+)[`"\']\s*\)')
        # 匹配window.open('...')
        open_pattern = re.compile(r'window\.open\s*\(\s*[\'"`]([^`"\']+)[`"\']')

        for match in location_pattern.finditer(self.js_content):
            url = match.group(1) or match.group(3)
            self.results['url_jumps'].append({
                'href': url,
                'source': 'JavaScript',
                'is_dynamic': True,
                'line': self._get_line_number(self.js_content, match.start())
            })

        for match in open_pattern.finditer(self.js_content):
            url = match.group(1)
            self.results['url_jumps'].append({
                'href': url,
                'source': 'JavaScript (window.open)',
                'is_dynamic': True,
                'line': self._get_line_number(self.js_content, match.start())
            })

    def _analyze_js_vulnerabilities(self):
        """分析JavaScript中的潜在安全漏洞"""
        vulnerability_patterns = {
            'xss_vulnerability': r'(innerHTML|outerHTML)\s*=|append\(|insertAdjacentHTML\(\s*[\'"](beforebegin|afterbegin|beforeend|afterend)[\'"]\s*,\s*[^)]+\)',
            'open_redirect': r'window\.location|window\.open',
            'sensitive_storage': r'(localStorage|sessionStorage)\.(setItem|getItem)\(\s*[\'"`]([^`"\']+)[`"\']',
            'script_injection': r'document\.write|document\.writeln|document\.createElement\(\s*[\'"`]script[\'"`]',
            'ajax_request': r'(fetch|XMLHttpRequest|jQuery\.ajax|\$\.ajax)\s*\(',
            'eval_risk': r'\beval\s*\('
        }

        for vuln_type, pattern in vulnerability_patterns.items():
            for match in re.finditer(pattern, self.js_content):
                self.results['potential_vulnerabilities'].append({
                    'type': vuln_type,
                    'match': match.group(0),
                    'line': self._get_line_number(self.js_content, match.start()),
                    'description': self._get_vulnerability_description(vuln_type)
                })

    def _analyze_event_listeners(self):
        """分析事件监听器"""
        if not self.js_content:
            return

        # 匹配addEventListener和内联事件处理
        pattern = re.compile(
            r'addEventListener\s*\(\s*[\'"`](click|submit|key|focus|blur|change)[\'"`]|on(click|submit|key|focus|blur|change)\s*=')

        for match in pattern.finditer(self.js_content):
            event_type = match.group(1) or match.group(2)
            self.results['event_listeners'].append({
                'event_type': event_type,
                'code_snippet': match.group(0),
                'line': self._get_line_number(self.js_content, match.start())
            })

    def _is_external_url(self, url):
        """判断URL是否为外部链接"""
        if not url or url.startswith('#') or url.startswith('javascript:'):
            return False
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and parsed.netloc != urlparse(self.soup.base.get('href', '')).netloc
        except:
            return False

    def _get_line_number(self, content, position):
        """获取匹配位置所在的行号"""
        return content.count('\n', 0, position) + 1

    def _get_vulnerability_description(self, vuln_type):
        """获取漏洞类型的描述"""
        descriptions = {
            'xss_vulnerability': '潜在的XSS漏洞，直接操作DOM内容',
            'open_redirect': '潜在的开放重定向漏洞',
            'sensitive_storage': '敏感信息存储在本地存储中',
            'script_injection': '动态脚本注入，可能导致XSS',
            'ajax_request': 'AJAX请求，可能暴露敏感API端点',
            'eval_risk': '使用eval函数，可能导致代码注入'
        }
        return descriptions.get(vuln_type, '潜在安全风险')


# 使用示例
def analyze_frontend(html_content, js_content=None):
    analyzer = FrontendAnalyzer(html_content, js_content)
    return analyzer.analyze()


# 如果作为独立脚本运行
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("使用方法: python frontend_analyzer.py <html_file> [js_file]")
        sys.exit(1)

    # 读取HTML文件
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        html_content = f.read()

    # 读取JavaScript文件(如果提供)
    js_content = None
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'r', encoding='utf-8') as f:
            js_content = f.read()

    # 执行分析
    results = analyze_frontend(html_content, js_content)

    # 输出结果
    print(json.dumps(results, indent=2, ensure_ascii=False))