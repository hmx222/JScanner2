import re


def remove_html_tags(html_text: str) -> str:
    if not html_text or not isinstance(html_text, str): return ""
    html_text_stripped = html_text.strip()
    if len(html_text_stripped) == 0: return ""
    has_html_tags = html_text_stripped.startswith('<') and '>' in html_text_stripped[:500]
    if not has_html_tags: return html_text
    pre_pattern = r'<pre[^>]*>(.*?)</pre>'
    pre_matches = re.findall(pre_pattern, html_text, re.DOTALL | re.IGNORECASE)
    if pre_matches: return '\n'.join(pre_matches).strip()
    return html_text
