"""
detector.py - WAF绕过特征检测引擎
分析HTTP响应，判断WAF是否被绕过，返回绕过类型和置信度

判定逻辑：
  BYPASS   - 确认绕过（响应包含攻击成功特征）
  BLOCKED  - 确认被WAF拦截
  PARTIAL  - 部分响应，需人工复核
  UNKNOWN  - 无法判断
"""

import re
from enum import Enum
from dataclasses import dataclass
from typing import Optional


class BypassStatus(Enum):
    BYPASS  = "BYPASS"    # 确认绕过WAF
    BLOCKED = "BLOCKED"   # 确认被WAF拦截
    PARTIAL = "PARTIAL"   # 需人工复核
    UNKNOWN = "UNKNOWN"   # 无法判断
    ERROR   = "ERROR"     # 请求本身出错


class BypassType(Enum):
    SQL_ERROR      = "SQL错误回显"
    SQL_DATA       = "SQL数据泄露"
    XSS_TRIGGER    = "XSS触发"
    XSS_REFLECT    = "XSS回显未过滤"
    CMD_OUTPUT     = "命令执行输出"
    FILE_READ      = "文件内容读取"
    SSRF_RESPONSE  = "SSRF成功响应"
    AUTH_BYPASS    = "认证绕过"
    SSTI_EVAL      = "模板注入执行"
    CVE_TRIGGER    = "CVE漏洞触发"
    GENERIC        = "通用绕过"


@dataclass
class DetectionResult:
    status: BypassStatus
    bypass_type: Optional[BypassType] = None
    confidence: float = 0.0        # 0.0~1.0
    matched_pattern: str = ""      # 匹配到的特征
    snippet: str = ""              # 响应摘要（前200字符）
    evidence: str = ""             # 证据描述


# ─────────────────────────────────────────────────────────────────────────────
# WAF拦截特征（出现这些 → BLOCKED）
# ─────────────────────────────────────────────────────────────────────────────
WAF_BLOCK_PATTERNS = [
    # 通用拦截关键词
    r'(?i)(access\s+denied)',
    r'(?i)(request\s+blocked)',
    r'(?i)(security\s+alert)',
    r'(?i)(blocked\s+by)',
    r'(?i)(attack\s+detected)',
    r'(?i)(forbidden)',
    r'(?i)(illegal\s+request)',
    r'(?i)(threat\s+detected)',
    # 中文拦截关键词
    r'已被拦截',
    r'非法请求',
    r'安全拦截',
    r'请求被拒绝',
    r'WAF拦截',
    r'已阻断',
    # 厂商特定
    r'(?i)sangfor',
    r'(?i)safeline',
    r'(?i)chaitin',
    r'(?i)nsfocus',
    r'(?i)ngsoc',
    r'(?i)ModSecurity',
    r'(?i)cloudflare',
    r'(?i)(your\s+IP\s+has\s+been)',
]

# ─────────────────────────────────────────────────────────────────────────────
# SQL注入成功特征（出现这些 → BYPASS + SQL_ERROR/SQL_DATA）
# ─────────────────────────────────────────────────────────────────────────────
SQL_ERROR_PATTERNS = [
    r'(?i)you\s+have\s+an\s+error\s+in\s+your\s+sql',
    r'(?i)mysql_fetch',
    r'(?i)mysql_num_rows',
    r'(?i)warning:\s+mysql',
    r'(?i)supplied\s+argument\s+is\s+not\s+a\s+valid\s+mysql',
    r'(?i)microsoft\s+ole\s+db\s+provider\s+for\s+sql',
    r'(?i)odbc\s+sql\s+server\s+driver',
    r'(?i)unclosed\s+quotation\s+mark',
    r'(?i)quoted\s+string\s+not\s+properly\s+terminated',
    r'(?i)postgresql.*error',
    r'(?i)pg_query\(\)',
    r'(?i)sqlite.*error',
    r'(?i)ora-\d{5}',           # Oracle错误
    r'(?i)syntax\s+error.*sql',
    r'(?i)XPATH\s+syntax\s+error',  # extractvalue报错
    r'(?i)sql\s+syntax',
]

SQL_DATA_PATTERNS = [
    r'(?i)root@',
    r'information_schema',
    r'(?i)database\(\)',
    r'(?i)version\(\)',
    r'\d+\.\d+\.\d+',           # 版本号（宽泛）
]

# ─────────────────────────────────────────────────────────────────────────────
# XSS成功特征（出现这些 → BYPASS + XSS_TRIGGER/XSS_REFLECT）
# ─────────────────────────────────────────────────────────────────────────────
XSS_TRIGGER_PATTERNS = [
    r'(?i)<script[^>]*>',       # script标签未过滤
    r'(?i)onerror\s*=',
    r'(?i)onload\s*=',
    r'(?i)onclick\s*=',
    r'(?i)ontoggle\s*=',
    r'(?i)alert\s*\(',
    r'(?i)confirm\s*\(',
    r'(?i)prompt\s*\(',
    r'(?i)javascript\s*:',
    r'(?i)<svg[^>]*onload',
    r'(?i)<img[^>]*onerror',
]

# ─────────────────────────────────────────────────────────────────────────────
# 命令执行成功特征（出现这些 → BYPASS + CMD_OUTPUT）
# ─────────────────────────────────────────────────────────────────────────────
CMD_OUTPUT_PATTERNS = [
    r'uid=\d+\(',               # Linux id命令输出
    r'gid=\d+\(',
    r'(?i)root:\s*x:\s*0:0',    # /etc/passwd内容
    r'(?i)volume\s+serial\s+number',  # Windows dir命令
    r'(?i)microsoft\s+windows',
    r'(?i)directory\s+of\s+c:\\',
    r'(?i)program\s+files',
    r'daemon:x:\d+',
    r'bin:x:\d+',
    r'(?i)total\s+\d+',         # ls -la 输出
    r'(?i)drwxr-xr-x',
    r'-rw-r--r--',
]

# ─────────────────────────────────────────────────────────────────────────────
# 文件读取成功特征（→ BYPASS + FILE_READ）
# ─────────────────────────────────────────────────────────────────────────────
FILE_READ_PATTERNS = [
    r'root:x:0:0',
    r'/bin/bash',
    r'/bin/sh',
    r'127\.0\.0\.1\s+localhost',  # hosts文件
    r'(?i)windows\s+ip\s+configuration',
    r'\[boot\s+loader\]',       # Windows boot.ini
    r'(?i)\[operating\s+systems\]',
    r'c:\\windows\\system32',
]

# ─────────────────────────────────────────────────────────────────────────────
# SSRF成功特征（→ BYPASS + SSRF_RESPONSE）
# ─────────────────────────────────────────────────────────────────────────────
SSRF_PATTERNS = [
    r'(?i)ami-id',
    r'(?i)instance-id',
    r'(?i)iam/security-credentials',
    r'(?i)computemetadata',
    r'(?i)redis_version',
    r'(?i)used_memory',
    r'\+OK',                    # Redis响应
    r'220\s+\w+\s+ESMTP',      # SMTP响应
    r'root:x:0:0',              # file://读passwd
]

# ─────────────────────────────────────────────────────────────────────────────
# 模板注入成功特征（→ BYPASS + SSTI_EVAL）
# ─────────────────────────────────────────────────────────────────────────────
SSTI_PATTERNS = [
    r'^49$',                    # 7*7=49
    r'(?m)^49\s*$',
    r'<jinja2\.',
    r'TemplateNotFound',        # 部分信息泄露
    r'uid=\d+\(',               # 命令执行（SSTI→RCE）
]

# ─────────────────────────────────────────────────────────────────────────────
# CVE触发特征
# ─────────────────────────────────────────────────────────────────────────────
CVE_PATTERNS = [
    r'(?i)jndi.*ldap.*exploit',
    r'uid=\d+\(',               # Log4Shell/Spring4Shell RCE
    r'(?i)webshell\s+uploaded',
    r'(?i)eval\(\$_POST',       # PHP webshell
]

# 所有规则集合
ALL_RULES = [
    # (patterns_list, bypass_type, confidence)
    (SQL_ERROR_PATTERNS,    BypassType.SQL_ERROR,   0.95),
    (SQL_DATA_PATTERNS,     BypassType.SQL_DATA,    0.80),
    (XSS_TRIGGER_PATTERNS,  BypassType.XSS_TRIGGER, 0.90),
    (CMD_OUTPUT_PATTERNS,   BypassType.CMD_OUTPUT,  0.95),
    (FILE_READ_PATTERNS,    BypassType.FILE_READ,   0.95),
    (SSRF_PATTERNS,         BypassType.SSRF_RESPONSE, 0.85),
    (SSTI_PATTERNS,         BypassType.SSTI_EVAL,   0.85),
    (CVE_PATTERNS,          BypassType.CVE_TRIGGER, 0.90),
]


def _snippet(text: str, maxlen: int = 200) -> str:
    """截取响应摘要"""
    text = text.strip()
    if len(text) > maxlen:
        return text[:maxlen] + '...'
    return text


def detect_bypass(
    response_status: int,
    response_body: str,
    response_headers: dict,
    payload_info: dict,
    vendor_config: dict
) -> DetectionResult:
    """
    核心检测函数：分析响应判断是否绕过WAF

    Args:
        response_status:  HTTP响应状态码
        response_body:    响应体文本
        response_headers: 响应头字典
        payload_info:     当前Payload信息（含category/bypass_indicators等）
        vendor_config:    厂商配置（含block_codes/block_keywords）

    Returns:
        DetectionResult
    """
    body = response_body or ''
    snippet = _snippet(body)
    block_codes = vendor_config.get('block_codes', [403, 406])
    block_keywords = vendor_config.get('block_keywords', [])

    # ── 步骤1: 检查响应码是否为WAF拦截码 ──────────────────────────────────
    if response_status in block_codes:
        return DetectionResult(
            status=BypassStatus.BLOCKED,
            confidence=0.95,
            snippet=snippet,
            evidence=f"HTTP {response_status}，在WAF拦截码列表中"
        )

    # ── 步骤2: 检查响应体中的WAF拦截关键词 ───────────────────────────────
    for pattern in WAF_BLOCK_PATTERNS:
        if re.search(pattern, body):
            return DetectionResult(
                status=BypassStatus.BLOCKED,
                matched_pattern=pattern,
                confidence=0.90,
                snippet=snippet,
                evidence=f"响应含WAF拦截关键词: {pattern}"
            )

    for kw in block_keywords:
        if kw in body:
            return DetectionResult(
                status=BypassStatus.BLOCKED,
                confidence=0.88,
                snippet=snippet,
                evidence=f"响应含厂商拦截关键词: {kw}"
            )

    # ── 步骤3: 响应码为400/500系列但不在拦截码中 ─────────────────────────
    if response_status >= 400:
        return DetectionResult(
            status=BypassStatus.BLOCKED,
            confidence=0.70,
            snippet=snippet,
            evidence=f"HTTP {response_status}，疑似被拦截（非2xx/3xx）"
        )

    # ── 步骤4: 检查Payload中用户自定义的绕过特征 ─────────────────────────
    user_indicators = payload_info.get('bypass_indicators', [])
    for indicator in user_indicators:
        if indicator.lower() in body.lower():
            category = payload_info.get('category', 'generic')
            # 根据类别推断绕过类型
            btype_map = {
                'sqli': BypassType.SQL_ERROR,
                'xss':  BypassType.XSS_TRIGGER,
                'cmd':  BypassType.CMD_OUTPUT,
                'lfi':  BypassType.FILE_READ,
                'ssrf': BypassType.SSRF_RESPONSE,
                'ssti': BypassType.SSTI_EVAL,
            }
            btype = btype_map.get(category, BypassType.GENERIC)
            return DetectionResult(
                status=BypassStatus.BYPASS,
                bypass_type=btype,
                confidence=0.92,
                matched_pattern=indicator,
                snippet=snippet,
                evidence=f"响应含自定义绕过特征: {indicator!r}"
            )

    # ── 步骤5: 规则库模式匹配 ─────────────────────────────────────────────
    for patterns, bypass_type, confidence in ALL_RULES:
        for pattern in patterns:
            m = re.search(pattern, body)
            if m:
                return DetectionResult(
                    status=BypassStatus.BYPASS,
                    bypass_type=bypass_type,
                    confidence=confidence,
                    matched_pattern=pattern,
                    snippet=snippet,
                    evidence=f"检测到 [{bypass_type.value}] 特征: {m.group()[:80]!r}"
                )

    # ── 步骤6: 响应为200但无明确特征（PARTIAL需人工复核）───────────────────
    if response_status == 200:
        body_len = len(body)
        if body_len > 5000:
            return DetectionResult(
                status=BypassStatus.PARTIAL,
                confidence=0.50,
                snippet=snippet,
                evidence=f"HTTP 200，响应体较大({body_len}B)，建议人工复核"
            )
        return DetectionResult(
            status=BypassStatus.PARTIAL,
            confidence=0.40,
            snippet=snippet,
            evidence=f"HTTP 200，无明确拦截或绕过特征，建议人工复核"
        )

    # ── 默认：无法判断 ───────────────────────────────────────────────────
    return DetectionResult(
        status=BypassStatus.UNKNOWN,
        confidence=0.0,
        snippet=snippet,
        evidence=f"HTTP {response_status}，无法判断结果"
    )


def is_false_positive(response_body: str, payload_info: dict) -> bool:
    """
    误报检测：正常请求是否被WAF误拦
    用于误报测试Payload（false_positive=True的规则）
    """
    # 正常请求被拦截了 → 误报
    body = response_body or ''
    for pattern in WAF_BLOCK_PATTERNS:
        if re.search(pattern, body):
            return True
    return False


if __name__ == '__main__':
    # 测试
    result = detect_bypass(
        response_status=200,
        response_body="You have an error in your SQL syntax; check the manual",
        response_headers={},
        payload_info={'category': 'sqli'},
        vendor_config={'block_codes': [403], 'block_keywords': ['深信服']}
    )
    print(f"状态: {result.status.value}")
    print(f"类型: {result.bypass_type}")
    print(f"置信度: {result.confidence:.0%}")
    print(f"证据: {result.evidence}")
