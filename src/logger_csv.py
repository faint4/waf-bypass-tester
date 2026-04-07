"""
logger_csv.py - CSV日志导出模块
将测试结果导出为CSV，方便Excel打开分析
"""

import csv
import os
from pathlib import Path
try:
    from .sender import SendResult
    from .detector import BypassStatus
except ImportError:
    from sender import SendResult
    from detector import BypassStatus

DEFAULT_RESULTS_DIR = Path(__file__).parent.parent / 'results'

CSV_HEADERS = [
    "时间戳", "厂商ID", "厂商名称",
    "攻击类别", "子类型",
    "原始Payload", "发送Payload", "编码方式",
    "目标URL", "靶机ID", "HTTP方法",
    "HTTP状态码", "WAF拦截", "绕过确认", "需复核",
    "绕过类型", "置信度", "匹配特征", "证据",
    "响应摘要(前200字)", "耗时(ms)",
    "错误信息", "OWASP", "严重度", "是否误报测试"
]


def _result_to_row(result: SendResult, vendor_name: str = "") -> list:
    """将SendResult转换为CSV行"""
    detection = result.detection
    p = result.payload_info

    waf_blocked = ""
    bypass_confirmed = ""
    partial = ""
    bypass_type = ""
    confidence = ""
    matched = ""
    evidence = ""
    snippet = ""

    if detection:
        status = detection.status
        waf_blocked    = "是" if status == BypassStatus.BLOCKED else "否"
        bypass_confirmed = "是" if status == BypassStatus.BYPASS  else "否"
        partial        = "是" if status == BypassStatus.PARTIAL  else "否"
        bypass_type    = detection.bypass_type.value if detection.bypass_type else ""
        confidence     = f"{detection.confidence:.0%}"
        matched        = detection.matched_pattern
        evidence       = detection.evidence
        snippet        = detection.snippet[:200] if detection.snippet else ""

    return [
        result.timestamp,
        result.vendor_id,
        vendor_name,
        p.get('category', ''),
        p.get('subcategory', ''),
        p.get('payload_original', ''),
        p.get('payload_encoded', ''),
        p.get('encoding', 'raw'),
        result.request_url,
        p.get('target_vm', ''),
        result.request_method,
        result.http_status,
        waf_blocked,
        bypass_confirmed,
        partial,
        bypass_type,
        confidence,
        matched,
        evidence,
        snippet,
        f"{result.duration_ms:.0f}",
        result.error,
        p.get('owasp', ''),
        p.get('severity', ''),
        "是" if p.get('false_positive', False) else "否",
    ]


def save_to_csv(
    results: list[SendResult],
    vendor_id: str,
    vendor_name: str = "",
    output_dir: str = None,
    bypass_only: bool = False
):
    """
    将结果保存为CSV文件

    Args:
        results:     SendResult列表
        vendor_id:   厂商ID（用于文件名）
        vendor_name: 厂商名称
        output_dir:  输出目录
        bypass_only: True=只保存绕过记录，False=保存全部
    """
    if output_dir is None:
        output_dir = str(DEFAULT_RESULTS_DIR)
    os.makedirs(output_dir, exist_ok=True)

    suffix = "_bypass" if bypass_only else "_all"
    filepath = os.path.join(output_dir, f"{vendor_id}{suffix}.csv")

    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)

        for result in results:
            if bypass_only:
                if not result.detection or result.detection.status != BypassStatus.BYPASS:
                    continue
            writer.writerow(_result_to_row(result, vendor_name))

    return filepath


def save_bypass_csv(results: list[SendResult], vendor_id: str,
                    vendor_name: str = "", output_dir: str = None) -> str:
    """仅保存绕过记录"""
    return save_to_csv(results, vendor_id, vendor_name, output_dir, bypass_only=True)


def save_all_csv(results: list[SendResult], vendor_id: str,
                 vendor_name: str = "", output_dir: str = None) -> str:
    """保存全部记录"""
    return save_to_csv(results, vendor_id, vendor_name, output_dir, bypass_only=False)
