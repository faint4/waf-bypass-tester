"""
logger_db.py - SQLite结构化日志模块
将每次发送结果写入SQLite数据库，支持精确查询
"""

import sqlite3
import os
import json
import datetime
from pathlib import Path
try:
    from .sender import SendResult
    from .detector import BypassStatus
except ImportError:
    from sender import SendResult
    from detector import BypassStatus


DEFAULT_DB_PATH = Path(__file__).parent.parent / 'results' / 'all_bypass.db'


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS bypass_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    vendor_id       TEXT NOT NULL,
    vendor_name     TEXT,
    category        TEXT,
    subcategory     TEXT,
    payload_original TEXT,
    payload_sent    TEXT,
    encoding        TEXT,
    target_url      TEXT,
    target_vm       TEXT,
    method          TEXT,
    http_code       INTEGER,
    waf_blocked     INTEGER DEFAULT 0,
    bypass_confirmed INTEGER DEFAULT 0,
    partial         INTEGER DEFAULT 0,
    bypass_type     TEXT,
    bypass_confidence REAL,
    matched_pattern TEXT,
    evidence        TEXT,
    response_snippet TEXT,
    duration_ms     REAL,
    error           TEXT,
    owasp           TEXT,
    severity        TEXT,
    is_false_positive INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_vendor ON bypass_log(vendor_id);
CREATE INDEX IF NOT EXISTS idx_category ON bypass_log(category);
CREATE INDEX IF NOT EXISTS idx_bypass ON bypass_log(bypass_confirmed);
CREATE INDEX IF NOT EXISTS idx_timestamp ON bypass_log(timestamp);
"""


def init_db(db_path: str = None) -> sqlite3.Connection:
    """初始化数据库，创建表和索引"""
    if db_path is None:
        db_path = str(DEFAULT_DB_PATH)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.executescript(CREATE_TABLE_SQL)
    conn.commit()
    return conn


def log_result(conn: sqlite3.Connection, result: SendResult, vendor_name: str = ""):
    """将单条SendResult写入数据库"""
    detection = result.detection
    p = result.payload_info

    waf_blocked = 0
    bypass_confirmed = 0
    partial = 0
    bypass_type = ""
    bypass_confidence = 0.0
    matched_pattern = ""
    evidence = ""
    snippet = ""

    if detection:
        if detection.status == BypassStatus.BLOCKED:
            waf_blocked = 1
        elif detection.status == BypassStatus.BYPASS:
            bypass_confirmed = 1
        elif detection.status == BypassStatus.PARTIAL:
            partial = 1
        bypass_type = detection.bypass_type.value if detection.bypass_type else ""
        bypass_confidence = detection.confidence
        matched_pattern = detection.matched_pattern
        evidence = detection.evidence
        snippet = detection.snippet

    conn.execute("""
        INSERT INTO bypass_log (
            timestamp, vendor_id, vendor_name,
            category, subcategory,
            payload_original, payload_sent, encoding,
            target_url, target_vm, method,
            http_code, waf_blocked, bypass_confirmed, partial,
            bypass_type, bypass_confidence, matched_pattern,
            evidence, response_snippet, duration_ms, error,
            owasp, severity, is_false_positive
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
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
        bypass_confidence,
        matched_pattern,
        evidence,
        snippet[:500],  # 最多500字符
        result.duration_ms,
        result.error,
        p.get('owasp', ''),
        p.get('severity', ''),
        1 if p.get('false_positive', False) else 0,
    ))
    conn.commit()


def log_batch(conn: sqlite3.Connection, results: list[SendResult], vendor_name: str = ""):
    """批量写入（使用事务提升性能）"""
    conn.execute("BEGIN TRANSACTION")
    try:
        for r in results:
            log_result(conn, r, vendor_name)
        conn.execute("COMMIT")
    except Exception as e:
        conn.execute("ROLLBACK")
        raise e


def query_bypasses(conn: sqlite3.Connection, vendor_id: str = None, category: str = None) -> list[dict]:
    """查询所有绕过记录"""
    sql = "SELECT * FROM bypass_log WHERE bypass_confirmed = 1"
    params = []
    if vendor_id:
        sql += " AND vendor_id = ?"
        params.append(vendor_id)
    if category:
        sql += " AND category = ?"
        params.append(category)
    sql += " ORDER BY timestamp DESC"
    conn.row_factory = sqlite3.Row
    cur = conn.execute(sql, params)
    return [dict(row) for row in cur.fetchall()]


def get_vendor_summary(conn: sqlite3.Connection, vendor_id: str) -> dict:
    """获取单厂商统计汇总"""
    cur = conn.execute("""
        SELECT
            COUNT(*) as total,
            SUM(waf_blocked) as blocked,
            SUM(bypass_confirmed) as bypassed,
            SUM(partial) as partial,
            category
        FROM bypass_log
        WHERE vendor_id = ?
        GROUP BY category
    """, (vendor_id,))
    rows = cur.fetchall()
    return {row[4]: {'total': row[0], 'blocked': row[1],
                     'bypassed': row[2], 'partial': row[3]}
            for row in rows}
