"""WAF Bypass Tester - Web应用防火墙安全测试工具

功能：CLI参数解析、发送端+接收端联合调度、实时彩色日志、断点续测、自动HTML报告

使用示例：
    python main.py --vendor sangfor --threads 20
    python main.py --vendor all --threads 20 --report
    python main.py --vendor all --category sqli,xss --proxy http://192.168.10.2:8080
    python main.py --report-only
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
import os
import asyncio
import argparse
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# ── 项目路径配置 ──────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.resolve()
SRC_DIR    = BASE_DIR / "src"
RULES_DIR  = BASE_DIR / "rules"
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR   = BASE_DIR / "logs"
DB_PATH    = LOGS_DIR / "waf_test_results.db"

sys.path.insert(0, str(SRC_DIR))

# ── ANSI 彩色控制台 ───────────────────────────────────────────────────────
class Colors:
    RED      = "\033[91m"
    GREEN    = "\033[92m"
    YELLOW   = "\033[93m"
    BLUE     = "\033[94m"
    MAGENTA  = "\033[95m"
    CYAN     = "\033[96m"
    WHITE    = "\033[97m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    RESET    = "\033[0m"

    @staticmethod
    def wrap(text: str, *styles) -> str:
        return "".join(styles) + text + Colors.RESET


# ── 实时进度条 ────────────────────────────────────────────────────────────
class ProgressBar:
    def __init__(self, total: int, desc: str = "测试进度", width: int = 50):
        self.total   = total
        self.current = 0
        self.desc    = desc
        self.width   = width
        self.start_t = time.time()
        self._closed = False

    def update(self, n: int = 1, status: str = "", note: str = ""):
        self.current = min(self.current + n, self.total)
        pct    = self.current / self.total * 100 if self.total else 0
        filled = int(self.width * self.current / max(self.total, 1))
        bar    = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start_t
        speed   = self.current / elapsed if elapsed > 0 else 0

        s_map = {"BYPASS": Colors.RED, "BLOCKED": Colors.GREEN,
                 "FALSE_POS": Colors.YELLOW, "ERROR": Colors.MAGENTA}
        sc = s_map.get(status, "")
        status_str = Colors.wrap(f"{status}", sc, Colors.BOLD) if sc else Colors.DIM + "进行中" + Colors.RESET

        line = (
            f"\r{Colors.BOLD}{self.desc}{Colors.RESET} |{bar}| "
            f"{self.current}/{self.total} ({pct:.1f}%) "
            f"{speed:.1f} req/s | {status_str} {Colors.DIM}{note}{Colors.RESET}"
        )
        print(line, end="", flush=True)

    def close(self):
        if not self._closed:
            print()
            self._closed = True

    def __enter__(self): return self
    def __exit__(self, *args): self.close()


# ── 实时日志打印 ──────────────────────────────────────────────────────────
class RealtimeLogger:
    def __init__(self):
        self.count = 0
        self.lock  = asyncio.Lock()

    async def log(self, result: str, vendor: str, attack_type: str,
                  target: str, method: str, payload: str, evidence: str = ""):
        async with self.lock:
            self.count += 1
            payload_short = payload[:60] + ("…" if len(payload) > 60 else "")
            ts = datetime.now().strftime("%H:%M:%S")

            if result == "BYPASS":
                icon = Colors.RED + "⚠️ BYPASS " + Colors.RESET
                p_cl = Colors.RED
            elif result == "BLOCKED":
                icon = Colors.GREEN + "✓ BLOCKED " + Colors.RESET
                p_cl = Colors.DIM
            elif result == "FALSE_POS":
                icon = Colors.YELLOW + "✗ FALSE_POS" + Colors.RESET
                p_cl = Colors.DIM
            else:
                icon = Colors.MAGENTA + "✗ ERROR   " + Colors.RESET
                p_cl = Colors.DIM

            line = (
                f"{Colors.DIM}[{ts}]{Colors.RESET} {icon} "
                f"{Colors.CYAN}[{vendor}]{Colors.RESET} "
                f"{Colors.BLUE}{attack_type:20s}{Colors.RESET} "
                f"{Colors.DIM}{method} {target}{Colors.RESET}"
            )
            if result == "BYPASS":
                line += f"\n    {p_cl}Payload: {Colors.RED}{payload_short}{Colors.RESET}"
                if evidence:
                    line += f"\n    {p_cl}特征: {Colors.GREEN}{evidence[:80]}{Colors.RESET}"

            print(line)
            if self.count % 100 == 0:
                print(Colors.DIM + "─" * 80 + Colors.RESET)

    def summary(self, stats: dict):
        print()
        print(Colors.BOLD + "═" * 80 + Colors.RESET)
        print(Colors.BOLD + "  WAF 测试汇总报告" + Colors.RESET)
        print(Colors.BOLD + "═" * 80 + Colors.RESET)
        for vendor, vstats in stats.items():
            total    = sum(vstats.values())
            blocked  = vstats.get("BLOCKED", 0)
            bypassed = vstats.get("BYPASS", 0)
            fp       = vstats.get("FALSE_POSITIVE", 0)
            br       = round(bypassed / total * 100, 1) if total else 0
            print(
                f"  {Colors.CYAN}{vendor:12s}{Colors.RESET} | "
                f"总请求: {total:4d} | "
                f"{Colors.GREEN}阻断: {blocked:4d}{Colors.RESET} | "
                f"{Colors.RED}绕过: {bypassed:4d} ({br}%){Colors.RESET} | "
                f"{Colors.YELLOW}误报: {fp:4d}{Colors.RESET}"
            )
        print(Colors.BOLD + "═" * 80 + Colors.RESET)


# ── 简化的LoggerDB（兼容 report_generator）────────────────────────────────
class SimpleLoggerDB:
    """简化的日志DB，使用 report_generator 期望的 schema"""

    CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        vendor      TEXT NOT NULL,
        target      TEXT,
        method      TEXT,
        attack_type TEXT,
        payload     TEXT,
        headers     TEXT,
        status_code INTEGER,
        response_body TEXT,
        result      TEXT,
        evidence    TEXT,
        transform   TEXT,
        confidence  TEXT,
        target_vm   TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_vendor  ON logs(vendor);
    CREATE INDEX IF NOT EXISTS idx_result  ON logs(result);
    CREATE INDEX IF NOT EXISTS idx_attack  ON logs(attack_type);
    """

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self):
        import sqlite3
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.executescript(self.CREATE_SQL)
        self.conn.commit()

    def log(self, **kwargs):
        self.conn.execute("""
            INSERT INTO logs (timestamp, vendor, target, method, attack_type,
                payload, headers, status_code, response_body,
                result, evidence, transform, confidence, target_vm)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            kwargs.get("timestamp", datetime.now().isoformat()),
            kwargs.get("vendor", ""),
            kwargs.get("target", ""),
            kwargs.get("method", ""),
            kwargs.get("attack_type", ""),
            kwargs.get("payload", ""),
            kwargs.get("headers", "{}"),
            kwargs.get("status_code", 0),
            kwargs.get("response_body", ""),
            kwargs.get("result", "UNKNOWN"),
            kwargs.get("evidence", ""),
            kwargs.get("transform", ""),
            kwargs.get("confidence", ""),
            kwargs.get("target_vm", ""),
        ))
        self.conn.commit()

    def query(self, sql: str, params=()):
        cur = self.conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def get_all_results(self) -> dict[str, dict[str, int]]:
        rows = self.query("SELECT vendor, result, COUNT(*) as cnt FROM logs GROUP BY vendor, result")
        data = {}
        for r in rows:
            data.setdefault(r["vendor"], {})[r["result"]] = r["cnt"]
        return data

    def get_bypass_logs(self, limit: int = 200) -> list[dict]:
        return self.query(
            "SELECT * FROM logs WHERE result='BYPASS' ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )

    def get_category_breakdown(self) -> dict:
        rows = self.query(
            "SELECT attack_type, vendor, result, COUNT(*) as cnt "
            "FROM logs GROUP BY attack_type, vendor, result"
        )
        breakdown = {}
        for r in rows:
            breakdown.setdefault(r["attack_type"], {}).setdefault(r["vendor"], {})[r["result"]] = r["cnt"]
        return breakdown

    def close(self):
        self.conn.close()


# ── CSV 导出（独立函数）────────────────────────────────────────────────────
def export_csv(db_path: str, out_path: str, vendor: str = None):
    import sqlite3
    import csv
    conn = sqlite3.connect(db_path)
    sql = "SELECT timestamp, vendor, target, method, attack_type, payload, status_code, result, evidence, transform FROM logs"
    params = []
    if vendor:
        sql += " WHERE vendor=?"
        params = [vendor]
    sql += " ORDER BY timestamp"
    rows = conn.execute(sql, params).fetchall()
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["时间戳", "厂商", "目标URL", "方法", "攻击类型",
                         "Payload", "状态码", "结果", "证据", "编码方式"])
        writer.writerows(rows)
    conn.close()
    return out_path


# ── HTML 报告生成（内嵌，无需import src/report_generator）─────────────────
def generate_html_report(db_path: str, out_path: str):
    import sqlite3
    from pathlib import Path

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # 确保 logs 表存在（首次运行 / --report-only 时数据库可能为空）
    conn.executescript(SimpleLoggerDB.CREATE_SQL)
    conn.commit()

    # 读取统计数据
    vdata = {}
    for row in conn.execute("SELECT vendor, result, COUNT(*) as cnt FROM logs GROUP BY vendor, result"):
        vdata.setdefault(row["vendor"], {})[row["result"]] = row["cnt"]

    bypass_rows = conn.execute(
        "SELECT * FROM logs WHERE result='BYPASS' ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()
    bypass_logs = [dict(r) for r in bypass_rows]

    cat_rows = conn.execute(
        "SELECT attack_type, vendor, result, COUNT(*) as cnt "
        "FROM logs GROUP BY attack_type, vendor, result"
    ).fetchall()
    breakdown = {}
    for r in cat_rows:
        breakdown.setdefault(r["attack_type"], {}).setdefault(r["vendor"], {})[r["result"]] = r["cnt"]

    total = sum(sum(v.values()) for v in vdata.values())
    blocked  = sum(v.get("BLOCKED", 0) for v in vdata.values())
    bypassed = sum(v.get("BYPASS", 0) for v in vdata.values())
    fp       = sum(v.get("FALSE_POSITIVE", 0) for v in vdata.values())
    avg_bp   = round(bypassed / total * 100, 1) if total else 0
    vendors  = list(vdata.keys())

    # 雷达图评分
    radar_dims = ["SQL注入防护","XSS防护","命令注入防护","SSRF防护",
                  "文件上传防护","LFI防护","路径遍历防护","认证绕过","NoSQL防护","SSTI防护"]
    mapping    = {"SQL Injection":"SQL注入防护","XSS":"XSS防护","Command Injection":"命令注入防护",
                  "SSRF":"SSRF防护","File Upload":"文件上传防护","LFI":"LFI防护",
                  "Path Traversal":"路径遍历防护","Auth Bypass":"认证绕过",
                  "NoSQL Injection":"NoSQL防护","SSTI":"SSTI防护"}
    radar_scores = {v: {d: 0.0 for d in radar_dims} for v in vendors}
    for atype, vdata2 in breakdown.items():
        dim = mapping.get(atype)
        if not dim: continue
        for vendor, rdata in vdata2.items():
            t = sum(rdata.values())
            b = rdata.get("BLOCKED", 0)
            if t > 0 and vendor in radar_scores:
                radar_scores[vendor][dim] = round(b / t * 100, 1)

    conn.close()

    # 颜色
    vcolors = {"sangfor":"#e84040","chaitin":"#50d060","nsfocus":"#60a0f0"}
    fallback = ["#e84040","#50d060","#60a0f0","#f0c040"]
    def vc(v): return vcolors.get(v, fallback[vendors.index(v) % len(fallback)] if v in vendors else "#888")

    # 绕过类型饼图
    type_counts = {}
    for log in bypass_logs:
        t = log.get("attack_type","Other")
        type_counts[t] = type_counts.get(t, 0) + 1
    pie_items = [{"name":k,"value":v} for k,v in type_counts.items()]

    # 分类行
    cat_html = ""
    for cat in sorted(breakdown.keys()):
        td = f'<tr><td>{cat}</td><td>{sum(sum(v.values()) for v in breakdown[cat].values())}</td>'
        for v in vendors:
            vd = breakdown[cat].get(v, {})
            tot = sum(vd.values())
            blk = vd.get("BLOCKED", 0)
            rate = round(blk/tot*100, 1) if tot else 0
            cls = "cell-pass" if rate>=80 else ("cell-warn" if rate>=50 else "cell-fail")
            td += f'<td class="{cls}">{rate}%</td>'
        cat_html += td + "</tr>\n"

    # 绕过详情
    bp_html = ""
    for log in bypass_logs[:80]:
        p = (log.get("payload","") or "")[:120]
        ev = (log.get("evidence","") or "")[:100]
        bp_html += f"""
    <div class="bypass-item">
      <div class="b-header">
        <span class="b-type">[{log.get('vendor','?')}] {log.get('attack_type','?')}</span>
        <span class="b-meta">{log.get('target','?')} | {log.get('method','?')} | {str(log.get('timestamp',''))[:19]}</span>
      </div>
      <div class="b-payload">{p}</div>
      <div class="b-evidence">确认特征: {ev}</div>
    </div>"""

    # 结论
    nm = {"sangfor":"深信服","chaitin":"长亭科技","nsfocus":"绿盟科技"}
    scores = {}
    for vendor, data in vdata.items():
        t = sum(data.values())
        scores[vendor] = round(data.get("BLOCKED",0)/t*100, 1) if t else 0
    sorted_v = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top2 = sorted_v[:2]
    rec = " + ".join(nm.get(v,v) for v,_ in top2) if top2 else "暂无测试数据"
    reasons = "".join(
        f'<li><strong>{nm.get(v,v)}</strong> 防护率 {s}%（绕过率 {round(100-s,1)}%），共测试 {sum(vdata[v].values())} 次</li>'
        for v,s in sorted_v
    ) if sorted_v else "<li>尚未进行测试，请先运行测试后再生成报告</li>"

    vendor_cards_html = _build_vendor_cards(vdata)

    html = _HTML_TEMPLATE.format(
        gen_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=total, blocked=blocked, bypassed=bypassed, fp=fp,
        avg_bp=avg_bp,
        vendor_cards=vendor_cards_html,
        bar_vendors=json.dumps(vendors),
        bar_blocked=json.dumps([vdata.get(v,{}).get("BLOCKED",0) for v in vendors]),
        bar_bypassed=json.dumps([vdata.get(v,{}).get("BYPASS",0) for v in vendors]),
        bar_fp=json.dumps([vdata.get(v,{}).get("FALSE_POSITIVE",0) for v in vendors]),
        pie_data=json.dumps(pie_items),
        radar_ind=json.dumps([{"name":d,"max":100} for d in radar_dims]),
        radar_legend=json.dumps(vendors),
        radar_series=json.dumps([
            {"value":[radar_scores[v].get(d,0) for d in radar_dims],
             "name":v,"lineStyle":{"color":vc(v)},"areaStyle":{"color":vc(v)+"40"},
             "itemStyle":{"color":vc(v)}}
            for v in vendors
        ]),
        th_vendors="".join(f'<th>{v}</th>' for v in vendors),
        cat_html=cat_html,
        bp_count=len(bypass_logs),
        bp_html=bp_html or "<div style='color:#7a8494;padding:30px;text-align:center;'>暂无绕过记录 ✓</div>",
        rec=rec,
        reasons=reasons,
    )

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(html, encoding="utf-8")
    return Path(out_path)


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF横向对比测试报告</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Microsoft YaHei','PingFang SC',Arial,sans-serif;background:#0f1419;color:#e6e8ea}}
  .container{{max-width:1400px;margin:0 auto;padding:24px 20px}}

  .report-header{{text-align:center;padding:40px 0 30px;border-bottom:1px solid #2a3040;margin-bottom:32px}}
  .report-header h1{{font-size:28px;font-weight:700;color:#fff;margin-bottom:10px;letter-spacing:1px}}
  .report-header .subtitle{{font-size:14px;color:#7a8494}}
  .report-header .badge-row{{margin-top:14px;display:flex;justify-content:center;gap:10px;flex-wrap:wrap}}
  .badge{{display:inline-block;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600}}
  .badge-red{{background:rgba(220,50,50,0.15);color:#e84040;border:1px solid rgba(220,50,50,0.3)}}
  .badge-green{{background:rgba(40,200,80,0.15);color:#50d060;border:1px solid rgba(40,200,80,0.3)}}
  .badge-blue{{background:rgba(50,130,230,0.15);color:#60a0f0;border:1px solid rgba(50,130,230,0.3)}}
  .badge-yellow{{background:rgba(230,180,40,0.15);color:#f0c040;border:1px solid rgba(230,180,40,0.3)}}

  .stats-row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:28px}}
  .stat-card{{background:linear-gradient(135deg,#1a2035,#1e2535);border:1px solid #2a3548;border-radius:10px;padding:18px 20px}}
  .stat-card .label{{font-size:12px;color:#7a8494;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px}}
  .stat-card .value{{font-size:28px;font-weight:700}}
  .stat-card .sub{{font-size:11px;color:#5a6578;margin-top:4px}}
  .c-red{{color:#e84040}}.c-green{{color:#50d060}}.c-blue{{color:#60a0f0}}.c-yellow{{color:#f0c040}}

  .section-title{{font-size:16px;font-weight:600;color:#fff;margin-bottom:16px;padding-left:12px;border-left:3px solid #60a0f0}}
  .vendor-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin-bottom:28px}}
  .vendor-card{{background:#161b22;border:1px solid #2a3040;border-radius:10px;padding:22px}}
  .vendor-card .vendor-name{{font-size:17px;font-weight:700;color:#fff;margin-bottom:14px;display:flex;align-items:center;gap:8px}}
  .vendor-card .vendor-name .dot{{width:10px;height:10px;border-radius:50%;display:inline-block}}
  .vendor-stats{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}}
  .v-stat{{background:#1e2535;border-radius:6px;padding:10px 8px;text-align:center}}
  .v-stat .v-label{{font-size:10px;color:#7a8494;text-transform:uppercase;letter-spacing:0.5px}}
  .v-stat .v-value{{font-size:20px;font-weight:700;margin-top:4px}}

  .chart-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:28px}}
  .chart-box{{background:#161b22;border:1px solid #2a3040;border-radius:10px;padding:20px}}
  .chart-box .chart-title{{font-size:14px;font-weight:600;color:#c0c8d8;margin-bottom:12px}}
  .chart-box .chart-container{{width:100%}}

  .radar-full{{background:#161b22;border:1px solid #2a3040;border-radius:10px;padding:20px;margin-bottom:28px}}
  .radar-full .chart-container{{width:100%;height:460px}}

  table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px;overflow:hidden}}
  thead th{{background:#1e2535;color:#8a9ab0;font-size:12px;text-transform:uppercase;padding:12px 16px;text-align:center;border-bottom:1px solid #2a3040}}
  thead th:first-child{{text-align:left}}
  tbody tr{{border-bottom:1px solid #1e2535;transition:background 0.15s}}
  tbody tr:hover{{background:#1a2035}}
  tbody td{{padding:10px 16px;font-size:13px;color:#c0c8d8;text-align:center}}
  tbody td:first-child{{text-align:left;color:#a0a8b8;font-weight:500}}
  .cell-pass{{color:#50d060;font-weight:700}}.cell-fail{{color:#e84040;font-weight:700}}.cell-warn{{color:#f0c040;font-weight:700}}

  .bypass-item{{background:#1a2035;border:1px solid #2a3040;border-left:3px solid #e84040;border-radius:6px;padding:12px 16px;margin-bottom:8px}}
  .bypass-item .b-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}}
  .bypass-item .b-type{{font-size:13px;font-weight:700;color:#e84040}}
  .bypass-item .b-meta{{font-size:11px;color:#7a8494}}
  .bypass-item .b-payload{{font-family:'Courier New',monospace;font-size:12px;color:#a0c8f0;background:#0f1419;border-radius:4px;padding:6px 10px;word-break:break-all;margin-top:6px}}
  .bypass-item .b-evidence{{font-size:12px;color:#50d060;margin-top:4px}}

  .conclusion{{background:linear-gradient(135deg,#1a2820,#1a2030);border:1px solid #2a4540;border-radius:10px;padding:28px;margin-top:28px}}
  .conclusion h2{{color:#50d060;font-size:18px;margin-bottom:18px}}
  .conclusion .rec-box{{background:#0f1419;border-radius:8px;padding:16px 20px;margin-bottom:14px}}
  .conclusion .rec-title{{font-size:13px;color:#7a8494;margin-bottom:8px}}
  .conclusion .rec-vendors{{font-size:18px;font-weight:700;color:#50d060;letter-spacing:1px}}
  .conclusion .reasons{{margin-top:16px}}
  .conclusion .reasons li{{font-size:13px;color:#a0b8b0;margin-bottom:6px;padding-left:16px;position:relative}}
  .conclusion .reasons li::before{{content:'▶';position:absolute;left:0;color:#50d060;font-size:10px;top:2px}}

  .footer{{text-align:center;padding:20px 0;color:#4a5568;font-size:11px;border-top:1px solid #1e2535;margin-top:30px}}

  @media(max-width:768px){{.chart-grid,.radar-full .chart-container{{grid-template-columns:1fr;height:360px}}}}
</style>
</head>
<body>
<div class="container">

  <div class="report-header">
    <h1>🛡️ WAF横向对比测试报告</h1>
    <div class="subtitle">Web Application Firewall Security Assessment</div>
    <div class="badge-row">
      <span class="badge badge-blue">生成时间: {gen_time}</span>
      <span class="badge badge-yellow">测试总Payload: {total} 条</span>
      <span class="badge badge-red">攻击类型: OWASP Top 10</span>
    </div>
  </div>

  <div class="stats-row">
    <div class="stat-card"><div class="label">总测试次数</div><div class="value c-blue">{total}</div><div class="sub">总计请求</div></div>
    <div class="stat-card"><div class="label">WAF阻断数</div><div class="value c-green">{blocked}</div><div class="sub">防护生效</div></div>
    <div class="stat-card"><div class="label">成功绕过数</div><div class="value c-red">{bypassed}</div><div class="sub">需关注 ⚠️</div></div>
    <div class="stat-card"><div class="label">平均绕过率</div><div class="value c-yellow">{avg_bp}%</div><div class="sub">越低越好</div></div>
  </div>

  <div style="margin-bottom:28px">
    <div class="section-title">📊 厂商防护能力对比</div>
    <div class="vendor-grid">
      {vendor_cards}
    </div>
  </div>

  <div class="chart-grid">
    <div class="chart-box"><div class="chart-title">各厂商阻断/绕过/误报对比</div><div id="chart-bar" class="chart-container" style="height:300px;"></div></div>
    <div class="chart-box"><div class="chart-title">绕过类型分布</div><div id="chart-pie" class="chart-container" style="height:300px;"></div></div>
  </div>

  <div class="radar-full">
    <div class="section-title" style="padding-left:0;">🎯 安全防护能力雷达图</div>
    <div id="chart-radar" class="chart-container" style="height:460px;"></div>
  </div>

  <div style="margin-bottom:32px">
    <div class="section-title">📋 分类防护能力详细对比</div>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>攻击类型</th><th>Payload数</th>{th_vendors}</tr></thead>
        <tbody>{cat_html}</tbody>
      </table>
    </div>
  </div>

  <div style="margin-bottom:32px">
    <div class="section-title">⚠️ 绕过事件详情（共 {bp_count} 条）</div>
    {bp_html}
  </div>

  <div class="conclusion">
    <h2>🏆 采购推荐结论</h2>
    <div class="rec-box">
      <div class="rec-title">🥇 推荐采购厂商（综合评分）</div>
      <div class="rec-vendors">{rec}</div>
    </div>
    <div class="reasons"><p style="font-size:13px;color:#7a8494;margin-bottom:10px;">综合防护率排名（越高越好）：</p><ul>{reasons}</ul></div>
  </div>

  <div class="footer">WAF Bypass Tester v1.0 &nbsp;|&nbsp; Generated automatically &nbsp;|&nbsp; Powered by Python + ECharts</div>
</div>

<script>
var chartBar=echarts.init(document.getElementById('chart-bar'));
var chartPie=echarts.init(document.getElementById('chart-pie'));
var chartRadar=echarts.init(document.getElementById('chart-radar'));

chartBar.setOption({{
  tooltip:{{trigger:'axis',axisPointer:{{type:'shadow'}}}},
  legend:{{data:['阻断','绕过','误报'],textStyle:{{color:'#7a8494'}}}},
  grid:{{left:'3%',right:'4%',bottom:'3%',top:'10%',containLabel:true}},
  xAxis:{{type:'category',data:{bar_vendors},axisLabel:{{color:'#7a8494'}},axisLine:{{lineStyle:{{color:'#2a3040'}}}}}},
  yAxis:{{type:'value',axisLabel:{{color:'#7a8494'}},splitLine:{{lineStyle:{{color:'#1e2535'}}}}}},
  series:[
    {{name:'阻断',type:'bar',data:{bar_blocked},itemStyle:{{color:'#50d060',borderRadius:[4,4,0,0]}}}},
    {{name:'绕过',type:'bar',data:{bar_bypassed},itemStyle:{{color:'#e84040',borderRadius:[4,4,0,0]}}}},
    {{name:'误报',type:'bar',data:{bar_fp},itemStyle:{{color:'#f0c040',borderRadius:[4,4,0,0]}}}}
  ]
}});

chartPie.setOption({{
  tooltip:{{trigger:'item',formatter:'{{b}}: {{c}} ({{d}}%)'}},
  legend:{{bottom:'0%',textStyle:{{color:'#7a8494'}}}},
  series:[{{
    type:'pie',radius:['40%','70%'],
    label:{{color:'#a0a8b8',formatter:'{{b}}: {{d}}%'}},
    data:{pie_data},
    itemStyle:{{borderRadius:6,borderColor:'#0f1419',borderWidth:2}}
  }}]
}});

chartRadar.setOption({{
  tooltip:{{}},
  legend:{{bottom:'0%',textStyle:{{color:'#7a8494'}},data:{radar_legend}}},
  radar:{{
    indicator:{radar_ind},
    splitNumber:5,
    axisName:{{color:'#7a8494',fontSize:12}},
    splitLine:{{lineStyle:{{color:'#2a3040'}}}},
    splitArea:{{areaStyle:{{color:['#161b22','#1a2035']}}}},
    axisLine:{{lineStyle:{{color:'#2a3040'}}}}
  }},
  series:[{{
    type:'radar',data:{radar_series}
  }}]
}});

window.addEventListener('resize',function(){{chartBar.resize();chartPie.resize();chartRadar.resize()}});
</script>
</body>
</html>"""


# ── 厂商卡片构建 ─────────────────────────────────────────────────────────
def _build_vendor_cards(vdata: dict) -> str:
    nm = {"sangfor":"深信服","chaitin":"长亭科技","nsfocus":"绿盟科技"}
    vcolors = {"sangfor":"#e84040","chaitin":"#50d060","nsfocus":"#60a0f0"}
    fallback = ["#e84040","#50d060","#60a0f0","#f0c040"]
    html = ""
    for i, (vendor, stats) in enumerate(vdata.items()):
        total = sum(stats.values())
        blk   = stats.get("BLOCKED", 0)
        byp   = stats.get("BYPASS", 0)
        fp    = stats.get("FALSE_POSITIVE", 0)
        br    = round(blk/total*100, 1) if total else 0
        byr   = round(byp/total*100, 1) if total else 0
        color = vcolors.get(vendor, fallback[i % len(fallback)])
        html += f"""
    <div class="vendor-card">
      <div class="vendor-name"><span class="dot" style="background:{color}"></span>{nm.get(vendor, vendor)}</div>
      <div class="vendor-stats">
        <div class="v-stat"><div class="v-label">阻断率</div><div class="v-value" style="color:#50d060">{br}%</div></div>
        <div class="v-stat"><div class="v-label">绕过率</div><div class="v-value" style="color:#e84040">{byr}%</div></div>
        <div class="v-stat"><div class="v-label">误报率</div><div class="v-value" style="color:#f0c040">{round(fp/max(total,1)*100,1)}%</div></div>
      </div>
      <div style="margin-top:12px;font-size:12px;color:#7a8494;">
        共测试 <strong style="color:#c0c8d8">{total}</strong> 次，阻断 <strong style="color:#50d060">{blk}</strong> 次，绕过 <strong style="color:#e84040">{byp}</strong> 次
      </div>
    </div>"""
    return html


# ── 主测试调度器 ─────────────────────────────────────────────────────────
class WAFTester:
    def __init__(self, args: argparse.Namespace):
        self.args   = args
        self.logger = RealtimeLogger()
        self.stats  = {}
        self.db     = SimpleLoggerDB(str(DB_PATH))

        self.targets = self._load_targets()
        self.vendors = self._resolve_vendors(args.vendor)

    @staticmethod
    def _load_targets() -> dict:
        path = CONFIG_DIR / "targets.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def _resolve_vendors(self, vendor_arg: str) -> list:
        path = CONFIG_DIR / "vendors.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        all_v_list = data.get("vendors", [])
        all_v = {v["id"]: v for v in all_v_list}
        if vendor_arg.lower() == "all":
            return list(all_v.keys()) if all_v else ["sangfor", "chaitin", "nsfocus"]
        return [v.strip() for v in vendor_arg.split(",")]

    def _load_vendor_config(self, vendor: str) -> dict:
        path = CONFIG_DIR / "vendors.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        all_v_list = data.get("vendors", [])
        all_v = {v["id"]: v for v in all_v_list}
        cfg = all_v.get(vendor, {})
        # 提取 block_codes / block_keywords 供 detector 使用
        proxy = cfg.get("proxy", {})
        block_codes = cfg.get("block_codes", [403, 406])
        block_kws   = cfg.get("block_keywords", [])
        if proxy and proxy.get("enabled"):
            proxy_kws = proxy.get("comment", "")
            block_kws = list(set(block_kws + [proxy_kws]))
        return {
            "id": cfg.get("id", vendor),
            "name": cfg.get("name", vendor),
            "block_codes": block_codes,
            "block_keywords": block_kws,
            "timeout": cfg.get("timeout", 15),
        }

    def _generate_payloads(self) -> list:
        # 直接调用 rules_loader 模块的函数
        rules_mod = __import__("rules_loader", fromlist=[
            "iter_all_payloads", "load_all_rules", "load_bypass_transforms"
        ])
        categories = self.args.category.split(",") if self.args.category else None
        return list(rules_mod.iter_all_payloads(
            rules_dir=str(RULES_DIR),
            categories=categories,
            expand_encodings=True,
        ))

    async def _test_vendor(self, vendor: str, payloads: list[dict]):
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'─'*80}")
        print(f"  🔍 正在测试: {vendor.upper()}")
        print(f"  📦 Payload总数: {len(payloads)} 条 | 并发: {self.args.threads}")
        print(f"{Colors.CYAN}{'─'*80}{Colors.RESET}")

        self.stats[vendor] = {"BLOCKED": 0, "BYPASS": 0, "FALSE_POSITIVE": 0, "ERROR": 0}

        # 动态导入 sender / detector
        sender_mod  = __import__("sender", fromlist=["send_batch","SendResult","BypassStatus","detect_bypass"])
        detect_mod = __import__("detector", fromlist=["detect_bypass","BypassStatus","DetectionResult"])
        BypassStatus = detect_mod.BypassStatus
        detect_bypass = detect_mod.detect_bypass

        vendor_cfg = self._load_vendor_config(vendor)
        pb = ProgressBar(len(payloads), desc=f"[{vendor}] 测试进度")

        for i, pld in enumerate(payloads):
            pb.update(1, note=f"{i+1}/{len(payloads)}")
            result_data = await self._send_and_detect(pld, vendor, vendor_cfg, sender_mod, detect_bypass, BypassStatus)
            await self.logger.log(
                result=result_data["result"],
                vendor=vendor,
                attack_type=pld.get("category", pld.get("attack_type", "?")),
                target=pld.get("target", "?"),
                method=pld.get("method", "?"),
                payload=pld.get("payload_original", pld.get("payload", "")),
                evidence=result_data.get("evidence", ""),
            )
            if result_data["result"] in self.stats[vendor]:
                self.stats[vendor][result_data["result"]] += 1
            self.db.log(**result_data)

        pb.close()
        print(f"\n{Colors.GREEN}✓ {vendor.upper()} 测试完成{Colors.RESET}")

    async def _send_and_detect(self, pld: dict, vendor: str, vendor_cfg: dict,
                                sender_mod, detect_bypass, BypassStatus) -> dict:
        import datetime, asyncio, time, httpx
        timestamp = datetime.datetime.now().isoformat(timespec="milliseconds")
        status_code = 0
        response_body = ""
        response_headers = {}
        duration_ms = 0.0
        error_msg = ""
        result = "UNKNOWN"
        evidence = ""

        try:
            # 解析 target_vm
            target_vm = pld.get("target_vm", "")
            target_cfg = None
            for t in self.targets.get("targets", []):
                if t.get("id", "").lower() == target_vm.lower():
                    target_cfg = t
                    break
            if not target_cfg:
                target_cfg = self.targets.get("targets", [{}])[0] if self.targets else {}

            host     = target_cfg.get("host", "127.0.0.1")
            port     = target_cfg.get("port", 80)
            protocol = target_cfg.get("protocol", "http")
            modules  = target_cfg.get("modules", {})
            tm_id    = pld.get("target_module", "default")
            path     = modules.get(tm_id, pld.get("path", "/"))

            payload_enc = pld.get("payload_encoded", pld.get("payload", ""))
            if "PAYLOAD" in path:
                path = path.replace("PAYLOAD", payload_enc)

            url = f"{protocol}://{host}:{port}{path}"
            method = pld.get("method", "GET").upper()
            param_loc = pld.get("param_location", "query")
            param_name = pld.get("param_name", "id")

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "keep-alive",
            }

            proxies = None
            if self.args.proxy:
                proxies = {"all://": self.args.proxy}

            timeout_val = self.args.timeout
            start = time.monotonic()

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout_val, connect=10.0),
                follow_redirects=True,
                # httpx >= 1.0 removed proxies/verify from client init;
                # proxy is now passed per-request (see below)
            ) as client:
                req_base = {"headers": headers}
                if proxies:
                    req_base["proxy"] = proxies
                params, data = {}, {}
                if param_loc == "query":
                    params[param_name] = payload_enc
                elif param_loc == "body":
                    data[param_name] = payload_enc
                elif param_loc == "header":
                    headers[param_name] = payload_enc
                elif param_loc == "cookie":
                    headers["Cookie"] = f"{param_name}={payload_enc}"

                if method == "GET":
                    r = await client.get(url, params=params, **req_base)
                elif method == "POST":
                    r = await client.post(url, data=data, **req_base)
                else:
                    r = await client.request(method, url, params=params, data=data, **req_base)

                duration_ms = (time.monotonic() - start) * 1000
                status_code = r.status_code
                response_body = r.text
                response_headers = dict(r.headers)

            # 绕过检测
            detection = detect_bypass(
                response_status=status_code,
                response_body=response_body,
                response_headers=response_headers,
                payload_info=pld,
                vendor_config=vendor_cfg,
            )
            result   = detection.status.value
            evidence = detection.evidence

        except httpx.TimeoutException:
            result, evidence, error_msg = "ERROR", "请求超时", "Timeout"
        except httpx.ConnectError as e:
            result, evidence, error_msg = "ERROR", f"连接失败: {e}", str(e)
        except Exception as e:
            result, evidence, error_msg = "ERROR", str(e), str(e)

        return {
            "timestamp": timestamp,
            "vendor": vendor,
            "target": url if 'url' in dir() else "",
            "method": method if 'method' in dir() else pld.get("method",""),
            "attack_type": pld.get("category", pld.get("attack_type", "")),
            "payload": pld.get("payload_original", pld.get("payload", "")),
            "headers": json.dumps(response_headers),
            "status_code": status_code,
            "response_body": response_body[:2000],
            "result": result,
            "evidence": evidence,
            "transform": pld.get("transform",""),
            "confidence": "",
            "target_vm": pld.get("target_vm",""),
        }

    async def run(self):
        print()
        print(Colors.BOLD + Colors.CYAN + "╔════════════════════════════════════════════════════════════╗" + Colors.RESET)
        print(Colors.BOLD + Colors.CYAN + "║         WAF Bypass Tester - Web应用防火墙安全测试          ║" + Colors.RESET)
        print(Colors.BOLD + Colors.CYAN + "╚════════════════════════════════════════════════════════════╝" + Colors.RESET)
        print(f"  {Colors.DIM}测试厂商: {', '.join(self.vendors)}")
        print(f"  {Colors.DIM}日志文件: {DB_PATH}")
        print(f"  {Colors.DIM}并发线程: {self.args.threads}")
        if self.args.proxy:
            print(f"  {Colors.DIM}代理地址: {self.args.proxy}")
        print()

        payloads = self._generate_payloads()
        total = len(payloads) * len(self.vendors)
        print(f"{Colors.YELLOW}📋 总计待测: {total} 次请求（{len(payloads)} Payload × {len(self.vendors)} 厂商）{Colors.RESET}\n")

        overall_pb = ProgressBar(len(self.vendors), desc="厂商进度")
        for idx, vendor in enumerate(self.vendors):
            overall_pb.update(1, note=f"正在测: {vendor}")
            start = time.time()
            await self._test_vendor(vendor, payloads)
            elapsed = time.time() - start
            print(f"  {Colors.DIM}  耗时: {elapsed:.1f}s{Colors.RESET}")
            csv_path = LOGS_DIR / f"{vendor}_results.csv"
            export_csv(str(DB_PATH), str(csv_path), vendor=vendor)
            print(f"  {Colors.DIM}  CSV已导出: {csv_path}{Colors.RESET}")
        overall_pb.close()

        self.logger.summary(self.stats)
        self._print_recommendation()

    def _print_recommendation(self):
        print()
        print(Colors.BOLD + "🏆 采购推荐结论" + Colors.RESET)
        print("─" * 60)
        nm = {"sangfor":"深信服","chaitin":"长亭科技","nsfocus":"绿盟科技"}
        scores = {}
        for vendor, vstats in self.stats.items():
            total = sum(vstats.values())
            scores[vendor] = round(vstats.get("BLOCKED",0)/total*100, 1) if total else 0
        sorted_v = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top2 = sorted_v[:2]
        for i, (vendor, score) in enumerate(sorted_v, 1):
            tag = "🥇" if i==1 else ("🥈" if i==2 else "  ")
            print(f"  {tag} {Colors.CYAN}{nm.get(vendor,vendor):8s}{Colors.RESET} "
                  f"防护率: {Colors.GREEN}{score:5.1f}%{Colors.RESET}  "
                  f"绕过率: {Colors.RED}{round(100-score,1):5.1f}%{Colors.RESET}")
        print()
        rec = " + ".join(nm.get(v,v) for v,_ in top2)
        print(f"  {Colors.BOLD}✅ 推荐采购: {Colors.GREEN}{rec}{Colors.RESET}")
        print("─" * 60)


# ── CLI ──────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="WAF Bypass Tester - Web应用防火墙安全测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --vendor sangfor --threads 20
  python main.py --vendor all --threads 20 --report
  python main.py --vendor all --category sqli,xss --proxy http://192.168.10.2:8080
  python main.py --report-only
  python main.py --report-only --output logs/报告.html
        """
    )
    mode = parser.add_argument_group("运行模式")
    mode.add_argument("--report-only", action="store_true", help="仅生成报告（不执行测试）")

    target = parser.add_argument_group("测试目标")
    target.add_argument("--vendor", default="all", help="WAF厂商：all / sangfor,chaitin,nsfocus")
    target.add_argument("--category", default="", help="攻击分类（逗号分隔）：sqli,xss,cmd,ssrf,lfi,upload,nosql,ssti,auth_bypass,cve")

    net = parser.add_argument_group("网络配置")
    net.add_argument("--proxy", default="", help="HTTP代理（如 http://192.168.10.2:8080）")
    net.add_argument("--timeout", type=int, default=15, help="请求超时秒数（默认15）")

    perf = parser.add_argument_group("性能配置")
    perf.add_argument("--threads", type=int, default=10, help="并发线程数（默认10）")

    out = parser.add_argument_group("输出配置")
    out.add_argument("--output","-o", default="", help="报告HTML输出路径")
    out.add_argument("--db", default=str(DB_PATH), help=f"SQLite数据库路径")
    return parser.parse_args()


def main():
    args = parse_args()
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    if args.report_only:
        db_p  = args.db or str(DB_PATH)
        out_p = args.output or str(LOGS_DIR / f"WAF测试报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        p = generate_html_report(db_p, out_p)
        print(f"{Colors.GREEN}✅ 报告已生成: {p}{Colors.RESET}")
        return

    tester = WAFTester(args)
    try:
        asyncio.run(tester.run())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  用户中断，数据已保存至: {DB_PATH}{Colors.RESET}")
        return

    db_p  = args.db or str(DB_PATH)
    out_p = args.output or str(LOGS_DIR / f"WAF测试报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    p = generate_html_report(db_p, out_p)
    csv_all = LOGS_DIR / "all_results.csv"
    export_csv(db_p, str(csv_all))
    print(f"\n{Colors.GREEN}✅ 所有测试完成！{Colors.RESET}")
    print(f"  数据库: {DB_PATH}")
    print(f"  全量CSV: {csv_all}")
    print(f"  HTML报告: {p}")


if __name__ == "__main__":
    main()
