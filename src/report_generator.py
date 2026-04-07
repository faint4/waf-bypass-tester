"""
report_generator.py - WAF测试报告生成器

功能：
- 读取SQLite数据库中的测试结果
- 生成带 ECharts 图表的HTML对比报告
- 支持三厂商防护率/绕过率/误报率横向对比
- 自动输出"推荐采购哪两家"结论
"""

import os
import sys
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# ── 路径定义 ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
DEFAULT_DB = BASE_DIR / "logs" / "waf_test_results.db"
DEFAULT_OUT = BASE_DIR / "logs" / f"WAF测试报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"


# ── HTML模板 ──────────────────────────────────────────────────────────────
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF横向对比测试报告</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Microsoft YaHei', 'PingFang SC', Arial, sans-serif; background: #0f1419; color: #e6e8ea; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px 20px; }

  /* 头部 */
  .report-header { text-align: center; padding: 40px 0 30px; border-bottom: 1px solid #2a3040; margin-bottom: 32px; }
  .report-header h1 { font-size: 28px; font-weight: 700; color: #fff; margin-bottom: 10px; letter-spacing: 1px; }
  .report-header .subtitle { font-size: 14px; color: #7a8494; }
  .report-header .badge-row { margin-top: 14px; display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; }
  .badge { display: inline-block; padding: 4px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; letter-spacing: 0.5px; }
  .badge-red    { background: rgba(220,50,50,0.15); color: #e84040; border: 1px solid rgba(220,50,50,0.3); }
  .badge-green  { background: rgba(40,200,80,0.15); color: #50d060; border: 1px solid rgba(40,200,80,0.3); }
  .badge-blue   { background: rgba(50,130,230,0.15); color: #60a0f0; border: 1px solid rgba(50,130,230,0.3); }
  .badge-yellow { background: rgba(230,180,40,0.15); color: #f0c040; border: 1px solid rgba(230,180,40,0.3); }

  /* 统计卡片行 */
  .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 28px; }
  .stat-card { background: linear-gradient(135deg, #1a2035, #1e2535); border: 1px solid #2a3548; border-radius: 10px; padding: 18px 20px; }
  .stat-card .label { font-size: 12px; color: #7a8494; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 6px; }
  .stat-card .value { font-size: 28px; font-weight: 700; }
  .stat-card .sub { font-size: 11px; color: #5a6578; margin-top: 4px; }
  .c-red   { color: #e84040; }
  .c-green { color: #50d060; }
  .c-blue  { color: #60a0f0; }
  .c-yellow{ color: #f0c040; }

  /* 厂商对比区 */
  .vendor-section { margin-bottom: 36px; }
  .section-title { font-size: 16px; font-weight: 600; color: #fff; margin-bottom: 16px; padding-left: 12px; border-left: 3px solid #60a0f0; }
  .vendor-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
  .vendor-card { background: #161b22; border: 1px solid #2a3040; border-radius: 10px; padding: 22px; }
  .vendor-card .vendor-name { font-size: 17px; font-weight: 700; color: #fff; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
  .vendor-card .vendor-name .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
  .vendor-stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }
  .v-stat { background: #1e2535; border-radius: 6px; padding: 10px 8px; text-align: center; }
  .v-stat .v-label { font-size: 10px; color: #7a8494; text-transform: uppercase; letter-spacing: 0.5px; }
  .v-stat .v-value { font-size: 20px; font-weight: 700; margin-top: 4px; }

  /* 图表容器 */
  .chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 28px; }
  .chart-box { background: #161b22; border: 1px solid #2a3040; border-radius: 10px; padding: 20px; }
  .chart-box .chart-title { font-size: 14px; font-weight: 600; color: #c0c8d8; margin-bottom: 12px; }
  .chart-box .chart-container { width: 100%; }

  /* 分类对比表 */
  .category-section { margin-bottom: 32px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; }
  thead th { background: #1e2535; color: #8a9ab0; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; padding: 12px 16px; text-align: center; border-bottom: 1px solid #2a3040; }
  thead th:first-child { text-align: left; }
  tbody tr { border-bottom: 1px solid #1e2535; transition: background 0.15s; }
  tbody tr:hover { background: #1a2035; }
  tbody td { padding: 10px 16px; font-size: 13px; color: #c0c8d8; text-align: center; }
  tbody td:first-child { text-align: left; color: #a0a8b8; font-weight: 500; }
  .cell-pass { color: #50d060; font-weight: 700; }
  .cell-fail { color: #e84040; font-weight: 700; }
  .cell-warn { color: #f0c040; font-weight: 700; }

  /* 绕过详情 - 分组折叠样式 */
  .bypass-section { margin-bottom: 32px; }

  /* 分组头 */
  .bypass-group { margin-bottom: 10px; border: 1px solid #2a3040; border-radius: 8px; overflow: hidden; }
  .bypass-group-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 18px; background: #1a2035; cursor: pointer;
    user-select: none; transition: background 0.15s;
  }
  .bypass-group-header:hover { background: #1f2842; }
  .bypass-group-header .g-left { display: flex; align-items: center; gap: 10px; }
  .bypass-group-header .g-vendor { font-size: 13px; font-weight: 700; color: #e84040; }
  .bypass-group-header .g-type  { font-size: 12px; color: #a0b0c0; }
  .bypass-group-header .g-badge {
    font-size: 11px; font-weight: 700; background: rgba(232,64,64,0.18);
    color: #e84040; border: 1px solid rgba(232,64,64,0.35);
    border-radius: 12px; padding: 2px 10px;
  }
  .bypass-group-header .g-arrow {
    font-size: 13px; color: #60a0f0; transition: transform 0.2s;
  }
  .bypass-group-header.open .g-arrow { transform: rotate(90deg); }

  /* 折叠内容区 */
  .bypass-group-body { display: none; padding: 8px 14px 12px; background: #111722; }
  .bypass-group-body.open { display: block; }

  /* 单条记录 */
  .bypass-item { background: #1a2035; border: 1px solid #252e44; border-left: 3px solid #e84040;
    border-radius: 5px; padding: 10px 14px; margin-bottom: 6px; }
  .bypass-item:last-child { margin-bottom: 0; }
  .bypass-item .b-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; }
  .bypass-item .b-type { font-size: 12px; font-weight: 700; color: #e84040; }
  .bypass-item .b-meta { font-size: 11px; color: #6a7890; max-width: 65%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bypass-item .b-payload { font-family: 'Courier New', monospace; font-size: 12px; color: #a0c8f0;
    background: #0f1419; border-radius: 4px; padding: 5px 10px; word-break: break-all; margin-top: 5px; }
  .bypass-item .b-evidence { font-size: 11px; color: #40c870; margin-top: 4px; }

  /* 结论区 */
  .conclusion { background: linear-gradient(135deg, #1a2820, #1a2030); border: 1px solid #2a4540; border-radius: 10px; padding: 28px; margin-top: 28px; }
  .conclusion h2 { color: #50d060; font-size: 18px; margin-bottom: 18px; }
  .conclusion .rec-box { background: #0f1419; border-radius: 8px; padding: 16px 20px; margin-bottom: 14px; }
  .conclusion .rec-title { font-size: 13px; color: #7a8494; margin-bottom: 8px; }
  .conclusion .rec-vendors { font-size: 18px; font-weight: 700; color: #50d060; letter-spacing: 1px; }
  .conclusion .reasons { margin-top: 16px; }
  .conclusion .reasons li { font-size: 13px; color: #a0b8b0; margin-bottom: 6px; padding-left: 16px; position: relative; }
  .conclusion .reasons li::before { content: '▶'; position: absolute; left: 0; color: #50d060; font-size: 10px; top: 2px; }

  /* 雷达图独占行 */
  .radar-full { background: #161b22; border: 1px solid #2a3040; border-radius: 10px; padding: 20px; margin-bottom: 28px; }
  .radar-full .chart-container { width: 100%; height: 480px; }

  /* 页脚 */
  .footer { text-align: center; padding: 20px 0; color: #4a5568; font-size: 11px; border-top: 1px solid #1e2535; margin-top: 30px; }

  @media (max-width: 768px) {
    .chart-grid, .radar-full .chart-container { grid-template-columns: 1fr; height: 360px; }
    .vendor-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- 头部 -->
  <div class="report-header">
    <h1>🛡️ WAF横向对比测试报告</h1>
    <div class="subtitle">Web Application Firewall Security Assessment</div>
    <div class="badge-row">
      <span class="badge badge-blue">生成时间: {gen_time}</span>
      <span class="badge badge-yellow">测试总Payload: {total_payloads} 条</span>
      <span class="badge badge-red">攻击类型: OWASP Top 10</span>
    </div>
  </div>

  <!-- 全局统计卡片 -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="label">总测试次数</div>
      <div class="value c-blue">{total_tests}</div>
      <div class="sub">总计请求</div>
    </div>
    <div class="stat-card">
      <div class="label">WAF阻断数</div>
      <div class="value c-green">{total_blocked}</div>
      <div class="sub">防护生效</div>
    </div>
    <div class="stat-card">
      <div class="label">成功绕过数</div>
      <div class="value c-red">{total_bypassed}</div>
      <div class="sub">需关注 ⚠️</div>
    </div>
    <div class="stat-card">
      <div class="label">平均绕过率</div>
      <div class="value c-yellow">{avg_bypass_rate}%</div>
      <div class="sub">越低越好</div>
    </div>
  </div>

  <!-- 厂商对比卡片 -->
  <div class="vendor-section">
    <div class="section-title">📊 厂商防护能力对比</div>
    <div class="vendor-grid">
      {vendor_cards}
    </div>
  </div>

  <!-- 柱状图 + 饼图 -->
  <div class="chart-grid">
    <div class="chart-box">
      <div class="chart-title">各厂商防护率 / 绕过率对比</div>
      <div id="chart-bar" class="chart-container" style="height:300px;"></div>
    </div>
    <div class="chart-box">
      <div class="chart-title">全厂商绕过类型分布</div>
      <div id="chart-pie" class="chart-container" style="height:300px;"></div>
    </div>
  </div>

  <!-- 雷达图 -->
  <div class="radar-full">
    <div class="section-title" style="padding-left:0;">🎯 安全防护能力雷达图</div>
    <div id="chart-radar" class="chart-container" style="height:460px;"></div>
  </div>

  <!-- 分类对比表 -->
  <div class="category-section">
    <div class="section-title">📋 分类防护能力详细对比</div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>攻击类型</th>
            <th>Payload数</th>
            {th_vendors}
          </tr>
        </thead>
        <tbody>
          {category_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- 绕过详情 -->
  <div class="bypass-section">
    <div class="section-title">⚠️ 绕过事件详情（共 {bypass_count} 条）</div>
    {bypass_items}
  </div>

  <!-- 结论 -->
  <div class="conclusion">
    <h2>🏆 采购推荐结论</h2>
    <div class="rec-box">
      <div class="rec-title">🥇 推荐采购厂商（综合评分）</div>
      <div class="rec-vendors">{recommended_vendors}</div>
    </div>
    {conclusion_reason}
  </div>

  <div class="footer">
    WAF Bypass Tester v1.0 &nbsp;|&nbsp; Generated automatically &nbsp;|&nbsp; Powered by Python + ECharts
  </div>
</div>

<script>
  // ECharts 全局注册
  var chartBar  = echarts.init(document.getElementById('chart-bar'));
  var chartPie  = echarts.init(document.getElementById('chart-pie'));
  var chartRadar= echarts.init(document.getElementById('chart-radar'));

  /* 柱状图 */
  chartBar.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { data: ['阻断', '绕过', '误报'], textStyle: { color: '#7a8494' } },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
    xAxis: { type: 'category', data: {bar_vendors_json}, axisLabel: { color: '#7a8494' }, axisLine: { lineStyle: { color: '#2a3040' } } },
    yAxis: { type: 'value', axisLabel: { color: '#7a8494' }, splitLine: { lineStyle: { color: '#1e2535' } } },
    series: [
      { name: '阻断', type: 'bar', data: {bar_blocked_json}, itemStyle: { color: '#50d060', borderRadius: [4,4,0,0] } },
      { name: '绕过', type: 'bar', data: {bar_bypassed_json}, itemStyle: { color: '#e84040', borderRadius: [4,4,0,0] } },
      { name: '误报', type: 'bar', data: {bar_false_json}, itemStyle: { color: '#f0c040', borderRadius: [4,4,0,0] } }
    ]
  });

  /* 饼图 */
  chartPie.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: '0%', textStyle: { color: '#7a8494' } },
    series: [{
      type: 'pie', radius: ['40%', '70%'],
      label: { color: '#a0a8b8', formatter: '{b}: {d}%' },
      data: {pie_data_json},
      itemStyle: { borderRadius: 6, borderColor: '#0f1419', borderWidth: 2 }
    }]
  });

  /* 雷达图 */
  chartRadar.setOption({
    tooltip: {},
    legend: { bottom: '0%', textStyle: { color: '#7a8494' }, data: {radar_legend_json} },
    radar: {
      indicator: {radar_indicators_json},
      splitNumber: 5,
      axisName: { color: '#7a8494', fontSize: 12 },
      splitLine: { lineStyle: { color: '#2a3040' } },
      splitArea:  { areaStyle: { color: ['#161b22','#1a2035'] } },
      axisLine:   { lineStyle: { color: '#2a3040' } }
    },
    series: [{
      type: 'radar',
      data: {radar_series_json}
    }]
  });

  window.addEventListener('resize', function() {
    chartBar.resize(); chartPie.resize(); chartRadar.resize();
  });

  /* 绕过详情分组折叠 */
  function toggleGroup(header) {
    header.classList.toggle('open');
    var body = header.nextElementSibling;
    body.classList.toggle('open');
  }
</script>
</body>
</html>
"""


class ReportGenerator:
    """WAF测试报告生成器"""

    VENDOR_COLORS = {
        "sangfor": "#e84040",   # 深信服 - 红
        "chaitin": "#50d060",   # 长亭   - 绿
        "nsfocus": "#60a0f0",   # 绿盟   - 蓝
    }

    RADAR_DIMENSIONS = [
        "SQL注入防护",
        "XSS防护",
        "命令注入防护",
        "SSRF防护",
        "文件上传防护",
        "文件包含防护",
        "路径遍历防护",
        "认证绕过防护",
        "NoSQL防护",
        "SSTI防护",
    ]

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: sqlite3.Connection | None = None

    # ── 数据库读取 ──────────────────────────────────────────────────────────

    def connect(self):
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

    def close(self):
        if self.conn:
            self.conn.close()

    def _query(self, sql: str, params=()) -> list[sqlite3.Row]:
        if not self.conn:
            self.connect()
        cur = self.conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    # ── 数据提取 ────────────────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        rows = self._query("SELECT COUNT(*) as cnt, result FROM logs GROUP BY result")
        total = sum(r["cnt"] for r in rows)
        blocked  = sum(r["cnt"] for r in rows if r["result"] == "BLOCKED")
        bypassed = sum(r["cnt"] for r in rows if r["result"] == "BYPASS")
        false_pos = sum(r["cnt"] for r in rows if r["result"] == "FALSE_POSITIVE")
        vendors = list(set(r["vendor"] for r in self._query("SELECT DISTINCT vendor FROM logs")))
        n_vendors = len(vendors)
        avg_bypass = round(bypassed / total * 100, 1) if total else 0
        return {
            "total": total, "blocked": blocked, "bypassed": bypassed,
            "false_pos": false_pos, "avg_bypass": avg_bypass,
            "vendors": vendors, "n_vendors": n_vendors,
        }

    def get_vendor_summary(self) -> Dict[str, Dict[str, int]]:
        rows = self._query(
            "SELECT vendor, result, COUNT(*) as cnt FROM logs GROUP BY vendor, result"
        )
        data = {}
        for r in rows:
            data.setdefault(r["vendor"], {})[r["result"]] = r["cnt"]
        return data

    def get_category_breakdown(self) -> Dict[str, Dict[str, Dict[str, int]]]:
        rows = self._query(
            "SELECT attack_type, vendor, result, COUNT(*) as cnt "
            "FROM logs GROUP BY attack_type, vendor, result"
        )
        data = {}
        for r in rows:
            data.setdefault(r["attack_type"], {}).setdefault(r["vendor"], {})[r["result"]] = r["cnt"]
        return data

    def get_bypass_logs(self, limit: int = 200) -> list[Dict]:
        return self._query(
            "SELECT * FROM logs WHERE result='BYPASS' ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )

    # attack_type 值（数据库实际存储）→ 雷达图维度名
    ATTACK_TYPE_MAP = {
        # 短名（本项目实际存储值）
        "sqli":           "SQL注入防护",
        "sql injection":  "SQL注入防护",
        "sql":            "SQL注入防护",
        "xss":            "XSS防护",
        "cmd":            "命令注入防护",
        "command injection": "命令注入防护",
        "rce":            "命令注入防护",
        "ssrf":           "SSRF防护",
        "upload":         "文件上传防护",
        "file upload":    "文件上传防护",
        "lfi":            "文件包含防护",
        "file inclusion": "文件包含防护",
        "path_traversal": "路径遍历防护",
        "path traversal": "路径遍历防护",
        "traversal":      "路径遍历防护",
        "auth_bypass":    "认证绕过防护",
        "auth bypass":    "认证绕过防护",
        "nosql":          "NoSQL防护",
        "nosqli":         "NoSQL防护",
        "ssti":           "SSTI防护",
        # 兼容旧英文全名（历史数据）
        "sql injection":  "SQL注入防护",
        "command injection": "命令注入防护",
        "file upload":    "文件上传防护",
        "auth bypass":    "认证绕过防护",
        "nosql injection":"NoSQL防护",
    }

    def get_radar_data(self) -> Dict[str, Dict[str, float]]:
        """计算各厂商各维度的安全评分(0-100)。
        只返回「有实际测试数据」的维度，无数据维度不纳入雷达图，
        避免出现一圈0的情况。
        """
        breakdown = self.get_category_breakdown()

        # 收集所有出现的厂商
        vendors: list[str] = []
        seen = set()
        for vdata in breakdown.values():
            for v in vdata:
                if v not in seen:
                    vendors.append(v)
                    seen.add(v)

        if not vendors:
            return {}

        # 初始化 scores，key = 数据库中实际的 attack_type 字符串
        # 先按 dimension 聚合
        dim_data: Dict[str, Dict[str, Dict[str, int]]] = {}
        # dim_data[dim][vendor] = {"BLOCKED": n, "BYPASS": n, ...}

        for atype, vdata in breakdown.items():
            dim = self.ATTACK_TYPE_MAP.get(atype.lower()) or self.ATTACK_TYPE_MAP.get(atype)
            if not dim:
                # 未知 attack_type，尝试模糊匹配
                atype_l = atype.lower()
                for key, d in self.ATTACK_TYPE_MAP.items():
                    if key in atype_l or atype_l in key:
                        dim = d
                        break
            if not dim:
                continue
            dim_data.setdefault(dim, {})
            for vendor, rdata in vdata.items():
                dim_data[dim].setdefault(vendor, {})
                for result, cnt in rdata.items():
                    dim_data[dim][vendor][result] = (
                        dim_data[dim][vendor].get(result, 0) + cnt
                    )

        # 只保留有数据的维度
        active_dims = [d for d in self.RADAR_DIMENSIONS if d in dim_data]

        # 计算评分
        scores: Dict[str, Dict[str, float]] = {v: {} for v in vendors}
        for dim in active_dims:
            for vendor in vendors:
                rdata = dim_data[dim].get(vendor, {})
                total = sum(rdata.values())
                blocked = rdata.get("BLOCKED", 0)
                scores[vendor][dim] = round(blocked / total * 100, 1) if total else 0.0

        # 附加 _active_dims 供调用者使用（避免重复计算）
        scores["__active_dims__"] = active_dims  # type: ignore[assignment]
        return scores

    # ── HTML 构建 ───────────────────────────────────────────────────────────

    def _vendor_card(self, vendor: str, vdata: Dict[str, int], color: str) -> str:
        total     = sum(vdata.values())
        blocked   = vdata.get("BLOCKED", 0)
        bypassed  = vdata.get("BYPASS", 0)
        false_pos = vdata.get("FALSE_POSITIVE", 0)
        block_rate  = round(blocked  / total * 100, 1) if total else 0
        bypass_rate = round(bypassed / total * 100, 1) if total else 0
        return f"""
    <div class="vendor-card">
      <div class="vendor-name">
        <span class="dot" style="background:{color}"></span>
        {vendor}
      </div>
      <div class="vendor-stats">
        <div class="v-stat">
          <div class="v-label">阻断率</div>
          <div class="v-value" style="color:#50d060">{block_rate}%</div>
        </div>
        <div class="v-stat">
          <div class="v-label">绕过率</div>
          <div class="v-value" style="color:#e84040">{bypass_rate}%</div>
        </div>
        <div class="v-stat">
          <div class="v-label">误报率</div>
          <div class="v-value" style="color:#f0c040">{round(false_pos/max(total,1)*100,1)}%</div>
        </div>
      </div>
      <div style="margin-top:12px; font-size:12px; color:#7a8494;">
        共测试 <strong style="color:#c0c8d8">{total}</strong> 次，阻断 <strong style="color:#50d060">{blocked}</strong> 次，绕过 <strong style="color:#e84040">{bypassed}</strong> 次
      </div>
    </div>"""

    def _category_rows(self, breakdown: Dict) -> str:
        categories = sorted(breakdown.keys())
        vendors = list({v for cdata in breakdown.values() for v in cdata.keys()})
        rows_html = ""
        for cat in categories:
            row = f'<tr><td>{cat}</td>'
            cdata = breakdown[cat]
            cat_total = sum(sum(v.values()) for v in cdata.values())
            row += f'<td>{cat_total}</td>'
            for v in vendors:
                vdata = cdata.get(v, {})
                total = sum(vdata.values())
                blocked = vdata.get("BLOCKED", 0)
                rate = round(blocked / total * 100, 1) if total else 0
                cls = "cell-pass" if rate >= 80 else ("cell-warn" if rate >= 50 else "cell-fail")
                row += f'<td class="{cls}">{rate}%</td>'
            rows_html += row + "</tr>\n"
        return rows_html, vendors

    def _bypass_items(self, logs: list) -> str:
        """按「厂商 + 攻击类型」分组，生成可折叠的绕过详情 HTML。
        默认第一组展开，其余折叠。
        """
        if not logs:
            return "<div style='color:#7a8494;text-align:center;padding:30px;'>暂无绕过记录 ✓</div>"

        # 分组：(vendor, attack_type) → list of logs
        from collections import OrderedDict
        groups: OrderedDict[tuple, list] = OrderedDict()
        for log in logs:
            key = (log.get("vendor", "?"), log.get("attack_type", "?"))
            groups.setdefault(key, []).append(log)

        html_parts = []
        for idx, ((vendor, atype), items) in enumerate(groups.items()):
            # 第一组默认展开
            open_cls = " open" if idx == 0 else ""

            # 单条记录 HTML
            items_html = ""
            for log in items:
                payload_short = self._esc((log.get("payload", "") or "")[:200])
                ev = self._esc((log.get("evidence", "") or "")[:150])
                ts = (log.get("timestamp", "") or "")[:19]
                target = self._esc((log.get("target", "") or "")[:80])
                method = log.get("method", "GET")
                items_html += f"""
      <div class="bypass-item">
        <div class="b-header">
          <span class="b-type">[{self._esc(vendor)}] {self._esc(atype)}</span>
          <span class="b-meta">{target} | {method} | {ts}</span>
        </div>
        <div class="b-payload">{payload_short}</div>
        <div class="b-evidence">✓ {ev}</div>
      </div>"""

            html_parts.append(f"""
  <div class="bypass-group">
    <div class="bypass-group-header{open_cls}" onclick="toggleGroup(this)">
      <div class="g-left">
        <span class="g-vendor">[{self._esc(vendor)}]</span>
        <span class="g-type">{self._esc(atype)} 攻击</span>
        <span class="g-badge">{len(items)} 条绕过</span>
      </div>
      <span class="g-arrow">▶</span>
    </div>
    <div class="bypass-group-body{open_cls}">{items_html}
    </div>
  </div>""")

        return "\n".join(html_parts)

    @staticmethod
    def _esc(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    def _build_conclusion(self, summary: Dict, vdata: Dict) -> tuple:
        """返回 (推荐厂商文字, 结论HTML段落)"""
        if not vdata:
            return "数据不足，无法给出推荐", ""
        scores = {}
        for vendor, data in vdata.items():
            total = sum(data.values())
            blocked = data.get("BLOCKED", 0)
            scores[vendor] = round(blocked / total * 100, 1) if total else 0

        sorted_vendors = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top2 = [v for v, _ in sorted_vendors[:2]]
        names_map = {
            "sangfor": "深信服", "chaitin": "长亭科技", "nsfocus": "绿盟科技"
        }
        rec_str = " + ".join(names_map.get(v, v) for v in top2)

        reasons = []
        for i, (vendor, score) in enumerate(sorted_vendors, 1):
            reasons.append(
                f"<li><strong>{names_map.get(vendor, vendor)}</strong> 防护率 {score}%（"
                f"{'第1推荐' if i == 1 else '第2推荐'}），"
                f"绕过率 {round(100 - score, 1)}%，共测试 "
                f"{sum(vdata[vendor].values())} 次</li>"
            )

        conclusion_html = f"""
    <div class="reasons">
      <p style="font-size:13px;color:#7a8494;margin-bottom:10px;">综合防护率排名（越高越好）：</p>
      <ul>{"".join(reasons)}</ul>
    </div>"""
        return rec_str, conclusion_html

    # ── 主生成方法 ───────────────────────────────────────────────────────────

    def generate(self, output_path: str | Path | None = None) -> Path:
        self.connect()
        try:
            summary  = self.get_summary()
            vdata    = self.get_vendor_summary()
            breakdown = self.get_category_breakdown()
            bypass_logs = self.get_bypass_logs()
            radar    = self.get_radar_data()
            vendors  = list(vdata.keys())

            # 颜色映射（随机分配或固定）
            colors = ["#e84040", "#50d060", "#60a0f0", "#f0c040", "#a060f0"]
            color_map = {v: colors[i % len(colors)] for i, v in enumerate(vendors)}

            # ── 厂商卡片
            vc_html = "".join(
                self._vendor_card(v, vdata.get(v, {}), color_map.get(v, "#888"))
                for v in vendors
            )

            # ── 分类表头
            th_v = "".join(f'<th>{v}</th>' for v in vendors)
            cat_rows, _ = self._category_rows(breakdown)

            # ── 柱状图数据
            bar_v = json.dumps(vendors)
            bar_b = json.dumps([vdata.get(v, {}).get("BLOCKED", 0) for v in vendors])
            bar_by = json.dumps([vdata.get(v, {}).get("BYPASS", 0) for v in vendors])
            bar_f = json.dumps([vdata.get(v, {}).get("FALSE_POSITIVE", 0) for v in vendors])

            # ── 饼图（绕过类型分布）
            type_counts = {}
            for log in bypass_logs:
                t = log.get("attack_type", "Other")
                type_counts[t] = type_counts.get(t, 0) + 1
            pie_data = [{"name": k, "value": v} for k, v in type_counts.items()]
            # 分配颜色
            pie_colors = ["#e84040","#f0c040","#50d060","#60a0f0","#a060f0","#f060a0","#a0f0f0"]
            for i, item in enumerate(pie_data):
                item["itemStyle"] = {"color": pie_colors[i % len(pie_colors)]}
            pie_json = json.dumps(pie_data)

            # ── 雷达图
            # 取出有数据的维度列表，并从 radar 字典中剔除辅助 key
            active_dims: list = radar.pop("__active_dims__", None) or self.RADAR_DIMENSIONS
            # 若无任何有效维度，fallback 显示全维度（值为0，让图显示轮廓）
            if not active_dims:
                active_dims = self.RADAR_DIMENSIONS

            radar_indicators = json.dumps(
                [{"name": d, "max": 100} for d in active_dims]
            )
            radar_series = []
            for vendor, scores in radar.items():
                values = [scores.get(d, 0.0) for d in active_dims]
                radar_series.append({
                    "value": values,
                    "name": vendor,
                    "lineStyle": {"color": color_map.get(vendor, "#888"), "width": 2},
                    "areaStyle": {"color": color_map.get(vendor, "#888") + "33"},
                    "itemStyle": {"color": color_map.get(vendor, "#888")}
                })
            radar_legend = json.dumps(vendors)
            radar_ind_json = radar_indicators
            radar_ser_json = json.dumps(radar_series)

            # ── 结论
            rec_vendors, rec_reason = self._build_conclusion(summary, vdata)

            # ── 渲染模板（用 replace 代替 format，避免 CSS 花括号冲突）
            replacements = {
                "{gen_time}":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "{total_payloads}":       str(summary["total"]),
                "{total_tests}":          str(summary["total"]),
                "{total_blocked}":        str(summary["blocked"]),
                "{total_bypassed}":       str(summary["bypassed"]),
                "{avg_bypass_rate}":      str(summary["avg_bypass"]),
                "{vendor_cards}":         vc_html,
                "{th_vendors}":           th_v,
                "{category_rows}":        cat_rows,
                "{bypass_count}":         str(len(bypass_logs)),
                "{bypass_items}":         self._bypass_items(bypass_logs),
                "{recommended_vendors}":  rec_vendors,
                "{conclusion_reason}":    rec_reason,
                "{bar_vendors_json}":     bar_v,
                "{bar_blocked_json}":     bar_b,
                "{bar_bypassed_json}":    bar_by,
                "{bar_false_json}":       bar_f,
                "{pie_data_json}":        pie_json,
                "{radar_indicators_json}": radar_ind_json,
                "{radar_legend_json}":    radar_legend,
                "{radar_series_json}":    radar_ser_json,
            }
            html = _HTML_TEMPLATE
            for placeholder, value in replacements.items():
                html = html.replace(placeholder, value)

            out_path = Path(output_path) if output_path else DEFAULT_OUT
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(html, encoding="utf-8")
            return out_path

        finally:
            self.close()


# ── CLI 入口 ──────────────────────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(description="生成WAF测试报告")
    parser.add_argument("--db",    default=str(DEFAULT_DB), help="SQLite数据库路径")
    parser.add_argument("--output","-o", help="HTML输出路径")
    args = parser.parse_args()

    gen = ReportGenerator(args.db)
    out = gen.generate(args.output)
    print(f"✅ 报告已生成: {out}")


if __name__ == "__main__":
    main()
