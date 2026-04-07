"""
run_level2.py - Level 2 Mock 模式自动测试脚本

工作流程：
  1. 备份原 config/*.json
  2. 替换为 config/*_mock.json（指向本地 127.0.0.1）
  3. 启动 mock_waf_server.py（后台常驻）
  4. 清空旧数据库，运行测试（限定 sqli,xss,cmd 三类，轻量集）
  5. 恢复原配置
  6. 生成 HTML 报告
  7. 停止 Mock 服务器

运行：python run_level2.py
"""

import sys
import os
import json
import time
import sqlite3
import subprocess
import shutil
import atexit
import signal

# ── 项目路径 ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "config")
LOGS_DIR   = os.path.join(SCRIPT_DIR, "logs")
DB_PATH    = os.path.join(LOGS_DIR, "waf_test_results.db")
PYTHON     = os.path.join(
    os.environ.get(
        "PYTHON312",
        r"C:\Users\liubi\AppData\Local\Programs\Python\Python312\python.exe"
    )
)

# ── 颜色输出 ──────────────────────────────────────────────────────────────────
def c(icon, msg, color=""):
    COLORS = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
              "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"}
    return f"{COLORS.get(color,'')}{icon} {msg}{COLORS['reset']}"

def step(num, title):
    print()
    print(c(f"[Step {num}]", title, "cyan"))

# ── 备份 / 恢复配置 ───────────────────────────────────────────────────────────
BACKUP_DIR = os.path.join(SCRIPT_DIR, ".config_backup")

def backup_configs():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    for fname in ["vendors.json", "targets.json"]:
        src = os.path.join(CONFIG_DIR, fname)
        dst = os.path.join(BACKUP_DIR, fname)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(c("  [OK]", f"已备份 {fname}", "green"))
        else:
            print(c("  [--]", f"{fname} 不存在，跳过", "yellow"))

def restore_configs():
    for fname in ["vendors.json", "targets.json"]:
        src = os.path.join(BACKUP_DIR, fname)
        dst = os.path.join(CONFIG_DIR, fname)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(c("  [OK]", f"已恢复 {fname}", "green"))

def apply_mock_configs():
    for base in ["vendors", "targets"]:
        src = os.path.join(CONFIG_DIR, f"{base}_mock.json")
        dst = os.path.join(CONFIG_DIR, f"{base}.json")
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(c("  [OK]", f"已应用 {base}_mock.json", "green"))

# ── 清空旧数据库（保留表结构） ────────────────────────────────────────────────
def reset_db():
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("DELETE FROM logs")
            conn.commit()
            conn.close()
            print(c("  [OK]", f"已清空 logs 表（保留结构）", "green"))
        except Exception as e:
            print(c("  [!!]", f"清空失败（可能为空数据库）: {e}", "yellow"))
            conn.close()

# ── Mock 服务器进程管理 ──────────────────────────────────────────────────────
_mock_proc = None

def start_mock_server():
    global _mock_proc
    srv = os.path.join(SCRIPT_DIR, "mock_waf_server.py")
    print(c("  [..]", "正在启动 Mock WAF 服务器...", "yellow"))
    _mock_proc = subprocess.Popen(
        [PYTHON, srv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    time.sleep(3)   # 给服务器留出启动时间
    if _mock_proc.poll() is not None:
        stdout, stderr = _mock_proc.communicate()
        print(c("  [FAIL]", f"Mock 服务器启动失败:\n{stderr.decode('utf-8', errors='replace')}", "red"))
        sys.exit(1)
    print(c("  [OK]",  "Mock WAF 服务器已启动（端口 18001/18002/18003/18080）", "green"))

def stop_mock_server():
    global _mock_proc
    if _mock_proc and _mock_proc.poll() is None:
        print(c("  [..]", "正在停止 Mock WAF 服务器...", "yellow"))
        _mock_proc.terminate()
        try:
            _mock_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _mock_proc.kill()
        print(c("  [OK]", "Mock WAF 服务器已停止", "green"))

# ── 运行测试 ─────────────────────────────────────────────────────────────────
def run_tests():
    main_py = os.path.join(SCRIPT_DIR, "main.py")
    # 限定 sqli + xss + cmd 三类，轻量集快速完成 Level 2 验证
    cmd = [
        PYTHON, main_py,
        "--vendor", "all",
        "--category", "sqli,xss,cmd",
        "--threads", "5",
        "--timeout", "10",
    ]
    print(c("  [CMD]", " ".join(cmd), "yellow"))
    print()
    result = subprocess.run(cmd, cwd=SCRIPT_DIR)
    if result.returncode != 0:
        print(c("  [FAIL]", f"测试进程返回码 {result.returncode}", "red"))
    else:
        print(c("  [OK]", "测试执行完成", "green"))
    return result.returncode

# ── 生成报告 ──────────────────────────────────────────────────────────────────
def generate_report():
    os.makedirs(LOGS_DIR, exist_ok=True)
    out_path = os.path.join(LOGS_DIR, "level2_report.html")
    # 动态调用 main.py 的报告函数
    sys.path.insert(0, SCRIPT_DIR)
    import main as main_mod
    main_mod.generate_html_report(DB_PATH, out_path)
    print(c("  [OK]", f"HTML 报告已生成: {out_path}", "green"))
    return out_path

# ── 打印数据库摘要 ───────────────────────────────────────────────────────────
def print_summary():
    if not os.path.exists(DB_PATH):
        print(c("  [--]", "数据库文件不存在，跳过摘要", "yellow"))
        return
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    if total == 0:
        print(c("  [--]", "数据库为空（无测试记录）", "yellow"))
        conn.close()
        return
    rows = conn.execute(
        "SELECT vendor, result, COUNT(*) as cnt FROM logs GROUP BY vendor, result"
    ).fetchall()
    conn.close()
    print()
    print(c("  [DB Summary]", f"共 {total} 条记录", "cyan"))
    vendor_stats = {}
    for r in rows:
        vendor_stats.setdefault(r["vendor"], {})[r["result"]] = r["cnt"]
    for vendor, stats in sorted(vendor_stats.items()):
        total_v = sum(stats.values())
        bypass_v = stats.get("BYPASS", 0)
        blocked_v = stats.get("BLOCKED", 0)
        bypass_rate = bypass_v / total_v * 100 if total_v else 0
        print(f"    {vendor:12s} | 绕过 {bypass_v:3d} / 拦截 {blocked_v:3d} / 总 {total_v:3d} | "
              f"绕过率 {bypass_rate:5.1f}%")

# ── 主流程 ────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Level 2 - Mock WAF 模式自动化测试")
    print("=" * 60)
    print(f"  Python : {PYTHON}")
    print(f"  Project: {SCRIPT_DIR}")
    print(f"  DB     : {DB_PATH}")

    atexit.register(restore_configs)           # 无论如何最终要恢复配置

    step(1, "备份原始配置文件")
    backup_configs()

    step(2, "应用 Mock 配置文件（指向本地 127.0.0.1）")
    apply_mock_configs()

    step(3, "启动 Mock WAF 服务器（后台）")
    start_mock_server()

    step(4, "清空旧测试数据")
    reset_db()

    step(5, "运行 Level 2 测试（sqli + xss + cmd，轻量集）")
    rc = run_tests()

    step(6, "恢复原始配置文件")
    restore_configs()

    step(7, "停止 Mock WAF 服务器")
    stop_mock_server()

    step(8, "生成 HTML 报告")
    report_path = generate_report()

    step(9, "打印测试摘要")
    print_summary()

    print()
    print("=" * 60)
    if rc == 0:
        print(c("  [ALL DONE]", "Level 2 Mock 测试完成！", "green"))
    else:
        print(c("  [WARNING]", f"测试进程返回非零码（{rc}），请检查上方日志", "yellow"))
    print(f"  报告路径: {report_path}")
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
