# WAF Bypass Tester

> 自动化 Web 应用防火墙（WAF）安全评估工具 — 支持深信服、长亭、绿盟三厂商横向对比测试，输出 ECharts 可视化报告，辅助三选二采购决策。

**⚠️ 仅限授权测试环境使用，禁止对非授权系统发起攻击。**

---

## 功能特性

| 特性 | 说明 |
|------|------|
| **三厂商横向测试** | 深信服 / 长亭雷池 / 绿盟，统一 Payload 同时评测 |
| **557 条增强变体** | SQL注入、XSS、命令注入、SSRF、LFI、路径遍历、NoSQL、SSTI、文件上传、CVE 等 12 类 |
| **13 种编码绕过** | URL双重编码、分块传输、SQL注释插入、Unicode规范化、HTML实体、空字节截断… |
| **异步并发引擎** | httpx + asyncio，线程数可配，支持代理、重试、超时控制 |
| **实时彩色输出** | Rich 表格实时展示：✅BLOCKED / 🔴BYPASS / 🟡PARTIAL |
| **断点续测** | 中断后可恢复，跳过已完成 Payload |
| **双日志格式** | SQLite（精确查询）+ CSV（Excel直接打开） |
| **ECharts 报告** | 柱状图 / 雷达图（仅展示有实测数据的维度）/ 饼图，绕过事件按分组折叠展示 |
| **Level 2 Mock 模式** | 无需真实 WAF 环境，本地 Mock 服务器全流程演练，一键生成对比报告 |

---

## 项目结构

```
waf_bypass_tester/
├── main.py                      # CLI 入口（全流程调度）
├── run_level2.py                # Level 2 Mock 模式一键测试脚本
├── src/
│   ├── encoder.py               # 13 种 WAF 绕过编码工具
│   ├── detector.py              # 绕过特征检测引擎（SQL/XSS/CMD/LFI/SSRF/SSTI 正则）
│   ├── rules_loader.py          # JSON 规则加载 + 编码变体自动展开
│   ├── sender.py                # 异步 HTTP 发送端（httpx / 代理 / 重试）
│   ├── receiver.py              # 接收端（VendorStats / CategoryStats / Rich 表格）
│   ├── logger_db.py             # SQLite 结构化日志
│   ├── logger_csv.py            # CSV 导出
│   └── report_generator.py      # HTML 报告生成（ECharts 图表）
├── rules/                       # 攻击规则（展开后 557 条变体）
│   ├── sqli.json     (168 条)
│   ├── xss.json      (111 条)
│   ├── cmd.json       (66 条)
│   ├── ssrf.json      (48 条)
│   ├── lfi.json       (36 条)
│   ├── ssti.json      (32 条)
│   ├── upload.json    (28 条)
│   ├── nosql.json     (24 条)
│   ├── auth_bypass.json (15 条)
│   ├── path_traversal.json (19 条)
│   ├── cve.json       (10 条)
│   └── bypass_transforms.json   # 全局编码增强规则
├── config/
│   ├── vendors.json             # ⚠️ 本地配置（IP/凭证，gitignore，勿提交）
│   ├── vendors.json.example     # 发布模板（占位符 IP）
│   ├── targets.json             # ⚠️ 本地靶机配置（勿提交）
│   └── targets.json.example     # 发布模板（占位符 IP）
├── logs/                        # 运行日志（gitignore）
├── requirements.txt
├── LICENSE
├── README.md
├── CHANGELOG.md
└── ARCHITECTURE.md
```

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置靶机和 WAF

复制模板文件，填写实际 IP：

```bash
cp config/vendors.json.example config/vendors.json
cp config/targets.json.example config/targets.json
```

编辑 `config/vendors.json`，填写 WAF 代理 IP：

```json
"proxy": {
  "host": "192.168.1.10",
  "port": 8080
}
```

编辑 `config/targets.json`，填写靶机 IP 和登录凭证。

### 3. 运行测试

```bash
# 测试深信服，全分类
python main.py --vendor sangfor --threads 20

# 测试指定分类
python main.py --vendor chaitin --category sqli,xss,cmd --threads 20

# 三厂商全测 + 生成报告
python main.py --vendor all --threads 20 --report

# 通过 Burp Suite 代理（抓包分析）
python main.py --vendor all --category sqli --proxy http://127.0.0.1:8080

# 断点续测（中断后可恢复）
python main.py --resume --threads 20

# 仅生成报告（不重新测试，从已有数据库生成）
python main.py --report-only --db logs/test_results.db --output logs/report.html

# 查看帮助
python main.py --help
```

### 4. 查看报告

报告自动生成在 `logs/` 目录：

- `sangfor_report.html` — 深信服 WAF 详细报告
- `chaitin_report.html` — 长亭 WAF 详细报告
- `nsfocus_report.html` — 绿盟 WAF 详细报告
- `all_comparison.html` — **三厂商横向对比报告（含推荐采购结论）**

---

## Level 2 Mock 模式（无需真实 WAF）

`run_level2.py` 提供了一套**全本地 Mock 模拟**流程，无需部署真实 WAF 设备即可完整演练测试链路、验证报告生成效果。

### 工作原理

```
run_level2.py
  ├── Step 1  备份 config/*.json
  ├── Step 2  写入 mock 配置（指向 127.0.0.1）
  ├── Step 3  启动 mock_waf_server.py（本地 Flask 服务，模拟 WAF 拦截/放行响应）
  ├── Step 4  清空旧数据库，执行测试（仅 sqli / xss / cmd 三类，轻量集）
  ├── Step 5  恢复原配置
  ├── Step 6  生成 HTML 对比报告
  └── Step 7  停止 Mock 服务器
```

### 运行方式

```bash
python run_level2.py
```

> Mock 服务器文件 `mock_waf_server.py` 和 `config/*_mock.json` 为本地测试专用，已加入 `.gitignore`，不提交到仓库。使用前需自行在项目根目录创建：
>
> - `mock_waf_server.py` — 本地 Flask WAF 模拟服务器
> - `config/vendors_mock.json` — Mock 模式厂商配置（代理指向 127.0.0.1）
> - `config/targets_mock.json` — Mock 模式靶机配置

---

## CLI 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--vendor` | 厂商：`sangfor` / `chaitin` / `nsfocus` / `all` | 必填 |
| `--category` | 攻击分类（逗号分隔） | 全部 |
| `--threads` | 并发线程数 | 10 |
| `--proxy` | 外部 HTTP 代理（如 Burp Suite） | 无 |
| `--report` | 测试完成后生成 HTML 报告 | False |
| `--report-only` | 仅从已有 DB 生成报告 | False |
| `--db` | 指定 SQLite 数据库路径 | `logs/test_results.db` |
| `--output` | 报告输出路径 | 自动生成 |
| `--resume` | 断点续测（跳过已完成 Payload） | False |
| `--target` | 指定靶机 ID | 全部启用靶机 |

---

## 报告说明

报告包含以下 ECharts 可视化图表：

1. **三厂商防护率柱状图** — 拦截率 / 绕过率 / 误报率横向对比
2. **雷达图** — 各厂商在不同攻击类型下的防护能力（仅展示有实测数据的维度，避免无意义的全零轮廓）
3. **绕过事件饼图** — 各攻击类别的绕过事件分布
4. **总览卡片** — 三厂商关键指标汇总 + 推荐采购结论
5. **绕过详情（分组折叠）** — 按「厂商 + 攻击类型」分组，点击展开/收起，避免大量记录平铺

---

## Payload 统计

| 攻击类别 | 规则文件 | 变体数量 |
|---------|---------|---------|
| SQL 注入 | sqli.json | 168 |
| XSS 跨站脚本 | xss.json | 111 |
| 命令注入 | cmd.json | 66 |
| SSRF | ssrf.json | 48 |
| 模板注入 SSTI | ssti.json | 32 |
| 文件上传绕过 | upload.json | 28 |
| NoSQL 注入 | nosql.json | 24 |
| 认证绕过 | auth_bypass.json | 15 |
| 路径遍历 | path_traversal.json | 19 |
| 文件包含 LFI | lfi.json | 36 |
| CVE 利用 | cve.json | 10 |
| **合计** | | **557** |

---

## 开发说明

### 模块说明

| 模块 | 职责 |
|------|------|
| `encoder.py` | Payload 编码变体生成（URL/HTML/Unicode/Base64/SQL注释等 13 种） |
| `detector.py` | 响应分析，检测绕过特征（SQL错误/XSS触发/命令回显等） |
| `rules_loader.py` | 解析 `rules/*.json`，调用 encoder 展开编码变体 |
| `sender.py` | 异步 HTTP 请求发送，含代理支持、重试机制 |
| `receiver.py` | 收集结果，更新统计表格（VendorStats / CategoryStats） |
| `logger_db.py` | SQLite 持久化 |
| `logger_csv.py` | CSV 导出 |
| `report_generator.py` | HTML + ECharts 报告生成（雷达图自适应维度 + 绕过详情折叠） |
| `run_level2.py` | Level 2 Mock 模式全流程自动化脚本 |

### 扩展攻击规则

在 `rules/` 目录下添加新的 `xxx.json` 文件即可自动加载：

```json
[
  {
    "id": "my-001",
    "payload": "' OR 1=1 --",
    "attack_type": "sqli",
    "method": "GET",
    "param_name": "id",
    "target_module": "sqli",
    "target_vm": "dvwa",
    "description": "基础 SQL 注入",
    "owasp": "A03",
    "severity": "HIGH",
    "expected_blocked": true
  }
]
```

> **注意**：`attack_type` 字段请使用短名（`sqli` / `xss` / `cmd` / `ssrf` / `lfi` / `ssti` / `upload` / `nosql` / `auth_bypass` / `path_traversal`），报告雷达图会自动映射到对应防护维度。

---

## 参考资料

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [Advanced SQL Injection Bypass Techniques (kleiton0x00)](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet)
- [nemesida-waf/waf-bypass](https://github.com/nemesida-waf/waf-bypass)

---

## 免责声明

本工具仅供以下场景使用：
- **授权的红蓝对抗 / 渗透测试项目**
- **企业内部 WAF 选型测评**
- **CTF 比赛 / 教育培训环境**

禁止将本工具用于任何未经授权的系统。违者须自行承担法律责任。
