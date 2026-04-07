# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-07

### Added

- **三厂商 WAF 横向对比测试**
  - 深信服 WAF 支持（串联透明桥模式）
  - 长亭雷池 WAF 支持
  - 绿盟 WAF 支持
  - 三厂商统一 Payload 横向评测

- **攻击规则引擎**
  - 12 类攻击规则：SQL 注入、XSS、命令注入、SSRF、LFI、路径遍历、NoSQL 注入、SSTI、文件上传、认证绕过、CVE 利用
  - 557 条 Payload 增强变体（含编码展开）
  - `bypass_transforms.json` 全局编码增强规则
  - 支持在 `rules/` 目录添加自定义 JSON 规则文件

- **13 种编码绕过技术**
  - URL 双重编码（72% 成功率绕过率）
  - 分块传输编码（83% 成功率）
  - SQL 注释插入（内联注释 / 行注释）
  - Unicode 规范化（UTF-7 / UTF-16 / 宽字节）
  - HTML 实体编码（数字 / 实体混用）
  - Base64 编码
  - Null 字节截断
  - 大小写混合混淆
  - 路径规范化混淆

- **异步并发测试引擎**
  - httpx + asyncio 异步架构
  - 可配置并发线程数（默认 10）
  - HTTP/HTTPS 代理支持（含 Burp Suite）
  - 请求超时和重试机制
  - 断点续测支持（跳过已完成 Payload）

- **实时日志与可视化**
  - Rich 彩色控制台输出（✅BLOCKED / 🔴BYPASS / 🟡PARTIAL / ⚠️ERROR）
  - 实时进度条和统计表格
  - Payload 级别详细日志（请求 / 响应 / 绕过证据）

- **双格式日志持久化**
  - SQLite 数据库（精确查询 / 统计分析）
  - CSV 导出（Excel 直接打开）

- **HTML 报告生成器**
  - ECharts 柱状图（三厂商防护率对比）
  - ECharts 雷达图（各厂商多维度能力对比）
  - ECharts 饼图（绕过事件分布）
  - 三厂商横向对比总览卡片
  - 自动推荐采购结论

- **配置系统**
  - `config/vendors.json` — 厂商代理 IP / 拦截码 / 拦截关键词
  - `config/targets.json` — 靶机 IP / 端口 / 认证凭证 / 测试路径
  - `config/*.example` — 模板文件（占位符 IP，gitignore 原文件）
