"""
WAF Bypass Tester - Web Application Firewall Security Testing Suite
Web应用防火墙安全测试工具包

模块说明：
- encoder   : 编码与混淆工具（URL/HTML/Unicode/Base64/分块传输等）
- rules_loader: 攻击规则加载与变体展开
- detector  : 响应绕过特征检测引擎
- sender    : 异步HTTP攻击请求发送端
- receiver  : 响应接收与分析端（含实时统计）
- logger_db : SQLite结构化日志持久化
- logger_csv: CSV格式导出
- report_generator: HTML报告生成（含ECharts图表）
"""

__version__ = "1.0.0"
__author__  = "WAF Testing Team"

from . import encoder
from . import detector
from . import rules_loader
from . import sender
from . import receiver
from . import logger_db
from . import logger_csv
from . import report_generator

__all__ = [
    "encoder",
    "detector",
    "rules_loader",
    "sender",
    "receiver",
    "logger_db",
    "logger_csv",
    "report_generator",
]
