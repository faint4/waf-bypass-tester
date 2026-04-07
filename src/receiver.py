"""
receiver.py - 结果接收端 & 统计分析模块
- 接收 SendResult 列表，进行统计分析
- 实时打印汇总进度和类别统计
- 生成每个厂商的防护分析报告数据
"""

import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, BarColumn, TaskProgressColumn,
    TimeElapsedColumn, TimeRemainingColumn, TextColumn, SpinnerColumn
)
from rich.text import Text
from rich import box

try:
    from .detector import BypassStatus, BypassType
    from .sender import SendResult
except ImportError:
    from detector import BypassStatus, BypassType
    from sender import SendResult

console = Console(highlight=False)


@dataclass
class CategoryStats:
    """单个攻击类别统计"""
    category: str
    total: int = 0
    blocked: int = 0
    bypassed: int = 0
    partial: int = 0
    error: int = 0
    bypass_details: list = field(default_factory=list)

    @property
    def block_rate(self) -> float:
        effective = self.total - self.error
        return self.blocked / effective if effective > 0 else 0.0

    @property
    def bypass_rate(self) -> float:
        effective = self.total - self.error
        return self.bypassed / effective if effective > 0 else 0.0


@dataclass
class VendorStats:
    """单个WAF厂商总体统计"""
    vendor_id: str
    vendor_name: str
    test_start: str = ""
    test_end: str = ""
    total_payloads: int = 0
    total_blocked: int = 0
    total_bypassed: int = 0
    total_partial: int = 0
    total_error: int = 0
    false_positive_count: int = 0
    false_positive_total: int = 0
    categories: dict = field(default_factory=lambda: defaultdict(CategoryStats))
    bypass_log: list = field(default_factory=list)  # 所有绕过记录

    @property
    def block_rate(self) -> float:
        effective = self.total_payloads - self.total_error
        return self.total_blocked / effective if effective > 0 else 0.0

    @property
    def bypass_rate(self) -> float:
        effective = self.total_payloads - self.total_error
        return self.total_bypassed / effective if effective > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        return (self.false_positive_count / self.false_positive_total
                if self.false_positive_total > 0 else 0.0)

    @property
    def score(self) -> float:
        """综合评分（0-100）
        防护率 × 60 + (1-误报率) × 20 + 响应速度评分 × 20
        """
        protection_score = self.block_rate * 60
        fp_score = (1.0 - min(self.false_positive_rate, 1.0)) * 20
        # 响应速度固定给15分（需结合实际延迟数据）
        speed_score = 15.0
        return protection_score + fp_score + speed_score


class Receiver:
    """
    结果接收端：收集SendResult，实时统计，打印汇总
    """

    def __init__(self, vendor_config: dict, total_payloads: int = 0):
        self.vendor_config = vendor_config
        self.vendor_id = vendor_config.get('id', 'unknown')
        self.vendor_name = vendor_config.get('name', 'Unknown WAF')
        self.total_payloads = total_payloads
        self.stats = VendorStats(
            vendor_id=self.vendor_id,
            vendor_name=self.vendor_name,
            test_start=datetime.datetime.now().isoformat(),
        )
        self._results: list[SendResult] = []

    def receive(self, result: SendResult):
        """接收单条结果，更新统计"""
        self._results.append(result)
        self._update_stats(result)

    def receive_batch(self, results: list[SendResult]):
        """批量接收结果"""
        for r in results:
            self.receive(r)
        self.stats.test_end = datetime.datetime.now().isoformat()

    def _update_stats(self, result: SendResult):
        """更新统计数据"""
        category = result.payload_info.get('category', 'unknown')
        is_fp = result.payload_info.get('false_positive', False)

        cat_stats = self.stats.categories[category]
        cat_stats.category = category
        cat_stats.total += 1
        self.stats.total_payloads += 1

        if is_fp:
            self.stats.false_positive_total += 1

        if result.detection:
            status = result.detection.status
            if status == BypassStatus.BLOCKED:
                cat_stats.blocked += 1
                self.stats.total_blocked += 1
                if is_fp:
                    # 正常请求被拦截 = 误报
                    self.stats.false_positive_count += 1
            elif status == BypassStatus.BYPASS:
                cat_stats.bypassed += 1
                self.stats.total_bypassed += 1
                cat_stats.bypass_details.append({
                    'payload': result.payload_info.get('payload_original', ''),
                    'encoding': result.payload_info.get('encoding', 'raw'),
                    'bypass_type': result.detection.bypass_type.value if result.detection.bypass_type else '',
                    'evidence': result.detection.evidence,
                    'http_status': result.http_status,
                })
                self.stats.bypass_log.append(result)
            elif status == BypassStatus.PARTIAL:
                cat_stats.partial += 1
                self.stats.total_partial += 1
            elif status == BypassStatus.ERROR:
                cat_stats.error += 1
                self.stats.total_error += 1
        else:
            cat_stats.error += 1
            self.stats.total_error += 1

    def print_live_summary(self, completed: int, total: int):
        """打印实时进度摘要（在进度条更新时调用）"""
        pass  # 由rich Progress处理

    def print_vendor_summary(self):
        """打印单厂商测试完成后的详细汇总表格"""
        stats = self.stats
        vendor_color = self.vendor_config.get('color', 'white')

        console.print()
        console.print(Panel(
            f"[bold]{self.vendor_name}  测试完成[/bold]",
            style=f"bold",
            border_style="bright_blue",
            expand=False
        ))

        # 总体统计表
        overview = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        overview.add_column("指标", style="cyan", width=18)
        overview.add_column("数值", justify="right", width=12)
        overview.add_column("比率", justify="right", width=10)

        effective = stats.total_payloads - stats.total_error
        overview.add_row("总Payload数量", str(stats.total_payloads), "100%")
        overview.add_row("[bold green]已拦截 (BLOCKED)", str(stats.total_blocked),
                         f"[green]{stats.block_rate:.1%}")
        overview.add_row("[bold red]已绕过 (BYPASS)",  str(stats.total_bypassed),
                         f"[red]{stats.bypass_rate:.1%}")
        overview.add_row("[yellow]需复核 (PARTIAL)", str(stats.total_partial),
                         f"[yellow]{stats.total_partial/effective:.1%}" if effective else "N/A")
        overview.add_row("[magenta]误报 (False Positive)", str(stats.false_positive_count),
                         f"[magenta]{stats.false_positive_rate:.1%}")
        overview.add_row("[bold]综合评分", f"[bold]{stats.score:.1f}/100", "")
        console.print(overview)
        console.print()

        # 分类统计表
        cat_table = Table(
            title="各攻击类别防护情况",
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold white on blue"
        )
        cat_table.add_column("攻击类别",    width=16)
        cat_table.add_column("总数",  justify="right", width=8)
        cat_table.add_column("拦截", justify="right", width=8)
        cat_table.add_column("绕过", justify="right", width=8)
        cat_table.add_column("防护率",  justify="right", width=10)
        cat_table.add_column("绕过样例(前3条)", width=50)

        for category, cs in sorted(stats.categories.items()):
            rate_color = "green" if cs.block_rate >= 0.9 else ("yellow" if cs.block_rate >= 0.7 else "red")
            examples = "; ".join(
                d['payload'][:30] + ('…' if len(d['payload']) > 30 else '')
                for d in cs.bypass_details[:3]
            )
            cat_table.add_row(
                category,
                str(cs.total),
                f"[green]{cs.blocked}",
                f"[red]{cs.bypassed}" if cs.bypassed > 0 else "0",
                f"[{rate_color}]{cs.block_rate:.1%}",
                f"[dim]{examples}" if examples else "[dim italic]无绕过",
            )

        console.print(cat_table)
        console.print()

    def get_report_data(self) -> dict:
        """返回结构化报告数据（供report_generator使用）"""
        stats = self.stats
        categories_data = {}
        for cat, cs in stats.categories.items():
            categories_data[cat] = {
                'total': cs.total,
                'blocked': cs.blocked,
                'bypassed': cs.bypassed,
                'partial': cs.partial,
                'block_rate': cs.block_rate,
                'bypass_rate': cs.bypass_rate,
                'bypass_details': cs.bypass_details,
            }

        return {
            'vendor_id': stats.vendor_id,
            'vendor_name': stats.vendor_name,
            'test_start': stats.test_start,
            'test_end': stats.test_end,
            'total_payloads': stats.total_payloads,
            'total_blocked': stats.total_blocked,
            'total_bypassed': stats.total_bypassed,
            'total_partial': stats.total_partial,
            'total_error': stats.total_error,
            'block_rate': stats.block_rate,
            'bypass_rate': stats.bypass_rate,
            'false_positive_rate': stats.false_positive_rate,
            'score': stats.score,
            'categories': categories_data,
        }


def print_comparison_table(all_stats: list[dict]):
    """打印三厂商横向对比表"""
    console.print()
    console.print(Panel(
        "[bold white]三厂商横向对比汇总[/bold white]",
        border_style="bright_yellow",
        expand=False
    ))

    table = Table(
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold white on dark_blue"
    )
    table.add_column("指标",        width=18, style="cyan")
    for s in all_stats:
        table.add_column(s['vendor_name'], width=14, justify="center")

    # 防护率
    block_rates = [s['block_rate'] for s in all_stats]
    max_block = max(block_rates) if block_rates else 0
    row = ["防护率 (越高越好)"]
    for s in all_stats:
        color = "bold green" if s['block_rate'] == max_block else "white"
        row.append(f"[{color}]{s['block_rate']:.1%}")
    table.add_row(*row)

    # 绕过率
    bypass_rates = [s['bypass_rate'] for s in all_stats]
    min_bypass = min(bypass_rates) if bypass_rates else 0
    row = ["绕过率 (越低越好)"]
    for s in all_stats:
        color = "bold green" if s['bypass_rate'] == min_bypass else "red"
        row.append(f"[{color}]{s['bypass_rate']:.1%}")
    table.add_row(*row)

    # 误报率
    fp_rates = [s['false_positive_rate'] for s in all_stats]
    min_fp = min(fp_rates) if fp_rates else 0
    row = ["误报率 (越低越好)"]
    for s in all_stats:
        color = "bold green" if s['false_positive_rate'] == min_fp else "yellow"
        row.append(f"[{color}]{s['false_positive_rate']:.1%}")
    table.add_row(*row)

    # 综合评分
    scores = [s['score'] for s in all_stats]
    max_score = max(scores) if scores else 0
    row = ["综合评分 (/100)"]
    for s in all_stats:
        color = "bold green" if s['score'] == max_score else "white"
        row.append(f"[{color}]{s['score']:.1f}")
    table.add_row(*row)

    console.print(table)
    console.print()

    # 采购建议
    sorted_stats = sorted(all_stats, key=lambda x: x['score'], reverse=True)
    if len(sorted_stats) >= 2:
        winner1 = sorted_stats[0]
        winner2 = sorted_stats[1]
        loser   = sorted_stats[2] if len(sorted_stats) >= 3 else None

        console.print(Panel(
            f"🏆 [bold green]推荐采购: {winner1['vendor_name']}（{winner1['score']:.1f}分）"
            f" + {winner2['vendor_name']}（{winner2['score']:.1f}分）[/bold green]\n"
            + (f"❌ [bold red]淘汰: {loser['vendor_name']}（{loser['score']:.1f}分）[/bold red]"
               if loser else ""),
            title="[bold yellow]三选二采购结论[/bold yellow]",
            border_style="bright_yellow",
            expand=False
        ))


def make_progress_bar(total: int, vendor_name: str):
    """创建Rich进度条"""
    return Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]{vendor_name}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("[dim]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        refresh_per_second=5,
    )
