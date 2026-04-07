"""
rules_loader.py - Payload规则加载器
- 扫描 rules/ 目录加载所有JSON规则文件
- 支持Payload变体自动展开（基础Payload × 编码变体）
- 支持过滤指定攻击类别
"""

import json
import os
import glob
from pathlib import Path
from typing import Generator

# encoder 可能以相对或绝对方式导入，统一尝试两种路径
try:
    from .encoder import get_variants, CATEGORY_DEFAULT_ENCODINGS
except ImportError:
    from encoder import get_variants, CATEGORY_DEFAULT_ENCODINGS


# rules/ 目录默认路径（相对于项目根目录）
DEFAULT_RULES_DIR = Path(__file__).parent.parent / 'rules'


def load_rule_file(filepath: str) -> dict:
    """加载单个规则JSON文件"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_all_rules(rules_dir: str = None, categories: list[str] = None) -> dict:
    """
    扫描rules/目录，加载所有规则文件

    Args:
        rules_dir: 规则目录路径，默认为 ../rules/
        categories: 限定加载的类别列表，None表示全部加载

    Returns:
        dict: {category_name: rule_data}
    """
    if rules_dir is None:
        rules_dir = DEFAULT_RULES_DIR

    rules = {}
    pattern = os.path.join(str(rules_dir), '*.json')
    files = glob.glob(pattern)

    for filepath in sorted(files):
        filename = os.path.basename(filepath)
        category = filename.replace('.json', '')

        # bypass_transforms 不算攻击类别，单独处理
        if category == 'bypass_transforms':
            continue

        if categories and category not in categories:
            continue

        try:
            rule_data = load_rule_file(filepath)
            rules[category] = rule_data
        except (json.JSONDecodeError, IOError) as e:
            print(f"[WARN] 加载规则文件失败: {filepath} → {e}")

    return rules


def load_bypass_transforms(rules_dir: str = None) -> dict:
    """加载全局bypass_transforms.json"""
    if rules_dir is None:
        rules_dir = DEFAULT_RULES_DIR

    transforms_file = os.path.join(str(rules_dir), 'bypass_transforms.json')
    if os.path.exists(transforms_file):
        return load_rule_file(transforms_file)
    return {}


def expand_payload_variants(
    rule: dict,
    category: str,
    global_transforms: dict = None,
    expand_encodings: bool = True
) -> list[dict]:
    """
    展开单条规则为多个Payload变体

    Args:
        rule: 单条规则字典，包含 payload、method、target_module 等
        category: 攻击类别（sqli/xss/cmd等）
        global_transforms: 全局变体配置
        expand_encodings: 是否展开编码变体

    Returns:
        List[dict]: 展开后的Payload列表
    """
    results = []
    base_payload = rule.get('payload', '')
    if not base_payload:
        return results

    # 从规则文件中获取允许的编码列表，或使用类别默认值
    encodings_override = rule.get('encodings')
    if encodings_override:
        encodings = encodings_override
    elif expand_encodings:
        encodings = CATEGORY_DEFAULT_ENCODINGS.get(category,
                     CATEGORY_DEFAULT_ENCODINGS['default'])
    else:
        encodings = ['raw']

    # 生成所有编码变体
    variants = get_variants(base_payload, encodings)

    for variant in variants:
        entry = {
            # 核心字段
            'category':         category,
            'subcategory':      rule.get('subcategory', ''),
            'payload_original': base_payload,
            'payload_encoded':  variant['payload'],
            'encoding':         variant['encoding'],

            # 请求配置
            'method':           rule.get('method', 'GET').upper(),
            'param_name':       rule.get('param_name', 'id'),
            'param_location':   rule.get('param_location', 'query'),  # query/body/header/cookie/path
            'target_module':    rule.get('target_module', ''),
            'target_vm':        rule.get('target_vm', ''),

            # 附加请求头/Cookie
            'extra_headers':    rule.get('extra_headers', {}),
            'extra_cookies':    rule.get('extra_cookies', {}),
            'body_template':    rule.get('body_template', ''),  # 用于POST请求体模板

            # 检测配置
            'expected_blocked': rule.get('expected_blocked', True),
            'bypass_indicators': rule.get('bypass_indicators', []),
            'false_positive':   rule.get('false_positive', False),

            # 元数据
            'description':      rule.get('description', ''),
            'owasp':            rule.get('owasp', ''),
            'severity':         rule.get('severity', 'HIGH'),
            'reference':        rule.get('reference', ''),

            # 特殊标记
            'use_chunked':      rule.get('use_chunked', False),
            'use_hpp':          rule.get('use_hpp', False),  # HTTP参数污染
            'use_oversized':    rule.get('use_oversized', False),  # 超大包
        }
        results.append(entry)

    return results


def iter_all_payloads(
    rules_dir: str = None,
    categories: list[str] = None,
    expand_encodings: bool = True,
    include_false_positives: bool = False
) -> Generator[dict, None, None]:
    """
    生成器：迭代所有Payload变体

    Args:
        rules_dir: 规则目录
        categories: 限定类别
        expand_encodings: 是否展开编码变体
        include_false_positives: 是否包含误报测试Payload

    Yields:
        dict: 单条展开后的Payload信息
    """
    rules_all = load_all_rules(rules_dir, categories)
    global_transforms = load_bypass_transforms(rules_dir)

    for category, rule_data in rules_all.items():
        payloads_list = rule_data.get('payloads', [])

        for rule in payloads_list:
            # 误报测试Payload
            if rule.get('false_positive', False) and not include_false_positives:
                continue

            variants = expand_payload_variants(
                rule, category, global_transforms, expand_encodings
            )
            for v in variants:
                yield v


def count_total_payloads(
    rules_dir: str = None,
    categories: list[str] = None,
    expand_encodings: bool = True
) -> tuple[int, dict]:
    """
    统计总Payload数量

    Returns:
        (total_count, per_category_count)
    """
    total = 0
    per_cat = {}

    for payload in iter_all_payloads(rules_dir, categories, expand_encodings):
        cat = payload['category']
        per_cat[cat] = per_cat.get(cat, 0) + 1
        total += 1

    return total, per_cat


def get_rules_summary(rules_dir: str = None) -> str:
    """生成规则摘要文本"""
    rules_all = load_all_rules(rules_dir)
    lines = ["规则摘要:"]
    total_base = 0
    for category, data in rules_all.items():
        base_count = len(data.get('payloads', []))
        encodings = CATEGORY_DEFAULT_ENCODINGS.get(category,
                    CATEGORY_DEFAULT_ENCODINGS['default'])
        expanded = base_count * len(encodings)
        total_base += base_count
        lines.append(
            f"  [{category:20s}] 基础: {base_count:4d}  编码变体: {len(encodings):2d}  "
            f"展开后: {expanded:5d}"
        )
    total_count, _ = count_total_payloads(rules_dir)
    lines.append(f"\n  总基础Payload: {total_base}")
    lines.append(f"  总展开Payload: {total_count}")
    return '\n'.join(lines)


if __name__ == '__main__':
    summary = get_rules_summary()
    print(summary)
