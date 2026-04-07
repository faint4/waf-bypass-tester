"""
sender.py - 异步攻击发送端
- 异步并发发送Payload（httpx + asyncio）
- 实时彩色控制台输出（rich）
- 支持HTTP/SOCKS代理（WAF串联链路）
- 支持GET/POST/PUT等方法，multipart表单
- 超时重试机制
- 分块传输编码、HTTP参数污染
"""

import asyncio
import time
import json
import httpx
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from rich.console import Console
from rich.text import Text

try:
    from .detector import detect_bypass, BypassStatus, DetectionResult
    from .encoder import build_chunked_body
except ImportError:
    from detector import detect_bypass, BypassStatus, DetectionResult
    from encoder import build_chunked_body

# 全局Rich控制台（线程安全）
console = Console(highlight=False)

# ANSI颜色方案
STATUS_STYLE = {
    BypassStatus.BYPASS:  "bold red",
    BypassStatus.BLOCKED: "bold green",
    BypassStatus.PARTIAL: "bold yellow",
    BypassStatus.UNKNOWN: "dim",
    BypassStatus.ERROR:   "bold magenta",
}

STATUS_ICON = {
    BypassStatus.BYPASS:  "🔴 BYPASS  ",
    BypassStatus.BLOCKED: "✅ BLOCKED ",
    BypassStatus.PARTIAL: "🟡 PARTIAL ",
    BypassStatus.UNKNOWN: "⚪ UNKNOWN ",
    BypassStatus.ERROR:   "❌ ERROR   ",
}


@dataclass
class SendResult:
    """单次发送结果"""
    payload_info: dict
    http_status: int = 0
    response_body: str = ""
    response_headers: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    detection: Optional[DetectionResult] = None
    error: str = ""
    request_url: str = ""
    request_method: str = ""
    request_body: str = ""
    vendor_id: str = ""
    target_id: str = ""
    timestamp: str = ""


def _build_target_url(payload_info: dict, target_config: dict) -> str:
    """构建目标URL（将PAYLOAD占位符替换为实际payload）"""
    target_vm = payload_info.get('target_vm', '')
    target_module = payload_info.get('target_module', 'default')
    payload_encoded = payload_info.get('payload_encoded', '')

    # 找到目标配置
    host = target_config.get('host', '127.0.0.1')
    port = target_config.get('port', 80)
    protocol = target_config.get('protocol', 'http')
    modules = target_config.get('modules', {})

    path = modules.get(target_module, '/')
    # 替换PAYLOAD占位符
    if 'PAYLOAD' in path:
        path = path.replace('PAYLOAD', payload_encoded)

    base_url = f"{protocol}://{host}:{port}"
    return base_url + path


def _build_request_params(payload_info: dict) -> dict:
    """
    构建HTTP请求参数
    Returns: dict with keys: method, url_path, params, data, headers, cookies
    """
    method = payload_info.get('method', 'GET').upper()
    param_name = payload_info.get('param_name', 'id')
    param_location = payload_info.get('param_location', 'query')
    payload_encoded = payload_info.get('payload_encoded', '')
    body_template = payload_info.get('body_template', '')
    extra_headers = payload_info.get('extra_headers', {})
    extra_cookies = payload_info.get('extra_cookies', {})

    params = {}
    data = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'keep-alive',
    }
    headers.update({k: v.replace('PAYLOAD', payload_encoded) if v == 'PAYLOAD' else v
                    for k, v in extra_headers.items()})
    cookies = {k: v.replace('PAYLOAD', payload_encoded) if v == 'PAYLOAD' else v
               for k, v in extra_cookies.items()}

    if param_location == 'query':
        params[param_name] = payload_encoded
    elif param_location == 'body':
        if body_template:
            # 使用模板替换
            data_str = body_template.replace('PAYLOAD', payload_encoded)
            # 解析application/x-www-form-urlencoded
            data = dict(pair.split('=', 1) for pair in data_str.split('&') if '=' in pair)
        else:
            data[param_name] = payload_encoded
    elif param_location == 'header':
        # 参数在请求头中
        headers[param_name] = payload_encoded
    elif param_location == 'cookie':
        cookies[param_name] = payload_encoded
    elif param_location == 'multipart':
        # 文件上传，由调用方特殊处理
        pass

    return {
        'method': method,
        'params': params,
        'data': data,
        'headers': headers,
        'cookies': cookies,
    }


def _build_proxy(vendor_config: dict, burp_proxy: str = None) -> Optional[str]:
    """构建代理URL"""
    if burp_proxy:
        return burp_proxy

    proxy_cfg = vendor_config.get('proxy', {})
    if not proxy_cfg or not proxy_cfg.get('enabled', False):
        return None

    host = proxy_cfg.get('host', '')
    port = proxy_cfg.get('port', 8080)
    ptype = proxy_cfg.get('type', 'http')

    if host:
        return f"{ptype}://{host}:{port}"
    return None


def _print_result(
    result: SendResult,
    vendor_name: str,
    seq: int,
    total: int
):
    """实时打印单条测试结果到控制台"""
    detection = result.detection
    status = detection.status if detection else BypassStatus.UNKNOWN
    style = STATUS_STYLE.get(status, "")
    icon = STATUS_ICON.get(status, "⚪ UNKNOWN")

    category = result.payload_info.get('category', '').upper()
    payload_orig = result.payload_info.get('payload_original', '')
    # 截短payload显示
    payload_display = payload_orig[:45] + '…' if len(payload_orig) > 45 else payload_orig

    encoding = result.payload_info.get('encoding', 'raw')
    target_vm = result.payload_info.get('target_vm', '')

    # 进度 [seq/total]
    progress = f"[{seq:4d}/{total}]"

    # 主行
    line = Text()
    line.append(f"[{result.timestamp[11:19]}] ", style="dim")
    line.append(icon, style=style)
    line.append(f" [{category:<12}]", style="cyan")
    line.append(f"  {payload_display:<46}", style="white")
    line.append(f"  →  {target_vm:<12}", style="blue")
    line.append(f"  HTTP/{result.http_status}", style="yellow")
    line.append(f"  [{result.duration_ms:.0f}ms]", style="dim")
    if encoding != 'raw':
        line.append(f"  ({encoding})", style="dim cyan")
    console.print(line)

    # 绕过详情（仅BYPASS/PARTIAL打印额外行）
    if detection and status in (BypassStatus.BYPASS, BypassStatus.PARTIAL):
        detail = Text()
        detail.append("           └─ ", style="dim")
        if detection.bypass_type:
            detail.append(f"绕过类型: {detection.bypass_type.value}", style=style)
        detail.append(f" | 证据: {detection.evidence[:80]}", style="yellow")
        console.print(detail)


def _print_error(result: SendResult, seq: int, total: int):
    """打印错误信息"""
    payload_orig = result.payload_info.get('payload_original', '')[:30]
    console.print(
        f"[{result.timestamp[11:19]}] ❌ ERROR    [{result.payload_info.get('category','?').upper():<12}]"
        f"  {payload_orig:<32}  → {result.error[:60]}",
        style="bold magenta"
    )


async def send_single_payload(
    payload_info: dict,
    target_config: dict,
    vendor_config: dict,
    client: httpx.AsyncClient,
    seq: int = 0,
    total: int = 0,
    print_results: bool = True
) -> SendResult:
    """
    异步发送单条Payload

    Args:
        payload_info:   展开后的Payload字典
        target_config:  目标靶机配置
        vendor_config:  WAF厂商配置
        client:         httpx异步客户端（复用）
        seq/total:      进度序号，用于日志
        print_results:  是否实时打印结果

    Returns:
        SendResult
    """
    import datetime
    timestamp = datetime.datetime.now().isoformat(timespec='milliseconds')

    result = SendResult(
        payload_info=payload_info,
        vendor_id=vendor_config.get('id', ''),
        target_id=target_config.get('id', ''),
        timestamp=timestamp,
    )

    try:
        # 构建请求参数
        url = _build_target_url(payload_info, target_config)
        req_params = _build_request_params(payload_info)

        result.request_url = url
        result.request_method = req_params['method']

        # 分块传输编码特殊处理
        use_chunked = payload_info.get('use_chunked', False)
        extra_headers = req_params['headers'].copy()
        content = None

        if use_chunked and req_params['method'] in ('POST', 'PUT'):
            body_str = '&'.join(f'{k}={v}' for k, v in req_params['data'].items())
            chunked = build_chunked_body(body_str)
            content = chunked.encode('utf-8')
            extra_headers['Transfer-Encoding'] = 'chunked'
            extra_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            req_params['data'] = {}

        # 文件上传处理
        param_location = payload_info.get('param_location', 'query')
        files = None
        if param_location == 'multipart':
            payload_encoded = payload_info.get('payload_encoded', '')
            subcategory = payload_info.get('subcategory', '')
            # 根据subcategory决定扩展名
            ext_map = {
                'double_ext': 'shell.php.jpg',
                'htaccess': '.htaccess',
                'gif_header': 'shell.jpg',
                'svgz': 'shell.svg',
                'jsp': 'shell.jsp',
                'aspx': 'shell.aspx',
                'case_bypass': 'shell.pHp',
            }
            filename = ext_map.get(subcategory, 'shell.php')
            mime_map = {
                'gif_header': 'image/gif',
                'svgz': 'image/svg+xml',
                'mime_fake': 'image/jpeg',
                'mime_bypass': 'image/jpeg',
            }
            mime = mime_map.get(subcategory, 'application/octet-stream')
            files = {'file': (filename, payload_encoded.encode(), mime)}
            req_params['data'] = {}
            content = None

        # 发送请求
        start_time = time.monotonic()

        timeout_val = vendor_config.get('timeout', 15)

        if req_params['method'] == 'GET':
            resp = await client.get(
                url,
                params=req_params['params'],
                headers=extra_headers,
                cookies=req_params['cookies'],
            )
        elif req_params['method'] == 'POST':
            if files:
                resp = await client.post(
                    url,
                    files=files,
                    headers=extra_headers,
                    cookies=req_params['cookies'],
                )
            elif content:
                resp = await client.post(
                    url,
                    content=content,
                    headers=extra_headers,
                    cookies=req_params['cookies'],
                )
            else:
                resp = await client.post(
                    url,
                    data=req_params['data'],
                    headers=extra_headers,
                    cookies=req_params['cookies'],
                )
        else:
            resp = await client.request(
                req_params['method'],
                url,
                params=req_params['params'],
                data=req_params['data'],
                headers=extra_headers,
                cookies=req_params['cookies'],
            )

        duration = (time.monotonic() - start_time) * 1000

        result.http_status = resp.status_code
        result.response_body = resp.text
        result.response_headers = dict(resp.headers)
        result.duration_ms = duration

        # 检测绕过
        detection = detect_bypass(
            response_status=resp.status_code,
            response_body=resp.text,
            response_headers=dict(resp.headers),
            payload_info=payload_info,
            vendor_config=vendor_config,
        )
        result.detection = detection

    except httpx.TimeoutException:
        result.error = "请求超时"
        result.detection = DetectionResult(
            status=BypassStatus.ERROR,
            evidence="请求超时"
        )
    except httpx.ConnectError as e:
        result.error = f"连接失败: {e}"
        result.detection = DetectionResult(
            status=BypassStatus.ERROR,
            evidence=f"连接失败: {e}"
        )
    except Exception as e:
        result.error = str(e)
        result.detection = DetectionResult(
            status=BypassStatus.ERROR,
            evidence=str(e)
        )

    # 实时打印
    if print_results:
        if result.error:
            _print_error(result, seq, total)
        else:
            _print_result(result, vendor_config.get('name', ''), seq, total)

    return result


async def send_batch(
    payloads: list[dict],
    targets_config: dict,
    vendor_config: dict,
    concurrency: int = 20,
    delay: float = 0.0,
    retries: int = 2,
    burp_proxy: str = None,
    print_results: bool = True,
    progress_callback: Optional[Callable[[int, int], Any]] = None,
    verify_ssl: bool = False
) -> list[SendResult]:
    """
    批量异步发送所有Payload

    Args:
        payloads:           Payload列表（已展开编码变体）
        targets_config:     靶机配置字典 {target_id: config}
        vendor_config:      WAF厂商配置
        concurrency:        并发数（默认20）
        delay:              每个请求间隔秒数（默认0，测试时可设0.1）
        retries:            失败重试次数
        burp_proxy:         Burp Suite代理（可选，调试用）
        print_results:      是否实时打印结果
        progress_callback:  进度回调 callback(completed, total)
        verify_ssl:         是否验证SSL证书

    Returns:
        List[SendResult]
    """
    proxy_url = _build_proxy(vendor_config, burp_proxy)
    total = len(payloads)
    results: list[SendResult] = []
    semaphore = asyncio.Semaphore(concurrency)

    timeout_val = vendor_config.get('timeout', 15)
    timeout = httpx.Timeout(timeout_val, connect=10.0)

    # 构建 targets 索引
    targets_by_id = {t['id']: t for t in targets_config.get('targets', [])}

    async def run_with_retry(payload_info: dict, seq: int, client: httpx.AsyncClient) -> SendResult:
        target_id = payload_info.get('target_vm', '')
        target_cfg = targets_by_id.get(target_id, {})
        if not target_cfg:
            # 找第一个enabled的靶机作为fallback
            for t in targets_config.get('targets', []):
                if t.get('enabled', True):
                    target_cfg = t
                    break

        last_result = None
        for attempt in range(retries + 1):
            async with semaphore:
                r = await send_single_payload(
                    payload_info, target_cfg, vendor_config,
                    client, seq, total,
                    print_results=(print_results and attempt == 0)
                )
                last_result = r
                if not r.error:
                    break
                if attempt < retries:
                    await asyncio.sleep(1.0)  # 重试前等1秒
        if delay > 0:
            await asyncio.sleep(delay)
        return last_result

    proxies = {"all://": proxy_url} if proxy_url else None

    async with httpx.AsyncClient(
        timeout=timeout,
        proxies=proxies,
        verify=verify_ssl,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency)
    ) as client:
        tasks = [
            asyncio.create_task(run_with_retry(p, i + 1, client))
            for i, p in enumerate(payloads)
        ]

        completed = 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            completed += 1
            if progress_callback:
                progress_callback(completed, total)

    return results
