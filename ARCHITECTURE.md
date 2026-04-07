# Architecture

## Overview

The WAF Bypass Tester follows a producer-consumer architecture with the following layers:

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI (main.py)                          │
│  argparse → resolve vendors → load config → orchestrate    │
└────────────────┬────────────────────────────────────────────┘
                 │
      ┌──────────┴──────────────┐
      │                         │
      ▼                         ▼
┌─────────────────┐      ┌────────────────────┐
│  rules_loader   │      │   config_loader    │
│  (load JSON)    │      │ (vendors/targets)  │
│  + encoder      │      └────────────────────┘
│  (expand variants)│
└────────┬─────────┘
         │ list[Payload]
         ▼
┌─────────────────────────────────────────────────────────────┐
│              Sender (asyncio producer)                     │
│  httpx.ClientSession → HTTP requests → concurrent queue    │
│  + proxy support, retry, timeout, rate limiting             │
└─────────────────────────────┬───────────────────────────────┘
                              │ SendResult (response data)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│           Detector (bypass analysis engine)                 │
│  HTTP status code + response body regex matching           │
│  → BypassStatus: BLOCKED / BYPASS / PARTIAL / ERROR        │
└─────────────────────────────┬───────────────────────────────┘
                              │ DetectionResult
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   logger_db     │  │   logger_csv    │  │   receiver      │
│   (SQLite)      │  │   (CSV export)  │  │ (live stats)    │
└─────────────────┘  └─────────────────┘  └─────────────────┘
                                                      │
                                                      ▼
                                             ┌─────────────────────┐
                                             │  Rich console       │
                                             │  (live progress)    │
                                             └─────────────────────┘
                                                      │
                                                      ▼
                                    ┌─────────────────────────────────┐
                                    │   report_generator.py          │
                                    │   HTML + ECharts (bar/radar/pie)│
                                    └─────────────────────────────────┘
```

## Data Models

### Payload (rules_loader.py)

```python
@dataclass
class Payload:
    id: str
    attack_type: str          # e.g. "SQL Injection"
    method: str               # GET / POST
    url: str                  # full URL with PAYLOAD placeholder replaced
    headers: dict
    body: str                 # POST body (may contain PAYLOAD)
    param_name: str
    encoding: str             # encoding technique applied
    expected_blocked: bool
    bypass_indicators: list   # regex patterns indicating bypass
    target_vm: str
    target_module: str
    severity: str
    description: str
```

### SendResult (sender.py)

```python
@dataclass
class SendResult:
    payload_id: str
    vendor: str
    status_code: int
    response_body: str
    headers: dict
    elapsed_ms: float
    error: str | None
```

### DetectionResult (detector.py)

```python
@dataclass
class DetectionResult:
    status: BypassStatus       # BLOCKED / BYPASS / PARTIAL / ERROR
    bypass_type: str | None   # e.g. "SQL error", "XSS trigger"
    evidence: str | None      # matched regex or description
    confidence: str           # HIGH / MEDIUM / LOW
```

## Key Design Decisions

### 1. Encoding Variants at Load Time, Not Send Time

Payloads are expanded into encoding variants when `rules_loader.py` loads the rules.
This means:
- ✅ All variants are known upfront (accurate progress bar)
- ✅ No runtime overhead during testing
- ✅ Easy to audit what variants exist

### 2. Relative Import Fallback

All `src/` modules use:

```python
try:
    from .xxx import Yyy
except ImportError:
    from xxx import Yyy
```

This allows running `python main.py` from the project root without `pip install -e .`.

### 3. Vendor Config as Detection Rules

Instead of hardcoding WAF-specific logic, vendor configs in `vendors.json` define:
- `block_codes`: HTTP status codes that indicate blocking
- `block_keywords`: Response body patterns indicating blocking
- `allow_codes`: Status codes that indicate the request passed through

The `detector.py` uses these at runtime to determine if a response was blocked.

### 4. Resume via DB Query

On `--resume`, the sender queries the existing SQLite DB for already-tested payload IDs
and skips them. No separate state file needed.

### 5. ECharts for Reporting

ECharts (via CDN) is used instead of matplotlib/plotly to produce self-contained HTML
reports that require no additional dependencies and work offline.

## Configuration Flow

```
CLI args
    ↓
main.py._resolve_vendors() → reads config/vendors.json
main.py._load_targets()    → reads config/targets.json
    ↓
rules_loader.iter_all_payloads() → reads rules/*.json + bypass_transforms.json
    ↓
Payload list (557 items after expansion)
    ↓
Asyncio gather (sender + receiver concurrent)
    ↓
SQLite DB + Rich Console + CSV (appended)
    ↓
report_generator (on demand or --report flag)
```

## Threading Model

- Uses `asyncio` for I/O concurrency (not threading)
- httpx `ClientSession` is shared across all requests within a vendor
- `asyncio.Semaphore(threads)` controls concurrency level
- Each vendor is processed sequentially; Payloads within a vendor are concurrent

## Error Handling Strategy

| Error Type | Behavior |
|-----------|----------|
| HTTP timeout | Retry up to 3 times, then log as ERROR |
| Connection refused | Retry 3 times, then ERROR |
| Proxy unreachable | Log ERROR and abort vendor |
| Invalid SSL cert | Log warning, optionally bypass (`--insecure`) |
| JSON parse error (rules) | Skip invalid entry, log warning |
| Empty response body | Treat as potential BYPASS (depends on detector) |
