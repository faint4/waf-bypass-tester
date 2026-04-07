# Contributing to WAF Bypass Tester

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/waf_bypass_tester.git`
3. Create a virtual environment: `python -m venv venv`
4. Activate it: `source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows)
5. Install dev dependencies: `pip install -r requirements.txt`
6. Create a feature branch: `git checkout -b feature/your-feature-name`

## How to Contribute

### Adding New Attack Payloads

Add new payloads to the appropriate JSON file in `rules/`:

```json
{
  "id": "unique-id",
  "payload": "your-payload-here",
  "attack_type": "SQL Injection",
  "method": "GET",
  "param_name": "id",
  "target_module": "sqli",
  "target_vm": "dvwa",
  "description": "Clear description of what this tests",
  "owasp": "A03",
  "severity": "HIGH",
  "expected_blocked": true
}
```

Supported fields:
- `id` (required) — unique identifier, e.g. `sqli-001`
- `payload` (required) — the attack payload string
- `attack_type` (required) — attack category name
- `method` — HTTP method: `GET` (default) or `POST`
- `param_name` — parameter name to inject payload into
- `param_location` — `query` (default), `body`, `header`
- `target_module` — module ID from `targets.json`
- `target_vm` — target VM ID from `targets.json`
- `description` — human-readable description
- `owasp` — OWASP Top 10 category (e.g. `A03` for Injection)
- `severity` — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- `expected_blocked` — whether the WAF should block this (boolean)
- `body_template` — POST body template with `PAYLOAD` placeholder
- `encodings` — override default encodings (array, e.g. `["raw", "url_double"]`)
- `bypass_indicators` — regex patterns that indicate a successful bypass

### Adding New Encoding Techniques

Edit `src/encoder.py` and add a new function following the existing pattern:

```python
def encode_your_technique(payload: str) -> str:
    """Description of what this encoding does."""
    # implementation
    return encoded_payload
```

Then add it to `CATEGORY_DEFAULT_ENCODINGS` in `encoder.py` and/or `rules/bypass_transforms.json`.

### Adding New WAF Vendors

Edit `config/vendors.json.example` (never hardcode real IPs — use the example file).
Add a new entry with:

```json
{
  "id": "vendor-id",
  "name": "Vendor Full Name",
  "short_name": "Short",
  "color": "#hexcolor",
  "proxy": {
    "enabled": true,
    "host": "PROXY_IP",
    "port": 8080,
    "type": "http"
  },
  "block_codes": [403, 406, 444],
  "block_keywords": ["blocked", "denied"],
  "allow_codes": [200, 301, 302],
  "timeout": 15,
  "enabled": true
}
```

### Bug Reports

Please include:
- Python version and OS
- Steps to reproduce
- Expected vs. actual behavior
- Full error traceback

### Pull Request Process

1. Update documentation if adding new features
2. Add tests if applicable (future: add a test suite)
3. Ensure all modules import without errors: `python -c "import src"`
4. Submit a PR with a clear description of the change

## Code Style

- Python 3.10+
- Use type hints where appropriate
- Maximum line length: 120 characters
- Use `async`/`await` for I/O-bound operations
- Relative imports with fallback: `try: from .xxx / except: from xxx`

## Security

- **Never commit real IP addresses, credentials, or API keys**
- Use `config/*.example` files for templates
- Keep actual config in `.gitignore`'d files
- If you discover a security issue, please do NOT open a public issue — contact the maintainer directly
