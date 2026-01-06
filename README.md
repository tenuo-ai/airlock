# airlock

SSRF-safe URL validation for Rust and Python.

## The Problem

```python
response = requests.get(user_url)  # AWS credentials leaked
```

## The Solution

```python
from airlock import validate_sync, Policy

result = validate_sync(user_url, Policy.PUBLIC_ONLY)
response = requests.get(result.url)
```

```rust
use airlock::{validate, Policy};

let result = validate("https://example.com/api", Policy::PublicOnly).await?;
```

## Installation

```bash
pip install airlock
```

```toml
[dependencies]
airlock = "0.1"
```

## What's Blocked

- Cloud metadata endpoints (AWS, GCP, Azure, Alibaba)
- Private IPs (10.x, 172.16.x, 192.168.x)
- Loopback (127.x, localhost, ::1)
- Link-local (169.254.x, fe80::)
- IPv6 equivalents of all the above
- Octal/decimal IP encoding tricks

## License

MIT OR Apache-2.0
