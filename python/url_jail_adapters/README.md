# url_jail Python HTTP Client Adapters

This directory contains pure Python adapters that wrap url_jail for popular HTTP clients.

## Usage

```python
# requests
from url_jail.adapters import safe_session
s = safe_session()
response = s.get(user_url)

# httpx
from url_jail.adapters import safe_httpx_client
client = safe_httpx_client()
response = client.get(user_url)

# aiohttp
from url_jail.adapters import safe_aiohttp_session
async with safe_aiohttp_session() as session:
    async with session.get(user_url) as response:
        body = await response.text()
```
