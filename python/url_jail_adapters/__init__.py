"""
url_jail HTTP Client Adapters

SSRF-safe adapters for popular Python HTTP clients.

Usage:
    # requests
    from url_jail.adapters import safe_session
    s = safe_session()
    response = s.get(user_url)

    # httpx (sync)
    from url_jail.adapters import safe_httpx_client
    client = safe_httpx_client()
    response = client.get(user_url)

    # httpx (async)
    from url_jail.adapters import safe_httpx_async_client
    async with safe_httpx_async_client() as client:
        response = await client.get(user_url)

    # aiohttp
    from url_jail.adapters import safe_aiohttp_session
    async with safe_aiohttp_session() as session:
        async with session.get(user_url) as response:
            body = await response.text()
"""

from url_jail import Policy

# Lazy imports to avoid requiring all client libraries
__all__ = [
    "Policy",
    "safe_session",
    "safe_httpx_client",
    "safe_httpx_async_client",
    "safe_aiohttp_session",
]


def safe_session(policy: Policy = Policy.PUBLIC_ONLY):
    """Create a requests.Session with SSRF protection.
    
    Requires: pip install requests
    """
    from .requests_adapter import safe_session as _safe_session
    return _safe_session(policy)


def safe_httpx_client(policy: Policy = Policy.PUBLIC_ONLY):
    """Create an httpx.Client with SSRF protection.
    
    Requires: pip install httpx
    """
    from .httpx_adapter import safe_httpx_client as _safe_httpx_client
    return _safe_httpx_client(policy)


def safe_httpx_async_client(policy: Policy = Policy.PUBLIC_ONLY):
    """Create an httpx.AsyncClient with SSRF protection.
    
    Requires: pip install httpx
    """
    from .httpx_adapter import safe_httpx_async_client as _safe_httpx_async_client
    return _safe_httpx_async_client(policy)


def safe_aiohttp_session(policy: Policy = Policy.PUBLIC_ONLY):
    """Create an aiohttp.ClientSession with SSRF protection.
    
    Requires: pip install aiohttp
    """
    from .aiohttp_adapter import safe_aiohttp_session as _safe_aiohttp_session
    return _safe_aiohttp_session(policy)
