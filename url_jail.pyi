"""Type stubs for url_jail - SSRF-safe URL validation."""

from typing import Optional

class Policy:
    """Validation policy determining what IPs are allowed."""
    PUBLIC_ONLY: Policy
    ALLOW_PRIVATE: Policy

class Validated:
    """Result of successful URL validation."""
    ip: str
    """The verified IP address to connect to."""
    host: str
    """Original hostname (use for Host header / SNI)."""
    port: int
    """Port number."""
    url: str
    """Full URL (normalized)."""
    https: bool
    """Whether HTTPS."""

class UrlJailError(Exception):
    """Base exception for url_jail errors."""
    ...

class SsrfBlocked(UrlJailError):
    """IP address or hostname is blocked by policy."""
    ...

class InvalidUrl(UrlJailError):
    """Invalid URL syntax or forbidden scheme."""
    ...

class DnsError(UrlJailError):
    """DNS resolution failed."""
    ...

def validate_sync(url: str, policy: Policy) -> Validated:
    """Validate a URL synchronously.
    
    Args:
        url: The URL to validate.
        policy: The validation policy to apply.
    
    Returns:
        Validated result with IP, host, port, and URL.
    
    Raises:
        SsrfBlocked: If the IP or hostname is blocked.
        InvalidUrl: If the URL is malformed.
        DnsError: If DNS resolution fails.
    """
    ...

async def validate(url: str, policy: Policy) -> Validated:
    """Validate a URL asynchronously.
    
    Args:
        url: The URL to validate.
        policy: The validation policy to apply.
    
    Returns:
        Validated result with IP, host, port, and URL.
    
    Raises:
        SsrfBlocked: If the IP or hostname is blocked.
        InvalidUrl: If the URL is malformed.
        DnsError: If DNS resolution fails.
    """
    ...

def get_sync(url: str, policy: Optional[Policy] = None) -> str:
    """Fetch a URL synchronously with SSRF protection.
    
    Validates the URL and all redirects against the policy.
    
    Args:
        url: The URL to fetch.
        policy: Validation policy (defaults to PUBLIC_ONLY).
    
    Returns:
        Response body as string.
    
    Raises:
        SsrfBlocked: If any URL in the redirect chain is blocked.
        InvalidUrl: If a URL is malformed.
        DnsError: If DNS resolution fails.
        UrlJailError: On HTTP errors or too many redirects.
    """
    ...

async def get(url: str, policy: Optional[Policy] = None) -> str:
    """Fetch a URL asynchronously with SSRF protection.
    
    Validates the URL and all redirects against the policy.
    
    Args:
        url: The URL to fetch.
        policy: Validation policy (defaults to PUBLIC_ONLY).
    
    Returns:
        Response body as string.
    
    Raises:
        SsrfBlocked: If any URL in the redirect chain is blocked.
        InvalidUrl: If a URL is malformed.
        DnsError: If DNS resolution fails.
        UrlJailError: On HTTP errors or too many redirects.
    """
    ...
