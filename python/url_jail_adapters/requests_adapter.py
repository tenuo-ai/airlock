"""
SSRF-safe adapter for requests.

Usage:
    from url_jail.adapters import safe_session
    
    s = safe_session()
    response = s.get(user_url)  # SSRF-safe!
"""

from typing import Any, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from url_jail import Policy, validate_sync, SsrfBlocked, InvalidUrl, DnsError


class UrlJailAdapter(HTTPAdapter):
    """requests HTTPAdapter that validates URLs via url_jail before sending.
    
    This adapter intercepts all requests and validates them against the SSRF
    blocklist before allowing the connection.
    
    Note: For full DNS rebinding protection, use url_jail.get_sync() instead.
    This adapter validates at request time but cannot guarantee the IP won't
    change between validation and connection.
    """
    
    def __init__(self, policy: Policy = Policy.PUBLIC_ONLY, **kwargs):
        self.policy = policy
        super().__init__(**kwargs)
    
    def send(self, request: requests.PreparedRequest, **kwargs) -> requests.Response:
        """Validate URL before sending the request."""
        if request.url:
            # Validate the URL - raises on blocked URLs
            validated = validate_sync(request.url, self.policy)
            
            # For maximum security, we could modify the request to use the
            # validated IP, but this breaks TLS (SNI mismatch). Instead, we
            # rely on the validation at request time.
            # 
            # For full DNS rebinding immunity, use url_jail.get_sync() instead.
        
        return super().send(request, **kwargs)


def safe_session(
    policy: Policy = Policy.PUBLIC_ONLY,
    max_retries: int = 3,
) -> requests.Session:
    """Create a requests.Session with SSRF protection.
    
    All HTTP and HTTPS requests made through this session will be validated
    against the url_jail blocklist before being sent.
    
    Args:
        policy: The validation policy (PUBLIC_ONLY or ALLOW_PRIVATE)
        max_retries: Maximum number of retries for failed requests
    
    Returns:
        A configured requests.Session
    
    Example:
        >>> s = safe_session()
        >>> response = s.get("https://example.com/api")
        >>> # This would raise SsrfBlocked:
        >>> # s.get("http://169.254.169.254/")
    
    Note:
        For full DNS rebinding protection, use url_jail.get_sync() instead.
        This session validates at request time but the DNS could change
        between validation and the actual connection.
    """
    session = requests.Session()
    
    # Mount our SSRF-safe adapter for both HTTP and HTTPS
    adapter = UrlJailAdapter(policy=policy, max_retries=Retry(total=max_retries))
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session
