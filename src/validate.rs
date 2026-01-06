//! URL validation with DNS resolution.

use std::net::IpAddr;

use hickory_resolver::TokioResolver;

use crate::blocklist::{is_hostname_blocked, is_ip_blocked};
use crate::error::Error;
use crate::policy::Policy;
use crate::safe_url::SafeUrl;

/// Result of successful URL validation.
#[derive(Debug, Clone)]
pub struct Validated {
    /// The verified IP address to connect to.
    pub ip: IpAddr,

    /// Original hostname (use for Host header / SNI).
    pub host: String,

    /// Port number.
    pub port: u16,

    /// Full URL (normalized).
    pub url: String,

    /// Whether HTTPS.
    pub https: bool,
}

/// Validate a URL, resolve DNS, and check the IP against the policy.
///
/// This is the primary entry point for SSRF protection. It:
/// 1. Parses and normalizes the URL
/// 2. Checks the hostname against the blocklist
/// 3. Resolves DNS to get the IP address
/// 4. Checks the IP against the policy
///
/// # Example
///
/// ```rust,no_run
/// use airlock::{validate, Policy};
///
/// # async fn example() -> Result<(), airlock::Error> {
/// let result = validate("https://example.com/api", Policy::PublicOnly).await?;
/// println!("Safe to connect to {} ({})", result.host, result.ip);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The URL is malformed or uses a forbidden scheme
/// - The hostname is in the blocklist
/// - DNS resolution fails
/// - The resolved IP is blocked by the policy
pub async fn validate(url: &str, policy: Policy) -> Result<Validated, Error> {
    // Step 1: Parse and normalize
    let safe_url = SafeUrl::parse(url)?;

    // Step 2: Check hostname blocklist
    if let Some(blocked_host) = is_hostname_blocked(safe_url.host()) {
        return Err(Error::hostname_blocked(
            url,
            safe_url.host(),
            format!("hostname {} is blocked", blocked_host),
        ));
    }

    // Step 3: Resolve DNS
    let ip = resolve_dns(safe_url.host()).await?;

    // Step 4: Check IP against policy
    if let Some(reason) = is_ip_blocked(ip, policy) {
        return Err(Error::ssrf_blocked(url, ip, reason));
    }

    Ok(Validated {
        ip,
        host: safe_url.host().to_string(),
        port: safe_url.port(),
        url: safe_url.as_str().to_string(),
        https: safe_url.is_https(),
    })
}

/// Synchronous version of [`validate`].
///
/// This blocks the current thread while performing DNS resolution.
/// Prefer the async version when possible.
///
/// This function works both inside and outside of a Tokio runtime.
/// When called from outside a runtime, it creates a temporary one.
pub fn validate_sync(url: &str, policy: Policy) -> Result<Validated, Error> {
    // Try to use an existing runtime first
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // We're inside a runtime, use block_in_place
        tokio::task::block_in_place(|| handle.block_on(validate(url, policy)))
    } else {
        // No runtime, create a temporary one
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::dns_error("runtime", e.to_string()))?;
        rt.block_on(validate(url, policy))
    }
}

/// Resolve a hostname to an IP address.
async fn resolve_dns(host: &str) -> Result<IpAddr, Error> {
    // Handle literal IP addresses (including bracketed IPv6)
    let host_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_str.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Resolve hostname via DNS using the builder API
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| Error::dns_error(host, e.to_string()))?
        .build();

    let response = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| Error::dns_error(host, e.to_string()))?;

    // Take the first IP
    response
        .iter()
        .next()
        .ok_or_else(|| Error::dns_error(host, "no IP addresses found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validate_public_ip() {
        // example.com should resolve to a public IP
        let result = validate("https://example.com/", Policy::PublicOnly).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_block_loopback() {
        let result = validate("http://127.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_metadata() {
        let result = validate("http://169.254.169.254/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_metadata_hostname() {
        let result = validate("http://metadata.google.internal/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_private_ip_policy() {
        let result = validate("http://192.168.1.1/", Policy::PublicOnly).await;
        assert!(result.is_err());

        // AllowPrivate should allow private IPs
        // Note: This will fail if 192.168.1.1 doesn't exist, but that's expected behavior
    }

    #[tokio::test]
    async fn test_reject_octal() {
        let result = validate("http://0177.0.0.1/", Policy::PublicOnly).await;
        assert!(result.is_err());
    }
}
