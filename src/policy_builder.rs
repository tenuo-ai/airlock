//! Custom policy builder for advanced SSRF protection.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::blocklist::is_ip_blocked;
use crate::policy::Policy;

/// A custom policy with user-defined blocklists and allowlists.
#[derive(Debug, Clone)]
pub struct CustomPolicy {
    base: Policy,
    blocked_cidrs: Vec<IpNet>,
    allowed_cidrs: Vec<IpNet>,
    blocked_hosts: Vec<String>,
    allowed_hosts: Vec<String>,
}

impl CustomPolicy {
    /// Check if an IP is allowed by this policy.
    pub fn is_ip_allowed(&self, ip: IpAddr) -> Result<(), String> {
        // Check explicit allowlist first
        for cidr in &self.allowed_cidrs {
            if cidr.contains(&ip) {
                return Ok(());
            }
        }

        // Check explicit blocklist
        for cidr in &self.blocked_cidrs {
            if cidr.contains(&ip) {
                return Err(format!("{} is in blocked CIDR {}", ip, cidr));
            }
        }

        // Fall back to base policy
        if let Some(reason) = is_ip_blocked(ip, self.base) {
            return Err(reason.to_string());
        }

        Ok(())
    }

    /// Check if a hostname is allowed by this policy.
    pub fn is_hostname_allowed(&self, host: &str) -> Result<(), String> {
        let host_lower = host.to_lowercase();

        // Check explicit allowlist first
        for pattern in &self.allowed_hosts {
            if matches_hostname_pattern(&host_lower, pattern) {
                return Ok(());
            }
        }

        // Check explicit blocklist
        for pattern in &self.blocked_hosts {
            if matches_hostname_pattern(&host_lower, pattern) {
                return Err(format!("hostname {} matches blocked pattern {}", host, pattern));
            }
        }

        Ok(())
    }
}

/// Builder for creating custom policies.
#[derive(Debug, Clone, Default)]
pub struct PolicyBuilder {
    base: Policy,
    blocked_cidrs: Vec<IpNet>,
    allowed_cidrs: Vec<IpNet>,
    blocked_hosts: Vec<String>,
    allowed_hosts: Vec<String>,
}

impl PolicyBuilder {
    /// Create a new builder with the given base policy.
    pub fn new(base: Policy) -> Self {
        Self {
            base,
            ..Default::default()
        }
    }

    /// Block an IP range (CIDR notation).
    ///
    /// # Example
    /// ```
    /// use url_jail::{PolicyBuilder, Policy};
    ///
    /// let policy = PolicyBuilder::new(Policy::AllowPrivate)
    ///     .block_cidr("10.0.0.0/8")
    ///     .build();
    /// ```
    pub fn block_cidr(mut self, cidr: &str) -> Self {
        if let Ok(net) = cidr.parse() {
            self.blocked_cidrs.push(net);
        }
        self
    }

    /// Allow an IP range (CIDR notation), overriding base policy.
    pub fn allow_cidr(mut self, cidr: &str) -> Self {
        if let Ok(net) = cidr.parse() {
            self.allowed_cidrs.push(net);
        }
        self
    }

    /// Block a hostname or pattern.
    ///
    /// Supports wildcards: `*.internal.example.com`
    pub fn block_host(mut self, pattern: &str) -> Self {
        self.blocked_hosts.push(pattern.to_lowercase());
        self
    }

    /// Allow a hostname or pattern, overriding base blocklist.
    pub fn allow_host(mut self, pattern: &str) -> Self {
        self.allowed_hosts.push(pattern.to_lowercase());
        self
    }

    /// Build the custom policy.
    pub fn build(self) -> CustomPolicy {
        CustomPolicy {
            base: self.base,
            blocked_cidrs: self.blocked_cidrs,
            allowed_cidrs: self.allowed_cidrs,
            blocked_hosts: self.blocked_hosts,
            allowed_hosts: self.allowed_hosts,
        }
    }
}

/// Match a hostname against a pattern (supports * wildcard).
fn matches_hostname_pattern(host: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        host.ends_with(suffix) || host == &pattern[2..]
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_cidr() {
        let policy = PolicyBuilder::new(Policy::AllowPrivate)
            .block_cidr("10.0.0.0/8")
            .build();

        assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()).is_err());
        assert!(policy.is_ip_allowed("192.168.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_allow_cidr_overrides() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_cidr("192.168.1.0/24")
            .build();

        // This private IP is explicitly allowed
        assert!(policy.is_ip_allowed("192.168.1.50".parse().unwrap()).is_ok());
        // Other private IPs still blocked by base policy
        assert!(policy.is_ip_allowed("192.168.2.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_block_host_pattern() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .block_host("*.internal.example.com")
            .build();

        assert!(policy.is_hostname_allowed("api.internal.example.com").is_err());
        assert!(policy.is_hostname_allowed("api.example.com").is_ok());
    }

    #[test]
    fn test_allow_host_pattern() {
        let policy = PolicyBuilder::new(Policy::PublicOnly)
            .allow_host("trusted.internal")
            .build();

        assert!(policy.is_hostname_allowed("trusted.internal").is_ok());
    }
}
