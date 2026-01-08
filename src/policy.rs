//! Policy configuration for URL validation.
//!
//! ## Design Principles
//!
//! Policies are **pure validation constraints**:
//!
//! - Based solely on IP addresses and hostnames
//! - No user identity or authentication
//! - No request context or headers
//! - No time-based logic
//! - No delegation or inheritance
//!
//! This separation ensures policies remain simple, auditable, and composable.
//! Authorization logic (who can access what) should be handled separately
//! from SSRF validation (what network locations are safe).
//!
//! ## Immutability
//!
//! [`Policy`] is `Copy` and cannot be mutated. [`CustomPolicy`](crate::CustomPolicy)
//! is created via [`PolicyBuilder`](crate::PolicyBuilder) and is immutable once built.

/// Validation policy that controls which IP ranges are allowed.
///
/// Policies are pure validation constraints based solely on IP addresses.
/// They do not consider user identity, request context, or time.
///
/// This enum is `Copy` and immutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// Block private IPs, loopback, link-local, and metadata endpoints.
    ///
    /// This is the default and recommended for most use cases where you're
    /// fetching URLs from untrusted sources (user input, webhooks, etc.).
    #[default]
    PublicOnly,

    /// Allow private IPs, but still block loopback and metadata endpoints.
    ///
    /// Use for internal service-to-service calls within a trusted network
    /// where you need to access private IP ranges but still want protection
    /// against localhost and cloud metadata attacks.
    AllowPrivate,
}
