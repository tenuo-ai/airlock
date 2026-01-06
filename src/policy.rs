//! Policy configuration for URL validation.

/// Validation policy that controls which IP ranges are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// Block private IPs, loopback, link-local, and metadata endpoints.
    /// This is the default and recommended for most use cases.
    #[default]
    PublicOnly,

    /// Allow private IPs, but still block loopback and metadata endpoints.
    /// Use for internal service-to-service calls within a trusted network.
    AllowPrivate,
}
