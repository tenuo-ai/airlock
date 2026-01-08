# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in `url_jail`, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainers directly or use GitHub's private vulnerability reporting
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for the fix.

## Security Model

`url_jail` protects against Server-Side Request Forgery (SSRF) attacks by:

### What We Protect Against

| Threat | Protection |
|--------|------------|
| Cloud metadata theft | Block `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200` |
| Internal network scanning | Block private IPs with `PublicOnly` policy |
| Localhost access | Always block `127.0.0.0/8`, `::1` |
| DNS rebinding | Return verified IP for connection |
| Redirect bypass | `fetch()` validates each hop |
| IP encoding tricks | Reject octal, hex, decimal, short-form |
| IPv6 bypass | Handle IPv4-mapped IPv6, link-local, ULA |

### What We Do NOT Protect Against

- **Application-layer vulnerabilities**: We validate URLs, not request content
- **Time-of-check/time-of-use**: Connect immediately after validation
- **DNS cache poisoning**: Out of scope (use DNSSEC)
- **Non-HTTP protocols**: Only `http://` and `https://` are supported
- **Malicious response content**: We don't inspect response bodies

### Best Practices

1. **Use the returned IP**: Always connect to `Validated.ip`, not DNS again
2. **Validate redirects**: Use `fetch()` or manually validate each redirect
3. **Set timeouts**: Configure `ValidateOptions.dns_timeout`
4. **Prefer PublicOnly**: Only use `AllowPrivate` when necessary

## Security Audits

This crate has not yet undergone a formal security audit. If you're using it in a security-critical context, consider:

1. Reviewing the source code
2. Running your own security tests
3. Sponsoring a professional audit

