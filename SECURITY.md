# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `z4j`,
**do not open a public GitHub issue**. Email `security@z4j.com` instead.

We follow the [disclose.io](https://disclose.io) baseline:

- Initial acknowledgement within **72 hours**.
- Coordinated disclosure timeline agreed before public release.
- Credit in the release notes (unless you prefer to remain anonymous).

PGP key and the full disclosure policy live in the
[z4j project security policy](https://github.com/z4jdev/z4j/blob/main/SECURITY.md).

## Supported versions

Only the latest minor release receives security fixes. See
[CHANGELOG.md](CHANGELOG.md) for the current version.

## Security-critical surface

This package ships the z4j brain (the control-plane server), which is
the most security-critical component in the ecosystem. Its surface:

- **Authentication**: session login with Argon2id password hashing,
  optional TOTP MFA with recovery codes and remember-device, and
  per-user MFA enforcement (login refusal when required but not
  enrolled). Login, MFA verify, MFA disable, and MFA enroll-complete
  are all rate-limited per IP.
- **Sessions and CSRF**: server-side sessions with rotation on
  login and credential change, cookie hardening, and double-submit
  CSRF protection on state-changing routes.
- **Authorization**: role-based access control (viewer / operator /
  admin) enforced per project on every API route, including
  WebSocket subscriptions and bulk actions.
- **Agent transport**: agent API-key issuance, hashing, and
  revocation; per-project key scoping; WebSocket auth handshake.
- **Automation**: the rule engine executes operator-defined actions;
  rules are authorized at fire time against the defining user's
  current permissions, not their permissions at rule-creation time.
- **Audit trail**: security-relevant actions (auth events, key
  lifecycle, bulk operations, rule fires, exports) are written to an
  append-only audit log.
- **Bundled dashboard**: the React SPA is served by the brain with a
  restrictive Content-Security-Policy; API responses that reach it
  pass through the redaction engine.

Vulnerability reports touching any of the above are treated as
release-blocking. Reports against packages this one merely depends on
(`z4j-core`, adapters) are routed to that package's policy.
