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

<!--
TODO: replace this block with the package-specific security-critical
surface. Example (from z4j-core):

- **Module X** (`z4j.x`) - describe why a bug here would
  have cross-cutting impact.
- **Module Y** - same.

If this package has no security-critical surface beyond the generic
ones covered by z4j-core, you can delete this section entirely.
-->

This package has no package-specific security-critical surface beyond
the generic ones owned by `z4j-core` (transport / redaction / policy).
