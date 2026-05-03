"""mTLS for the brain-side ``SchedulerService``.

Defense-in-depth: gRPC's TLS layer already validates that the client
cert was signed by the operator-configured CA bundle. This module
adds a second check on every RPC: extract the cert subject's CN +
SANs and verify they match a configured allow-list. That stops a
case where the operator's CA mint-procedure leaks - a stolen cert
issued by the same CA but for a different service still gets
rejected at the application boundary.

Phase 1 surface:

- :func:`mint_scheduler_cert` - CLI helper that produces a fresh
  cert + key pair for an operator to install on a scheduler instance.
  Uses the brain's existing PKI material (``Z4J_SCHEDULER_GRPC_CA_*``
  pair) to sign. Output is two PEM-encoded byte strings written to
  the operator's chosen path; the brain itself stores no copy.
- :class:`SchedulerAllowlistInterceptor` - ``grpc.aio.ServerInterceptor``
  that validates the peer's cert SAN against
  ``Settings.scheduler_grpc_allowed_cns``.

Operator workflow:

1. Brain operator runs ``z4j mint-scheduler-cert --name
   scheduler-1 --out-dir /etc/z4j/scheduler-1/`` once per scheduler
   instance.
2. Adds ``scheduler-1`` to ``Z4J_SCHEDULER_GRPC_ALLOWED_CNS``.
3. Restarts brain, deploys the certs to the scheduler host.

A future Phase 2 enhancement adds a ``schedulers`` table so this
allow-list is dynamic + revocable from the dashboard. v1 keeps it
in env config for simplicity - the operator already manages the
CA + bind-port via env, so adding a CN list is no extra friction.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Awaitable, Callable

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:  # pragma: no cover
    from pathlib import Path

logger = logging.getLogger("z4j.brain.scheduler_grpc.auth")

# Default validity window for minted scheduler certs. One year is
# the conventional length for service-to-service mTLS - long enough
# that operators don't have to rotate constantly, short enough that
# a leaked cert has finite blast radius.
_DEFAULT_VALIDITY_DAYS = 365

# RSA key size. 2048 is the floor for current-era TLS (NIST SP
# 800-57 still recognises through 2030). 4096 gives more headroom
# at the cost of ~5x signing time - we pick 2048 for service mTLS
# where the cert is rotated yearly.
_KEY_SIZE_BITS = 2048


# =====================================================================
# Cert minting (CLI helper)
# =====================================================================


def mint_scheduler_cert(
    *,
    name: str,
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    validity_days: int = _DEFAULT_VALIDITY_DAYS,
) -> tuple[bytes, bytes]:
    """Mint a fresh mTLS client cert for a scheduler instance.

    Args:
        name: CN + DNS SAN of the cert. The brain's interceptor
            checks this against the configured allow-list, so it
            must match an entry in ``Z4J_SCHEDULER_GRPC_ALLOWED_CNS``.
        ca_cert_pem: PEM-encoded CA certificate that will sign.
        ca_key_pem: PEM-encoded CA private key.
        validity_days: How long the cert stays valid.

    Returns:
        ``(cert_pem, key_pem)`` byte strings.

    The CA private key is loaded but never persisted by this
    function - the caller (CLI) reads it from a path the operator
    supplies and discards the in-memory copy on return.
    """
    if not name:
        raise ValueError("name must be a non-empty string")
    if validity_days <= 0:
        raise ValueError(f"validity_days must be positive; got {validity_days}")

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=_KEY_SIZE_BITS,
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "z4j"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "scheduler"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ],
    )

    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        # 64-bit randomness in the serial is the RFC 5280 floor for
        # reissue-collision protection. ``randbits`` is fine here
        # because cert serials are not secrets.
        .serial_number(int.from_bytes(secrets.token_bytes(8), "big"))
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
    )
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # ``NoEncryption`` is acceptable here - the operator is
        # expected to protect the on-disk file with filesystem ACLs.
        # A passphrase would just shift the secret to wherever the
        # passphrase is stored.
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def write_minted_cert(
    *,
    out_dir: Path,
    name: str,
    cert_pem: bytes,
    key_pem: bytes,
) -> tuple[Path, Path]:
    """Write a freshly-minted cert + key pair under ``out_dir``.

    Uses race-safe primitives from :mod:`z4j_brain.utils.fs_safe`:

    - :func:`ensure_dir_secure` creates ``out_dir`` with
      ``mode=0o700`` AND re-chmods if it already exists (so an
      operator re-running mint against a pre-existing loose-perms
      dir gets the perms tightened).
    - :func:`write_bytes_secure` writes each file with the strict
      ``0o600`` mode set at create time via ``os.open``, defeating
      the TOCTOU window the previous write-then-chmod pattern left
      open on POSIX (audit fix S005, 1.4.0).

    Returns the (cert_path, key_path) for caller logging.
    """
    from z4j_brain.utils.fs_safe import (  # noqa: PLC0415
        ensure_dir_secure,
        write_bytes_secure,
    )

    ensure_dir_secure(out_dir, mode=0o700)
    cert_path = out_dir / f"{name}.crt"
    key_path = out_dir / f"{name}.key"
    write_bytes_secure(cert_path, cert_pem, mode=0o600)
    write_bytes_secure(key_path, key_pem, mode=0o600)
    return cert_path, key_path


# =====================================================================
# Server-side interceptor
# =====================================================================


class SchedulerAllowlistInterceptor(grpc.aio.ServerInterceptor):
    """Reject RPCs whose client cert CN is not in the allow-list.

    The TLS layer has already verified the cert signature - this
    interceptor adds the application-layer CN check. If the
    allow-list is empty (operator chose not to configure one) the
    interceptor permits any cert that passed TLS validation; this
    matches the "trust the CA" deployment model where the CA itself
    is the access boundary.
    """

    def __init__(self, *, allowed_cns: tuple[str, ...]) -> None:
        # Frozen tuple of CNs (or DNS SANs) we accept. Empty = allow
        # all CA-validated certs.
        self._allowed = frozenset(allowed_cns)

    async def intercept_service(
        self,
        continuation: Callable[
            [grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler],
        ],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        if not self._allowed:
            # Operator opted into "trust the CA". Pass through.
            return await continuation(handler_call_details)

        # The cert is on the AuthContext; that is materialised per-
        # call by the runtime. We don't have direct access at
        # interceptor time so we wrap the handler and check inside.
        original = await continuation(handler_call_details)
        if original is None:
            return original

        return _wrap_with_cn_check(original, self._allowed)


def _wrap_with_cn_check(
    handler: grpc.RpcMethodHandler,
    allowed: frozenset[str],
) -> grpc.RpcMethodHandler:
    """Wrap an RpcMethodHandler so each call validates the peer CN."""
    # gRPC has four method-handler shapes (unary-unary, unary-stream,
    # stream-unary, stream-stream). We only wrap the two we actually
    # use (unary-unary + unary-stream).

    if handler.unary_unary is not None:
        original_fn = handler.unary_unary

        async def wrapped_unary_unary(request: Any, context: grpc.aio.ServicerContext) -> Any:
            await _enforce_cn(context, allowed)
            return await original_fn(request, context)

        return grpc.unary_unary_rpc_method_handler(
            wrapped_unary_unary,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    if handler.unary_stream is not None:
        original_stream = handler.unary_stream

        async def wrapped_unary_stream(request: Any, context: grpc.aio.ServicerContext) -> Any:
            await _enforce_cn(context, allowed)
            async for item in original_stream(request, context):
                yield item

        return grpc.unary_stream_rpc_method_handler(
            wrapped_unary_stream,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    # Fallthrough - bidi/stream-unary not used by SchedulerService;
    # don't wrap, just return as-is so the call still works.
    return handler


def _normalise_cn(cn: str) -> str:
    """Normalise a peer-cert CN/SAN entry for allow-list lookup.

    gRPC's AuthContext sometimes returns SAN entries with a URI-style
    prefix (``DNS:scheduler-1``) and the CN as just the bare name.
    This helper strips known prefixes and trims whitespace.

    **Important**: uses ``removeprefix`` (NOT ``lstrip``). ``lstrip``
    takes a SET of characters and would strip any leading combination
    of ``D``, ``N``, ``S``, ``:``, so a legitimate CN like
    ``"DNS-Scheduler-1"`` or ``"Scheduler-1"`` would silently lose
    its leading characters and fail the allow-list. Pinned by
    ``tests/unit/test_scheduler_grpc.py::TestNormaliseCnDoesNotMangle``.

    Round-9 audit fix R9-Sched-MED (Apr 2026): also strip ``IP:``,
    ``URI:``, ``email:`` general-name prefixes. Pre-fix the embedded
    server's IP-SAN (``127.0.0.1``, ``::1``) was returned as the
    literal string ``"IP:127.0.0.1"`` so allow-list operators had
    to list the prefixed form, undocumented and a footgun.
    """
    bare = cn
    for prefix in ("DNS:", "IP:", "URI:", "email:"):
        if bare.startswith(prefix):
            bare = bare.removeprefix(prefix)
            break
    return bare.strip()


async def _enforce_cn(
    context: grpc.aio.ServicerContext,
    allowed: frozenset[str],
) -> None:
    """Abort the call with PERMISSION_DENIED if the peer CN is unknown."""
    auth_ctx = context.auth_context()
    # gRPC's AuthContext key naming has shifted across versions. Older
    # builds (1.5x and earlier) returned bytes-keyed entries
    # (``b"x509_common_name"``); 1.6x+ on grpc.aio returns the SAME
    # logical entries under str keys (``"x509_common_name"``). We try
    # both shapes so the interceptor works against the whole supported
    # range without an explicit version pin. Discovered Apr 2026 when
    # the embedded sidecar (grpc 1.80) silently rejected its own
    # auto-minted client cert because every key lookup returned [].
    cn_candidates: set[str] = set()

    def _entries(key: str) -> list:
        return list(auth_ctx.get(key, [])) + list(
            auth_ctx.get(key.encode(), []),
        )

    for entry in _entries("x509_subject_alternative_name"):
        try:
            cn_candidates.add(
                entry.decode() if isinstance(entry, bytes) else str(entry),
            )
        except UnicodeDecodeError:
            continue

    for entry in _entries("x509_common_name"):
        try:
            cn_candidates.add(
                entry.decode() if isinstance(entry, bytes) else str(entry),
            )
        except UnicodeDecodeError:
            continue

    normalised = {_normalise_cn(c) for c in cn_candidates}

    if not normalised & allowed:
        # Don't echo the actual rejected CN back to the caller -
        # logs only. The caller gets a generic permission denied.
        logger.warning(
            "z4j.brain.scheduler_grpc: rejected RPC; "
            "peer CNs %r not in allow-list",
            sorted(normalised),
        )
        await context.abort(
            grpc.StatusCode.PERMISSION_DENIED,
            "scheduler not authorised - CN not on allow-list",
        )


# Forward-declared for typing; the import is conditional on Phase 1
# enrolment landing.
def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


__all__ = [
    "SchedulerAllowlistInterceptor",
    "mint_scheduler_cert",
    "write_minted_cert",
]
