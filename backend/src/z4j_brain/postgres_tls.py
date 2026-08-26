"""Translate libpq-style PostgreSQL TLS URL options for asyncpg.

SQLAlchemy's asyncpg dialect expands URL query parameters into keyword
arguments to :func:`asyncpg.connect`.  ``asyncpg.connect`` does not accept
``sslmode``, ``sslrootcert``, ``sslcert``, or ``sslkey`` as keyword arguments,
even though asyncpg accepts those names when it parses a libpq DSN itself.
Keep the documented URL format, remove only those driver-incompatible keys,
and pass one explicit ``ssl`` argument to asyncpg instead.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.engine import URL, make_url

_TLS_QUERY_KEYS = frozenset({"sslmode", "sslrootcert", "sslcert", "sslkey"})
_TLS_MODES = frozenset(
    {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"},
)
_VERIFY_MODES = frozenset({"verify-ca", "verify-full"})


class PostgresTLSConfigurationError(ValueError):
    """The PostgreSQL URL contains an unsafe or unusable TLS configuration."""


@dataclass(frozen=True, slots=True)
class PostgresTLSOptions:
    """Parsed TLS values plus the URL safe to hand to SQLAlchemy."""

    url: URL
    mode: str | None
    root_certificate: str | None
    client_certificate: str | None
    client_key: str | None


def _single_query_value(url: URL, name: str) -> tuple[str | None, set[str]]:
    matches = [(key, value) for key, value in url.query.items() if key.lower() == name]
    if not matches:
        return None, set()
    if len(matches) != 1:
        raise PostgresTLSConfigurationError(
            f"database URL must include exactly one {name} value when supplied",
        )
    key, raw_value = matches[0]
    if isinstance(raw_value, tuple):
        if len(raw_value) != 1:
            raise PostgresTLSConfigurationError(
                f"database URL must include exactly one {name} value when supplied",
            )
        raw_value = raw_value[0]
    value = str(raw_value)
    if not value:
        raise PostgresTLSConfigurationError(
            f"database URL {name} parameter must not be empty",
        )
    return value, {key}


def parse_asyncpg_tls_options(database_url: str) -> PostgresTLSOptions:
    """Validate TLS query structure without opening certificate files."""

    try:
        url = make_url(database_url)
    except Exception as exc:
        raise PostgresTLSConfigurationError("database URL is malformed") from exc
    if url.drivername != "postgresql+asyncpg":
        return PostgresTLSOptions(url, None, None, None, None)

    extracted: dict[str, str | None] = {}
    removed_keys: set[str] = set()
    for name in sorted(_TLS_QUERY_KEYS):
        value, matching_keys = _single_query_value(url, name)
        extracted[name] = value
        removed_keys.update(matching_keys)

    mode = extracted["sslmode"]
    root_certificate = extracted["sslrootcert"]
    client_certificate = extracted["sslcert"]
    client_key = extracted["sslkey"]
    if mode is None:
        if root_certificate or client_certificate or client_key:
            raise PostgresTLSConfigurationError(
                "sslrootcert, sslcert, and sslkey require an explicit sslmode",
            )
    else:
        mode = mode.lower()
        if mode not in _TLS_MODES:
            choices = ", ".join(sorted(_TLS_MODES))
            raise PostgresTLSConfigurationError(
                f"database URL sslmode must be one of: {choices}",
            )
        if mode in _VERIFY_MODES and root_certificate is None:
            raise PostgresTLSConfigurationError(
                f"sslmode={mode} requires an explicit sslrootcert",
            )
        if mode == "disable" and (root_certificate or client_certificate or client_key):
            raise PostgresTLSConfigurationError(
                "sslmode=disable cannot be combined with TLS certificate material",
            )
        if mode in {"allow", "prefer"} and (root_certificate or client_certificate or client_key):
            raise PostgresTLSConfigurationError(
                f"sslmode={mode} cannot safely combine fallback-to-plaintext with "
                "explicit TLS certificate material",
            )

    if bool(client_certificate) != bool(client_key):
        raise PostgresTLSConfigurationError(
            "sslcert and sslkey must be supplied together",
        )

    return PostgresTLSOptions(
        url.difference_update_query(removed_keys),
        mode,
        root_certificate,
        client_certificate,
        client_key,
    )


def _material_path(raw_path: str, name: str, *, private: bool = False) -> Path:
    try:
        path = Path(raw_path).expanduser().resolve(strict=True)
        observed = path.stat()
    except OSError as exc:
        raise PostgresTLSConfigurationError(
            f"PostgreSQL TLS {name} does not exist or cannot be read: {raw_path}",
        ) from exc
    if not path.is_file():
        raise PostgresTLSConfigurationError(
            f"PostgreSQL TLS {name} is not a regular file: {raw_path}",
        )
    if private and os.name != "nt" and observed.st_mode & 0o077:
        raise PostgresTLSConfigurationError(
            "PostgreSQL TLS client private key must not be accessible by group or others",
        )
    return path


def _strict_ssl_context(options: PostgresTLSOptions) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if options.root_certificate is not None:
        root = _material_path(options.root_certificate, "root certificate")
        try:
            context.load_verify_locations(cafile=str(root))
        except (OSError, ssl.SSLError) as exc:
            raise PostgresTLSConfigurationError(
                f"PostgreSQL TLS root certificate cannot be loaded: {root}",
            ) from exc
        context.verify_mode = ssl.CERT_REQUIRED

    if options.mode in _VERIFY_MODES:
        # parse_asyncpg_tls_options() requires an explicit root in these modes.
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = options.mode == "verify-full"

    if options.client_certificate is not None and options.client_key is not None:
        certificate = _material_path(
            options.client_certificate,
            "client certificate",
        )
        key = _material_path(options.client_key, "client private key", private=True)
        try:
            context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise PostgresTLSConfigurationError(
                "PostgreSQL TLS client certificate or private key cannot be loaded",
            ) from exc
    return context


def _connect_args(options: PostgresTLSOptions) -> dict[str, Any]:
    """Build asyncpg TLS arguments for already parsed options."""

    if options.url.drivername != "postgresql+asyncpg" or options.mode is None:
        return {}
    if options.mode == "disable":
        return {"ssl": False}
    if options.mode in {"allow", "prefer"}:
        # asyncpg understands these mode strings and owns the TLS/plaintext
        # retry ordering. Explicit certificate material is rejected above.
        return {"ssl": options.mode}
    return {"ssl": _strict_ssl_context(options)}


def asyncpg_tls_connect_args(database_url: str) -> dict[str, Any]:
    """Return explicit asyncpg TLS kwargs without rendering the URL again."""

    return _connect_args(parse_asyncpg_tls_options(database_url))


def asyncpg_dsn_and_connect_args(
    database_url: str,
) -> tuple[str, dict[str, Any]]:
    """Return a raw asyncpg DSN and explicit TLS connection arguments.

    Dedicated LISTEN connections cannot use the SQLAlchemy engine, but they
    must apply exactly the same libpq-style TLS normalization as the engine.
    Render the sanitized URL with asyncpg's native ``postgresql`` scheme only
    after the TLS query keys have been removed.
    """

    options = parse_asyncpg_tls_options(database_url)
    dsn_url = options.url
    if dsn_url.drivername == "postgresql+asyncpg":
        dsn_url = dsn_url.set(drivername="postgresql")
    return (
        dsn_url.render_as_string(hide_password=False),
        _connect_args(options),
    )


def asyncpg_engine_url_and_connect_args(
    database_url: str,
) -> tuple[str, dict[str, Any]]:
    """Return a SQLAlchemy URL and asyncpg connect args with working TLS."""

    options = parse_asyncpg_tls_options(database_url)
    normalized_url = options.url.render_as_string(hide_password=False)
    return normalized_url, _connect_args(options)


__all__ = [
    "PostgresTLSConfigurationError",
    "PostgresTLSOptions",
    "asyncpg_dsn_and_connect_args",
    "asyncpg_engine_url_and_connect_args",
    "asyncpg_tls_connect_args",
    "parse_asyncpg_tls_options",
]
