"""One-open, provenance-preserving configuration capture.

Boundary F requires configuration files to be treated as inputs to one
validated snapshot, not as paths that Pydantic, Alembic, the CLI, and the
admin UI may independently reopen.  This module captures process environment,
``.env``, ``config.env``, and the restricted ``secret.env`` store once and
records which source supplied every effective value.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, get_args, get_origin
from urllib.parse import urlsplit

from dotenv.parser import parse_stream
from z4j_core.paths import z4j_home

from z4j_brain.secret_store import (
    ALLOWED_SECRET_STORE_KEYS,
    SecretStoreError,
    read_secret_store,
)

if TYPE_CHECKING:
    from z4j_brain.settings import Settings

_MAX_EXPLICIT_FILE_BYTES = 1024 * 1024
_SENSITIVE_NAME_PARTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
    "CREDENTIAL",
)
_STRUCTURED_DATABASE_KEYS = (
    "Z4J_DATABASE_HOST",
    "Z4J_DATABASE_PORT",
    "Z4J_DATABASE_USER",
    "Z4J_DATABASE_PASSWORD",
    "Z4J_DATABASE_NAME",
)

# These values are consumed by the CLI or middleware rather than the Pydantic
# Settings model, but they are still legitimate, non-secret config.env
# tunables. Keep the exception set here, beside the derived Settings allowlist,
# so the validator does not regress to accepting every invented Z4J_* name.
NON_SETTINGS_TUNABLE_ENV_KEYS = frozenset(
    {
        "Z4J_ALEMBIC_INI",
        "Z4J_AUTO_MIGRATE",
        "Z4J_DEBUG_HOST_ERRORS",
    }
)

_NON_SETTINGS_TUNABLE_VALUE_SETS: dict[str, frozenset[str]] = {
    "Z4J_AUTO_MIGRATE": frozenset({"false", "true"}),
    "Z4J_DEBUG_HOST_ERRORS": frozenset({"0", "1", "false", "true", "no", "yes", "off", "on"}),
}


class ConfigurationCaptureError(RuntimeError):
    """A configuration input could not be proved safe and unambiguous."""


@dataclass(frozen=True, slots=True)
class ConfigurationSnapshot:
    """Immutable effective values plus exact source attribution."""

    values: Mapping[str, str]
    sources: Mapping[str, str]
    process_environment: Mapping[str, str]

    def source_for_env_key(self, key: str) -> str:
        return self.sources.get(key.upper(), "default")

    def source_for_field(self, field: str) -> str:
        return self.source_for_env_key(f"Z4J_{field.upper()}")

    def settings_kwargs(self) -> dict[str, str]:
        return {
            key.removeprefix("Z4J_").lower(): value
            for key, value in self.values.items()
            if key.startswith("Z4J_")
        }


_active_snapshot: ConfigurationSnapshot | None = None


def set_active_configuration_snapshot(
    snapshot: ConfigurationSnapshot | None,
) -> None:
    """Publish or clear the captured snapshot used for introspection."""

    global _active_snapshot  # noqa: PLW0603  one immutable process snapshot
    _active_snapshot = snapshot


def active_configuration_snapshot() -> ConfigurationSnapshot | None:
    """Return the process snapshot, if an entrypoint has captured one."""

    return _active_snapshot


def _identity(st: os.stat_result) -> tuple[int, int]:
    return (int(st.st_dev), int(st.st_ino))


def _database_url_has_credentials(value: str) -> bool:
    try:
        split = urlsplit(value)
    except ValueError:
        return True
    if split.username is not None or split.password is not None:
        return True
    query = split.query.upper()
    return any(part in query for part in _SENSITIVE_NAME_PARTS)


def _document_contains_sensitive_value(values: Mapping[str, str]) -> bool:
    for raw_key, value in values.items():
        key = raw_key.upper()
        if any(part in key for part in _SENSITIVE_NAME_PARTS):
            return True
        if key == "Z4J_DATABASE_URL" and _database_url_has_credentials(value):
            return True
    return False


def _normalize_database_configuration(
    effective: dict[str, str],
    sources: dict[str, str],
) -> None:
    """Turn complete structured PostgreSQL fields into one unambiguous URL."""

    supplied = {key for key in _STRUCTURED_DATABASE_KEYS if key in effective}
    if "Z4J_DATABASE_URL" in effective:
        # An explicit URL is the documented higher-level override.  Do not
        # leak auxiliary fields into Settings, where they are not model fields.
        for key in _STRUCTURED_DATABASE_KEYS:
            effective.pop(key, None)
            sources.pop(key, None)
        return
    if not supplied:
        return

    missing = set(_STRUCTURED_DATABASE_KEYS) - supplied
    if missing:
        names = ", ".join(sorted(missing))
        raise ConfigurationCaptureError(
            f"incomplete structured PostgreSQL configuration; missing {names}",
        )

    components = {key: effective[key] for key in _STRUCTURED_DATABASE_KEYS}
    empty = [key for key, value in components.items() if not value]
    if empty:
        names = ", ".join(sorted(empty))
        raise ConfigurationCaptureError(
            f"structured PostgreSQL configuration has empty values: {names}",
        )
    if any("\x00" in value or "\n" in value or "\r" in value for value in components.values()):
        raise ConfigurationCaptureError(
            "structured PostgreSQL configuration contains a forbidden control character",
        )

    port_text = components["Z4J_DATABASE_PORT"]
    if not port_text.isascii() or not port_text.isdecimal():
        raise ConfigurationCaptureError(
            "Z4J_DATABASE_PORT must be an integer from 1 through 65535",
        )
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ConfigurationCaptureError(
            "Z4J_DATABASE_PORT must be an integer from 1 through 65535",
        )

    host = components["Z4J_DATABASE_HOST"]
    if host != host.strip() or any(character in host for character in "/@?#[]"):
        raise ConfigurationCaptureError(
            "Z4J_DATABASE_HOST must be an unbracketed hostname or IP address",
        )
    database = components["Z4J_DATABASE_NAME"]
    if any(character in database for character in "?#"):
        raise ConfigurationCaptureError(
            "Z4J_DATABASE_NAME cannot contain '?' or '#'",
        )

    # URL.create quotes usernames and passwords as URL data rather than
    # syntax.  This is the critical distinction for valid passwords such as
    # ``r4:p@ss/word%``; string interpolation silently changes their meaning.
    from sqlalchemy import URL

    effective["Z4J_DATABASE_URL"] = URL.create(
        "postgresql+asyncpg",
        username=components["Z4J_DATABASE_USER"],
        password=components["Z4J_DATABASE_PASSWORD"],
        host=host,
        port=port,
        database=database,
    ).render_as_string(hide_password=False)
    sources["Z4J_DATABASE_URL"] = "derived from structured PostgreSQL configuration"
    for key in _STRUCTURED_DATABASE_KEYS:
        effective.pop(key)
        sources.pop(key)


def _parse_explicit_document(raw: bytes, path: Path) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationCaptureError(f"{path} is not valid UTF-8") from exc

    values: dict[str, str] = {}
    seen: set[str] = set()
    for binding in parse_stream(StringIO(text)):
        if not binding.error and binding.key is None:
            # Blank lines and comments are represented as keyless bindings.
            continue
        if binding.error or binding.key is None:
            line = binding.original.line
            raise ConfigurationCaptureError(
                f"{path} contains a malformed assignment at line {line}",
            )
        key = binding.key.strip().upper()
        if not key:
            raise ConfigurationCaptureError(
                f"{path} contains an empty key at line {binding.original.line}",
            )
        if key in seen:
            raise ConfigurationCaptureError(
                f"{path} contains duplicate key {key!r}",
            )
        seen.add(key)
        if binding.value is None:
            raise ConfigurationCaptureError(
                f"{path} key {key!r} has no value",
            )
        values[key] = binding.value
    return values


def _read_explicit_file(  # noqa: PLR0912, PLR0915  one-open identity validation
    path: Path,
    *,
    required: bool = False,
) -> dict[str, str]:
    """Open one explicit dotenv file without following or later reopening it."""

    if os.name == "nt":
        try:
            path.lstat()
        except FileNotFoundError:
            if required:
                raise ConfigurationCaptureError(f"{path} does not exist") from None
            return {}
        except OSError as exc:
            raise ConfigurationCaptureError(f"cannot inspect {path}: {exc}") from exc

        def _requires_private_acl(raw: bytes) -> bool:
            return _document_contains_sensitive_value(
                _parse_explicit_document(raw, path),
            )

        try:
            from z4j_brain._windows_secure_io import read_stable_path

            raw = read_stable_path(
                path,
                maximum_bytes=_MAX_EXPLICIT_FILE_BYTES,
                private_decider=_requires_private_acl,
            )
        except OSError as exc:
            raise ConfigurationCaptureError(
                f"cannot safely read {path}: {exc}",
            ) from exc
        if raw is None:
            if required:
                raise ConfigurationCaptureError(
                    f"{path} disappeared while it was opened",
                )
            return {}
        return _parse_explicit_document(raw, path)

    try:
        before_path = path.lstat()
    except FileNotFoundError:
        if required:
            raise ConfigurationCaptureError(f"{path} does not exist") from None
        return {}
    except OSError as exc:
        raise ConfigurationCaptureError(f"cannot inspect {path}: {exc}") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise ConfigurationCaptureError(f"{path} must be a regular file, not a link")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigurationCaptureError(f"cannot safely open {path}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ConfigurationCaptureError(f"{path} must be a regular file")
        chunks: list[bytes] = []
        remaining = _MAX_EXPLICIT_FILE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or before.st_size != after.st_size:
            raise ConfigurationCaptureError(f"{path} changed while it was read")
        raw = b"".join(chunks)
        if len(raw) > _MAX_EXPLICIT_FILE_BYTES:
            raise ConfigurationCaptureError(f"{path} exceeds the 1 MiB safety bound")
    finally:
        os.close(fd)

    try:
        after_path = path.lstat()
    except OSError as exc:
        raise ConfigurationCaptureError(f"{path} pathname changed after read") from exc
    if stat.S_ISLNK(after_path.st_mode) or _identity(after_path) != _identity(after):
        raise ConfigurationCaptureError(
            f"{path} pathname no longer names the opened file",
        )

    values = _parse_explicit_document(raw, path)
    if _document_contains_sensitive_value(values):
        if before.st_uid != os.getuid():
            raise ConfigurationCaptureError(
                f"{path} contains secrets but is not owned by the current uid",
            )
        if before.st_mode & 0o077:
            raise ConfigurationCaptureError(
                f"{path} contains secrets and must be owner-private (chmod 600)",
            )
    return values


def capture_explicit_configuration_file(path: Path) -> dict[str, str]:
    """Capture one required dotenv file through the startup-safe reader.

    Operator commands that inspect an explicit candidate must use this
    entrypoint instead of reopening the pathname with ``Path.read_text``.
    """

    return _read_explicit_file(path, required=True)


def supported_settings_environment_keys() -> frozenset[str]:
    """Exact environment keys accepted by the startup settings pipeline."""

    from z4j_brain.settings import Settings

    field_keys = {f"Z4J_{field.upper()}" for field in Settings.model_fields}
    return frozenset(
        field_keys | set(_STRUCTURED_DATABASE_KEYS) | set(NON_SETTINGS_TUNABLE_ENV_KEYS)
    )


def validate_non_settings_tunable_values(values: Mapping[str, str]) -> None:
    """Validate config.env tunables that live outside ``Settings``."""

    for key, accepted in _NON_SETTINGS_TUNABLE_VALUE_SETS.items():
        if key not in values:
            continue
        raw_value = values[key]
        if raw_value != raw_value.strip():
            raise ConfigurationCaptureError(
                f"{key} must not contain surrounding whitespace",
            )
        normalized = raw_value.lower()
        if normalized not in accepted:
            choices = ", ".join(sorted(accepted))
            raise ConfigurationCaptureError(
                f"{key} must be one of: {choices}",
            )
    if "Z4J_ALEMBIC_INI" in values and not values["Z4J_ALEMBIC_INI"].strip():
        raise ConfigurationCaptureError("Z4J_ALEMBIC_INI cannot be empty")


def configuration_snapshot_from_values(
    values: Mapping[str, str],
    *,
    source: str,
) -> ConfigurationSnapshot:
    """Build one startup-equivalent snapshot from already-captured values."""

    effective = {key.upper(): value for key, value in values.items()}
    sources = dict.fromkeys(effective, source)
    _normalize_database_configuration(effective, sources)
    return ConfigurationSnapshot(
        values=MappingProxyType(effective),
        sources=MappingProxyType(sources),
        process_environment=MappingProxyType({}),
    )


def capture_configuration(
    *,
    home: Path | None = None,
    cwd: Path | None = None,
    process_environment: Mapping[str, str] | None = None,
    include_secret_store: bool = True,
) -> ConfigurationSnapshot:
    """Capture the documented configuration precedence exactly once."""

    home_path = home or z4j_home()
    cwd_path = cwd or Path.cwd()
    process = dict(os.environ if process_environment is None else process_environment)

    try:
        store_path = home_path / "secret.env"
        try:
            store_path.lstat()
        except FileNotFoundError:
            store_values = {}
        else:
            store_values = read_secret_store(store_path).values if include_secret_store else {}
    except SecretStoreError as exc:
        raise ConfigurationCaptureError(str(exc)) from exc
    config_values = _read_explicit_file(home_path / "config.env")
    dotenv_values = _read_explicit_file(cwd_path / ".env")

    effective: dict[str, str] = {}
    sources: dict[str, str] = {}

    for key, value in store_values.items():
        normalized = key.upper()
        if normalized not in ALLOWED_SECRET_STORE_KEYS:
            raise ConfigurationCaptureError(
                f"secret.env contains unsupported key {normalized!r}",
            )
        effective[normalized] = value
        sources[normalized] = "secret.env"
    for label, values in (("config.env", config_values), (".env", dotenv_values)):
        for key, value in values.items():
            effective[key] = value
            sources[key] = label
    for key, value in process.items():
        normalized = key.upper()
        if normalized.startswith("Z4J_"):
            effective[normalized] = value
            sources[normalized] = f"env ({key})"

    _normalize_database_configuration(effective, sources)
    return ConfigurationSnapshot(
        values=MappingProxyType(effective),
        sources=MappingProxyType(sources),
        process_environment=MappingProxyType(process),
    )


def settings_from_snapshot(snapshot: ConfigurationSnapshot) -> Settings:
    """Construct Settings without any Pydantic env-file reopen."""

    from z4j_brain.settings import Settings

    kwargs: dict[str, object] = {}
    for field, raw in snapshot.settings_kwargs().items():
        model_field = Settings.model_fields.get(field)
        annotation = model_field.annotation if model_field is not None else None
        origins = {get_origin(annotation), annotation}
        origins.update(get_origin(argument) for argument in get_args(annotation))
        if origins & {dict, list, set, tuple}:
            try:
                kwargs[field] = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ConfigurationCaptureError(
                    f"Z4J_{field.upper()} is not valid JSON",
                ) from exc
        else:
            kwargs[field] = raw
    return Settings(_env_file=None, **kwargs)  # type: ignore[call-arg]


def merge_secret_store_snapshot(
    snapshot: ConfigurationSnapshot,
    store_values: Mapping[str, str],
) -> ConfigurationSnapshot:
    """Supply only auto-secret keys absent from higher-precedence sources."""

    values = dict(snapshot.values)
    sources = dict(snapshot.sources)
    for raw_key, value in store_values.items():
        key = raw_key.upper()
        if key not in ALLOWED_SECRET_STORE_KEYS:
            raise ConfigurationCaptureError(
                f"secret.env contains unsupported key {key!r}",
            )
        if key not in values:
            values[key] = value
            sources[key] = "secret.env"
    return ConfigurationSnapshot(
        values=MappingProxyType(values),
        sources=MappingProxyType(sources),
        process_environment=snapshot.process_environment,
    )


def apply_secret_store_winner(
    snapshot: ConfigurationSnapshot,
    store_values: Mapping[str, str],
) -> ConfigurationSnapshot:
    """Apply one locked safe-store winner without shadowing explicit sources."""

    unknown = {key.upper() for key in store_values} - ALLOWED_SECRET_STORE_KEYS
    if unknown:
        raise ConfigurationCaptureError(
            f"secret.env contains unsupported keys {sorted(unknown)!r}",
        )
    values = dict(snapshot.values)
    sources = dict(snapshot.sources)
    for key in ALLOWED_SECRET_STORE_KEYS:
        source = sources.get(key, "default")
        if source not in {"default", "secret.env"}:
            continue
        if key in store_values:
            values[key] = store_values[key]
            sources[key] = "secret.env"
        elif source == "secret.env":
            values.pop(key, None)
            sources.pop(key, None)
    return ConfigurationSnapshot(
        values=MappingProxyType(values),
        sources=MappingProxyType(sources),
        process_environment=snapshot.process_environment,
    )


def overlay_runtime_environment(
    snapshot: ConfigurationSnapshot,
    environment: Mapping[str, str] | None = None,
) -> ConfigurationSnapshot:
    """Apply CLI/runtime overrides without reopening any captured path."""

    values = dict(snapshot.values)
    sources = dict(snapshot.sources)
    for raw_key, value in (os.environ if environment is None else environment).items():
        key = raw_key.upper()
        if not key.startswith("Z4J_"):
            continue
        if values.get(key) == value:
            continue
        values[key] = value
        sources[key] = f"runtime/CLI ({raw_key})"
    return ConfigurationSnapshot(
        values=MappingProxyType(values),
        sources=MappingProxyType(sources),
        process_environment=snapshot.process_environment,
    )


def export_snapshot_environment(snapshot: ConfigurationSnapshot) -> None:
    """Export effective values for child tools that accept only environment."""

    for key, value in snapshot.values.items():
        if key.startswith("Z4J_"):
            os.environ[key] = value
    set_active_configuration_snapshot(snapshot)


__all__ = [
    "NON_SETTINGS_TUNABLE_ENV_KEYS",
    "ConfigurationCaptureError",
    "ConfigurationSnapshot",
    "active_configuration_snapshot",
    "apply_secret_store_winner",
    "capture_configuration",
    "capture_explicit_configuration_file",
    "configuration_snapshot_from_values",
    "export_snapshot_environment",
    "merge_secret_store_snapshot",
    "overlay_runtime_environment",
    "set_active_configuration_snapshot",
    "settings_from_snapshot",
    "supported_settings_environment_keys",
    "validate_non_settings_tunable_values",
]
