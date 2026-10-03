"""Encryption at rest for JSON columns that carry third-party credentials.

Notification channel configs (Slack webhook URLs, SMTP passwords, webhook
HMAC secrets, PagerDuty integration keys) used to sit in plaintext JSONB.
This module gives them the same protection ``users.mfa_secret_encrypted``
has had since MFA shipped, built on the same primitive as
:mod:`z4j_brain.domain.mfa.crypto`: AES-256-GCM under a key derived from
the master ``Z4J_SECRET`` with HKDF-SHA256, a random 96-bit nonce per
write, and ``Z4J_PREVIOUS_SECRETS`` honoured on decrypt.

Storage format
--------------

A stored value is one text token::

    z4jenc1:<base64(nonce || ciphertext || tag)>

The ``z4jenc1:`` prefix is the format version. It is what lets the
migration and the re-wrap command tell an encrypted value from a plaintext
JSON document without trying to decrypt it, so both are idempotent.

The plaintext is the canonical JSON encoding of the Python value (sorted
keys, no whitespace, UTF-8), so two writes of the same dict differ only by
nonce.

Key derivation and domain separation
------------------------------------

Each column has a *purpose* string (``"notification_channels.config"``).
HKDF's ``info`` carries that string, so the key for one column cannot
decrypt another, and neither can decrypt a TOTP blob: the MFA module
derives under its own salt and info. The purpose string is also the
AES-GCM associated data.

Why the AAD is the purpose and not the row id: the SQLAlchemy type
decorator that applies this module sees only the value being bound or
loaded, never the row it belongs to, so row-id binding is not available at
the type level without a second write after the INSERT assigns the id. The
MFA column keeps its user-id AAD because its two call sites are explicit
service code that knows the user. What the purpose-only AAD does not
prevent is an operator with database write access pasting one channel's
ciphertext onto another channel row of the same table; such an operator
could as well have pasted the plaintext before this change, and channel
edits are in the HMAC-chained audit log either way. What it does prevent
is the same ciphertext being read back through a different column or a
different format version.

Key rotation
------------

Decrypt tries the current master first, then each ``Z4J_PREVIOUS_SECRETS``
entry in order. A value that decrypts only under a previous secret is
reported as ``needs_rewrap``; every write re-encrypts under the current
master, so a channel edit re-wraps that row. The lesson from the TOTP
orphaning in the 1.9.0 audit is that "re-wrapped on next use" is not a
retirement plan: rows that are never touched stay under the old master
forever, and dropping it from ``Z4J_PREVIOUS_SECRETS`` orphans them.
``z4j secrets rewrap`` (:func:`rewrap_all_secret_fields`) walks every
encrypted row, notification configs and TOTP secrets alike, and re-wraps
each one under the current master in one transaction. Running it to a
clean report is the step that makes dropping a previous secret safe.

The same walk encrypts a config row that carries no prefix at all. Such a
row is written by a brain running a release from before this column was
encrypted (a downgrade and re-upgrade that skipped the migration's row
walk), or by hand; the type reads it as plaintext JSON and logs a WARNING
so it is not silent, and the walk reports it as ``plaintext`` and brings
it under the current master.

Process binding
---------------

The type decorator needs a keyring at bind and load time and has no access
to ``Settings``. The three entry points that own a ``Settings`` object
bind one explicitly: ``create_app`` for the server and the test suite, the
``secrets rewrap`` command, and the migration that encrypts existing rows.
With no keyring bound the type fails closed on every write and on every
read of an encrypted value, rather than silently storing plaintext or
guessing a key; only a non-prefixed row, which needs no key, is returned
without one.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import sqlalchemy as sa
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.exc import DontWrapMixin

from z4j_brain.domain.mfa.crypto import (
    NONCE_BYTES,
    DecryptionFailed,
    decrypt_totp_secret,
    encrypt_totp_secret,
)
from z4j_brain.persistence.types import (
    NOTIFICATION_CHANNEL_CONFIG_PURPOSE,
    USER_CHANNEL_CONFIG_PURPOSE,
    EncryptedJSONWriteError,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

    from z4j_brain.settings import Settings

#: Format-version prefix on every encrypted value.
ENCRYPTED_PREFIX = "z4jenc1:"

#: Purpose strings for the two notification config columns. Defined next to
#: the column type (the models cannot import this package without a cycle)
#: and re-exported here so the migration, the model and the re-wrap command
#: can never disagree on the HKDF info or the AAD.
NOTIFICATION_CHANNEL_CONFIG = NOTIFICATION_CHANNEL_CONFIG_PURPOSE
USER_CHANNEL_CONFIG = USER_CHANNEL_CONFIG_PURPOSE

#: Columns :func:`rewrap_all_secret_fields` walks, as (table, purpose).
ENCRYPTED_JSON_COLUMNS: tuple[tuple[str, str], ...] = (
    ("notification_channels", NOTIFICATION_CHANNEL_CONFIG),
    ("user_channels", USER_CHANNEL_CONFIG),
)

#: The migration that made the two ``config`` columns ``TEXT`` and encrypted
#: their rows. Below it the columns are still ``JSON`` (``JSONB`` on
#: Postgres), so the plaintext repair in :func:`rewrap_json_column` would
#: write the ``z4jenc1:`` string into a JSON column: a row the brain of that
#: release cannot read, and on Postgres a statement the column rejects.
#: ``z4j secrets rewrap`` refuses a database whose head is not at or above
#: this revision on the migration chain.
ENCRYPTED_JSON_COLUMNS_REVISION = "v1_12_channel_config_encrypted"

_HKDF_SALT = b"z4j-secret-fields-salt-v1"
_HKDF_INFO_PREFIX = b"z4j-secret-field:"
_AAD_PREFIX = b"z4j-secret-field:"
_KEY_LEN = 32


class SecretKeyringUnbound(RuntimeError, DontWrapMixin):  # noqa: N818  public exception name, kept stable
    """No keyring has been bound in this process.

    Raised by the ``EncryptedJSON`` type on every write and on the read of
    an encrypted value. The fix is at the entry point, not the call site:
    ``create_app``, the CLI command and the migration each call
    :func:`bind_keyring_from_settings`.

    ``DontWrapMixin``: when a bind processor raises, SQLAlchemy wraps the
    exception in a ``StatementError`` whose text carries the bound
    parameters, which here are the plaintext config. The mixin makes it
    raise this exception as it is; the message names the column, never
    the value.
    """


@dataclass(frozen=True)
class SecretKeyring:
    """The current master secret plus every previous one still accepted."""

    current: bytes
    previous: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if not self.current:
            raise ValueError("SecretKeyring.current is empty")

    @classmethod
    def from_settings(cls, settings: Settings) -> SecretKeyring:
        """Build the keyring the way the MFA module reads its secrets."""
        secrets = settings.all_secrets_for_verification()
        return cls(current=secrets[0], previous=tuple(s for s in secrets[1:] if s))

    @classmethod
    def from_secrets(cls, current: str, previous: Iterable[str] = ()) -> SecretKeyring:
        """Build a keyring from string secrets (tests and the migration)."""
        return cls(
            current=current.encode("utf-8"),
            previous=tuple(p.encode("utf-8") for p in previous if p),
        )

    def candidates(self) -> tuple[bytes, ...]:
        return (self.current, *self.previous)


def _derive_key(master: bytes, purpose: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=_HKDF_SALT,
        info=_HKDF_INFO_PREFIX + purpose.encode("utf-8"),
    ).derive(master)


def _aad(purpose: str) -> bytes:
    return _AAD_PREFIX + purpose.encode("utf-8")


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def is_encrypted(value: object) -> bool:
    """True when ``value`` is a stored token this module produced."""
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def encrypt_json(value: Any, *, keyring: SecretKeyring, purpose: str) -> str:
    """Encrypt a JSON-serialisable value under the current master."""
    key = _derive_key(keyring.current, purpose)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, canonical_json(value), _aad(purpose))
    return ENCRYPTED_PREFIX + base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_json(blob: str, *, keyring: SecretKeyring, purpose: str) -> tuple[Any, bool]:
    """Decrypt a stored token.

    Returns ``(value, needs_rewrap)``; ``needs_rewrap`` is True when only a
    previous secret could decrypt it. Raises :class:`DecryptionFailed` when
    no candidate can, which is the symptom of a previous secret dropped
    before ``z4j secrets rewrap`` was run.
    """
    if not is_encrypted(blob):
        raise DecryptionFailed("value does not carry the z4jenc1 prefix")
    try:
        raw = base64.b64decode(blob[len(ENCRYPTED_PREFIX) :], validate=True)
    except ValueError as exc:
        raise DecryptionFailed("encrypted value is not valid base64") from exc
    if len(raw) <= NONCE_BYTES:
        raise DecryptionFailed("encrypted value too short to carry nonce + ciphertext")
    nonce, ciphertext = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
    aad = _aad(purpose)
    for index, candidate in enumerate(keyring.candidates()):
        try:
            plaintext = AESGCM(_derive_key(candidate, purpose)).decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            continue
        return json.loads(plaintext.decode("utf-8")), index > 0
    raise DecryptionFailed(
        f"{purpose} could not be decrypted with the current Z4J_SECRET or any value "
        "listed in Z4J_PREVIOUS_SECRETS; put the previous secret back and run "
        "`z4j secrets rewrap` before retiring it",
    )


# ---------------------------------------------------------------------------
# Process-wide keyring binding (consumed by persistence.types.EncryptedJSON)
# ---------------------------------------------------------------------------

_bound_keyring: SecretKeyring | None = None


def bind_keyring(keyring: SecretKeyring | None) -> None:
    """Bind (or with ``None`` unbind) the process keyring."""
    global _bound_keyring  # noqa: PLW0603  one keyring per process, set at the entry point
    _bound_keyring = keyring


def bind_keyring_from_settings(settings: Settings) -> SecretKeyring:
    keyring = SecretKeyring.from_settings(settings)
    bind_keyring(keyring)
    return keyring


def active_keyring() -> SecretKeyring:
    """The bound keyring, or :class:`SecretKeyringUnbound`."""
    if _bound_keyring is None:
        raise SecretKeyringUnbound(
            "no secret keyring is bound in this process; the entry point must call "
            "z4j_brain.domain.secret_fields.bind_keyring_from_settings(settings) "
            "before any encrypted column is read or written",
        )
    return _bound_keyring


# ---------------------------------------------------------------------------
# Bulk re-wrap (z4j secrets rewrap, and the migration's row walk)
# ---------------------------------------------------------------------------


@dataclass
class ColumnRewrapReport:
    """Counts for one encrypted column after a re-wrap walk.

    Every scanned row lands in exactly one of ``already_current``,
    ``rewrapped``, ``plaintext``, ``changed_under_us`` or ``failed``.
    In a dry run ``rewrapped`` and ``plaintext`` count what would be
    written.
    """

    table: str
    column: str
    scanned: int = 0
    #: Decrypted under the current master; nothing to do.
    already_current: int = 0
    #: Decrypted only under a previous secret; re-encrypted under the current one.
    rewrapped: int = 0
    #: Carried no ``z4jenc1:`` prefix; parsed as JSON and encrypted.
    plaintext: int = 0
    #: Changed by another writer between the walk's read and its write, and
    #: left as is: the guarded UPDATE did not apply. Listed in ``failed`` as
    #: well when the value found on re-read is not under the current master.
    changed_under_us: int = 0
    #: Rows left not under the current master, by id: no listed secret
    #: decrypts them, or they carry no prefix and are not JSON either, or
    #: they changed under the walk to a value that is not current.
    failed: list[str] = field(default_factory=list)
    #: How many of ``failed`` are non-prefixed rows that are not JSON; they
    #: are not ciphertext, so they say nothing about the keyring.
    malformed: int = 0

    @property
    def decrypted(self) -> int:
        return self.rewrapped + self.already_current


@dataclass
class RewrapReport:
    """Whole-run result of :func:`rewrap_all_secret_fields`."""

    columns: list[ColumnRewrapReport] = field(default_factory=list)
    dry_run: bool = False

    @property
    def scanned(self) -> int:
        return sum(c.scanned for c in self.columns)

    @property
    def rewrapped(self) -> int:
        return sum(c.rewrapped for c in self.columns)

    @property
    def plaintext(self) -> int:
        return sum(c.plaintext for c in self.columns)

    @property
    def changed_under_us(self) -> int:
        return sum(c.changed_under_us for c in self.columns)

    @property
    def decrypted(self) -> int:
        return sum(c.decrypted for c in self.columns)

    @property
    def failed(self) -> int:
        return sum(len(c.failed) for c in self.columns)

    @property
    def refused(self) -> bool:
        """True when encrypted rows exist and not one of them decrypts.

        That keyring cannot be the one the rows were written under, so
        writing anything would be the wrong move; the operator needs to
        put the right previous secret back first. Plaintext and malformed
        rows are not ciphertext and say nothing either way, which also
        means a database holding only plaintext rows cannot tell a wrong
        keyring from the right one: run the walk with the ``Z4J_SECRET``
        the brain runs with. Rows that changed under the walk were judged
        on re-read and are left out of the arithmetic too.
        """
        not_ciphertext = sum(c.plaintext + c.malformed + c.changed_under_us for c in self.columns)
        return self.scanned - not_ciphertext > 0 and self.decrypted == 0


#: How one stored JSON value stands relative to the current master.
_StoredKind = Literal["current", "previous", "plaintext", "malformed"]


def _classify_stored_json(
    stored: object, *, keyring: SecretKeyring, purpose: str
) -> tuple[Any, _StoredKind]:
    """Decode one stored column value and say what the walk must do with it.

    Raises :class:`DecryptionFailed` for a prefixed value no listed secret
    decrypts. A non-prefixed value is plaintext JSON text (or, on a dialect
    that decoded it already, the JSON value itself); one that is not JSON
    is ``malformed`` and comes back with ``None``.
    """
    if is_encrypted(stored):
        value, needs_rewrap = decrypt_json(str(stored), keyring=keyring, purpose=purpose)
        return value, ("previous" if needs_rewrap else "current")
    if not isinstance(stored, str):
        return stored, "plaintext"
    try:
        return json.loads(stored), "plaintext"
    except ValueError:
        return None, "malformed"


def rewrap_json_column(
    connection: Connection,
    *,
    table: str,
    purpose: str,
    keyring: SecretKeyring,
    column: str = "config",
    dry_run: bool = False,
) -> ColumnRewrapReport:
    """Bring every value of one column under the current master.

    Two kinds of row are written: one that decrypts only under a previous
    secret (``rewrapped``), and one that carries no ``z4jenc1:`` prefix at
    all (``plaintext``: written by a brain from before the column was
    encrypted, or by hand), which is parsed as JSON and encrypted. A
    non-prefixed row that is not JSON cannot be read by the brain either;
    it is listed in ``failed`` and counted in ``malformed``.

    Each UPDATE is guarded by the value the walk read (``AND column =
    :old``), so an edit a running brain commits between the read and the
    write wins. Such a row is counted as ``changed_under_us`` and left as
    is; it is re-read, and listed in ``failed`` too when what is there now
    is not under the current master (a writer running with other keys),
    which a second run then picks up.

    One statement per written row rather than an executemany batch: the
    guard needs each statement's own row count, and executemany does not
    report one on every dialect. Channel tables hold hundreds of rows on a
    large installation, so that is one round trip per row that actually
    changes, not per row scanned.
    """
    report = ColumnRewrapReport(table=table, column=column)
    select_all = sa.text(f'SELECT id, "{column}" FROM {table} ORDER BY id')  # noqa: S608 # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text  identifiers are module constants
    select_one = sa.text(f'SELECT "{column}" FROM {table} WHERE id = :id')  # noqa: S608 # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    guarded_update = f'UPDATE {table} SET "{column}" = :value WHERE id = :id AND "{column}" = :old'  # noqa: S608
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    update = sa.text(guarded_update)
    for row_id, stored in connection.execute(select_all).all():
        report.scanned += 1
        try:
            value, kind = _classify_stored_json(stored, keyring=keyring, purpose=purpose)
        except DecryptionFailed:
            report.failed.append(str(row_id))
            continue
        if kind == "malformed":
            report.malformed += 1
            report.failed.append(str(row_id))
            continue
        if kind == "current":
            report.already_current += 1
            continue
        if dry_run:
            _count_written(report, kind)
            continue
        written = connection.execute(
            update,
            {
                # SQLite returns the Uuid column as hex text, Postgres as a
                # native uuid; passing back what the SELECT returned works on both.
                "id": row_id,
                "old": stored,
                "value": encrypt_json(value, keyring=keyring, purpose=purpose),
            },
        ).rowcount
        if written != 0:  # 1, or -1 on a dialect that cannot count; none of ours
            _count_written(report, kind)
            continue
        report.changed_under_us += 1
        now = connection.execute(select_one, {"id": row_id}).scalar()
        try:
            _value, kind_now = _classify_stored_json(now, keyring=keyring, purpose=purpose)
        except DecryptionFailed:
            report.failed.append(str(row_id))
            continue
        if kind_now != "current":
            report.failed.append(str(row_id))
    return report


def _count_written(report: ColumnRewrapReport, kind: _StoredKind) -> None:
    if kind == "previous":
        report.rewrapped += 1
    else:
        report.plaintext += 1


def rewrap_mfa_secrets(
    connection: Connection,
    *,
    keyring: SecretKeyring,
    dry_run: bool = False,
) -> ColumnRewrapReport:
    """Re-wrap every ``users.mfa_secret_encrypted`` under the current master.

    Uses the MFA module's own primitive, user-id AAD included, so the blob
    this writes is byte-for-byte what the login path would have written.
    The UPDATE carries the same guard as :func:`rewrap_json_column`: a user
    who re-enrolled between the read and the write keeps the new secret,
    and the row is counted as ``changed_under_us``. On re-read a cleared
    secret (MFA disabled meanwhile) is nothing to re-wrap; a new secret not
    under the current master is listed in ``failed``.
    """
    report = ColumnRewrapReport(table="users", column="mfa_secret_encrypted")
    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    select_all = sa.text(
        "SELECT id, mfa_secret_encrypted FROM users "
        "WHERE mfa_secret_encrypted IS NOT NULL ORDER BY id",
    )
    select_one = sa.text("SELECT mfa_secret_encrypted FROM users WHERE id = :id")
    update = sa.text(
        "UPDATE users SET mfa_secret_encrypted = :value "
        "WHERE id = :id AND mfa_secret_encrypted = :old",
    )

    def _decrypt(blob: bytes, user_id: uuid.UUID) -> tuple[bytes, bool]:
        return decrypt_totp_secret(
            blob,
            master_secret=keyring.current,
            user_id=user_id,
            previous_secrets=keyring.previous,
        )

    for row_id, stored in connection.execute(select_all).all():
        report.scanned += 1
        user_id = row_id if isinstance(row_id, uuid.UUID) else uuid.UUID(str(row_id))
        old = bytes(stored)
        try:
            plaintext, needs_rewrap = _decrypt(old, user_id)
        except DecryptionFailed:
            report.failed.append(str(user_id))
            continue
        if not needs_rewrap:
            report.already_current += 1
            continue
        if dry_run:
            report.rewrapped += 1
            continue
        written = connection.execute(
            update,
            {
                # SQLite returns the Uuid column as hex text, Postgres as a
                # native uuid; passing back what the SELECT returned works on both.
                "id": row_id,
                "old": old,
                "value": encrypt_totp_secret(
                    plaintext,
                    master_secret=keyring.current,
                    user_id=user_id,
                ),
            },
        ).rowcount
        if written != 0:
            report.rewrapped += 1
            continue
        report.changed_under_us += 1
        now = connection.execute(select_one, {"id": row_id}).scalar()
        if now is None:
            continue
        try:
            _plaintext, needs_rewrap_now = _decrypt(bytes(now), user_id)
        except DecryptionFailed:
            report.failed.append(str(user_id))
            continue
        if needs_rewrap_now:
            report.failed.append(str(user_id))
    return report


def rewrap_all_secret_fields(
    connection: Connection,
    *,
    keyring: SecretKeyring,
    dry_run: bool = False,
) -> RewrapReport:
    """Walk every encrypted column in one transaction the caller owns.

    The caller decides whether to commit: when ``report.refused`` is True
    nothing was written, and when ``report.failed`` is non-zero the rows
    that did decrypt have been re-wrapped, every plaintext row has been
    encrypted, and the failing ids are listed so the operator can put the
    missing previous secret back and run again.
    """
    report = RewrapReport(dry_run=dry_run)
    for table, purpose in ENCRYPTED_JSON_COLUMNS:
        report.columns.append(
            rewrap_json_column(
                connection,
                table=table,
                purpose=purpose,
                keyring=keyring,
                dry_run=True,
            ),
        )
    report.columns.append(rewrap_mfa_secrets(connection, keyring=keyring, dry_run=True))
    if dry_run or report.refused:
        return report
    # The dry pass above decided whether writing is allowed at all; now do
    # the writes with the same keyring. The counts match the dry pass
    # unless a row changes under the walk, which the write pass reports.
    report = RewrapReport(dry_run=False)
    for table, purpose in ENCRYPTED_JSON_COLUMNS:
        report.columns.append(
            rewrap_json_column(connection, table=table, purpose=purpose, keyring=keyring),
        )
    report.columns.append(rewrap_mfa_secrets(connection, keyring=keyring))
    return report


__all__ = [
    "ENCRYPTED_JSON_COLUMNS",
    "ENCRYPTED_JSON_COLUMNS_REVISION",
    "ENCRYPTED_PREFIX",
    "NOTIFICATION_CHANNEL_CONFIG",
    "USER_CHANNEL_CONFIG",
    "ColumnRewrapReport",
    "DecryptionFailed",
    "EncryptedJSONWriteError",
    "RewrapReport",
    "SecretKeyring",
    "SecretKeyringUnbound",
    "active_keyring",
    "bind_keyring",
    "bind_keyring_from_settings",
    "canonical_json",
    "decrypt_json",
    "encrypt_json",
    "is_encrypted",
    "rewrap_all_secret_fields",
    "rewrap_json_column",
    "rewrap_mfa_secrets",
]
