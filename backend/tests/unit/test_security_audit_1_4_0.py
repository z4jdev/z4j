"""Regression tests for the 1.4.0 security audit fixes.

Covers brain-side findings only; scheduler-side findings (S002,
plus the symmetric S004 case) live in the z4j-scheduler suite.

- S001: ListSchedules.page_size clamp
- S004: scheduler_grpc_require_allowlist startup-fail opt-in
- S005: write_minted_cert against a pre-existing loose-perms dir

See ``RELEASE-1.4.0-SECURITY-AUDIT.md`` for the original audit
narrative and ``RELEASE-1.4.0-PLAN.md §4.7`` for the policy.
"""

from __future__ import annotations

import os
import secrets
import stat
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("grpc")
pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.persistence.base import Base
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import Project, Schedule
from z4j_brain.scheduler_grpc.auth import (
    mint_scheduler_cert,
    write_minted_cert,
)
from z4j_brain.scheduler_grpc.handlers import (
    _DEFAULT_LIST_PAGE_SIZE,
    _MAX_LIST_PAGE_SIZE,
    SchedulerServiceImpl,
)
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.settings import Settings


def _self_signed_ca() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")],
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(8), "big"))
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


class _NoopContext:
    def cancelled(self) -> bool:
        return False

    async def abort(self, code: object, details: str) -> None:
        raise AssertionError(f"unexpected abort: {code} {details}")

    def auth_context(self) -> dict:
        return {}


# =====================================================================
# S001 -- ListSchedules.page_size clamp
# =====================================================================


class TestS001PageSizeClamp:
    """Audit fix S001: ListSchedules.page_size is clamped to a hard max.

    Pre-fix the caller-supplied page_size went straight into
    ``stmt.limit(page_size)``. A misbehaving or compromised
    scheduler client could request ``page_size=2_000_000_000`` and
    force the brain to allocate a giant ORM batch.
    """

    def test_max_is_sane(self) -> None:
        # Sanity: the cap exists and is well above the default but
        # well below memory-pressure territory.
        assert _DEFAULT_LIST_PAGE_SIZE <= _MAX_LIST_PAGE_SIZE
        assert _MAX_LIST_PAGE_SIZE >= 100
        assert _MAX_LIST_PAGE_SIZE <= 100_000

    @pytest.mark.asyncio
    async def test_oversized_page_size_clamped(
        self,
        brain_settings: Settings,
    ) -> None:
        """Request with page_size = 10**9 must not OOM the brain.

        We can't directly observe the SQL ``LIMIT`` from the streaming
        servicer, but we CAN verify two things:

        1. The handler completes without error against an oversized
           value (no ValueError for huge int -> SQL).
        2. With ``_MAX_LIST_PAGE_SIZE + N`` rows in the DB and a
           caller asking for 10**9, the response includes ALL rows
           (so the cap doesn't accidentally truncate legitimate
           queries) but is delivered via paginated batches that
           respect the cap.

        Item 2 is the meaningful regression guard: if a future
        refactor accidentally drops the ``min()``, the test still
        passes, but if the cap is set absurdly low (truncating the
        result), this test catches it.
        """
        engine = create_async_engine(brain_settings.database_url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            db = DatabaseManager(engine)
            project_id = uuid.uuid4()

            async with db.session() as session:
                project = Project(
                    id=project_id,
                    slug="s001-test",
                    name="s001",
                )
                session.add(project)
                # Insert _MAX_LIST_PAGE_SIZE + 5 rows so a working
                # paginator returns them all across multiple batches.
                for i in range(_MAX_LIST_PAGE_SIZE + 5):
                    session.add(
                        Schedule(
                            project_id=project_id,
                            engine="celery",
                            scheduler="z4j-scheduler",
                            name=f"s-{i}",
                            task_name="t.t",
                            kind=ScheduleKind.CRON,
                            expression="0 * * * *",
                            timezone="UTC",
                            args=[],
                            kwargs={},
                            is_enabled=True,
                        ),
                    )
                await session.commit()

            servicer = SchedulerServiceImpl(
                settings=brain_settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            request = pb.ListSchedulesRequest(
                project_id=str(project_id),
                page_size=1_000_000_000,
            )
            results = []
            async for sched in servicer.ListSchedules(
                request,
                _NoopContext(),
            ):
                results.append(sched)

            assert len(results) == _MAX_LIST_PAGE_SIZE + 5, (
                "clamping the page_size must not lose rows -- "
                "the paginator should still return all matches "
                "across multiple batches"
            )
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_zero_page_size_uses_default(
        self,
        brain_settings: Settings,
    ) -> None:
        """Empty/zero page_size falls back to the default, not 0.

        Pre-fix this also worked, but the new ``min()`` path is a
        common place to introduce a regression where 0 sneaks in
        as the SQL LIMIT.
        """
        engine = create_async_engine(brain_settings.database_url, future=True)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            db = DatabaseManager(engine)
            project_id = uuid.uuid4()
            async with db.session() as session:
                session.add(
                    Project(
                        id=project_id,
                        slug="s001-zero",
                        name="zero",
                    ),
                )
                session.add(
                    Schedule(
                        project_id=project_id,
                        engine="celery",
                        scheduler="z4j-scheduler",
                        name="only-one",
                        task_name="t.t",
                        kind=ScheduleKind.CRON,
                        expression="0 * * * *",
                        timezone="UTC",
                        args=[],
                        kwargs={},
                        is_enabled=True,
                    ),
                )
                await session.commit()

            servicer = SchedulerServiceImpl(
                settings=brain_settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            # page_size=0 in proto3 is the default-int value, so this
            # also covers "field not set on the wire".
            request = pb.ListSchedulesRequest(
                project_id=str(project_id),
                page_size=0,
            )
            results = []
            async for sched in servicer.ListSchedules(
                request,
                _NoopContext(),
            ):
                results.append(sched)
            assert len(results) == 1
        finally:
            await engine.dispose()


# =====================================================================
# S004 -- scheduler_grpc_require_allowlist startup-fail opt-in
# =====================================================================


class TestS004RequireAllowlist:
    """Audit fix S004: brain refuses to start scheduler gRPC server
    when ``scheduler_grpc_require_allowlist=true`` and allow-list
    is empty.

    The default (False) preserves "trust the CA" mode with a loud
    startup warning, so existing deployments don't break. Operators
    flipping the flag opt into fail-closed defense in depth.
    """

    def test_default_is_false(self, brain_settings: Settings) -> None:
        # Hard guard against accidentally flipping the default in a
        # future refactor; flipping it would silently break
        # tasks.jfk.work and any operator running without an
        # allow-list.
        assert brain_settings.scheduler_grpc_require_allowlist is False

    @pytest.mark.asyncio
    async def test_start_raises_when_required_and_empty(
        self,
        brain_settings: Settings,
        tmp_path: Path,
    ) -> None:
        """``SchedulerGrpcServer.start`` raises before binding the port."""
        from z4j_brain.scheduler_grpc.server import SchedulerGrpcServer

        # Need TLS material to get past the cert-loading guards.
        ca_cert, ca_key = _self_signed_ca()
        cert_pem, key_pem = mint_scheduler_cert(
            name="srv",
            ca_cert_pem=ca_cert,
            ca_key_pem=ca_key,
        )
        ca_path = tmp_path / "ca.crt"
        cert_path = tmp_path / "srv.crt"
        key_path = tmp_path / "srv.key"
        ca_path.write_bytes(ca_cert)
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)

        # Build settings: gRPC enabled, TLS configured, BUT
        # require_allowlist=True with empty allowed_cns -> fail.
        s = brain_settings.model_copy(
            update={
                "scheduler_grpc_enabled": True,
                "scheduler_grpc_bind_host": "127.0.0.1",
                "scheduler_grpc_bind_port": 0,
                "scheduler_grpc_tls_cert": str(cert_path),
                "scheduler_grpc_tls_key": str(key_path),
                "scheduler_grpc_tls_ca": str(ca_path),
                "scheduler_grpc_allowed_cns": [],
                "scheduler_grpc_require_allowlist": True,
            },
        )

        engine = create_async_engine(s.database_url, future=True)
        try:
            db = DatabaseManager(engine)
            server = SchedulerGrpcServer(
                settings=s,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            with pytest.raises(
                RuntimeError,
                match="require_allowlist",
            ):
                await server.start()
        finally:
            await engine.dispose()


# =====================================================================
# S005 -- write_minted_cert against a pre-existing loose-perms dir
# =====================================================================


class TestS005WriteMintedCertHardensExistingDir:
    """Audit fix S005: ``write_minted_cert`` tightens perms on a
    pre-existing dir + writes the key with the strict mode set at
    ``os.open`` (no TOCTOU window between write and chmod).
    """

    def test_pre_existing_loose_dir_gets_tightened(
        self,
        tmp_path: Path,
    ) -> None:
        if os.name != "posix":
            pytest.skip("POSIX-only mode bits assertion")

        # Create the dir loose first to mimic an operator re-running
        # the cert-mint command against a previous output dir.
        out_dir = tmp_path / "out"
        out_dir.mkdir(mode=0o755)
        out_dir.chmod(0o755)
        # Sanity check: real perms are 0o755 before our call.
        assert stat.S_IMODE(out_dir.lstat().st_mode) == 0o755

        ca_cert, ca_key = _self_signed_ca()
        cert_pem, key_pem = mint_scheduler_cert(
            name="sch",
            ca_cert_pem=ca_cert,
            ca_key_pem=ca_key,
        )
        cert_path, key_path = write_minted_cert(
            out_dir=out_dir,
            name="sch",
            cert_pem=cert_pem,
            key_pem=key_pem,
        )

        # The fix re-chmods the existing dir to 0o700.
        assert oct(out_dir.stat().st_mode)[-3:] == "700", (
            "write_minted_cert must tighten the perms of a "
            "pre-existing dir, not silently leave it loose"
        )
        # Files have strict mode set at create time (not after).
        assert oct(cert_path.stat().st_mode)[-3:] == "600"
        assert oct(key_path.stat().st_mode)[-3:] == "600"

    def test_files_use_atomic_secure_write_helper(
        self,
        tmp_path: Path,
    ) -> None:
        """Round-trip: bytes written must equal bytes read.

        Regression guard: a Windows-specific bug where ``os.open``
        defaulted to text mode caused PEM ``\\n`` to become
        ``\\r\\n``. The 1.4.0 ``fs_safe.write_bytes_secure`` adds
        ``O_BINARY`` to defeat this on Windows; this test fails
        loudly if a future refactor drops it.
        """
        ca_cert, ca_key = _self_signed_ca()
        cert_pem, key_pem = mint_scheduler_cert(
            name="sch",
            ca_cert_pem=ca_cert,
            ca_key_pem=ca_key,
        )
        cert_path, key_path = write_minted_cert(
            out_dir=tmp_path / "out2",
            name="sch",
            cert_pem=cert_pem,
            key_pem=key_pem,
        )
        assert cert_path.read_bytes() == cert_pem
        assert key_path.read_bytes() == key_pem


# =====================================================================
# S007 -- DNS cache LRU cap
# =====================================================================


class TestS007DnsCacheLRU:
    """Audit fix S007: ``_DNS_CACHE`` in notifications/channels is
    a bounded LRU.

    Pre-fix the cache was an unbounded ``dict``. An authenticated
    tenant who creates webhook channels for many distinct hostnames
    could grow it without bound. The 30s TTL evicts on next-lookup
    of an entry, but a continuous flow of new hostnames accumulates
    stale entries between sweeps. Hard cap closes that.
    """

    def setup_method(self) -> None:
        # Each test starts with a clean cache so insertion order is
        # deterministic. Module-global state otherwise; the LRU
        # invariants are easier to assert from a known empty state.
        from z4j_brain.domain.notifications import channels

        channels._DNS_CACHE.clear()

    def test_constants_present(self) -> None:
        from z4j_brain.domain.notifications import channels

        assert hasattr(channels, "_DNS_CACHE_MAX")
        assert channels._DNS_CACHE_MAX >= 1000
        assert channels._DNS_CACHE_MAX <= 100_000

    def test_set_entry_caps_at_max(self) -> None:
        """Inserting beyond ``_DNS_CACHE_MAX`` evicts oldest first."""
        from z4j_brain.domain.notifications import channels

        cap = channels._DNS_CACHE_MAX
        # Force a tiny cap for the test so we don't allocate 10k entries.
        original_cap = channels._DNS_CACHE_MAX
        channels._DNS_CACHE_MAX = 5
        try:
            for i in range(10):
                channels._set_dns_cache_entry(
                    f"host-{i}.example.com",
                    time.monotonic() + 10_000,
                    [f"10.0.0.{i}"],
                )
            assert len(channels._DNS_CACHE) == 5, "cache must be capped at the configured max"
            # Oldest (host-0..host-4) must be evicted; newest 5 remain.
            for i in range(5):
                assert f"host-{i}.example.com" not in channels._DNS_CACHE
            for i in range(5, 10):
                assert f"host-{i}.example.com" in channels._DNS_CACHE
        finally:
            channels._DNS_CACHE_MAX = original_cap
            channels._DNS_CACHE.clear()
            assert cap == channels._DNS_CACHE_MAX

    @pytest.mark.asyncio
    async def test_hot_entry_survives_eviction(self) -> None:
        """A hostname touched recently must NOT be evicted by churn."""
        from z4j_brain.domain.notifications import channels

        original_cap = channels._DNS_CACHE_MAX
        channels._DNS_CACHE_MAX = 3
        try:
            # Seed three distinct entries.
            for i in range(3):
                channels._set_dns_cache_entry(
                    f"host-{i}.example.com",
                    time.monotonic() + 10_000,
                    [f"10.0.0.{i}"],
                )
            # Touch host-0 via _resolve_cached: it's still within
            # TTL so we get a cache hit, which moves it to MRU end.
            ips = await channels._resolve_cached("host-0.example.com")
            assert ips == ["10.0.0.0"]
            # Now insert two NEW entries -- this should evict host-1
            # and host-2 (the actually-oldest), NOT host-0 (touched).
            channels._set_dns_cache_entry(
                "host-new1.example.com",
                time.monotonic() + 10_000,
                ["10.1.0.1"],
            )
            channels._set_dns_cache_entry(
                "host-new2.example.com",
                time.monotonic() + 10_000,
                ["10.1.0.2"],
            )
            assert "host-0.example.com" in channels._DNS_CACHE, (
                "MRU touch must protect a hot entry from eviction"
            )
            assert "host-1.example.com" not in channels._DNS_CACHE
            assert "host-2.example.com" not in channels._DNS_CACHE
            assert "host-new1.example.com" in channels._DNS_CACHE
            assert "host-new2.example.com" in channels._DNS_CACHE
        finally:
            channels._DNS_CACHE_MAX = original_cap
            channels._DNS_CACHE.clear()


# =====================================================================
# M1 -- Invitation accept must enforce password policy
# =====================================================================


class TestM1InvitationAcceptPasswordPolicy:
    """Audit fix M1 (1.4.0 pre-release pass): invitation acceptance
    must call ``hasher.validate_policy()`` before ``hasher.hash()``.

    Pre-fix the public POST /invitations/accept handler hashed the
    request password directly, bypassing the 3-of-4-character-classes
    + common-password denylist + max-length checks. Length was still
    enforced via Pydantic ``Field(min_length=12)``, but a value like
    ``"qwertyuiop12"`` (12 chars, only lowercase+digit, 2 classes)
    or ``"PasswordABC1"`` (in the common-password denylist) would
    pass.

    Every other write path (auth.py password change, users.py admin
    create / set, cli.py changepassword, setup_service first-boot,
    startup admin bootstrap) calls ``validate_policy()``. M1 closes
    the inconsistency.
    """

    @pytest.mark.asyncio
    async def test_accept_handler_rejects_weak_password_before_side_effects(
        self,
        brain_settings,
    ) -> None:
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        from z4j_brain.api.invitations import (
            InvitationAcceptRequest,
            accept_invitation,
        )
        from z4j_brain.auth.passwords import PasswordError

        project_id = uuid.uuid4()
        row = SimpleNamespace(
            id=uuid.uuid4(),
            project_id=project_id,
            email="invitee@example.test",
            role="viewer",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            revoked_at=None,
            accepted_at=None,
        )
        invitations = SimpleNamespace(
            get_by_hash=AsyncMock(return_value=row),
            accept=AsyncMock(),
        )
        users = SimpleNamespace(
            get_by_email=AsyncMock(return_value=None),
            add=AsyncMock(),
        )
        memberships = SimpleNamespace(grant=AsyncMock())
        projects = SimpleNamespace(
            get=AsyncMock(
                return_value=SimpleNamespace(
                    id=project_id,
                    slug="invited-project",
                    name="Invited project",
                ),
            ),
        )
        audit = SimpleNamespace(record=AsyncMock())
        db_session = SimpleNamespace(commit=AsyncMock())
        body = InvitationAcceptRequest(
            token="invitation-token",
            password="qwertyuiop12",
            display_name="Invitee",
        )

        with pytest.raises(PasswordError, match="at least 3"):
            await accept_invitation(
                body=body,
                invitations=invitations,
                users=users,
                memberships=memberships,
                projects=projects,
                settings=brain_settings,
                audit=audit,
                audit_log=object(),
                db_session=db_session,
                ip="127.0.0.1",
            )

        users.add.assert_not_awaited()
        memberships.grant.assert_not_awaited()
        invitations.accept.assert_not_awaited()
        audit.record.assert_not_awaited()
        db_session.commit.assert_not_awaited()

    def test_validate_policy_rejects_invitation_grade_weak_passwords(
        self,
        brain_settings,
    ) -> None:
        """Behavior guard: validate_policy actually rejects the
        weak-but-12-char passwords that pre-M1 invitation accept
        would have happily hashed."""
        from z4j_brain.auth.passwords import PasswordError, PasswordHasher

        hasher = PasswordHasher(brain_settings)

        # 12 chars, only lowercase + digit (2 classes) -- fails the
        # 3-of-4-character-classes rule.
        with pytest.raises(PasswordError) as exc:
            hasher.validate_policy("qwertyuiop12")
        assert exc.value.code == "password_too_simple"

        # 12 chars, 3 classes (upper + lower + digit) but in the
        # common-password denylist.
        with pytest.raises(PasswordError) as exc:
            hasher.validate_policy("Password1234")
        assert exc.value.code == "password_in_breach_list"

        # Sanity: a strong 12-char password passes (so the test isn't
        # over-rejecting and accidentally proving "everything fails").
        hasher.validate_policy("MyStr0ng!Pass")  # no exception


# =====================================================================
# Low/Config-2 -- HTTPS-only webhook default
# =====================================================================


class TestLowConfig2HttpsOnlyWebhooks:
    """Audit fix Low/Config-2 (1.4.0 pre-release pass): generic
    webhook channels default to HTTPS-only.

    Pre-fix ``_ALLOWED_SCHEMES = frozenset({"https", "http"})``
    permitted plaintext webhook delivery to any operator-configured
    URL, leaking JSON payloads + custom headers in cleartext.
    Operators with legitimate internal-network http endpoints opt in
    via ``Z4J_NOTIFICATIONS_WEBHOOK_ALLOW_HTTP=true``.
    """

    def setup_method(self) -> None:
        # Each test starts in the secure default (HTTPS-only) so the
        # behavior is independent of test ordering. Seed the real resolver
        # cache with a public address: these are scheme-policy tests, and
        # external DNS availability must not decide their verdict.
        from z4j_brain.domain.notifications import channels

        channels.set_allow_http_webhooks(False)
        channels._DNS_CACHE.clear()
        channels._set_dns_cache_entry(
            "example.com",
            time.monotonic() + 60,
            ["93.184.216.34"],
        )

    def teardown_method(self) -> None:
        from z4j_brain.domain.notifications import channels

        channels.set_allow_http_webhooks(False)
        channels._DNS_CACHE.clear()

    @pytest.mark.asyncio
    async def test_http_url_rejected_by_default(self) -> None:
        from z4j_brain.domain.notifications import channels

        err = await channels.validate_webhook_url("http://example.com/hook")
        assert err is not None
        assert "http" in err.lower()
        assert "Z4J_NOTIFICATIONS_WEBHOOK_ALLOW_HTTP" in err

    @pytest.mark.asyncio
    async def test_https_url_accepted_by_default(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.domain.notifications import channels

        def fail_external_dns(*_args, **_kwargs):
            raise AssertionError("scheme-policy test attempted external DNS")

        monkeypatch.setattr(channels.socket, "getaddrinfo", fail_external_dns)
        # The setup seeds this public host in the resolver cache; the SSRF
        # guard still parses and classifies the IP, without a network oracle.
        err = await channels.validate_webhook_url("https://example.com/hook")
        assert err is None, f"expected accept, got: {err!r}"

    @pytest.mark.asyncio
    async def test_http_url_accepted_when_operator_opts_in(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from z4j_brain.domain.notifications import channels

        def fail_external_dns(*_args, **_kwargs):
            raise AssertionError("scheme-policy test attempted external DNS")

        monkeypatch.setattr(channels.socket, "getaddrinfo", fail_external_dns)
        channels.set_allow_http_webhooks(True)
        err = await channels.validate_webhook_url("http://example.com/hook")
        assert err is None, f"expected accept after opt-in, got: {err!r}"

    def test_default_setting_is_false(self, brain_settings) -> None:
        # Hard guard against accidentally flipping the default.
        # Flipping it back to True would silently re-open the
        # plaintext-delivery surface for every existing deployment.
        assert brain_settings.notifications_webhook_allow_http is False
