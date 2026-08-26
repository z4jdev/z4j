"""Tests for the brain-side scheduler_grpc module.

Three layers:

1. Pure-helper coverage (``mint_scheduler_cert``, ``_schedule_to_pb``,
   ``_ts_iso``) - no I/O, no DB.
2. Settings + lifecycle wiring - the disabled-by-default behaviour
   short-circuits and never imports the gRPC runtime.
3. Handlers smoke - construct the servicer against the test DB and
   call each RPC's pure-Python entry point. We don't spin up an
   actual gRPC server here; that path is exercised by the scheduler
   package's integration suite (which has both sides).

Layer 3 runs against a MIGRATED database rather than a create_all() one.
Every Boundary-D guard lives in a migration, so a create_all() schema
refuses nothing: it would take hand-built ``schedules`` rows that an
operator's database rejects outright, which is how a handler can pass its
whole test file and raise on first use.
"""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest

# The scheduler-grpc surface is in an optional extra. Skip the
# whole module when those deps aren't installed - the default brain
# install path is grpc-free.
pytest.importorskip("grpc")
pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from z4j_brain.persistence.database import DatabaseManager
from z4j_brain.persistence.enums import ScheduleKind
from z4j_brain.persistence.models import Project, Schedule
from z4j_brain.persistence.repositories.schedule_control import (
    ScheduleControlRepository,
)
from z4j_brain.scheduler_grpc.auth import (
    SchedulerAllowlistInterceptor,
    mint_scheduler_cert,
    write_minted_cert,
)
from z4j_brain.scheduler_grpc.handlers import (
    SchedulerServiceImpl,
    _schedule_to_pb,
    _ts_iso,
)
from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.server import SchedulerGrpcServer
from z4j_brain.settings import Settings

from tests.unit._schedule_seeding import project_external_schedule

# =====================================================================
# Helpers
# =====================================================================


def _self_signed_ca() -> tuple[bytes, bytes]:
    """Mint a throwaway CA cert + key for cert-minting tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test-ca"),
        ],
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


# =====================================================================
# Helper coverage
# =====================================================================


class TestTsIso:
    def test_unset_timestamp_returns_empty_string(self) -> None:
        from google.protobuf.timestamp_pb2 import Timestamp

        assert _ts_iso(Timestamp()) == ""

    def test_set_timestamp_returns_iso(self) -> None:
        from google.protobuf.timestamp_pb2 import Timestamp

        ts = Timestamp()
        ts.FromDatetime(datetime(2026, 4, 26, 15, 0, tzinfo=UTC))
        result = _ts_iso(ts)
        # Formatted as ISO-8601 with timezone.
        assert result.startswith("2026-04-26T15:00:00")


class TestScheduleToPb:
    def test_minimal_schedule(self) -> None:
        # A minimal Schedule mock with the fields _schedule_to_pb reads.
        sched = _make_schedule_obj()
        msg = _schedule_to_pb(sched)
        assert msg.id == str(sched.id)
        assert msg.project_id == str(sched.project_id)
        assert msg.engine == "celery"
        assert msg.kind == "cron"
        assert msg.expression == "0 * * * *"
        assert msg.timezone == "UTC"
        assert msg.is_enabled is True
        assert msg.catch_up == "skip"
        assert json.loads(msg.args_json.decode()) == []
        assert json.loads(msg.kwargs_json.decode()) == {}
        assert msg.control_token == ""
        assert msg.schedule_revision == 0
        assert msg.definition_digest == ""
        assert msg.cadence_semantics_version == 0
        assert msg.cadence_runtime_fingerprint == ""

    def test_current_control_generation(self) -> None:
        sched = _make_schedule_obj()
        token = uuid.uuid4()
        sched.control_token = token
        sched.schedule_revision = 41
        sched.definition_digest = "d" * 64
        sched.cadence_semantics_version = 1
        sched.cadence_runtime_fingerprint = "f" * 64
        msg = _schedule_to_pb(sched)
        assert msg.control_token == str(token)
        assert msg.schedule_revision == 41
        assert msg.definition_digest == "d" * 64
        assert msg.cadence_semantics_version == 1
        assert msg.cadence_runtime_fingerprint == "f" * 64


# =====================================================================
# Mint
# =====================================================================


class TestMintCert:
    def test_mint_produces_valid_pem(self) -> None:
        ca_cert, ca_key = _self_signed_ca()
        cert_pem, key_pem = mint_scheduler_cert(
            name="scheduler-1",
            ca_cert_pem=ca_cert,
            ca_key_pem=ca_key,
        )
        # Both are valid PEM.
        cert = x509.load_pem_x509_certificate(cert_pem)
        serialization.load_pem_private_key(key_pem, password=None)

        # Subject CN matches the requested name.
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        assert cn.value == "scheduler-1"

        # SAN contains the DNS name.
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        ).value
        assert "scheduler-1" in [n.value for n in san]

    def test_empty_name_rejected(self) -> None:
        ca_cert, ca_key = _self_signed_ca()
        with pytest.raises(ValueError, match="non-empty"):
            mint_scheduler_cert(
                name="",
                ca_cert_pem=ca_cert,
                ca_key_pem=ca_key,
            )

    def test_zero_validity_rejected(self) -> None:
        ca_cert, ca_key = _self_signed_ca()
        with pytest.raises(ValueError, match="positive"):
            mint_scheduler_cert(
                name="scheduler-1",
                ca_cert_pem=ca_cert,
                ca_key_pem=ca_key,
                validity_days=0,
            )

    def test_write_minted_cert_writes_files_with_strict_mode(
        self,
        tmp_path: Path,
    ) -> None:
        ca_cert, ca_key = _self_signed_ca()
        cert_pem, key_pem = mint_scheduler_cert(
            name="sch",
            ca_cert_pem=ca_cert,
            ca_key_pem=ca_key,
        )
        cert_path, key_path = write_minted_cert(
            out_dir=tmp_path / "out",
            name="sch",
            cert_pem=cert_pem,
            key_pem=key_pem,
        )
        assert cert_path.read_bytes() == cert_pem
        assert key_path.read_bytes() == key_pem
        # On Windows the mode bits we care about don't apply, so we
        # only assert mode on POSIX.
        import os

        if os.name == "posix":
            assert oct(cert_path.stat().st_mode)[-3:] == "600"
            assert oct(key_path.stat().st_mode)[-3:] == "600"


# =====================================================================
# Allow-list interceptor
# =====================================================================


class TestAllowlistInterceptor:
    def test_construct_with_empty_allowlist(self) -> None:
        # Empty allow-list = trust the CA. Construction must succeed
        # without raising.
        interceptor = SchedulerAllowlistInterceptor(allowed_cns=())
        assert interceptor._allowed == frozenset()

    def test_construct_with_populated_allowlist(self) -> None:
        interceptor = SchedulerAllowlistInterceptor(
            allowed_cns=("scheduler-1", "scheduler-2"),
        )
        assert interceptor._allowed == {"scheduler-1", "scheduler-2"}


class TestEnforceCnAuthContextShape:
    """Regression tests for the bytes/str AuthContext key ambiguity.

    grpcio's ``ServicerContext.auth_context()`` historically returned
    ``Mapping[bytes, list[bytes]]`` (the keys themselves were bytes).
    grpc.aio in 1.6x+ shifted to ``Mapping[str, list[bytes]]``. The
    previous implementation looked up ``auth_ctx.get(b"x509_common_name")``
    only, which silently returned ``[]`` against newer grpc.aio - the
    auto-minted scheduler-embedded cert was rejected as
    ``peer CNs []`` against an embedded brain in the Apr 2026 e2e run.

    These tests pin the dual-shape lookup so a future "cleanup" of
    the dual-key code does not silently regress. Both shapes are
    accepted; both populate ``cn_candidates`` correctly.
    """

    @pytest.mark.asyncio
    async def test_str_keyed_auth_context_accepts_known_cn(
        self,
    ) -> None:
        from z4j_brain.scheduler_grpc.auth import _enforce_cn

        # AsyncMock surrogate for ServicerContext that:
        # - Returns a str-keyed auth_context (grpc.aio 1.6+ shape).
        # - Records whether ``abort`` was called.
        class _Ctx:
            aborted = False

            def auth_context(self) -> dict[str, list[bytes]]:
                return {
                    "x509_common_name": [b"scheduler-1"],
                    "transport_security_type": [b"ssl"],
                }

            async def abort(self, code, msg) -> None:
                self.aborted = True

        ctx = _Ctx()
        await _enforce_cn(ctx, frozenset({"scheduler-1"}))  # type: ignore[arg-type]
        assert not ctx.aborted, "str-keyed AuthContext path failed to accept a known CN"

    @pytest.mark.asyncio
    async def test_bytes_keyed_auth_context_accepts_known_cn(
        self,
    ) -> None:
        from z4j_brain.scheduler_grpc.auth import _enforce_cn

        class _Ctx:
            aborted = False

            def auth_context(self) -> dict[bytes, list[bytes]]:
                # Older grpc shape - bytes keys + bytes values.
                return {
                    b"x509_common_name": [b"scheduler-1"],
                    b"transport_security_type": [b"ssl"],
                }

            async def abort(self, code, msg) -> None:
                self.aborted = True

        ctx = _Ctx()
        await _enforce_cn(ctx, frozenset({"scheduler-1"}))  # type: ignore[arg-type]
        assert not ctx.aborted, "bytes-keyed AuthContext path failed to accept a known CN"

    @pytest.mark.asyncio
    async def test_san_dns_prefix_stripped(self) -> None:
        # gRPC sometimes embeds DNS SAN entries as ``DNS:scheduler-1``.
        # ``removeprefix`` (NOT lstrip) strips that, otherwise a
        # legitimate CN starting with D/N/S/colon would be silently
        # corrupted (lstrip strips ANY of those characters).
        from z4j_brain.scheduler_grpc.auth import _enforce_cn

        class _Ctx:
            aborted = False

            def auth_context(self) -> dict[str, list[bytes]]:
                return {
                    "x509_subject_alternative_name": [b"DNS:scheduler-1"],
                }

            async def abort(self, code, msg) -> None:
                self.aborted = True

        ctx = _Ctx()
        await _enforce_cn(ctx, frozenset({"scheduler-1"}))  # type: ignore[arg-type]
        assert not ctx.aborted

    @pytest.mark.asyncio
    async def test_unknown_cn_aborts_with_permission_denied(self) -> None:
        from z4j_brain.scheduler_grpc.auth import _enforce_cn

        captured: dict[str, object] = {}

        class _Ctx:
            def auth_context(self) -> dict[str, list[bytes]]:
                return {"x509_common_name": [b"intruder"]}

            async def abort(self, code, msg) -> None:
                captured["code"] = code
                captured["msg"] = msg
                # Real gRPC abort raises; mirror the behaviour so the
                # surrounding code path matches production semantics.
                raise RuntimeError("aborted")

        ctx = _Ctx()
        with pytest.raises(RuntimeError, match="aborted"):
            await _enforce_cn(ctx, frozenset({"scheduler-1"}))  # type: ignore[arg-type]
        # Don't assert specific status code module-bound; just confirm
        # the abort path was taken with a non-empty message.
        assert captured.get("msg")

    @pytest.mark.asyncio
    async def test_lstrip_dns_does_not_corrupt_cn_starting_with_d(
        self,
    ) -> None:
        # If the implementation ever regresses to ``lstrip("DNS:")``,
        # a CN like "Drone-1" would be silently mangled to "rone-1"
        # (lstrip strips ANY characters in the set "DNS:"). This test
        # makes that regression loud.
        from z4j_brain.scheduler_grpc.auth import _enforce_cn

        class _Ctx:
            aborted = False

            def auth_context(self) -> dict[str, list[bytes]]:
                return {"x509_common_name": [b"Drone-1"]}

            async def abort(self, code, msg) -> None:
                self.aborted = True

        ctx = _Ctx()
        await _enforce_cn(ctx, frozenset({"Drone-1"}))  # type: ignore[arg-type]
        assert not ctx.aborted, (
            "lstrip-style prefix stripping silently corrupted a "
            "legitimate CN starting with D/N/S/colon"
        )


# =====================================================================
# Server lifecycle
# =====================================================================


@pytest.fixture
def settings(migrated_db_url: str, migrated_audit_chain_secret: str) -> Settings:
    return Settings(
        database_url=migrated_db_url,
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        # A migrated database has Boundary F activated and refuses an audit
        # row that carries no chain authentication.
        audit_chain_secret=migrated_audit_chain_secret,  # type: ignore[arg-type]
        log_json=False,
        environment="dev",
    )


class TestServerLifecycleDisabled:
    @pytest.mark.asyncio
    async def test_disabled_start_is_noop(self, settings: Settings) -> None:
        # No TLS material, no allow-list, no port - but disabled
        # gates everything. start/stop must not blow up.
        engine = create_async_engine(settings.database_url, future=True)
        try:
            db = DatabaseManager(engine)
            srv = SchedulerGrpcServer(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            await srv.start()
            assert srv._server is None
            await srv.stop()  # noop on disabled
        finally:
            await engine.dispose()


class TestServerLifecycleEnabledMissingTls:
    @pytest.mark.asyncio
    async def test_enabled_without_tls_material_raises(
        self,
        migrated_db_url: str,
    ) -> None:
        # Operator set ENABLED=true but didn't supply cert paths.
        # We expect a clear RuntimeError pointing at the env var.
        # Built fresh rather than copied from the fixture: the point is that
        # a real Settings accepts this configuration and start() is what
        # refuses it.
        bad = Settings(
            database_url=migrated_db_url,
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            log_json=False,
            environment="dev",
            scheduler_grpc_enabled=True,
            # All three TLS paths missing.
        )
        engine = create_async_engine(bad.database_url, future=True)
        try:
            db = DatabaseManager(engine)
            srv = SchedulerGrpcServer(
                settings=bad,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            with pytest.raises(RuntimeError, match="TLS_CERT"):
                await srv.start()
        finally:
            await engine.dispose()


# =====================================================================
# Handlers smoke (Ping + ListSchedules)
# =====================================================================


class TestPingHandler:
    @pytest.mark.asyncio
    async def test_ping_returns_brain_version(
        self,
        settings: Settings,
    ) -> None:
        engine = create_async_engine(settings.database_url, future=True)
        try:
            db = DatabaseManager(engine)
            servicer = SchedulerServiceImpl(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            response = await servicer.Ping(pb.PingRequest(), _NoopContext())
            from z4j_brain import __version__

            assert response.brain_version == __version__
            # brain_time set; non-zero seconds.
            assert response.brain_time.seconds > 0
        finally:
            await engine.dispose()


class TestListSchedulesHandler:
    @pytest.mark.asyncio
    async def test_lists_only_z4j_scheduler_rows(
        self,
        settings: Settings,
    ) -> None:
        engine = create_async_engine(settings.database_url, future=True)
        try:
            db = DatabaseManager(engine)
            project_id = uuid.uuid4()

            async with db.session() as session:
                session.add(
                    Project(
                        id=project_id,
                        slug="test-project",
                        name="test",
                    ),
                )
                await session.flush()
                # One row that belongs to z4j-scheduler, planned through the
                # control repository because Boundary D refuses a direct
                # INSERT into schedules.
                await ScheduleControlRepository(session).create_current(
                    project_id=project_id,
                    data={
                        "engine": "celery",
                        "scheduler": "z4j-scheduler",
                        "name": "ours",
                        "task_name": "t.t",
                        "kind": ScheduleKind.CRON.value,
                        "expression": "0 * * * *",
                        "timezone": "UTC",
                        "args": [],
                        "kwargs": {},
                        "is_enabled": True,
                    },
                    planning_at=datetime.now(UTC),
                )
                await session.commit()

            # Another row owned by celery-beat, which must be filtered out.
            # There is no direct route to one: an externally owned schedule
            # exists only as the projection of an adapter's snapshot, and the
            # guards enforce that. Seeding it the real way is what makes this
            # a test of the owner filter against a row an operator can hold.
            await project_external_schedule(
                db,
                project_id=project_id,
                name="theirs",
            )

            servicer = SchedulerServiceImpl(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            # Both rows are really there, so "one result" means filtered and
            # not "the second row was never seeded".
            async with db.session() as session:
                owners = sorted(
                    (await session.execute(select(Schedule.scheduler))).scalars().all(),
                )
            assert owners == ["celery-beat", "z4j-scheduler"]

            request = pb.ListSchedulesRequest(project_id=str(project_id))
            results = []
            async for sched in servicer.ListSchedules(request, _NoopContext()):
                results.append(sched)
            assert len(results) == 1
            assert results[0].name == "ours"
        finally:
            await engine.dispose()


# =====================================================================
# Fakes
# =====================================================================


def _make_schedule_obj() -> object:
    """Light schedule-shaped object covering the fields _schedule_to_pb reads."""

    class _S:
        id = uuid.uuid4()
        project_id = uuid.uuid4()
        engine = "celery"
        name = "every-hour"
        task_name = "tasks.heartbeat"
        kind = ScheduleKind.CRON
        expression = "0 * * * *"
        timezone = "UTC"
        queue = ""
        args: ClassVar[list] = []
        kwargs: ClassVar[dict] = {}
        is_enabled = True
        last_run_at = None
        next_run_at = None
        total_runs = 0
        catch_up = "skip"
        source = "dashboard"
        source_hash = ""

    return _S()


class _NoopContext:
    """Stand-in for grpc.aio.ServicerContext for handler unit tests.

    Implements just enough surface for the handlers we exercise.
    Anything beyond Ping/ListSchedules will need extra methods.
    """

    def cancelled(self) -> bool:
        return False

    async def abort(self, code: object, details: str) -> None:
        raise AssertionError(f"unexpected abort: {code} {details}")

    def auth_context(self) -> dict:
        return {}


# =====================================================================
# CN normalisation regression guard (v1.1.0 audit finding 3)
# =====================================================================


class TestNormaliseCnDoesNotMangle:
    """``_normalise_cn`` strips a URI-style ``DNS:`` prefix once.

    Regression guard: a careless refactor to ``lstrip("DNS:")`` would
    pass every existing CN-equality test (because production
    deployments use names like ``scheduler-prod`` that don't start
    with ``D`` / ``N`` / ``S`` / ``:``) but would silently corrupt
    CNs that DO. These cases pin the correct behaviour explicitly
    so the bug can't sneak back in.
    """

    def test_strips_uri_prefix_once(self) -> None:
        from z4j_brain.scheduler_grpc.auth import _normalise_cn

        assert _normalise_cn("DNS:scheduler-prod") == "scheduler-prod"

    def test_does_not_strip_naked_cn(self) -> None:
        from z4j_brain.scheduler_grpc.auth import _normalise_cn

        assert _normalise_cn("scheduler-prod") == "scheduler-prod"

    def test_preserves_cn_starting_with_dns_letters(self) -> None:
        """``DNS-Scheduler-1`` looks like the prefix but isn't (it
        contains a hyphen, not a colon). A ``lstrip("DNS:")``
        regression would corrupt this to ``"-Scheduler-1"`` because
        lstrip eats any combination of the chars in its argument
        from the left. ``removeprefix`` only matches the exact full
        prefix and leaves this name intact.
        """
        from z4j_brain.scheduler_grpc.auth import _normalise_cn

        assert _normalise_cn("DNS-Scheduler-1") == "DNS-Scheduler-1"

    def test_preserves_cn_with_individual_prefix_chars(self) -> None:
        """Concrete cases: CNs starting with ``D``, ``N``, ``S``, or
        ``:`` would be silently mangled by ``lstrip``. None start
        with the literal substring ``"DNS:"`` so all must round-trip
        unchanged.
        """
        from z4j_brain.scheduler_grpc.auth import _normalise_cn

        for cn in ("Drone-1", "Node-A", "Scheduler-1", ":weird-cn"):
            assert _normalise_cn(cn) == cn, (
                f"{cn!r} corrupted to {_normalise_cn(cn)!r}; regression to lstrip()?"
            )

    def test_strips_surrounding_whitespace(self) -> None:
        from z4j_brain.scheduler_grpc.auth import _normalise_cn

        assert _normalise_cn("  scheduler-prod  ") == "scheduler-prod"
        assert _normalise_cn("DNS: scheduler-prod") == "scheduler-prod"
