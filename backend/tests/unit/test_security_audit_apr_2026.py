"""Regression tests for the Apr 2026 z4j-scheduler security audit.

Each test pins one fix from the audit so a future refactor that
silently reverts the protection trips the suite. Test class names
match the audit finding IDs (``test_h1``, ``test_l1``, ``test_m6``,
etc.) so the audit report's evidence pointers stay accurate over
time.

The audit report is at `docs/SECURITY_AUDIT_2026_04.md`. Read
that for the full context on each finding.
"""

from __future__ import annotations

import secrets
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest


# =====================================================================
# H-1: gRPC server logs loud warning when CN allow-list is empty
# =====================================================================


class TestH1EmptyAllowListWarning:
    def test_empty_allow_list_logs_warning_at_startup(self) -> None:
        """An empty Z4J_SCHEDULER_GRPC_ALLOWED_CNS must produce a
        loud warning so operators can spot a misconfig in their
        log aggregator."""
        pytest.importorskip("grpc")
        pytest.importorskip("cryptography")

        import logging  # noqa: PLC0415

        from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
        from sqlalchemy.pool import StaticPool  # noqa: PLC0415

        from z4j_brain.persistence.base import Base  # noqa: PLC0415
        from z4j_brain.persistence.database import (  # noqa: PLC0415
            DatabaseManager,
        )
        from z4j_brain.scheduler_grpc.server import (  # noqa: PLC0415
            SchedulerGrpcServer,
        )
        from z4j_brain.settings import Settings  # noqa: PLC0415

        async def _go() -> None:
            engine = create_async_engine(
                "sqlite+aiosqlite:///:memory:",
                poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            settings = Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
                scheduler_grpc_enabled=True,
                # Crucially, allow-list is empty.
                scheduler_grpc_allowed_cns=[],
                # Skip TLS material validation by not actually
                # binding the port - we just exercise the start
                # path until the warning is emitted.
                scheduler_grpc_tls_cert="/tmp/fake.crt",
                scheduler_grpc_tls_key="/tmp/fake.key",
                scheduler_grpc_tls_ca="/tmp/fake.ca",
            )
            db = DatabaseManager(engine)
            srv = SchedulerGrpcServer(
                settings=settings,
                db=db,
                command_dispatcher=None,  # type: ignore[arg-type]
                audit_service=None,  # type: ignore[arg-type]
            )
            # The server's `start()` will fail later when it tries
            # to bind, but the warning fires before that.
            with patch.object(
                logging.getLogger("z4j.brain.scheduler_grpc.server"),
                "warning",
            ) as mock_warning:
                try:
                    await srv.start()
                except Exception:  # noqa: BLE001
                    pass  # expected - fake TLS material won't load
                # Confirm the audit-fix warning fired with the
                # ``scheduler_grpc_open_ca`` event tag (in either
                # the message body or the structured ``event``
                # extra).
                assert mock_warning.called, (
                    "empty allow-list must log a warning"
                )
                msg = mock_warning.call_args.args[0]
                extras = mock_warning.call_args.kwargs.get("extra", {})
                assert (
                    "scheduler_grpc_open_ca" in msg
                    or extras.get("event") == "scheduler_grpc_open_ca"
                )

        import asyncio

        asyncio.run(_go())


# =====================================================================
# L-1: gRPC NOTIFY watch path uses connection kwargs, not URL string
# =====================================================================


class TestL1DsnHandling:
    def test_handlers_module_does_not_render_password_into_string(
        self,
    ) -> None:
        """Audit fix: pre-fix the WatchSchedules NOTIFY path
        rendered the SQLAlchemy URL with ``hide_password=False``
        into a plain string. The fix uses
        ``translate_connect_args`` instead.

        We assert at the source level rather than dynamically
        because the fix is a contract: future contributors should
        NOT re-introduce the string rendering.
        """
        from pathlib import Path  # noqa: PLC0415

        source = (
            Path(__file__).resolve().parents[2]
            / "src" / "z4j_brain" / "scheduler_grpc" / "handlers.py"
        ).read_text()
        assert "hide_password=False" not in source, (
            "Found `hide_password=False` in handlers.py - the "
            "audit fix L-1 forbids materializing the DB password "
            "into a heap string. Use translate_connect_args() "
            "kwargs instead."
        )
        assert "translate_connect_args" in source


# =====================================================================
# M-3 / L-3: Error message sanitizer
# =====================================================================


class TestErrorSanitizer:
    def test_truncates_long_messages(self) -> None:
        from z4j_brain.scheduler_grpc.handlers import (  # noqa: PLC0415
            _sanitize_error_message,
        )

        long_msg = "x" * 5000
        result = _sanitize_error_message(long_msg)
        assert result is not None
        assert len(result) <= 500
        assert result.endswith("...")

    def test_strips_control_characters(self) -> None:
        from z4j_brain.scheduler_grpc.handlers import (  # noqa: PLC0415
            _sanitize_error_message,
        )

        # ANSI escape, NUL, newline, carriage return, bell
        injected = "real error\x1b[31m\x00\nINJECTED LOG LINE\rmore"
        result = _sanitize_error_message(injected)
        assert result is not None
        assert "\x00" not in result
        assert "\n" not in result
        assert "\r" not in result
        assert "\x1b" not in result

    def test_empty_or_whitespace_returns_none(self) -> None:
        from z4j_brain.scheduler_grpc.handlers import (  # noqa: PLC0415
            _sanitize_error_message,
        )

        assert _sanitize_error_message("") is None
        assert _sanitize_error_message(None) is None
        assert _sanitize_error_message("   \n\t  ") is None

    def test_keeps_normal_text(self) -> None:
        from z4j_brain.scheduler_grpc.handlers import (  # noqa: PLC0415
            _sanitize_error_message,
        )

        # Normal error text passes through largely untouched.
        msg = "agent failed: TimeoutError after 30s"
        result = _sanitize_error_message(msg)
        assert result == msg


# =====================================================================
# REST H-1: args/kwargs size cap
# =====================================================================


class TestRestArgsKwargsSizeCap:
    def test_oversized_kwargs_rejected_at_schema(self) -> None:
        from pydantic import ValidationError as PydanticValidationError

        from z4j_brain.api.schedules import (  # noqa: PLC0415
            ScheduleCreateIn,
        )

        # Build a kwargs dict whose serialised size exceeds the
        # 64 KB cap.
        big_value = "x" * 70_000
        with pytest.raises(PydanticValidationError) as ei:
            ScheduleCreateIn(
                name="big", engine="celery", kind="cron",
                expression="0 * * * *",
                task_name="t.t",
                kwargs={"payload": big_value},
            )
        assert "64" in str(ei.value) or "exceeds" in str(ei.value)

    def test_normal_size_kwargs_accepted(self) -> None:
        from z4j_brain.api.schedules import (  # noqa: PLC0415
            ScheduleCreateIn,
        )

        s = ScheduleCreateIn(
            name="ok", engine="celery", kind="cron",
            expression="0 * * * *",
            task_name="t.t",
            kwargs={"a": 1, "b": "x" * 100},
        )
        assert s.kwargs == {"a": 1, "b": "x" * 100}


# =====================================================================
# REST H-2: kind enum validation at schema
# =====================================================================


class TestRestKindEnum:
    def test_unknown_kind_rejected(self) -> None:
        from pydantic import ValidationError as PydanticValidationError

        from z4j_brain.api.schedules import (  # noqa: PLC0415
            ScheduleCreateIn,
        )

        with pytest.raises(PydanticValidationError):
            ScheduleCreateIn(
                name="x", engine="celery",
                kind="quantum",  # not in vocab
                expression="0 * * * *",
                task_name="t.t",
            )

    def test_each_known_kind_accepted(self) -> None:
        from z4j_brain.api.schedules import (  # noqa: PLC0415
            ScheduleCreateIn,
        )

        for k in ("cron", "interval", "one_shot", "solar"):
            s = ScheduleCreateIn(
                name="x", engine="celery", kind=k,
                expression="0 * * * *",
                task_name="t.t",
            )
            assert s.kind == k


# =====================================================================
# REST H-3: replace_for_source source allow-list
# =====================================================================


class TestRestReplaceForSourceAllowList:
    def test_dashboard_source_rejected(self) -> None:
        from z4j_brain.api.schedules import (  # noqa: PLC0415
            _validate_replace_for_source_label,
        )

        # The exploit case: source_filter="dashboard", schedules=[]
        # would wipe every dashboard-managed schedule.
        with pytest.raises(ValueError, match="not in"):
            _validate_replace_for_source_label("dashboard")

    def test_empty_source_rejected(self) -> None:
        from z4j_brain.api.schedules import (  # noqa: PLC0415
            _validate_replace_for_source_label,
        )

        with pytest.raises(ValueError, match="non-empty"):
            _validate_replace_for_source_label("")
        with pytest.raises(ValueError, match="non-empty"):
            _validate_replace_for_source_label(None)

    def test_typo_source_rejected(self) -> None:
        from z4j_brain.api.schedules import (  # noqa: PLC0415
            _validate_replace_for_source_label,
        )

        # Typo of a real source label - operator mistake. Must not
        # become a destructive operation.
        with pytest.raises(ValueError, match="not in"):
            _validate_replace_for_source_label("declarative-django")
        with pytest.raises(ValueError, match="not in"):
            _validate_replace_for_source_label("imported-celery")
        with pytest.raises(ValueError, match="not in"):
            _validate_replace_for_source_label("Declarative:Django")

    def test_each_legitimate_source_accepted(self) -> None:
        from z4j_brain.api.schedules import (  # noqa: PLC0415
            _validate_replace_for_source_label,
        )

        for label in (
            "declarative:django",
            "declarative:flask",
            "declarative:fastapi",
            "imported_celerybeat",
            "imported_rq",
            "imported_apscheduler",
            "imported_cron",
            "imported",
        ):
            assert _validate_replace_for_source_label(label) == label


# =====================================================================
# Embedded sidecar 4.1: PKI path traversal
# =====================================================================


class TestEmbeddedPkiPathValidator:
    def test_etc_rejected(self) -> None:
        # POSIX system path - the exploit case.
        from z4j_brain.embedded_scheduler import (  # noqa: PLC0415
            _validate_pki_out_dir,
        )

        # On Windows the resolver translates /etc to a relative
        # path; the validator only catches the actual POSIX root.
        # We test with an absolute Windows system path AND a POSIX
        # path that the resolver leaves unmunged.
        import sys  # noqa: PLC0415

        if sys.platform == "win32":
            with pytest.raises(ValueError, match="system path"):
                _validate_pki_out_dir(Path("C:/Windows/Temp"))
        else:
            with pytest.raises(ValueError, match="system path"):
                _validate_pki_out_dir(Path("/etc/z4j"))

    def test_root_rejected(self) -> None:
        from z4j_brain.embedded_scheduler import (  # noqa: PLC0415
            _validate_pki_out_dir,
        )
        import sys  # noqa: PLC0415

        if sys.platform != "win32":
            with pytest.raises(ValueError, match="system path"):
                _validate_pki_out_dir(Path("/usr/lib/z4j"))

    def test_legitimate_path_accepted(self, tmp_path: Path) -> None:
        from z4j_brain.embedded_scheduler import (  # noqa: PLC0415
            _validate_pki_out_dir,
        )

        _validate_pki_out_dir(tmp_path / "z4j-pki")  # no raise


# =====================================================================
# Embedded sidecar 3.2: env whitelist for subprocess
# =====================================================================


class TestEmbeddedEnvWhitelist:
    def test_supervisor_env_does_not_leak_brain_secrets(self) -> None:
        """Brain secrets (DATABASE_URL, Z4J_SECRET, AWS_*, etc.)
        must NOT be forwarded into the subprocess env."""
        from unittest.mock import MagicMock  # noqa: PLC0415

        from z4j_brain.embedded_scheduler import (  # noqa: PLC0415
            EmbeddedSchedulerSupervisor,
            mint_loopback_pki,
        )

        # Realistic operator env: brain secrets + whitelisted vars
        # + AWS creds should all be present in the parent.
        spoofed = {
            "PATH": "/usr/bin",
            "HOME": "/home/test",
            "Z4J_SECRET": "brain-master-key-DO-NOT-LEAK",
            "Z4J_SESSION_SECRET": "session-key-also-secret",
            "Z4J_DATABASE_URL": "postgres://u:pw@brain-db:5432/db",
            "AWS_ACCESS_KEY_ID": "AKIA-LEAK-TEST",
            "AWS_SECRET_ACCESS_KEY": "secret-aws-key",
            "GITHUB_TOKEN": "ghp_test_token",
            "Z4J_SCHEDULER_LOG_LEVEL": "DEBUG",  # passes whitelist
        }
        # Build a real supervisor + PKI to exercise the env builder.
        import tempfile  # noqa: PLC0415

        with tempfile.TemporaryDirectory(prefix="z4j-env-test-") as tmp:
            pki = mint_loopback_pki(Path(tmp))
            settings = MagicMock()
            settings.embedded_scheduler_argv = ["serve"]
            settings.embedded_scheduler_restart_max_attempts = 1
            settings.embedded_scheduler_restart_backoff_seconds = 1.0
            settings.embedded_scheduler_shutdown_grace_seconds = 1.0
            sup = EmbeddedSchedulerSupervisor(
                settings=settings,
                pki=pki,
                brain_grpc_host="127.0.0.1",
                brain_grpc_port=12345,
                brain_rest_url="http://127.0.0.1:7700",
            )
            with patch.dict("os.environ", spoofed, clear=True):
                env = sup._build_subprocess_env()

        # Brain secrets MUST NOT be in the subprocess env.
        assert "Z4J_SECRET" not in env, (
            "Brain master secret leaked to subprocess env"
        )
        assert "Z4J_SESSION_SECRET" not in env
        assert "Z4J_DATABASE_URL" not in env
        assert "AWS_ACCESS_KEY_ID" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "GITHUB_TOKEN" not in env
        # Whitelisted vars MUST be present.
        assert env.get("PATH") == "/usr/bin"
        assert env.get("HOME") == "/home/test"
        # Z4J_SCHEDULER_* whitelist via prefix.
        assert env.get("Z4J_SCHEDULER_LOG_LEVEL") == "DEBUG"
        # Embedded-mode-specific vars set by the supervisor.
        assert env.get("Z4J_SCHEDULER_BRAIN_GRPC_URL") == "127.0.0.1:12345"
        assert env.get("Z4J_SCHEDULER_LEADER_BACKEND") == "single"


# =====================================================================
# Embedded sidecar 7.1: restart-cap exhaustion sets
# permanently_failed flag
# =====================================================================


class TestEmbeddedPermanentlyFailedFlag:
    def test_supervisor_starts_with_flag_false(self) -> None:
        from unittest.mock import MagicMock  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        from z4j_brain.embedded_scheduler import (  # noqa: PLC0415
            EmbeddedSchedulerSupervisor,
            mint_loopback_pki,
        )

        with tempfile.TemporaryDirectory(prefix="z4j-flag-test-") as tmp:
            pki = mint_loopback_pki(Path(tmp))
            settings = MagicMock()
            sup = EmbeddedSchedulerSupervisor(
                settings=settings, pki=pki,
                brain_grpc_host="127.0.0.1",
                brain_grpc_port=1, brain_rest_url="http://x:1",
            )
        assert sup.permanently_failed is False

    def test_flag_exposed_via_property(self) -> None:
        from unittest.mock import MagicMock  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        from z4j_brain.embedded_scheduler import (  # noqa: PLC0415
            EmbeddedSchedulerSupervisor,
            mint_loopback_pki,
        )

        with tempfile.TemporaryDirectory(prefix="z4j-flag-test2-") as tmp:
            pki = mint_loopback_pki(Path(tmp))
            settings = MagicMock()
            sup = EmbeddedSchedulerSupervisor(
                settings=settings, pki=pki,
                brain_grpc_host="127.0.0.1",
                brain_grpc_port=1, brain_rest_url="http://x:1",
            )
        # Setting the private flag (simulating watchdog give-up)
        # surfaces via the public property.
        sup._permanently_failed = True  # noqa: SLF001
        assert sup.permanently_failed is True


# =====================================================================
# M-5 (closed Apr 2026 follow-up): per-cert project binding for
# SchedulerService RPCs.
#
# Originally deferred as "by design per spec §22"; closed after
# follow-up review concluded that for true multi-tenant deployments
# every allow-listed cert having cross-project authority is a real
# authorization gap.
#
# These tests pin:
# - The settings parser accepts JSON env-var form
# - The binding helper allows when bindings are empty (legacy mode)
# - The binding helper allows when the peer's CN isn't in the map
#   (mixed mode preserves cross-project authority for unbound CNs)
# - The binding helper aborts with PERMISSION_DENIED when the peer
#   IS bound and the project is not in the binding list
# - FireSchedule honors the binding (end-to-end)
# =====================================================================


class TestM5BindingsSettingParser:
    def test_empty_string_yields_empty_dict(self) -> None:
        from z4j_brain.settings import Settings  # noqa: PLC0415

        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            log_json=False,
            scheduler_grpc_cn_project_bindings={},
        )
        assert s.scheduler_grpc_cn_project_bindings == {}

    def test_json_string_parses_to_dict(self) -> None:
        from z4j_brain.settings import Settings  # noqa: PLC0415

        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
            environment="dev",
            log_json=False,
            scheduler_grpc_cn_project_bindings='{"sched-1": ["acme", "globex"]}',
        )
        assert s.scheduler_grpc_cn_project_bindings == {
            "sched-1": ["acme", "globex"],
        }

    def test_malformed_json_rejected(self) -> None:
        from z4j_brain.settings import Settings  # noqa: PLC0415

        with pytest.raises(Exception, match="JSON object"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
                scheduler_grpc_cn_project_bindings="{not json",
            )

    def test_non_dict_rejected(self) -> None:
        from z4j_brain.settings import Settings  # noqa: PLC0415

        with pytest.raises(Exception, match="JSON object"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
                scheduler_grpc_cn_project_bindings='["acme"]',
            )

    def test_value_must_be_list_of_strings(self) -> None:
        from z4j_brain.settings import Settings  # noqa: PLC0415

        with pytest.raises(Exception, match="list of non-empty"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
                environment="dev",
                log_json=False,
                scheduler_grpc_cn_project_bindings={
                    "sched-1": "acme",  # str, not list
                },
            )


class _BindingTestContext:
    """Mock ServicerContext with a configurable peer-CN auth context."""

    def __init__(self, *, cn: str | None = None) -> None:
        self._cn = cn
        self.aborted_with: tuple[object, str] | None = None

    def auth_context(self) -> dict:
        if self._cn is None:
            return {}
        return {
            "x509_common_name": [self._cn.encode()],
        }

    async def abort(self, code: object, details: str) -> None:
        self.aborted_with = (code, details)
        raise _BindingAbortError(code, details)

    def cancelled(self) -> bool:
        return False


class _BindingAbortError(Exception):
    """Raised by _BindingTestContext.abort to short-circuit the call."""


@pytest.fixture
def _binding_db():
    """Spin up an in-memory engine + DatabaseManager + one project."""
    import asyncio  # noqa: PLC0415

    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
    from sqlalchemy.pool import StaticPool  # noqa: PLC0415

    from z4j_brain.persistence.base import Base  # noqa: PLC0415
    from z4j_brain.persistence.database import DatabaseManager  # noqa: PLC0415
    from z4j_brain.persistence.models import Project  # noqa: PLC0415

    async def _setup():
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        db = DatabaseManager(engine)
        project_id = uuid.uuid4()
        async with db.session() as s:
            s.add(Project(id=project_id, slug="acme", name="Acme"))
            await s.commit()
        return engine, db, project_id

    engine, db, project_id = asyncio.run(_setup())
    yield db, project_id
    asyncio.run(engine.dispose())


class TestM5BindingHelper:
    @pytest.mark.asyncio
    async def test_empty_bindings_is_noop(self, _binding_db) -> None:
        """Legacy mode: no bindings -> every CN keeps cross-project authority."""
        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            enforce_cn_project_binding,
        )

        db, project_id = _binding_db
        ctx = _BindingTestContext(cn="any-cn")
        # Must not raise.
        await enforce_cn_project_binding(
            context=ctx,
            project_id=project_id,
            bindings={},
            db=db,
        )
        assert ctx.aborted_with is None

    @pytest.mark.asyncio
    async def test_unbound_cn_keeps_authority(self, _binding_db) -> None:
        """Mixed mode: a CN not in the map keeps cross-project auth."""
        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            enforce_cn_project_binding,
        )

        db, project_id = _binding_db
        ctx = _BindingTestContext(cn="unbound-cn")
        await enforce_cn_project_binding(
            context=ctx,
            project_id=project_id,
            bindings={"different-cn": ["acme"]},
            db=db,
        )
        assert ctx.aborted_with is None

    @pytest.mark.asyncio
    async def test_bound_cn_with_matching_project_allowed(
        self, _binding_db,
    ) -> None:
        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            enforce_cn_project_binding,
        )

        db, project_id = _binding_db
        ctx = _BindingTestContext(cn="sched-1")
        await enforce_cn_project_binding(
            context=ctx,
            project_id=project_id,
            bindings={"sched-1": ["acme"]},
            db=db,
        )
        assert ctx.aborted_with is None

    @pytest.mark.asyncio
    async def test_bound_cn_with_unbound_project_rejected(
        self, _binding_db,
    ) -> None:
        """The exploit path: bound CN tries to act on a project NOT
        in its binding list. Must abort PERMISSION_DENIED."""
        import grpc  # noqa: PLC0415

        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            enforce_cn_project_binding,
        )

        db, project_id = _binding_db
        ctx = _BindingTestContext(cn="sched-1")
        with pytest.raises(_BindingAbortError):
            await enforce_cn_project_binding(
                context=ctx,
                project_id=project_id,  # acme
                bindings={"sched-1": ["different-project"]},
                db=db,
            )
        assert ctx.aborted_with is not None
        code, _details = ctx.aborted_with
        assert code == grpc.StatusCode.PERMISSION_DENIED

    @pytest.mark.asyncio
    async def test_unknown_project_rejected(self, _binding_db) -> None:
        """Bound CN against a non-existent project -> PERMISSION_DENIED.

        Don't reveal "project doesn't exist" vs "you're not bound to it"
        at the auth boundary.
        """
        import grpc  # noqa: PLC0415

        from z4j_brain.scheduler_grpc.binding import (  # noqa: PLC0415
            enforce_cn_project_binding,
        )

        db, _project_id = _binding_db
        ctx = _BindingTestContext(cn="sched-1")
        with pytest.raises(_BindingAbortError):
            await enforce_cn_project_binding(
                context=ctx,
                project_id=uuid.uuid4(),  # not in DB
                bindings={"sched-1": ["acme"]},
                db=db,
            )
        code, _details = ctx.aborted_with  # type: ignore[misc]
        assert code == grpc.StatusCode.PERMISSION_DENIED


# =====================================================================
# Rate limit (closed Apr 2026 follow-up): FireSchedule per-cert
# token bucket.
#
# Originally deferred pending operator input on backend choice;
# closed by landing a Postgres/SQLite-portable token bucket keyed by
# cert CN. These tests pin:
# - Disabled flag short-circuits and always allows
# - Empty CN bypasses the limit (consistent with no-mTLS fallback)
# - First observation seeds the bucket at full capacity
# - Burst of N requests within capacity all succeed
# - The N+1 request denied
# - Refill restores tokens after time passes
# - Asking for more tokens than capacity is denied (no negative seed)
# =====================================================================


@pytest.fixture
def _rate_db():
    import asyncio  # noqa: PLC0415

    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
    from sqlalchemy.pool import StaticPool  # noqa: PLC0415

    from z4j_brain.persistence.base import Base  # noqa: PLC0415
    from z4j_brain.persistence.database import DatabaseManager  # noqa: PLC0415

    async def _setup():
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return engine, DatabaseManager(engine)

    engine, db = asyncio.run(_setup())
    yield db
    asyncio.run(engine.dispose())


def _rate_settings(
    *, enabled: bool = True, capacity: float = 5.0, rate: float = 1.0,
):
    from z4j_brain.settings import Settings  # noqa: PLC0415

    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        session_secret=secrets.token_urlsafe(48),  # type: ignore[arg-type]
        environment="dev",
        log_json=False,
        scheduler_grpc_fire_rate_limit_enabled=enabled,
        scheduler_grpc_fire_rate_capacity=capacity,
        scheduler_grpc_fire_rate_per_second=rate,
    )


class TestFireScheduleRateLimiter:
    @pytest.mark.asyncio
    async def test_disabled_always_allows(self, _rate_db) -> None:
        from z4j_brain.domain.scheduler_rate_limiter import (  # noqa: PLC0415
            SchedulerRateLimiter,
        )

        rl = SchedulerRateLimiter(
            db=_rate_db,
            settings=_rate_settings(enabled=False, capacity=1.0),
        )
        # 100 calls, capacity 1, disabled -> all allowed.
        for _ in range(100):
            assert await rl.consume(cert_cn="any") is True

    @pytest.mark.asyncio
    async def test_empty_cn_bypasses_limit(self, _rate_db) -> None:
        from z4j_brain.domain.scheduler_rate_limiter import (  # noqa: PLC0415
            SchedulerRateLimiter,
        )

        rl = SchedulerRateLimiter(
            db=_rate_db,
            settings=_rate_settings(capacity=1.0),
        )
        for _ in range(10):
            assert await rl.consume(cert_cn="") is True

    @pytest.mark.asyncio
    async def test_burst_within_capacity_all_allowed(self, _rate_db) -> None:
        from z4j_brain.domain.scheduler_rate_limiter import (  # noqa: PLC0415
            SchedulerRateLimiter,
        )

        rl = SchedulerRateLimiter(
            db=_rate_db,
            settings=_rate_settings(capacity=5.0, rate=0.01),
        )
        # First 5 calls within capacity -> all True.
        for i in range(5):
            assert await rl.consume(cert_cn="sched-1") is True, f"call {i}"
        # 6th call -> over budget (refill rate is 0.001/sec, so the
        # ~ms between calls won't refill a full token).
        assert await rl.consume(cert_cn="sched-1") is False

    @pytest.mark.asyncio
    async def test_per_cert_isolation(self, _rate_db) -> None:
        """One cert exhausting its bucket must not affect another."""
        from z4j_brain.domain.scheduler_rate_limiter import (  # noqa: PLC0415
            SchedulerRateLimiter,
        )

        rl = SchedulerRateLimiter(
            db=_rate_db,
            settings=_rate_settings(capacity=2.0, rate=0.01),
        )
        # Drain sched-1.
        assert await rl.consume(cert_cn="sched-1") is True
        assert await rl.consume(cert_cn="sched-1") is True
        assert await rl.consume(cert_cn="sched-1") is False
        # sched-2 still has its full bucket.
        assert await rl.consume(cert_cn="sched-2") is True
        assert await rl.consume(cert_cn="sched-2") is True

    @pytest.mark.asyncio
    async def test_refill_restores_capacity(self, _rate_db) -> None:
        """After enough wall-clock for refill, denied calls become
        allowed again. We verify by manually backdating last_refill
        on the persisted row (otherwise the test would have to sleep
        seconds, which is too brittle for CI)."""
        import asyncio  # noqa: PLC0415
        from datetime import UTC, datetime, timedelta  # noqa: PLC0415

        from sqlalchemy import update  # noqa: PLC0415

        from z4j_brain.domain.scheduler_rate_limiter import (  # noqa: PLC0415
            SchedulerRateLimiter,
        )
        from z4j_brain.persistence.models import (  # noqa: PLC0415
            SchedulerRateBucket,
        )

        rl = SchedulerRateLimiter(
            db=_rate_db,
            settings=_rate_settings(capacity=2.0, rate=1.0),
        )
        # Drain.
        assert await rl.consume(cert_cn="sched-1") is True
        assert await rl.consume(cert_cn="sched-1") is True
        assert await rl.consume(cert_cn="sched-1") is False

        # Backdate last_refill 10 seconds. With rate=1.0 that's 10
        # tokens of refill; capped at capacity=2.
        async with _rate_db.session() as s:
            await s.execute(
                update(SchedulerRateBucket)
                .where(SchedulerRateBucket.cert_cn == "sched-1")
                .values(
                    last_refill=datetime.now(UTC) - timedelta(seconds=10),
                ),
            )
            await s.commit()

        # Now another call should succeed (refilled).
        assert await rl.consume(cert_cn="sched-1") is True

        # And avoid leaking pending tasks for asyncio.
        await asyncio.sleep(0)

    @pytest.mark.asyncio
    async def test_request_exceeding_capacity_denied(self, _rate_db) -> None:
        """Asking for more tokens than the bucket can ever hold is
        denied immediately rather than seeding at negative."""
        from z4j_brain.domain.scheduler_rate_limiter import (  # noqa: PLC0415
            SchedulerRateLimiter,
        )

        rl = SchedulerRateLimiter(
            db=_rate_db,
            settings=_rate_settings(capacity=5.0),
        )
        assert await rl.consume(cert_cn="sched-1", tokens=10.0) is False
