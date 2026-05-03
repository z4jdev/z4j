"""Tests for the embedded scheduler sidecar (P6-A).

Two surfaces:

1. :func:`mint_loopback_pki` - fast, deterministic-ish (the keys
   are random but the file layout + cert structure is fixed).
2. :class:`EmbeddedSchedulerSupervisor` - we drive it with a fake
   subprocess command (``sys.executable -c "import sys; sys.exit(0)"``)
   so we don't need the real ``z4j-scheduler`` binary on the test
   PATH and we control crash + restart timing precisely.

The supervisor tests run real subprocesses but each one terminates
within a fraction of a second, so the suite stays fast.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from z4j_brain.embedded_scheduler import (
    BRAIN_SERVER_CN,
    EmbeddedSchedulerSupervisor,
    SCHEDULER_CLIENT_CN,
    mint_loopback_pki,
)


# =====================================================================
# PKI minting
# =====================================================================


class TestMintLoopbackPKI:
    """The auto-minted PKI must produce a usable mTLS bundle.

    These tests verify the structural properties that the
    SchedulerGrpcServer + scheduler grpc.aio client will rely on.
    A drift in CN or SAN here would manifest as a TLS handshake
    failure at brain startup with a cryptic ``BAD_CERTIFICATE``
    error, so it's worth pinning at the unit level.
    """

    def test_writes_five_files_at_correct_modes(
        self, tmp_path: Path,
    ) -> None:
        bundle = mint_loopback_pki(tmp_path / "pki")

        for path in (
            bundle.ca_pem,
            bundle.server_cert_pem,
            bundle.server_key_pem,
            bundle.client_cert_pem,
            bundle.client_key_pem,
        ):
            assert path.is_file(), f"missing {path}"
            # On Windows the chmod is a no-op (POSIX permissions
            # don't apply); skip the mode check there.
            if sys.platform != "win32":
                mode = path.stat().st_mode & 0o777
                assert mode == 0o600, (
                    f"{path} has mode {oct(mode)}, expected 0o600"
                )

    def test_server_cert_has_localhost_san(self, tmp_path: Path) -> None:
        bundle = mint_loopback_pki(tmp_path / "pki")
        cert = x509.load_pem_x509_certificate(
            bundle.server_cert_pem.read_bytes(),
        )
        # CN check
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME,
        )[0].value
        assert cn == BRAIN_SERVER_CN
        # SAN check - must include both localhost (DNS) and
        # 127.0.0.1 (IP) so the subprocess can connect via either.
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        ).value
        dns_names = san_ext.get_values_for_type(x509.DNSName)
        assert "localhost" in dns_names
        ip_names = [str(ip) for ip in san_ext.get_values_for_type(
            x509.IPAddress,
        )]
        assert "127.0.0.1" in ip_names
        # Server EKU
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage,
        ).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    def test_client_cert_has_scheduler_cn(self, tmp_path: Path) -> None:
        bundle = mint_loopback_pki(tmp_path / "pki")
        cert = x509.load_pem_x509_certificate(
            bundle.client_cert_pem.read_bytes(),
        )
        cn = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME,
        )[0].value
        assert cn == SCHEDULER_CLIENT_CN
        # Client EKU - critical because the brain's interceptor
        # uses this to distinguish a scheduler from any other
        # service that happens to be signed by the same CA.
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage,
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    def test_leaves_signed_by_ca(self, tmp_path: Path) -> None:
        """Both server + client certs must verify under the CA."""
        bundle = mint_loopback_pki(tmp_path / "pki")
        ca = x509.load_pem_x509_certificate(bundle.ca_pem.read_bytes())
        for leaf_path in (bundle.server_cert_pem, bundle.client_cert_pem):
            leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
            assert leaf.issuer == ca.subject, (
                f"{leaf_path} not issued by CA"
            )
            # Verify signature (raises InvalidSignature on tamper)
            ca.public_key().verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                # pyright: ignore[reportGeneralTypeIssues]
                __import__(
                    "cryptography.hazmat.primitives.asymmetric.padding",
                    fromlist=["PKCS1v15"],
                ).PKCS1v15(),
                leaf.signature_hash_algorithm,
            )

    def test_keys_are_pkcs8_unencrypted(self, tmp_path: Path) -> None:
        """gRPC's ssl_credentials require unencrypted PKCS8."""
        bundle = mint_loopback_pki(tmp_path / "pki")
        for key_path in (bundle.server_key_pem, bundle.client_key_pem):
            # No password should be needed.
            serialization.load_pem_private_key(
                key_path.read_bytes(), password=None,
            )

    def test_idempotent_directory_create(self, tmp_path: Path) -> None:
        """Running twice into the same dir must not crash."""
        target = tmp_path / "pki"
        bundle1 = mint_loopback_pki(target)
        bundle2 = mint_loopback_pki(target)
        # Second run overwrites - both bundles exist on disk now.
        assert bundle1.ca_pem == bundle2.ca_pem
        assert bundle2.ca_pem.is_file()


# =====================================================================
# Supervisor lifecycle
# =====================================================================


def _make_settings(
    *,
    argv: list[str] | None = None,
    restart_max: int = 0,
    restart_backoff: float = 0.05,
    grace: float = 1.0,
) -> MagicMock:
    """Build a Settings stand-in with only the fields the supervisor reads.

    The real Settings class enforces a hundred unrelated invariants
    (secrets, allowed_hosts, etc) which would force every test to
    construct a full production-shaped config. The supervisor only
    looks at the embedded_* fields, so a MagicMock with explicit
    attributes is the right scope.
    """
    s = MagicMock()
    s.embedded_scheduler_argv = argv or [
        "-c", "import time; time.sleep(60)",
    ]
    s.embedded_scheduler_restart_max_attempts = restart_max
    s.embedded_scheduler_restart_backoff_seconds = restart_backoff
    s.embedded_scheduler_shutdown_grace_seconds = grace
    return s


def _make_pki(tmp_path: Path) -> object:
    """Quick PKI bundle for supervisor tests; the certs are not
    actually validated by the fake subprocess so we just need
    something with the five attributes the supervisor reads."""
    return mint_loopback_pki(tmp_path / "pki")


@pytest.mark.asyncio
class TestEmbeddedSchedulerSupervisor:

    async def test_start_spawns_subprocess(
        self, tmp_path: Path,
    ) -> None:
        # Use a do-nothing python -c that sleeps. We're not running
        # real z4j-scheduler; we override the argv directly. But
        # the supervisor builds argv as ``[sys.executable, "-m",
        # "z4j_scheduler", *settings.embedded_scheduler_argv]`` -
        # to avoid needing z4j_scheduler installed in the test
        # env we monkeypatch the spawn target.
        sup = EmbeddedSchedulerSupervisor(
            settings=_make_settings(),
            pki=_make_pki(tmp_path),  # type: ignore[arg-type]
            brain_grpc_host="127.0.0.1",
            brain_grpc_port=12345,
            brain_rest_url="http://127.0.0.1:7700",
        )
        # Override the spawn argv: skip the ``-m z4j_scheduler``
        # so the subprocess is just python -c "...".
        original_spawn = sup._spawn_subprocess

        async def spawn_with_direct_argv() -> None:
            argv = [sys.executable, *sup._settings.embedded_scheduler_argv]
            sup._proc = await asyncio.create_subprocess_exec(
                *argv,
                env=sup._build_subprocess_env(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        sup._spawn_subprocess = spawn_with_direct_argv  # type: ignore[method-assign]

        await sup.start()
        try:
            assert sup.is_running
            assert sup._proc is not None
            assert sup._proc.pid > 0
        finally:
            await sup.stop()
        assert not sup.is_running

    async def test_stop_terminates_subprocess(
        self, tmp_path: Path,
    ) -> None:
        sup = EmbeddedSchedulerSupervisor(
            settings=_make_settings(),
            pki=_make_pki(tmp_path),  # type: ignore[arg-type]
            brain_grpc_host="127.0.0.1",
            brain_grpc_port=12345,
            brain_rest_url="http://127.0.0.1:7700",
        )

        async def spawn_with_direct_argv() -> None:
            argv = [sys.executable, *sup._settings.embedded_scheduler_argv]
            sup._proc = await asyncio.create_subprocess_exec(
                *argv,
                env=sup._build_subprocess_env(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        sup._spawn_subprocess = spawn_with_direct_argv  # type: ignore[method-assign]

        await sup.start()
        proc = sup._proc
        assert proc is not None
        await sup.stop()
        # Subprocess must be reaped.
        assert proc.returncode is not None

    async def test_stop_idempotent(self, tmp_path: Path) -> None:
        sup = EmbeddedSchedulerSupervisor(
            settings=_make_settings(),
            pki=_make_pki(tmp_path),  # type: ignore[arg-type]
            brain_grpc_host="127.0.0.1",
            brain_grpc_port=12345,
            brain_rest_url="http://127.0.0.1:7700",
        )
        # Stop without start - must not raise.
        await sup.stop()
        await sup.stop()

    async def test_env_overrides_embedded_vars(
        self, tmp_path: Path,
    ) -> None:
        """The subprocess env must carry the loopback wiring."""
        pki = _make_pki(tmp_path)
        sup = EmbeddedSchedulerSupervisor(
            settings=_make_settings(),
            pki=pki,  # type: ignore[arg-type]
            brain_grpc_host="127.0.0.1",
            brain_grpc_port=54321,
            brain_rest_url="http://127.0.0.1:7700",
        )
        env = sup._build_subprocess_env()
        assert env["Z4J_SCHEDULER_BRAIN_GRPC_URL"] == "127.0.0.1:54321"
        assert env["Z4J_SCHEDULER_BRAIN_REST_URL"] == "http://127.0.0.1:7700"
        assert env["Z4J_SCHEDULER_TLS_CERT"] == str(
            pki.client_cert_pem,  # type: ignore[attr-defined]
        )
        assert env["Z4J_SCHEDULER_TLS_KEY"] == str(
            pki.client_key_pem,  # type: ignore[attr-defined]
        )
        assert env["Z4J_SCHEDULER_TLS_CA"] == str(
            pki.ca_pem,  # type: ignore[attr-defined]
        )
        # Embedded mode forces single-instance leader (the brain
        # process is the unit of HA, not the embedded scheduler).
        assert env["Z4J_SCHEDULER_LEADER_BACKEND"] == "single"

    async def test_restart_cap_zero_disables_auto_restart(
        self, tmp_path: Path,
    ) -> None:
        """``restart_max_attempts=0`` means a single crash is permanent."""
        # Subprocess that exits immediately.
        sup = EmbeddedSchedulerSupervisor(
            settings=_make_settings(
                argv=["-c", "import sys; sys.exit(7)"],
                restart_max=0,
            ),
            pki=_make_pki(tmp_path),  # type: ignore[arg-type]
            brain_grpc_host="127.0.0.1",
            brain_grpc_port=12345,
            brain_rest_url="http://127.0.0.1:7700",
        )

        async def spawn_with_direct_argv() -> None:
            argv = [sys.executable, *sup._settings.embedded_scheduler_argv]
            sup._proc = await asyncio.create_subprocess_exec(
                *argv,
                env=sup._build_subprocess_env(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        sup._spawn_subprocess = spawn_with_direct_argv  # type: ignore[method-assign]

        await sup.start()
        # Wait long enough for the subprocess to die + watchdog
        # to observe.
        await asyncio.sleep(0.3)
        await sup.stop()
        # Watchdog must NOT have respawned.
        assert sup.restart_count == 1, (
            f"expected exactly 1 crash with no restart, got "
            f"{sup.restart_count}"
        )

    async def test_restart_cap_positive_respawns(
        self, tmp_path: Path,
    ) -> None:
        """With cap=2 a fast-crashing subprocess respawns up to 2 times."""
        crash_count = {"n": 0}

        sup = EmbeddedSchedulerSupervisor(
            settings=_make_settings(
                argv=["-c", "import sys; sys.exit(7)"],
                restart_max=2,
                restart_backoff=0.01,
            ),
            pki=_make_pki(tmp_path),  # type: ignore[arg-type]
            brain_grpc_host="127.0.0.1",
            brain_grpc_port=12345,
            brain_rest_url="http://127.0.0.1:7700",
        )

        async def spawn_with_direct_argv() -> None:
            crash_count["n"] += 1
            argv = [sys.executable, *sup._settings.embedded_scheduler_argv]
            sup._proc = await asyncio.create_subprocess_exec(
                *argv,
                env=sup._build_subprocess_env(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        sup._spawn_subprocess = spawn_with_direct_argv  # type: ignore[method-assign]

        await sup.start()
        # Long enough for 1 initial + 2 respawns + watchdog give-up.
        await asyncio.sleep(1.0)
        await sup.stop()
        # 1 initial + 2 respawns = 3 total spawn calls. Each spawn
        # crashes immediately (sys.exit(7)) so restart_count is
        # incremented 3 times - on the 3rd the cap is exceeded
        # (3 > 2) and the watchdog gives up.
        assert crash_count["n"] == 3, (
            f"expected 3 spawns (1 initial + 2 retries), got {crash_count['n']}"
        )
        assert sup.restart_count == 3
