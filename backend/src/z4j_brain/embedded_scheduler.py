"""Embedded scheduler sidecar (docs/SCHEDULER.md §21.3).

When ``Z4J_EMBEDDED_SCHEDULER=true`` the brain image starts a
``z4j-scheduler serve`` subprocess in its own lifespan. The
subprocess talks to brain's gRPC endpoint over loopback using PKI
auto-minted at boot - the operator does not have to mint or
distribute certificates.

Two pieces:

- :func:`mint_loopback_pki` - generates an in-memory CA, a server
  cert (CN ``brain-embedded``, SAN ``localhost`` + ``127.0.0.1``)
  signed by the CA, and a client cert (CN ``scheduler-embedded``,
  SAN ``scheduler-embedded``) also signed by the CA. Writes them
  with mode 0o600 into ``out_dir``.
- :class:`EmbeddedSchedulerSupervisor` - async lifecycle wrapper
  around an ``asyncio.subprocess.Process``. Handles spawn,
  graceful stop, and bounded auto-restart on crash. The watchdog
  task survives a single crash so a transient OOM doesn't
  permanently disable the scheduler.

The minted PKI is *not* a long-term identity. It rotates on every
brain restart unless the operator points
``embedded_scheduler_pki_dir`` at a persistent path. For a
single-container homelab deploy that's exactly the right trade -
the scheduler subprocess restarts in lockstep with brain anyway.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:  # pragma: no cover
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.embedded_scheduler")

#: CN used by the brain's gRPC server cert in embedded mode. Not
#: secret; baked into the auto-minted PKI so the scheduler
#: subprocess can verify the server cert by name.
BRAIN_SERVER_CN = "brain-embedded"

#: CN used by the scheduler subprocess's client cert in embedded
#: mode. Brain's allow-list is set to exactly this value so a
#: stolen scheduler cert from a non-embedded deployment can't be
#: replayed against an embedded brain.
SCHEDULER_CLIENT_CN = "scheduler-embedded"

#: RSA key size. 2048 is the floor for current-era TLS. We pick
#: it (over 4096) for boot speed - mint runs at every brain start.
_KEY_SIZE_BITS = 2048

#: Validity window. 365 days for the embedded scheduler is more
#: than enough since the certs are typically discarded on the
#: next restart anyway, but keeping the window long means an
#: operator who pins ``embedded_scheduler_pki_dir`` doesn't see
#: spurious expiry mid-year.
_VALIDITY_DAYS = 365


# =====================================================================
# PKI minting
# =====================================================================


@dataclass(frozen=True, slots=True)
class LoopbackPKI:
    """Filesystem layout of a freshly-minted embedded PKI bundle.

    All five paths are absolute and point at files written with
    mode 0o600 inside a directory minted at mode 0o700. The
    caller is responsible for cleaning the directory up if
    desired - :class:`EmbeddedSchedulerSupervisor` does not
    manage cleanup so a tempdir-based caller can use
    :class:`tempfile.TemporaryDirectory` independently.

    Attributes:
        ca_pem: Self-signed CA cert. Both subjects are signed
                with this; the scheduler's gRPC client uses it
                as its ``root_certificates`` and brain's gRPC
                server uses it as its ``root_certificates`` for
                client validation.
        server_cert_pem: Brain's gRPC server cert.
                         CN=BRAIN_SERVER_CN, SAN includes
                         ``localhost`` and ``127.0.0.1`` so the
                         subprocess can connect via either.
        server_key_pem: Brain's gRPC server private key.
        client_cert_pem: Scheduler subprocess's mTLS client cert.
                         CN=SCHEDULER_CLIENT_CN.
        client_key_pem: Scheduler subprocess's private key.
    """

    ca_pem: Path
    server_cert_pem: Path
    server_key_pem: Path
    client_cert_pem: Path
    client_key_pem: Path


_REFUSED_PKI_DIR_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    # Windows equivalents - normalized via Path.resolve() below.
    "C:\\Windows",
    "C:\\Program Files",
)


def _validate_pki_out_dir(out_dir: Path) -> None:
    """Refuse to mint PKI into a system-critical directory.

    Audit fix 4.1 (Apr 2026): if an attacker (or a misguided
    operator) sets ``Z4J_EMBEDDED_SCHEDULER_PKI_DIR=/etc``, the
    minter would overwrite ``/etc/ca.crt`` and chmod ``/etc`` to
    0o700. Refuse on a conservative blocklist; legitimate paths
    (system tempdirs, user homes, ``/var/lib/z4j``) are allowed.
    """
    import os  # noqa: PLC0415

    # Resolve to an absolute path WITHOUT requiring it to exist
    # (the minter creates it). This expands .. segments + normalizes
    # separators so attackers can't slip past via ``//etc`` etc.
    try:
        resolved = Path(os.path.abspath(str(out_dir)))
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"PKI dir {out_dir!r} could not be resolved: {exc}",
        ) from exc

    resolved_str = str(resolved)
    for prefix in _REFUSED_PKI_DIR_PREFIXES:
        # Compare on normalized form so case + slash flavor matches.
        if (
            resolved_str.lower() == prefix.lower()
            or resolved_str.lower().startswith(prefix.lower() + os.sep.lower())
            or resolved_str.lower().startswith(prefix.lower() + "/")
        ):
            raise ValueError(
                f"refusing to mint PKI under system path {prefix!r} "
                f"(resolved={resolved_str!r}). Set "
                f"Z4J_EMBEDDED_SCHEDULER_PKI_DIR to a dedicated "
                f"directory like /var/lib/z4j/scheduler-pki or use "
                f"the default per-process tempdir.",
            )


def mint_loopback_pki(out_dir: Path) -> LoopbackPKI:
    """Generate the embedded PKI bundle into ``out_dir``.

    Creates ``out_dir`` (and parents) at mode 0o700. Writes five
    PEM files at mode 0o600. The caller owns the directory's
    lifetime - if it should be cleaned up on shutdown, wrap the
    call in :class:`tempfile.TemporaryDirectory`.

    The five files are::

        ca.crt
        brain-embedded.crt
        brain-embedded.key
        scheduler-embedded.crt
        scheduler-embedded.key

    Audit fix 4.1 (Apr 2026): refuses to write into a directory
    whose parent is a system-critical path. Without this check,
    an operator (or a privilege-escalated process inside the
    brain container) could set
    ``Z4J_EMBEDDED_SCHEDULER_PKI_DIR=/etc`` and brain would
    happily overwrite ``/etc/ca.crt`` + reduce ``/etc`` to
    mode 0o700, breaking the host. The allow-list below is
    deliberately conservative, operators with legitimate need
    for an exotic path should set a path under one of these
    prefixes (e.g. ``/var/lib/z4j/scheduler-pki``).

    Raises:
        OSError: ``out_dir`` is unwritable.
        ValueError: ``out_dir`` falls under a refused system path.
    """
    _validate_pki_out_dir(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Re-chmod because mkdir mode does not retro-apply on existing
    # dirs and umask may have stripped bits.
    out_dir.chmod(0o700)

    ca_cert, ca_key = _mint_ca()
    server_cert = _mint_leaf(
        cn=BRAIN_SERVER_CN,
        ca_cert=ca_cert,
        ca_key=ca_key,
        sans=[
            x509.DNSName("localhost"),
            x509.DNSName(BRAIN_SERVER_CN),
            x509.IPAddress(_ip("127.0.0.1")),
            x509.IPAddress(_ip("::1")),
        ],
        is_server=True,
    )
    client_cert = _mint_leaf(
        cn=SCHEDULER_CLIENT_CN,
        ca_cert=ca_cert,
        ca_key=ca_key,
        sans=[x509.DNSName(SCHEDULER_CLIENT_CN)],
        is_server=False,
    )

    bundle = LoopbackPKI(
        ca_pem=out_dir / "ca.crt",
        server_cert_pem=out_dir / f"{BRAIN_SERVER_CN}.crt",
        server_key_pem=out_dir / f"{BRAIN_SERVER_CN}.key",
        client_cert_pem=out_dir / f"{SCHEDULER_CLIENT_CN}.crt",
        client_key_pem=out_dir / f"{SCHEDULER_CLIENT_CN}.key",
    )

    _write_pem(bundle.ca_pem, ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(
        bundle.server_cert_pem,
        server_cert[0].public_bytes(serialization.Encoding.PEM),
    )
    _write_pem(
        bundle.server_key_pem,
        _key_to_pem(server_cert[1]),
    )
    _write_pem(
        bundle.client_cert_pem,
        client_cert[0].public_bytes(serialization.Encoding.PEM),
    )
    _write_pem(
        bundle.client_key_pem,
        _key_to_pem(client_cert[1]),
    )
    logger.info(
        "z4j.brain.embedded_scheduler: minted loopback PKI in %s "
        "(server CN=%s, client CN=%s)",
        out_dir, BRAIN_SERVER_CN, SCHEDULER_CLIENT_CN,
    )
    return bundle


def _mint_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Self-signed CA used to sign both the server and client leaves."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=_KEY_SIZE_BITS,
    )
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "z4j"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "embedded"),
            x509.NameAttribute(
                NameOID.COMMON_NAME, "z4j-embedded-loopback-ca",
            ),
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
        .not_valid_after(now + timedelta(days=_VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert, key


def _mint_leaf(
    *,
    cn: str,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    sans: list[x509.GeneralName],
    is_server: bool,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Sign a leaf cert under ``ca_cert`` for the given CN + SANs."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=_KEY_SIZE_BITS,
    )
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "z4j"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                "embedded-server" if is_server else "embedded-client",
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ],
    )
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(8), "big"))
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=_VALIDITY_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.SERVER_AUTH
                    if is_server
                    else x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                ],
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(sans), critical=False,
        )
    )
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return cert, key


def _key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_pem(path: Path, data: bytes) -> None:
    """Write a PEM file atomically with 0o600 perms.

    Thin wrapper over :func:`z4j_brain.utils.fs_safe.write_bytes_secure`,
    kept for backwards compatibility with callers in this module.
    The implementation moved to ``utils/fs_safe.py`` in 1.4.0
    (audit fix S005) so the cert-mint helper in
    ``scheduler_grpc/auth.py`` shares the same race-safe primitive.
    """
    from z4j_brain.utils.fs_safe import write_bytes_secure  # noqa: PLC0415

    write_bytes_secure(path, data)


def _ip(value: str):  # noqa: ANN202 - tiny helper
    import ipaddress

    return ipaddress.ip_address(value)


# =====================================================================
# Subprocess supervisor
# =====================================================================


class EmbeddedSchedulerSupervisor:
    """Spawn + supervise a ``z4j-scheduler serve`` subprocess.

    The subprocess reads its config from environment variables
    that the supervisor sets at spawn time. The supervisor
    overrides only the variables that embedded mode controls
    (``BRAIN_GRPC_URL``, the three TLS paths, ``INSTANCE_ID``);
    everything else - bind ports, log level, etc. - is inherited
    from the parent's environment, so the operator can still tune
    the scheduler via env vars without recompiling.

    Construction is cheap (no process spawn). :meth:`start`
    spawns the subprocess and a watchdog task that auto-restarts
    on crash. :meth:`stop` is idempotent; the supervisor handles
    SIGTERM-then-SIGKILL transparently.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        pki: LoopbackPKI,
        brain_grpc_host: str,
        brain_grpc_port: int,
        brain_rest_url: str,
    ) -> None:
        self._settings = settings
        self._pki = pki
        self._brain_grpc_host = brain_grpc_host
        self._brain_grpc_port = brain_grpc_port
        self._brain_rest_url = brain_rest_url
        self._proc: asyncio.subprocess.Process | None = None
        self._watchdog: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._restart_count = 0
        # Audit fix (Apr 2026 follow-up): track the stdout/stderr
        # forwarder tasks so we can cancel them before re-spawning.
        # Pre-fix every restart leaked two new asyncio tasks; after
        # 100 restarts brain held 200 dead tasks reading from
        # already-closed pipes (they exited on EOF eventually so
        # no FD leak, but ``asyncio.all_tasks()`` introspection +
        # task-name registry got cluttered).
        self._stdout_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        # Audit fix 7.1 (Apr 2026): when the watchdog gives up
        # after the restart cap is exhausted, flip this flag so
        # operator-facing health checks (brain's /api/v1/health
        # path can read it) and metrics scrapers can detect that
        # embedded mode is permanently down. Pre-fix the watchdog
        # logged CRITICAL once and returned, leaving brain looking
        # healthy while fires silently stopped.
        self._permanently_failed = False

    @property
    def is_running(self) -> bool:
        """True iff the supervised subprocess is alive."""
        return self._proc is not None and self._proc.returncode is None

    @property
    def restart_count(self) -> int:
        """Number of auto-restarts performed since :meth:`start`."""
        return self._restart_count

    @property
    def permanently_failed(self) -> bool:
        """True iff the watchdog gave up after the restart cap.

        Operators with /health probes should treat this as a
        ``critical`` signal: the embedded scheduler is not
        coming back without a brain restart. Default False.
        """
        return self._permanently_failed

    @property
    def health_state(self) -> str:
        """Round-9 audit fix R9-Sched-H1 (Apr 2026): tri-state.

        Returns one of:

        - ``"running"``, subprocess is alive and accepting work.
        - ``"restarting"``, subprocess is currently down but the
          watchdog has not yet exhausted its restart budget. /health
          probes should treat this as transient (do NOT page).
        - ``"failed"``, watchdog gave up; only a brain restart
          will recover. /health probes should treat as critical.

        Pre-fix the only signal was ``is_running`` (instantaneous)
        and ``permanently_failed`` (set after the cap). A k8s
        readiness probe checking ``is_running`` flapped red on
        every transient crash during the backoff window even
        though the watchdog was about to respawn, paging
        operators on harmless restarts.
        """
        if self._permanently_failed:
            return "failed"
        if self.is_running:
            return "running"
        return "restarting"

    async def start(self) -> None:
        """Spawn the subprocess and the watchdog task.

        Called once at brain startup. Returns once the subprocess
        is launched - it does *not* wait for the scheduler's own
        readiness probe, because the scheduler can take a few
        seconds to bind its FastAPI port and we don't want brain's
        own startup to stall on it. If the subprocess fails
        immediately, the watchdog will surface the failure on its
        first restart attempt.
        """
        if self._watchdog is not None:
            raise RuntimeError(
                "EmbeddedSchedulerSupervisor.start called twice",
            )
        self._stop_event.clear()
        await self._spawn_subprocess()
        self._watchdog = asyncio.create_task(
            self._supervise(),
            name="z4j.embedded_scheduler.supervisor",
        )

    async def stop(self) -> None:
        """Graceful shutdown. Idempotent.

        Sends SIGTERM, waits up to
        ``embedded_scheduler_shutdown_grace_seconds``, then
        SIGKILL if the subprocess hasn't exited. Cancels the
        watchdog task so a death during teardown isn't replayed.
        """
        self._stop_event.set()
        if self._watchdog is not None:
            self._watchdog.cancel()
            try:
                await self._watchdog
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._watchdog = None
        await self._terminate_subprocess()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _spawn_subprocess(self) -> None:
        """Launch ``python -m z4j_scheduler <argv>`` with embedded env.

        Audit fix (Apr 2026 follow-up): cancel any previous
        stdout/stderr forwarder tasks before re-spawning so we
        don't accumulate dead readers across restart cycles.
        """
        # Cancel previous forwarders if any. They normally exit
        # naturally on pipe EOF when the previous subprocess died,
        # but ``cancel`` is idempotent and ensures we don't depend
        # on ordering.
        for prev_task_attr in ("_stdout_task", "_stderr_task"):
            prev: asyncio.Task | None = getattr(self, prev_task_attr)
            if prev is not None and not prev.done():
                prev.cancel()
                try:
                    await prev
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
            setattr(self, prev_task_attr, None)

        # Round-9 audit fix R9-Sched-H2 (Apr 2026): validate every
        # element of ``embedded_scheduler_argv`` against an allow-list.
        # Pre-fix the operator-controlled list was splatted straight
        # into ``create_subprocess_exec``, a misconfigured operator,
        # a future Settings loader that exposed this via dashboard /
        # API, or a compromised .env file could inject arbitrary
        # arguments into the trusted subprocess (e.g. swap to a
        # different module, inject ``-c "import os; ..."``-shaped
        # tricks via flag-value confusion). The allow-list is the
        # known-good set of z4j_scheduler subcommands + their flags.
        _SCHEDULER_ARG_ALLOWLIST = {
            "serve", "import", "export", "verify",
            "--config", "--log-level", "--leader-backend",
            "--brain-url", "--instance-id", "--healthcheck-port",
        }
        validated_extra: list[str] = []
        for raw in self._settings.embedded_scheduler_argv:
            arg = str(raw)
            head = arg.split("=", 1)[0]  # support --flag=value
            if head not in _SCHEDULER_ARG_ALLOWLIST:
                raise RuntimeError(
                    f"embedded_scheduler_argv element {arg!r} is not in "
                    f"the safe-flag allow-list; refusing to launch the "
                    f"scheduler subprocess (set Z4J_EMBEDDED_SCHEDULER_ARGV "
                    f"to a known-good value or omit the flag).",
                )
            validated_extra.append(arg)
        argv = [sys.executable, "-m", "z4j_scheduler", *validated_extra]
        env = self._build_subprocess_env()
        # Round-4 audit fix (Apr 2026): protect against orphan
        # subprocess on stop()-mid-spawn cancellation. Pre-fix, if
        # ``stop()`` cancelled the watchdog while the spawn
        # awaitable was in flight, the asyncio.create_subprocess_exec
        # could have already forked the child; the cancellation
        # interrupted the assignment to ``self._proc`` BEFORE the
        # child handle was registered, so ``_terminate_subprocess``
        # never found it and the orphan PID survived.
        # Now: assign immediately, AND re-terminate on
        # CancelledError so the orphan is killed even if we never
        # got past the spawn boundary.
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._proc = proc
        except FileNotFoundError as exc:
            # The python executable is gone? Should never happen
            # because ``sys.executable`` is the running interpreter.
            # Log loudly and bail - watchdog won't be able to
            # recover.
            logger.critical(
                "z4j.brain.embedded_scheduler: failed to spawn "
                "subprocess (%s); embedded mode disabled",
                exc,
            )
            raise
        except asyncio.CancelledError:
            # If the subprocess HAD already spawned before the
            # cancellation, terminate the orphan before re-raising.
            if proc is not None and proc.returncode is None:
                logger.warning(
                    "z4j.brain.embedded_scheduler: cancellation "
                    "during spawn; terminating orphan PID=%s",
                    proc.pid,
                )
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
            raise
        # Drain stdout/stderr in the background so the OS pipe
        # buffer doesn't fill (which would block the subprocess on
        # write). We forward each line to logger at INFO/WARNING.
        # Stash references so the next ``_spawn_subprocess`` call
        # can cancel them cleanly (audit fix above).
        self._stdout_task = asyncio.create_task(
            self._forward_stream(self._proc.stdout, "stdout"),
            name="z4j.embedded_scheduler.stdout",
        )
        self._stderr_task = asyncio.create_task(
            self._forward_stream(self._proc.stderr, "stderr"),
            name="z4j.embedded_scheduler.stderr",
        )
        logger.info(
            "z4j.brain.embedded_scheduler: spawned subprocess "
            "(pid=%s, brain_grpc=%s:%s)",
            self._proc.pid, self._brain_grpc_host, self._brain_grpc_port,
        )

    def _build_subprocess_env(self) -> dict[str, str]:
        """Build a minimal-surface env for the supervised subprocess.

        Audit fix 3.2 (Apr 2026): pre-fix the supervisor inherited
        the brain process's full ``os.environ``. That meant brain
        secrets the scheduler doesn't need (``DATABASE_URL`` with
        embedded password, ``Z4J_SECRET``, ``AWS_*``, GitHub PAT,
        etc.) were forwarded into the subprocess. If the
        scheduler ever printed its env on a crash, those secrets
        leaked to brain's logs.

        We now whitelist only the env families the subprocess
        actually needs:

        - ``PATH`` / ``PYTHONPATH`` / ``LANG`` / ``LC_*`` / ``TZ``
          / ``HOME`` / ``USER`` / ``LOGNAME`` / ``TERM`` /
          ``TMPDIR``, runtime essentials.
        - ``Z4J_SCHEDULER_*``, the scheduler's own config
          surface (env vars consumed by ``z4j_scheduler.settings``).
        - On Windows: ``SYSTEMROOT``, ``COMSPEC``, ``PATHEXT``,
          ``USERPROFILE``, ``APPDATA``, ``LOCALAPPDATA``, Python
          + uvloop need these to start.
        """
        # Whitelist of env-var prefixes / exact names the subprocess
        # needs. Everything else is dropped.
        _ALLOWED_PREFIXES = ("Z4J_SCHEDULER_", "LC_")
        _ALLOWED_EXACT = frozenset({
            "PATH", "PYTHONPATH", "PYTHONHOME", "LANG", "LANGUAGE",
            "TZ", "HOME", "USER", "LOGNAME", "TERM", "TMPDIR",
            "TMP", "TEMP",
            # Windows runtime essentials
            "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "PATHEXT",
            "USERPROFILE", "APPDATA", "LOCALAPPDATA", "WINDIR",
            "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
        })
        env: dict[str, str] = {
            k: v for k, v in os.environ.items()
            if k in _ALLOWED_EXACT
            or any(k.startswith(p) for p in _ALLOWED_PREFIXES)
        }

        env["Z4J_SCHEDULER_BRAIN_GRPC_URL"] = (
            f"{self._brain_grpc_host}:{self._brain_grpc_port}"
        )
        env["Z4J_SCHEDULER_BRAIN_REST_URL"] = self._brain_rest_url
        env["Z4J_SCHEDULER_TLS_CERT"] = str(self._pki.client_cert_pem)
        env["Z4J_SCHEDULER_TLS_KEY"] = str(self._pki.client_key_pem)
        env["Z4J_SCHEDULER_TLS_CA"] = str(self._pki.ca_pem)
        # Distinct instance id so audit logs separate embedded
        # subprocesses from external scheduler containers when both
        # exist in a hybrid deploy. The trailing ``-embedded`` is
        # not a SAN check - it's a label only.
        # Round-9 audit fix R9-Sched-MED (Apr 2026): use
        # ``socket.gethostname()`` as the cross-platform hostname
        # fallback instead of the static literal ``"brain"``.
        # ``os.uname()`` raises AttributeError on Windows so the
        # ``hasattr`` guard worked, but every Windows brain
        # replica then got the identical ``brain-embedded``
        # instance_id, colliding in the audit log when more than
        # one Windows replica ran (e.g. blue/green test
        # environments). ``socket.gethostname()`` is portable and
        # returns the actual machine name on both POSIX and
        # Windows.
        import socket as _socket  # noqa: PLC0415
        try:
            _hostname = (
                os.uname().nodename if hasattr(os, "uname")
                else _socket.gethostname()
            )
        except Exception:  # noqa: BLE001
            _hostname = "brain"
        env.setdefault(
            "Z4J_SCHEDULER_INSTANCE_ID",
            f"{_hostname}-embedded",
        )
        # Embedded mode never participates in HA - the brain process
        # is the unit of HA, not the embedded scheduler. Force
        # ``leader_backend=single`` so the subprocess doesn't try to
        # advisory-lock anything.
        env["Z4J_SCHEDULER_LEADER_BACKEND"] = "single"
        return env

    async def _forward_stream(
        self,
        stream: asyncio.StreamReader | None,
        label: str,
    ) -> None:
        """Pipe a subprocess stream into brain's logger.

        Each line is logged at INFO. We don't try to detect WARN/
        ERROR severity in the child output because the scheduler
        emits structured JSON logs and a substring match on
        ``"level":"error"`` would be fragile. Operators wanting
        per-severity routing should ship the scheduler's own
        stdout to their log aggregator directly.

        Round-8 audit fix R8-Bootstrap-MED (Apr 2026): redact
        lines that mention secret-bearing TLS material paths
        (``Z4J_SCHEDULER_TLS_*``, ``BEGIN PRIVATE KEY``,
        ``CERTIFICATE``) before forwarding. The scheduler's own
        debug paths sometimes log file paths that an upstream
        log aggregator should not see verbatim.
        """
        if stream is None:
            return
        # Patterns we never want surfaced into brain's log pipeline.
        _REDACT_TOKENS = (
            "Z4J_SCHEDULER_TLS_KEY",
            "Z4J_SCHEDULER_TLS_CERT",
            "BEGIN PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN ENCRYPTED PRIVATE KEY",
            "BEGIN CERTIFICATE",
        )
        try:
            while True:
                line = await stream.readline()
                if not line:
                    return
                try:
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                except Exception:  # noqa: BLE001
                    decoded = repr(line)
                # R8-Bootstrap-MED: redact whole lines that look
                # secret-bearing rather than try to scrub in-line.
                if any(t in decoded for t in _REDACT_TOKENS):
                    logger.warning(
                        "z4j.brain.embedded_scheduler[%s]: <redacted "
                        "line containing TLS material>",
                        label,
                    )
                    continue
                logger.info(
                    "z4j.brain.embedded_scheduler[%s]: %s", label, decoded,
                )
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            return

    async def _supervise(self) -> None:
        """Watchdog that auto-restarts the subprocess on crash.

        Runs until :meth:`stop` flips ``_stop_event``. Each crash
        increments ``_restart_count``; once it exceeds
        ``embedded_scheduler_restart_max_attempts`` the watchdog
        gives up and logs CRITICAL. The operator's only recovery
        is to restart brain.
        """
        max_attempts = (
            self._settings.embedded_scheduler_restart_max_attempts
        )
        backoff = float(
            self._settings.embedded_scheduler_restart_backoff_seconds,
        )
        while not self._stop_event.is_set():
            if self._proc is None:
                return
            try:
                returncode = await self._proc.wait()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j.brain.embedded_scheduler: subprocess wait failed",
                )
                return
            if self._stop_event.is_set():
                return
            self._restart_count += 1
            if max_attempts == 0 or self._restart_count > max_attempts:
                # Audit fix 7.1 (Apr 2026): flip the
                # ``permanently_failed`` flag so brain's /health
                # probe + any operator-facing dashboard can
                # detect that embedded mode is down. Pre-fix the
                # watchdog logged CRITICAL once and returned;
                # brain looked healthy while fires silently
                # stopped.
                self._permanently_failed = True
                logger.critical(
                    "z4j.brain.embedded_scheduler: subprocess exited "
                    "(returncode=%s); restart cap (%d) exceeded - "
                    "embedded scheduler is now permanently down. "
                    "supervisor.permanently_failed=True. "
                    "Restart brain to recover.",
                    returncode, max_attempts,
                )
                return
            # Audit fix (Apr 2026 follow-up): randomised backoff
            # (decorrelated jitter) defends against thundering-
            # herd in multi-replica brain deployments. Pre-fix,
            # all replicas crashed in lockstep on a shared
            # dependency outage and respawned in lockstep, hitting
            # brain's gRPC port simultaneously. Multiplying by
            # uniform(0.7, 1.3) decorrelates restart times by up
            # to 60% within the cap.
            import random  # noqa: PLC0415

            base_delay = min(60.0, backoff * (2 ** (self._restart_count - 1)))
            delay = base_delay * random.uniform(0.7, 1.3)
            delay = min(60.0, max(0.1, delay))
            logger.warning(
                "z4j.brain.embedded_scheduler: subprocess exited "
                "(returncode=%s); restart attempt %d/%d in %.1fs",
                returncode, self._restart_count, max_attempts, delay,
            )
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(), timeout=delay,
                )
                return  # stop fired during backoff
            except TimeoutError:
                pass
            try:
                await self._spawn_subprocess()
            except Exception:  # noqa: BLE001
                logger.exception(
                    "z4j.brain.embedded_scheduler: respawn failed; "
                    "watchdog continuing",
                )
                # Round-4 audit fix (Apr 2026): when respawn
                # raises, the next loop iteration's
                # ``await self._proc.wait()`` returns IMMEDIATELY
                # because ``self._proc`` is still the previous
                # dead handle (``returncode`` is set). Pre-fix,
                # the loop then incremented ``_restart_count``
                # for what is essentially a phantom restart -
                # within seconds the cap was "exhausted" by
                # phantom increments and ``_permanently_failed``
                # was set despite the failure being a transient
                # spawn error. Fix: sleep a backoff window AND
                # decrement the counter so the failed spawn
                # doesn't burn an attempt.
                self._restart_count = max(0, self._restart_count - 1)
                # Guard against tight loop with backoff.
                await asyncio.sleep(min(60.0, delay))

    async def _terminate_subprocess(self) -> None:
        """SIGTERM, wait, SIGKILL fallback. Idempotent."""
        proc = self._proc
        if proc is None or proc.returncode is not None:
            self._proc = None
            return
        grace = float(
            self._settings.embedded_scheduler_shutdown_grace_seconds,
        )
        try:
            proc.terminate()
        except ProcessLookupError:
            self._proc = None
            return
        except Exception:  # noqa: BLE001
            logger.exception(
                "z4j.brain.embedded_scheduler: terminate() raised",
            )
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace)
        except TimeoutError:
            logger.warning(
                "z4j.brain.embedded_scheduler: subprocess did not exit "
                "within %.1fs; sending SIGKILL", grace,
            )
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except TimeoutError:
                logger.error(
                    "z4j.brain.embedded_scheduler: subprocess survived "
                    "SIGKILL; leaking pid=%s", proc.pid,
                )
        self._proc = None


__all__ = [
    "BRAIN_SERVER_CN",
    "EmbeddedSchedulerSupervisor",
    "LoopbackPKI",
    "SCHEDULER_CLIENT_CN",
    "mint_loopback_pki",
]
