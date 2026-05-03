"""Lifespan startup hooks.

Two responsibilities at boot:

1. **First-boot detection** - if ``users`` is empty, try the
   operator-friendly paths first (env-var bootstrap), and fall
   back to minting a setup token + printing the ASCII banner. The
   plaintext token only ever exists in memory + on stdout; we
   never log it through structlog (operators may ship structlog
   elsewhere).
2. **Settings sanity check** - re-run the security invariants
   defensively after the engine is up. Mostly belt-and-braces;
   the Settings constructor already enforces them.

These run from inside the FastAPI lifespan in :func:`create_app`.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import structlog

from z4j_brain.persistence.repositories import (
    FirstBootTokenRepository,
    MembershipRepository,
    ProjectRepository,
    UserRepository,
)

if TYPE_CHECKING:
    from z4j_brain.domain.setup_service import SetupService
    from z4j_brain.persistence.database import DatabaseManager
    from z4j_brain.settings import Settings

logger = structlog.get_logger("z4j.brain.startup")


# Round-8 audit fix R8-HIGH-4 (Apr 2026): module-level holder for
# the bootstrap password supplied via ``z4j serve
# --admin-password``. Stays in process memory only, never lands in
# ``os.environ`` (where ``/proc/<pid>/environ`` would expose it to
# other processes under the same UID, AND every subprocess we fork
# would inherit it). Single-use: ``run_first_boot_check`` consumes
# it and overwrites with None on first read.
_CLI_BOOTSTRAP_PASSWORD: str | None = None


def set_cli_bootstrap_password(password: str) -> None:
    """Stash the cli-supplied admin password in process memory.

    Called from ``z4j_brain.cli._run_serve`` when the operator
    passes ``--admin-password``. ``run_first_boot_check`` consumes
    via :func:`_consume_cli_bootstrap_password`. Never written
    to disk, never copied into ``os.environ``.
    """
    global _CLI_BOOTSTRAP_PASSWORD
    _CLI_BOOTSTRAP_PASSWORD = password


def _consume_cli_bootstrap_password() -> str | None:
    global _CLI_BOOTSTRAP_PASSWORD
    value = _CLI_BOOTSTRAP_PASSWORD
    _CLI_BOOTSTRAP_PASSWORD = None
    return value


async def run_first_boot_check(
    *,
    db: DatabaseManager,
    setup_service: SetupService,
    settings: Settings,
) -> None:
    """Detect first-boot, mint a token OR auto-provision, print banner.

    Precedence when ``users`` is empty:

    1. ``Z4J_BOOTSTRAP_ADMIN_EMAIL`` + ``Z4J_BOOTSTRAP_ADMIN_PASSWORD``
       env vars present → auto-create the admin user + default
       project, skip the token flow entirely. This is the path
       Kubernetes / Helm / CI pipelines want: provision via secret
       mounts, no log-scraping. The env vars are single-use - they
       are only honored when the ``users`` table is empty, so
       leaving them set in a manifest across restarts is harmless.
    2. Otherwise mint a one-time setup token with 15-minute TTL
       and print a clickable URL to stdout. Hobbyist / single-
       container path.

    Idempotent: on every startup, if ``users`` is empty we wipe
    any stale tokens and mint a fresh one. Once the bootstrap
    admin exists, this is a quick read + return.

    Postgres advisory lock would serialize concurrent worker
    starts in production. We omit it for now - the brain is
    single-process in v1, and the inner re-check inside
    :meth:`SetupService.complete` already protects against the
    multi-worker race when it actually matters.
    """
    bootstrap_email = os.environ.get("Z4J_BOOTSTRAP_ADMIN_EMAIL", "").strip()
    bootstrap_password = os.environ.get("Z4J_BOOTSTRAP_ADMIN_PASSWORD", "")
    bootstrap_name = (
        os.environ.get("Z4J_BOOTSTRAP_ADMIN_DISPLAY_NAME", "").strip() or None
    )
    # Round-8 audit fix R8-HIGH-4 (Apr 2026): consume the cli-supplied
    # password from the in-process holder. cli.py never puts it into
    # ``os.environ`` so /proc/<pid>/environ leakage and subprocess
    # inheritance are both eliminated.
    cli_password = _consume_cli_bootstrap_password()
    if cli_password:
        bootstrap_password = cli_password
    # Round-8 audit fix R8-HIGH-5 (Apr 2026): pop the env-var
    # variant of the password as soon as we've captured it locally.
    # On Linux it was previously readable via /proc/<pid>/environ
    # for the entire process lifetime AND propagated to every
    # subprocess we fork. Email + display name are non-secret and
    # left in place for diagnostic visibility.
    if bootstrap_password:
        os.environ.pop("Z4J_BOOTSTRAP_ADMIN_PASSWORD", None)

    # Env-var auto-bootstrap takes precedence. Wrapped in its own
    # session so a failure here has no cross-session rollback risk
    # (audit H5 - the prior implementation reused one session
    # across env-bootstrap, banner-mint, and setup token delete,
    # which left SQLAlchemy in a partial-tx state after a
    # partial-flush-then-raise).
    if bootstrap_email and bootstrap_password:
        async with db.session() as bootstrap_session:
            users = UserRepository(bootstrap_session)
            if not await setup_service.is_first_boot(users):
                logger.info("z4j first-boot already completed")
                return
            try:
                await _auto_bootstrap_admin(
                    session=bootstrap_session,
                    setup_service=setup_service,
                    settings=settings,
                    email=bootstrap_email,
                    password=bootstrap_password,
                    display_name=bootstrap_name,
                )
                await bootstrap_session.commit()
            except Exception:  # noqa: BLE001
                await bootstrap_session.rollback()
                logger.exception(
                    "z4j auto-bootstrap failed, falling back "
                    "to setup-token banner",
                )
            else:
                logger.info(
                    "z4j auto-bootstrap complete",
                    email=bootstrap_email,
                )
                return

    # Banner path in a fresh session. Re-check is_first_boot inside
    # the transaction (audit H5): closes the TOCTOU where the UI
    # POSTs /api/v1/setup/complete between the outer check and the
    # token mint.
    async with db.session() as session:
        users = UserRepository(session)
        tokens = FirstBootTokenRepository(session)

        if not await setup_service.is_first_boot(users):
            logger.info("z4j first-boot already completed")
            return

        plaintext, expires_at = await setup_service.mint_token(tokens)
        await session.commit()

    _print_setup_banner(
        token=plaintext,
        expires_at=expires_at.isoformat(timespec="seconds"),
        public_url=settings.public_url,
    )


async def _auto_bootstrap_admin(
    *,
    session,  # type: ignore[no-untyped-def]
    setup_service: SetupService,
    settings: Settings,
    email: str,
    password: str,
    display_name: str | None,
) -> None:
    """Create the admin user + default project from env vars.

    Produces the same outcome as the UI-driven setup flow - same
    argon2 parameters, same canonical email, same ``default``
    project, same default-subscription materialization, same audit
    row - minus the setup-token + rate-limit checks (there is no
    untrusted input here; env vars come from the operator).

    Raises if the password fails the configured policy. Caller
    rolls back the session and falls through to the banner path so
    the operator can still recover.
    """
    from datetime import UTC, datetime

    from z4j_brain.domain.auth_service import canonicalize_email
    from z4j_brain.domain.notifications import NotificationService
    from z4j_brain.persistence.enums import ProjectRole
    from z4j_brain.persistence.models import Project, User
    from z4j_brain.persistence.models.notification import (
        ProjectDefaultSubscription,
    )

    # Validate password policy up front. If it fails, argon2 never
    # runs - saves a second of pointless hashing on a bad config.
    setup_service._hasher.validate_policy(password)  # noqa: SLF001

    email_canonical = canonicalize_email(email)
    password_hash = setup_service._hasher.hash(password)  # noqa: SLF001

    users_repo = UserRepository(session)
    projects_repo = ProjectRepository(session)
    memberships_repo = MembershipRepository(session)

    user = User(
        email=email_canonical,
        password_hash=password_hash,
        display_name=(display_name.strip() if display_name else None),
        is_admin=True,
        is_active=True,
        password_changed_at=datetime.now(UTC),
    )
    await users_repo.add(user)

    project = Project(slug="default", name="Default")
    await projects_repo.add(project)
    await memberships_repo.grant(
        user_id=user.id, project_id=project.id, role=ProjectRole.ADMIN,
    )

    # Same default subscription pattern as the UI path: every new
    # project gets ``task.failed -> in-app``, and the bootstrap
    # admin's own subscription is materialized so the bell fires
    # from day one.
    session.add(
        ProjectDefaultSubscription(
            project_id=project.id,
            trigger="task.failed",
            in_app=True,
        ),
    )
    await session.flush()
    await NotificationService().materialize_defaults_for_member(
        session=session,
        user_id=user.id,
        project_id=project.id,
    )


def _print_setup_banner(
    *,
    token: str,
    expires_at: str,
    public_url: str,
) -> None:
    """Print the first-boot setup URL to stderr.

    Uses ``print(..., file=sys.stderr)`` NOT structlog, because
    operators MUST see this even if logging is misconfigured - but
    also NOT stdout, because container log drivers
    (docker / k8s / journald) archive stdout to persistent
    aggregators where the one-time token would live forever
    (audit finding A4).

    Even stderr is captured by most orchestrators. The 15-minute
    single-use TTL bounds the window of exposure; operators who
    want zero exposure should use the ``Z4J_BOOTSTRAP_ADMIN_*``
    environment variables instead - those materialize the admin
    directly without a token passing through logs.
    """
    import sys as _sys

    base = public_url.rstrip("/")
    url = f"{base}/setup?token={token}"
    bar = "═" * 70
    out = _sys.stderr
    print(file=out)  # noqa: T201
    print(f"╔{bar}╗", file=out)  # noqa: T201
    print("║" + " z4j first-boot setup ".center(70) + "║", file=out)  # noqa: T201
    print(f"║{' ' * 70}║", file=out)  # noqa: T201
    print(
        "║" + " Open this URL in your browser to create the admin: ".ljust(70) + "║",
        file=out,
    )  # noqa: T201
    print(f"║{' ' * 70}║", file=out)  # noqa: T201
    print(f"║ {url}".ljust(71) + "║", file=out)  # noqa: T201
    print(f"║{' ' * 70}║", file=out)  # noqa: T201
    print(
        "║" + f" Token expires at: {expires_at} (UTC) ".ljust(70) + "║",
        file=out,
    )  # noqa: T201
    print(
        "║" + " Single-use. Restart the brain to generate a new one. ".ljust(70) + "║",
        file=out,
    )  # noqa: T201
    print(
        "║" + " For zero-log-exposure setup, use Z4J_BOOTSTRAP_ADMIN_*. ".ljust(70) + "║",
        file=out,
    )  # noqa: T201
    print(f"╚{bar}╝", file=out)  # noqa: T201
    print(file=out)  # noqa: T201


__all__ = ["run_first_boot_check"]
