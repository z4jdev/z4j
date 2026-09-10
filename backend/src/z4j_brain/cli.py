"""``z4j`` operator CLI.

It owns normal server startup plus migration, backup/restore, audit,
credential-recovery, configuration and release-maintenance commands.
``z4j <command> --help`` is the authoritative command inventory.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from z4j_core.paths import (
    ensure_z4j_home,
    reject_deprecated_path_env,
    z4j_home,
)

from z4j_brain import __version__

if TYPE_CHECKING:
    from z4j_brain.settings import Settings


def main(argv: Sequence[str] | None = None) -> int:  # noqa: PLR0911, PLR0912, PLR0915  flat CLI dispatch
    """Entry point installed as the ``z4j`` console script.

    The pre-1.4.0 ``z4j-brain`` alias was dropped in the
    consolidation cut. ``pip install z4j-brain`` still works (via
    the metadata shim) but the only console script the wheel
    ships is ``z4j``.
    """
    prog = "z4j"

    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "z4j server (AGPL v3) - operator CLI.\n"
            "\n"
            "Common flows:\n"
            f"  {prog} serve                     # start the dashboard + API\n"
            f"  {prog} check                     # validate config + DB\n"
            f"  {prog} status                    # current-state summary\n"
            f"  {prog} createsuperuser ...       # create the first admin\n"
            f"  {prog} changepassword <email>    # reset a user's password\n"
            f"  {prog} reset --force             # reset domain state\n"
            f"  {prog} migrate upgrade head      # run alembic migrations\n"
            f"  {prog} audit verify              # verify active HMACs + frozen digest\n"
            f"  {prog} --version                 # print installed version\n"
            "\n"
            f"Run `{prog} <command> --help` for per-command flags."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Standard Python convention: ``--version`` / ``-V`` print the
    # version and exit. Mirrors the existing ``z4j version``
    # subcommand and bare ``z4j`` (no subcommand) - all three paths
    # produce the same output. -v (lowercase) is intentionally NOT
    # bound here so it stays free for a future --verbose flag,
    # matching pip / docker / kubectl convention.
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=__version__,
    )
    sub = parser.add_subparsers(
        dest="command",
        required=False,
        title="commands",
        metavar="<command>",
    )

    # serve
    serve = sub.add_parser("serve", help="run uvicorn against create_app")
    serve.add_argument("--host", default=None, help="bind host")
    serve.add_argument("--port", type=int, default=None, help="bind port")
    serve.add_argument(
        "--workers",
        type=int,
        default=None,
        help=(
            "Number of uvicorn worker processes. Default: "
            "min(4, os.cpu_count()). The pre-1.5 default of 1 caused "
            "agent flap under modest load (single asyncio event loop "
            "couldn't dispatch WebSocket PONGs while ingesting events). "
            "Set explicitly to request another count. SQLite / the "
            "in-memory registry and embedded-scheduler mode always force "
            "one worker for correctness, even when a larger value is "
            "requested."
        ),
    )
    serve.add_argument("--reload", action="store_true")
    # --environment / --env: CLI shortcut for setting Z4J_ENVIRONMENT.
    # Wins over the env var (CLI > env > auto-detect default). Most
    # operators set this once via systemd Environment= and never
    # touch it; the flag exists for one-off testing ("does this work
    # in production mode without restart loops?") and for the dev
    # workflow ("flip to production for a smoke test, back to dev
    # for the next iteration"). The choices are deliberately strict
    # - no `prod` shorthand because Settings.environment is also
    # a string field and accepting `prod` here would create a path
    # that bypasses Settings's own validation.
    serve.add_argument(
        "--environment",
        "--env",
        default=None,
        choices=("dev", "production"),
        metavar="MODE",
        help=(
            "set the brain's security posture (dev | production). "
            "Wins over Z4J_ENVIRONMENT. dev = loopback-only bind, "
            "relaxed cookies, no HSTS, host validation off. production = "
            "TLS-required (Z4J_PUBLIC_URL must be https://), explicit "
            "Z4J_ALLOWED_HOSTS required, Secure cookies + __Host- prefix, "
            "HSTS sent. Default: production if both Z4J_PUBLIC_URL=https:// "
            "and Z4J_ALLOWED_HOSTS are set, else dev."
        ),
    )
    serve.add_argument(
        "--admin-email",
        default=None,
        help="auto-create admin user on first boot (skips setup wizard)",
    )
    serve.add_argument(
        "--admin-password",
        default=None,
        help="password for the auto-created admin user",
    )
    serve.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        metavar="HOST",
        help=(
            "Add a host to the Host: header allow-list. Repeatable. "
            "Merged with Z4J_ALLOWED_HOSTS env, the auto-detected system "
            "hostname, and localhost. Use this when you reach the brain "
            "via a hostname or IP that the auto-detect missed - e.g. "
            "`--allowed-host brain.internal.lan`."
        ),
    )
    serve.add_argument(
        "--debug-host-errors",
        action="store_true",
        help=(
            "DEV ONLY: include the rejected Host header, the configured "
            "allow-list, and a fix command in the body of the 400 response. "
            "Default behaviour returns a minimal `{error,message,request_id}` "
            "body so reverse-proxy / public-internet callers cannot enumerate "
            "internal hostnames. Sets Z4J_DEBUG_HOST_ERRORS=1 for the "
            "middleware. Refused entirely outside dev mode."
        ),
    )

    # migrate
    migrate = sub.add_parser("migrate", help="run an alembic command")
    migrate.add_argument(
        "action",
        choices=(
            "upgrade",
            "downgrade",
            "revision",
            "current",
            "history",
            "sync",
            "prepare-runtime-rollback",
        ),
    )
    migrate.add_argument("rest", nargs=argparse.REMAINDER)
    migrate.add_argument(
        "--allow-future-schema",
        action="store_true",
        default=False,
        help=(
            "When the DB head is unknown to this code (e.g. you "
            "downgraded brain across a migration boundary), "
            "``migrate sync`` STAMPS the DB back to this code's "
            "head and DROPS identifier-safe unknown tables the newer "
            "code added. It does not remove newer columns from tables "
            "this code knows. Destructive - rows in dropped tables are "
            "lost. Required for the sync action to proceed when a future "
            "schema is detected."
        ),
    )
    migrate.add_argument(
        "--i-know-this-can-corrupt-data",
        action="store_true",
        default=False,
        help=(
            "Required confirmation flag for destructive operations "
            "in ``migrate sync --allow-future-schema``. The brain "
            "refuses without this so an operator never destroys "
            "rows by accident from a script that wraps `migrate "
            "sync`."
        ),
    )

    # audit
    audit = sub.add_parser("audit", help="audit-log subcommands")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_verify = audit_sub.add_parser(
        "verify",
        help=(
            "verify active-row HMACs and the authenticated aggregate "
            "snapshot of frozen audit history"
        ),
    )
    audit_verify.add_argument(
        "--limit",
        type=int,
        default=1_000,
        help=(
            "page size for the chain walk (default: 1000, max: 5000). "
            "The command pages through the ENTIRE active generation in "
            "chain order; this only controls active rows fetched per query. "
            "Frozen legacy rows are loaded as one canonical snapshot and "
            "checked against its authenticated count and aggregate digest."
        ),
    )
    audit_verify.add_argument(
        "--known-head",
        default=None,
        metavar="JSON",
        help=(
            "optional versioned known-head JSON envelope. The exact result is "
            "CURRENT_MATCH, PRUNE_MATCH, CURRENT_PRUNE_MATCH, "
            "VERIFIED_ANCESTOR, INVALID, or UNPROVABLE."
        ),
    )
    audit_export_head = audit_sub.add_parser(
        "export-head",
        help=(
            "print the authenticated current chain head as the JSON envelope "
            "that `audit verify --known-head` accepts"
        ),
    )
    audit_export_head.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help=(
            "write the envelope to PATH instead of stdout, atomically. Prefer "
            "this over a shell redirect: `> file` truncates the target before "
            "this command runs, so a refusal would destroy the anchor you "
            "already had. With --output an existing file is replaced only "
            "after a complete envelope has been written."
        ),
    )
    audit_export_head.add_argument(
        "--verify",
        action="store_true",
        help=(
            "walk the active generation first and refuse to print a head from "
            "a chain that did not verify clean. Slower, and the right default "
            "for an unattended job that anchors the result somewhere durable."
        ),
    )
    audit_rotate_key = audit_sub.add_parser(
        "rotate-chain-key",
        help=(
            "complete an explicit audit-key rotation, or begin/resume the "
            "crash-safe packaged-SQLite safe-store rotation"
        ),
    )
    audit_rotate_key.add_argument(
        "--begin-managed",
        action="store_true",
        help=(
            "mint and begin one new safe-store-managed SQLite rotation when "
            "the file and authenticated state currently agree. Omit this flag "
            "to resume a file-first pending transition idempotently."
        ),
    )
    audit_retire_key = audit_sub.add_parser(
        "retire-chain-key",
        help=(
            "prove an old audit key has no live active rows and retire it from "
            "the packaged safe store, or authorize explicit-config removal"
        ),
    )
    audit_retire_key.add_argument(
        "--key-id",
        required=True,
        help="exact lowercase 64-hex hmac_key_id to retire",
    )
    audit_activate = audit_sub.add_parser(
        "activate-chain-state",
        help=(
            "finalize or apply the offline manifest-bound Boundary-F "
            "legacy-audit activation ceremony"
        ),
    )
    audit_activate.add_argument(
        "--manifest",
        required=True,
        metavar="PATH",
        help=(
            "owner-private finalized manifest path; generation creates it "
            "exclusively and --apply reads the same immutable document"
        ),
    )
    audit_activate.add_argument(
        "--apply",
        action="store_true",
        help="apply a previously finalized manifest to the preparation-head DB",
    )
    audit_activate.add_argument(
        "--legacy-key-window-complete",
        action="store_true",
        default=None,
        help=(
            "attest that every candidate pre-1.8 master key is configured, "
            "allowing unmatched signed rows to be classified as invalid"
        ),
    )
    audit_activate.add_argument(
        "--attest-manifest-digest",
        default=None,
        metavar="SHA256",
        help=(
            "exact finalized manifest digest required to apply any ambiguous "
            "classification; this is not a generic yes/no confirmation"
        ),
    )
    audit_activate.add_argument(
        "--known-head",
        default=None,
        metavar="JSON",
        help=(
            "optional pre-1.8 external head envelope to assess and bind into "
            "the finalized cutover manifest"
        ),
    )
    audit_activate.add_argument(
        "--restore-operation",
        default=None,
        metavar="UUID",
        help=(
            "bind manifest generation/application to one exact pending "
            "legacy database-restore operation"
        ),
    )
    audit_export_frozen = audit_sub.add_parser(
        "export-and-delete-frozen",
        help=(
            "offline crash-resumable export and exact deletion of all frozen pre-1.8 audit history"
        ),
    )
    audit_export_frozen.add_argument(
        "--operation",
        required=True,
        metavar="UUID",
        help=("operator-chosen operation UUID; reuse the exact value to resume after a crash"),
    )
    audit_export_frozen.add_argument(
        "--destination",
        required=True,
        metavar="PATH",
        help=(
            "new or byte-identical local owner-private regular file populated "
            "from the retained private spool"
        ),
    )
    audit_export_frozen.add_argument(
        "--acknowledge-destination-digest",
        default=None,
        metavar="SHA256",
        help=(
            "after deletion, acknowledge the exact ceremony export digest; "
            "the private spool remains until this acknowledgement"
        ),
    )
    audit_export_frozen.add_argument(
        "--cleanup",
        action="store_true",
        help=(
            "remove only the identity-checked private spool/phase after exact "
            "destination-digest acknowledgement"
        ),
    )

    # audit fork-cleanup: quarantine duplicate prev_row_hmac rows
    # so the v1.1.0+ partial UNIQUE index can apply. Shipped in
    # 1.1.1 after the index migration crashed deployments that had
    # pre-existing chain forks (real bugs in older z4j releases or
    # replay artefacts during testing). Auto-backs up before any
    # write; preserves every fork row in audit_log_legacy_forks.
    audit_fork_cleanup = audit_sub.add_parser(
        "fork-cleanup",
        help=(
            "quarantine duplicate prev_row_hmac rows so the UNIQUE "
            "chain index can apply (v1.1.0+ migration prerequisite)"
        ),
    )
    audit_fork_cleanup.add_argument(
        "--apply",
        action="store_true",
        help=(
            "skip the [y/N] prompt and apply the cleanup. Use in "
            "scripts and CI; interactive use should omit this flag "
            "to inspect the diff first."
        ),
    )
    audit_fork_cleanup.add_argument(
        "--no-backup",
        action="store_true",
        help=(
            "skip the auto-backup step. Only set if you have your "
            "own backup strategy; the default is safer."
        ),
    )

    # audit reseal-watermark (H1): re-sign a LEGACY, unauthenticated prune
    # watermark under the current secret. Needed once after upgrading an
    # install that pruned under a pre-1.7.1 z4j: those watermarks were
    # stored as a bare row_hmac (no MAC) and now fail authentication, so
    # ``z4j audit verify`` false-alarms "chain truncation". We NEVER
    # auto-retag (signing an unauthenticated value would bless a possibly
    # forged truncation anchor); the operator runs this explicitly AFTER
    # confirming the chain verifies.
    audit_reseal = audit_sub.add_parser(
        "reseal-watermark",
        help=(
            "re-sign a legacy (pre-1.7.1) unauthenticated prune watermark "
            "under the current secret, after you have verified the chain"
        ),
    )
    audit_reseal.add_argument(
        "--i-have-verified-the-chain",
        action="store_true",
        dest="chain_verified",
        help=(
            "REQUIRED to write. Assert that you have independently run "
            "`z4j audit verify` and confirmed the chain is intact apart "
            "from the unauthenticated watermark. Resealing blesses the "
            "row_hmac the watermark points at as the genuine prune anchor; "
            "only do this when you trust the chain."
        ),
    )
    audit_reseal.add_argument(
        "--force-bare",
        action="store_true",
        help=(
            "also reseal a TAGGED watermark that fails to verify under the "
            "current secret window (normally that means a forged value OR a "
            "secret rotated fully out of Z4J_PREVIOUS_SECRETS). Prefer "
            "restoring the rotated-out secret instead; use this only if you "
            "are certain the embedded row_hmac is genuine."
        ),
    )

    # projects: operator-initiated project-scoped data operations.
    # Currently exposes ``rewrite-scheduler`` for the explicit
    # migration of ``Schedule.scheduler`` values when an operator
    # has flipped a project's ``default_scheduler_owner`` and wants
    # to retroactively migrate existing rows. We deliberately do
    # NOT auto-rewrite at PATCH time; operators who want migration
    # use this command.
    projects_cmd = sub.add_parser(
        "projects",
        help="project-scoped operations (rewrite-scheduler, ...)",
    )
    projects_sub = projects_cmd.add_subparsers(
        dest="projects_command",
        required=True,
    )
    rewrite_sched = projects_sub.add_parser(
        "rewrite-scheduler",
        help=("preview or finalize an explicit scheduler-owner cutover"),
        description=(
            "Owner changes are a two-step, manifest-bound operation. First run "
            "with --dry-run and save the printed manifest digest. Quiesce the "
            "old and new scheduler fleets, then rerun with --operation-id, "
            "--preview-manifest-digest, and "
            "--attest-all-schedulers-quiesced. External-source cutovers always "
            "move the complete sealed stream; reserved-source cutovers require "
            "one or more explicit --schedule-id values."
        ),
    )
    rewrite_sched.add_argument(
        "--slug",
        required=True,
        help="project slug (URL-safe identifier)",
    )
    rewrite_sched.add_argument(
        "--from",
        dest="from_scheduler",
        required=True,
        help="current scheduler value to rewrite from",
    )
    rewrite_sched.add_argument(
        "--to",
        dest="to_scheduler",
        required=True,
        help="new scheduler value to rewrite to",
    )
    rewrite_sched.add_argument(
        "--source-scope",
        required=True,
        help="canonical source scope for the current owner",
    )
    rewrite_sched.add_argument(
        "--target-source-scope",
        help="canonical target source scope (required when --to is external)",
    )
    rewrite_sched.add_argument(
        "--schedule-id",
        action="append",
        default=[],
        help=(
            "exact schedule UUID to move; repeatable and required only when --from z4j-scheduler"
        ),
    )
    rewrite_sched.add_argument(
        "--cursor-policy",
        choices=("PRESERVE", "PRESERVE_FUTURE", "RESET_CURSOR"),
        default="PRESERVE",
        help="cursor handling policy bound into the preview (default: PRESERVE)",
    )
    rewrite_sched.add_argument(
        "--operation-id",
        help="stable UUID for finalization and exact replay",
    )
    rewrite_sched.add_argument(
        "--preview-manifest-digest",
        help="digest emitted by the matching --dry-run preview",
    )
    rewrite_sched.add_argument(
        "--attest-all-schedulers-quiesced",
        action="store_true",
        help="REQUIRED to finalize: attest both old and new scheduler fleets are stopped",
    )
    rewrite_sched.add_argument(
        "--target-adapter-instance-id",
        help="fresh external adapter instance id (required for an external target)",
    )
    rewrite_sched.add_argument(
        "--target-agent-id",
        help="target external executor agent UUID",
    )
    rewrite_sched.add_argument(
        "--target-registry-owner-id",
        help="target external executor registry-owner UUID",
    )
    rewrite_sched.add_argument(
        "--target-session-generation",
        help="target external executor immutable session generation",
    )
    rewrite_sched.add_argument(
        "--target-worker-id",
        help="target external executor worker id, when present",
    )
    rewrite_sched.add_argument(
        "--all-sources",
        action="store_true",
        help=(
            "deprecated and refused: use a complete external stream or explicit "
            "--schedule-id selection"
        ),
    )
    rewrite_sched.add_argument(
        "--dry-run",
        action="store_true",
        help="print the canonical cutover preview and digest without writing",
    )

    # misfires: project-wide misfire history. The shell-side twin of the
    # VIEWER-facing REST endpoint -- lists the project's
    # ``scheduler.misfire_detected`` audit rows across ALL its schedules,
    # newest first, so an operator can triage missed slots without the
    # dashboard. ``--json`` mirrors the machine-readable output shape the
    # other read-only commands (e.g. ``upgrade``) use for scripting.
    misfires_cmd = sub.add_parser(
        "misfires",
        help="list a project's detected schedule misfires (newest first)",
        description=(
            "List the project's detected schedule misfires, newest "
            "first. A misfire is a system-detected 'this enabled "
            "schedule missed its expected slot past the grace window' "
            "event, recorded by the brain's misfire detector. The rows "
            "span every schedule in the project; each row shows its own "
            "schedule id.\n"
            "\n"
            "Default output is an aligned text table; pass --json for a "
            "machine-readable array."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    misfires_cmd.add_argument(
        "--project",
        "--slug",
        dest="project",
        required=True,
        metavar="SLUG",
        help="project slug (URL-safe identifier)",
    )
    misfires_cmd.add_argument(
        "--limit",
        type=int,
        default=50,
        help="max rows to return (default: 50, capped at 1000)",
    )
    misfires_cmd.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of a text table",
    )

    # bootstrap-admin: imperative first-boot admin creation.
    # Complements the Z4J_BOOTSTRAP_ADMIN_* env var path so operators
    # who prefer a CLI step (or want to re-create an admin after
    # losing credentials via DB reset) have one.
    bootstrap = sub.add_parser(
        "bootstrap-admin",
        help="create the initial admin user + default project (first-boot only)",
    )
    bootstrap.add_argument(
        "--email",
        required=True,
        help="admin email address",
    )
    bootstrap.add_argument(
        "--display-name",
        default=None,
        help="optional display name",
    )
    bootstrap_pw = bootstrap.add_mutually_exclusive_group(required=True)
    bootstrap_pw.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin (recommended; no shell history leak)",
    )
    bootstrap_pw.add_argument(
        "--password",
        default=None,
        help="password on the command line (NOT recommended - visible in ps/history)",
    )

    # reset-setup (narrow: only pending tokens; signed setup audit evidence is
    # preserved and a reset record is appended; refuses if any user exists). The
    # broader `reset` below wipes
    # everything including the admin. Both exist because they solve
    # different problems.
    reset_setup = sub.add_parser(
        "reset-setup",
        help=(
            "wipe pending first-boot tokens while preserving signed setup "
            "audit evidence. "
            "REFUSES if any user already exists."
        ),
    )
    reset_setup.add_argument(
        "--force",
        action="store_true",
        help="proceed without the safety prompt (for scripts)",
    )

    # reset (destructive; authenticated generation reset)
    reset = sub.add_parser(
        "reset",
        help=(
            "delete domain data and start a new authenticated generation. "
            "Schema, installation identity, monotonic namespaces, and a "
            "signed reset genesis are retained."
        ),
        description=(
            "Delete domain data and put the brain into first-boot setup "
            "state. The next `serve` mints a new setup token and prints a "
            "one-time admin-creation URL.\n"
            "\n"
            "The ordinary reset intentionally retains:\n"
            "  - the alembic schema and ~/.z4j/secret.env\n"
            "  - authenticated installation identity\n"
            "  - monotonic schedule revision / external-epoch namespaces\n"
            "  - one signed reset-genesis audit row replacing prior history\n"
            "\n"
            "Domain rows are not recoverable without a backup. --nuke-secrets "
            "instead performs packaged-SQLite retirement: it creates a fresh "
            "replacement while retaining the old database/key pair in an "
            "explicitly recoverable retirement bundle. REQUIRES --force."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    reset.add_argument(
        "--force",
        action="store_true",
        help="proceed without the safety prompt (required to wipe)",
    )
    reset.add_argument(
        "--nuke-secrets",
        action="store_true",
        help=(
            "for a packaged SQLite install, retire the existing database/key "
            "pair into a recoverable bundle and create a fresh replacement. "
            "Existing credentials do not authenticate to the replacement; "
            "the retained bundle is destroyed only by the explicit recovery "
            "command and matching manifest digest."
        ),
    )
    reset.add_argument(
        "--preview-manifest",
        metavar="PATH",
        help=(
            "write an owner-private, non-mutating finalized reset "
            "manifest and stopped-executor attestation challenge"
        ),
    )
    reset.add_argument(
        "--attest-stopped-executors",
        metavar="SHA256",
        help=(
            "attest that every executor in the exact preview manifest "
            "is stopped; value must equal that preview's challenge"
        ),
    )

    recovery = sub.add_parser(
        "recovery",
        help="manage crash-resumable packaged installation recovery bundles",
    )
    recovery_sub = recovery.add_subparsers(
        dest="recovery_action",
        title="actions",
        metavar="<action>",
    )
    destroy_retired = recovery_sub.add_parser(
        "destroy-retired-installation",
        help=(
            "logically remove one exact retained installation bundle after "
            "checking its authenticated replacement binding"
        ),
    )
    destroy_retired.add_argument(
        "--operation",
        required=True,
        metavar="UUID",
        help="exact packaged retirement operation UUID",
    )
    destroy_retired.add_argument(
        "--confirm-manifest-digest",
        required=True,
        metavar="SHA256",
        help="typed old-bundle manifest digest shown by reset --nuke-secrets",
    )

    # createsuperuser (alias to bootstrap-admin; Django-familiar name)
    createsuperuser = sub.add_parser(
        "createsuperuser",
        help="create an admin user (Django-style alias for bootstrap-admin)",
    )
    createsuperuser.add_argument(
        "--email",
        required=True,
        help="admin email address",
    )
    createsuperuser.add_argument(
        "--display-name",
        default=None,
        help="optional display name",
    )
    createsuperuser_pw = createsuperuser.add_mutually_exclusive_group(
        required=True,
    )
    createsuperuser_pw.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin (recommended)",
    )
    createsuperuser_pw.add_argument(
        "--password",
        default=None,
        help="password on the command line (NOT recommended)",
    )

    # changepassword
    changepassword = sub.add_parser(
        "changepassword",
        help="change a user's password (admin recovery / CLI-only ops)",
    )
    changepassword.add_argument("email", help="email of the user to reset")
    changepassword_pw = changepassword.add_mutually_exclusive_group(
        required=True,
    )
    changepassword_pw.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin (recommended)",
    )
    changepassword_pw.add_argument(
        "--password",
        default=None,
        help="password on the command line (NOT recommended)",
    )

    # reset-mfa (1.6.0). Shell-only escape hatch for lost-phone /
    # lost-recovery-codes; clears the user's MFA secret, recovery
    # codes, and trusted devices in one transaction. Audit row is
    # written attributed to the OS user invoking the CLI.
    reset_mfa = sub.add_parser(
        "reset-mfa",
        help=(
            "clear a user's MFA enrollment, recovery codes, and "
            "trusted devices (lost-phone recovery; shell-only)"
        ),
    )
    reset_mfa.add_argument("email", help="email of the user to reset")
    reset_mfa.add_argument(
        "--confirm",
        action="store_true",
        help="skip the interactive 'are you sure' prompt",
    )

    # check
    sub.add_parser(
        "check",
        help=(
            "validate config + DB connectivity, and print whatever migration "
            "revision is stored. Does NOT compare it against this build's "
            "head, and exits 0 even with no alembic_version table: use "
            "`z4j migrate current --check-heads` for that. Non-destructive."
        ),
    )

    # status
    sub.add_parser(
        "status",
        help=(
            "print the stored migration revision and total row counts for "
            "users, projects, agents, tasks, sessions, and audit history."
        ),
    )

    # allowed-hosts (manage the persistent ~/.z4j/allowed-hosts file)
    ah = sub.add_parser(
        "allowed-hosts",
        help=(
            "manage the persistent Host: header allow-list at "
            "~/.z4j/allowed-hosts. Hosts added here are merged into the "
            "auto-detect set on every `z4j serve` start, so you don't "
            "need to set Z4J_ALLOWED_HOSTS or pass --allowed-host every "
            "time."
        ),
    )
    ah_sub = ah.add_subparsers(
        dest="ah_action",
        required=True,
        title="actions",
        metavar="<action>",
    )
    ah_sub.add_parser("list", help="print the current persisted allow-list")
    ah_add = ah_sub.add_parser("add", help="add one or more hosts to the file")
    ah_add.add_argument("hosts", nargs="+", metavar="HOST", help="hostname or IP literal to allow")
    ah_rm = ah_sub.add_parser("remove", help="remove one or more hosts from the file")
    ah_rm.add_argument("hosts", nargs="+", metavar="HOST", help="hostname or IP literal to remove")
    ah_sub.add_parser("path", help="print the file path the brain reads from")

    # doctor
    sub.add_parser(
        "doctor",
        help=(
            "run `check`, then report configuration warnings it cannot "
            "raise: dev mode on a public bind, debug host errors, "
            "auto-minted secrets needing an off-host backup, public "
            "metrics, and first-boot gaps. Takes no options. Like `check` "
            "it does NOT verify the schema is at head; use "
            "`migrate current --check-heads` for that."
        ),
    )

    # backup
    backup = sub.add_parser(
        "backup",
        help=(
            "snapshot the brain database to a single file. SQLite uses "
            "VACUUM INTO (online; brain keeps serving). PostgreSQL "
            "shells out to pg_dump (custom format)."
        ),
    )
    backup.add_argument(
        "--output",
        "-o",
        required=True,
        metavar="PATH",
        help="output file path (e.g. ./z4j-2026-04-24.dump)",
    )

    # restore
    restore = sub.add_parser(
        "restore",
        help=(
            "run the authenticated, crash-resumable database restore "
            "ceremony. STOP every brain and scheduler/executor process "
            "before running."
        ),
    )
    restore.add_argument(
        "source",
        nargs="?",
        metavar="PATH",
        help=(
            "path to a backup file produced by `z4j backup`; omit it when "
            "resuming with --operation, which takes its source from the "
            "staged operation"
        ),
    )
    restore.add_argument(
        "--force",
        action="store_true",
        help="acknowledge that the brain process is stopped",
    )
    restore.add_argument(
        "--operation",
        metavar="UUID",
        help=(
            "resume one exact staged restore operation (required when "
            "the first pass reports a stopped-executor challenge); needs "
            "no PATH, because the staged operation already holds one"
        ),
    )
    restore.add_argument(
        "--expected-sha256",
        metavar="SHA256",
        help="require the first staged source bytes to match this digest",
    )
    restore.add_argument(
        "--known-head",
        metavar="JSON",
        help=(
            "optional retained audit-head JSON envelope used to assess "
            "whether the restored history is current or an ancestor"
        ),
    )
    restore.add_argument(
        "--attest-stopped-executors",
        metavar="SHA256",
        help=(
            "attest every source/target executor named by the staged "
            "operation is stopped; must equal its exact challenge"
        ),
    )
    restore.add_argument(
        "--rollback-operation",
        metavar="UUID",
        help=("restore the exact retained pre-operation target for one pending restore UUID"),
    )

    # metrics-token
    mt = sub.add_parser(
        "metrics-token",
        help=(
            "manage the /metrics bearer token (auto-minted for a fresh "
            "packaged SQLite install, otherwise configured explicitly). Default action "
            "prints the token; `rotate` mints a new one."
        ),
    )
    mt_sub = mt.add_subparsers(
        dest="metrics_action",
        title="actions",
        metavar="<action>",
    )
    mt_sub.add_parser(
        "show",
        help=(
            "print the effective token using startup precedence: process "
            "environment, .env, config.env, then secret.env"
        ),
    )
    mt_sub.add_parser(
        "rotate",
        help=(
            "when secret.env is the effective source, mint and persist a "
            "fresh token there, then print it; refuses when process env, "
            ".env, or config.env wins. Requires a brain restart for the "
            "new token to take effect on the live process. Update your "
            "Prometheus scrape config before restarting."
        ),
    )

    # mint-scheduler-cert
    msc = sub.add_parser(
        "mint-scheduler-cert",
        help=(
            "mint a fresh mTLS client certificate for a z4j-scheduler "
            "instance. Requires the brain operator's CA cert + key "
            "(typically the same CA that signed the brain's gRPC "
            "server cert). Writes <name>.crt and <name>.key into "
            "--out-dir with mode 0600."
        ),
    )
    msc.add_argument(
        "--name",
        required=True,
        help=(
            "CN + DNS SAN of the cert (e.g. 'scheduler-1'). Add this "
            "value to Z4J_SCHEDULER_GRPC_ALLOWED_CNS on the brain "
            "before deploying the cert."
        ),
    )
    msc.add_argument(
        "--ca-cert",
        required=True,
        metavar="PATH",
        help="path to the CA certificate (PEM)",
    )
    msc.add_argument(
        "--ca-key",
        required=True,
        metavar="PATH",
        help="path to the CA private key (PEM, unencrypted)",
    )
    msc.add_argument(
        "--out-dir",
        required=True,
        metavar="PATH",
        help="directory where <name>.crt and <name>.key will be written",
    )
    msc.add_argument(
        "--validity-days",
        type=int,
        default=365,
        help="certificate validity in days (default: 365)",
    )

    # upgrade
    upgrade = sub.add_parser(
        "upgrade",
        help="check / apply z4j package upgrades from PyPI",
        description=(
            "List the installed z4j-* packages and the latest version "
            "published on PyPI. With --apply, run `pip install -U` for "
            "the z4j umbrella (which pulls every adapter to the latest "
            "compatible version).\n"
            "\n"
            "By default this is a check-only dry run: no installs, no\n"
            "venv mutation. For scheduled jobs, exit 1 means at least\n"
            "one package is behind; exit 2 means a lookup/configuration\n"
            "error made the result incomplete. An installed version newer\n"
            "than PyPI is reported as newer and is not treated as behind."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    upgrade.add_argument(
        "--apply",
        action="store_true",
        help=(
            "after a complete successful scan, run `pip install -U z4j` "
            "to apply upgrades. A lookup/comparison error refuses to mutate "
            "the environment. Default is check-only."
        ),
    )
    upgrade.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of a text table",
    )
    upgrade.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help=(
            "PyPI scan budget in seconds (default: 10). No new lookup starts "
            "after max(5, 2x budget); an in-flight request may finish later."
        ),
    )

    # init - scaffold ~/.z4j/config.env from a documented template.
    init = sub.add_parser(
        "init",
        help="scaffold ~/.z4j/config.env (one-time setup helper)",
    )
    init.add_argument(
        "--force",
        action="store_true",
        default=False,
        help=(
            "overwrite an existing config.env. Default behavior is "
            "to refuse so an operator never accidentally clobbers "
            "their tuned values."
        ),
    )

    # config - introspect and validate the runtime tunables file.
    config_cmd = sub.add_parser(
        "config",
        help="inspect and validate ~/.z4j/config.env",
    )
    config_sub = config_cmd.add_subparsers(
        dest="config_command",
        required=True,
    )
    config_show = config_sub.add_parser(
        "show",
        help="print effective settings + their source (env / file / default)",
    )
    config_show.add_argument(
        "--reveal-secrets",
        action="store_true",
        default=False,
        help=(
            "print secret values in cleartext. Default is to mask "
            "every secret as ***. Required for one-off debugging "
            '("is this secret what I expect") but should never '
            "land in a script."
        ),
    )
    config_validate = config_sub.add_parser(
        "validate",
        help="parse a candidate config file and report errors",
    )
    config_validate.add_argument(
        "path",
        nargs="?",
        default=None,
        help=("path to a candidate .env file. Defaults to $Z4J_HOME/config.env."),
    )

    # version
    sub.add_parser("version", help="print installed z4j version")

    args = parser.parse_args(argv)

    if args.command == "version" or args.command is None:
        print(__version__)  # noqa: T201
        return 0

    if args.command == "serve":
        return _run_serve(args)

    if args.command == "migrate":
        return _run_migrate(args)

    if args.command == "audit":
        return _run_audit(args)

    if args.command == "projects":
        return _run_projects(args)

    if args.command == "misfires":
        return _run_misfires(args)

    if args.command == "bootstrap-admin":
        return _run_bootstrap_admin(args)

    if args.command == "reset-setup":
        return _run_reset_setup(args)

    if args.command == "reset":
        return _run_reset(args)

    if args.command == "recovery":
        return _run_recovery(args)

    if args.command == "createsuperuser":
        # Identical shape to bootstrap-admin; dispatch through the
        # same implementation to keep one code path.
        return _run_bootstrap_admin(args)

    if args.command == "changepassword":
        return _run_changepassword(args)

    if args.command == "reset-mfa":
        return _run_reset_mfa(args)

    if args.command == "check":
        return _run_check(args)

    if args.command == "status":
        return _run_status(args)

    if args.command == "allowed-hosts":
        return _run_allowed_hosts(args)

    if args.command == "backup":
        return _run_backup(args)

    if args.command == "restore":
        return _run_restore(args)

    if args.command == "metrics-token":
        return _run_metrics_token(args)

    if args.command == "doctor":
        return _run_doctor(args)

    if args.command == "mint-scheduler-cert":
        return _run_mint_scheduler_cert(args)

    if args.command == "upgrade":
        return _run_upgrade(args)

    if args.command == "init":
        return _run_init(args)

    if args.command == "config":
        if args.config_command == "show":
            return _run_config_show(args)
        if args.config_command == "validate":
            return _run_config_validate(args)
        parser.error(f"unknown config subcommand {args.config_command!r}")
        return 2

    parser.error(f"unknown command {args.command!r}")
    return 2


def _run_upgrade(args: argparse.Namespace) -> int:  # noqa: PLR0911, PLR0912, PLR0915  upgrade check + apply dispatch
    """Dispatch ``z4j upgrade``.

    Compares installed z4j package versions against PyPI's
    /pypi/<pkg>/json endpoint and prints a one-row-per-package
    summary. Exit code is 0 when every installed package is current
    or newer than PyPI, 1 when at least one package is behind, and 2
    when a lookup/comparison error makes the scan incomplete. With
    --apply the umbrella ``z4j`` is upgraded via a child ``pip
    install -U`` call only after a complete scan.
    """
    import json as _json
    import shlex
    import shutil
    import subprocess
    from importlib.metadata import PackageNotFoundError, version

    import httpx
    from packaging.version import InvalidVersion, Version

    from z4j_brain.domain.version_check import load_bundled

    # The release-generated snapshot is already the runtime's package
    # catalogue. Derive from it rather than keeping a second hand-maintained
    # list that can omit a newly-added adapter.
    _z4j_packages = tuple(sorted(load_bundled().packages))
    if not _z4j_packages:
        print(  # noqa: T201  CLI output
            "z4j upgrade: bundled package catalogue is missing or invalid",
            file=sys.stderr,
        )
        return 2

    rows: list[dict[str, str | bool]] = []
    network_errors: list[str] = []  # aggregate
    behind = 0
    newer = 0

    # Bound when the CLI may START another request. Each request receives a
    # share of the catalogue-wide budget (with a 2s floor); after
    # max(5s, 2 * args.timeout) no further request starts. The final in-flight
    # request can finish after that threshold, exactly as the CLI help says.
    import time

    started_at = time.monotonic()
    walltime_budget = max(5.0, args.timeout * 2)
    per_call_timeout = max(2.0, args.timeout / max(1, len(_z4j_packages)))

    with httpx.Client(timeout=per_call_timeout) as client:
        for pkg in _z4j_packages:
            try:
                installed = version(pkg)
            except PackageNotFoundError:
                continue  # not installed in this venv

            elapsed = time.monotonic() - started_at
            if elapsed > walltime_budget:
                # Walltime exceeded: don't even try the call.
                network_errors.append(
                    f"{pkg}: skipped (walltime budget exhausted)",
                )
                rows.append(
                    {
                        "package": pkg,
                        "installed": installed,
                        "latest": "(skipped: timeout)",
                        "behind": False,
                        "status": "lookup failed",
                    }
                )
                continue

            try:
                resp = client.get(f"https://pypi.org/pypi/{pkg}/json")
                if resp.status_code == 404:
                    rows.append(
                        {
                            "package": pkg,
                            "installed": installed,
                            "latest": "(not on PyPI)",
                            "behind": False,
                            "status": "unpublished",
                        }
                    )
                    continue
                resp.raise_for_status()
                latest = resp.json().get("info", {}).get("version", "?")
            except httpx.HTTPError as exc:
                network_errors.append(
                    f"{pkg}: {type(exc).__name__}: {exc}",
                )
                rows.append(
                    {
                        "package": pkg,
                        "installed": installed,
                        "latest": "(lookup failed)",
                        "behind": False,
                        "status": "lookup failed",
                    }
                )
                continue

            try:
                installed_version = Version(installed)
                latest_version = Version(str(latest))
            except InvalidVersion as exc:
                network_errors.append(
                    f"{pkg}: invalid version in comparison: {exc}",
                )
                rows.append(
                    {
                        "package": pkg,
                        "installed": installed,
                        "latest": str(latest),
                        "behind": False,
                        "status": "comparison failed",
                    }
                )
                continue

            is_behind = installed_version < latest_version
            is_newer = installed_version > latest_version
            if is_behind:
                behind += 1
            elif is_newer:
                newer += 1
            rows.append(
                {
                    "package": pkg,
                    "installed": installed,
                    "latest": str(latest),
                    "behind": is_behind,
                    "status": ("behind" if is_behind else "newer" if is_newer else "current"),
                }
            )

    # Backwards-compat single-string for the JSON shape callers
    # already test against:
    network_error = "; ".join(network_errors) if network_errors else None

    if args.json:
        print(  # noqa: T201  CLI output
            _json.dumps(
                {
                    "ok": behind == 0 and network_error is None,
                    "behind_count": behind,
                    "newer_count": newer,
                    "rows": rows,
                    "network_error": network_error,
                }
            )
        )
    else:
        if not rows:
            print("z4j upgrade: no z4j packages installed in this venv.")  # noqa: T201
            return 0
        col_pkg = max(len(str(r["package"])) for r in rows) + 2
        col_inst = max(len(str(r["installed"])) for r in rows) + 2
        col_last = max(len(str(r["latest"])) for r in rows) + 2
        header = f"{'PACKAGE':<{col_pkg}}{'INSTALLED':<{col_inst}}{'LATEST':<{col_last}}STATUS"
        print(header)  # noqa: T201
        print("-" * len(header))  # noqa: T201
        for r in rows:
            status = str(r["status"])
            print(  # noqa: T201
                f"{r['package']!s:<{col_pkg}}"
                f"{r['installed']!s:<{col_inst}}"
                f"{r['latest']!s:<{col_last}}{status}",
            )
        print()  # noqa: T201
        if network_error:
            print(  # noqa: T201
                f"warning: at least one PyPI lookup failed: {network_error}",
            )
        if behind:
            print(  # noqa: T201
                f"{behind} package(s) behind. Run `z4j upgrade --apply` "
                "to upgrade the umbrella (and adapters via dependency "
                "constraints), or pip install each one explicitly.",
            )
        elif network_error:
            print("upgrade status is incomplete because a lookup failed.")  # noqa: T201
        elif newer:
            print(  # noqa: T201
                f"all z4j packages are current or newer than PyPI ({newer} newer).",
            )
        else:
            print("all z4j packages are up to date.")  # noqa: T201

    # A partial scan is never a safe basis for mutation. This also keeps the
    # documented hard-error status stable when another package was found
    # behind before the failed lookup: incompleteness wins over "behind".
    if network_error:
        return 2
    if not args.apply:
        return 1 if behind else 0

    # --apply: shell out to pip install -U z4j
    pip_cmd = [sys.executable, "-m", "pip", "install", "-U", "z4j"]
    print(f"running: {shlex.join(pip_cmd)}")  # noqa: T201
    if shutil.which(sys.executable) is None:
        print("error: cannot locate python executable", file=sys.stderr)  # noqa: T201
        return 2
    try:
        proc = subprocess.run(pip_cmd, check=False)  # noqa: S603  fixed internal pip upgrade command
    except OSError as exc:
        print(f"error: pip invocation failed: {exc}", file=sys.stderr)  # noqa: T201
        return 2
    return proc.returncode


def _run_mint_scheduler_cert(args: argparse.Namespace) -> int:
    """Dispatch ``z4j mint-scheduler-cert``.

    Reads the operator's CA material, mints a fresh cert + key for
    the named scheduler instance, writes them to ``--out-dir``, and
    prints the on-disk paths so the operator can scp them to the
    scheduler host.

    Imported lazily so the ``cryptography`` dep is only required for
    operators who actually run this command.
    """
    try:
        from z4j_brain.scheduler_grpc.auth import (
            mint_scheduler_cert,
            write_minted_cert,
        )
    except ImportError as exc:
        print(  # noqa: T201  CLI output
            "z4j: mint-scheduler-cert requires the scheduler-grpc extra. "
            "Install with: pip install 'z4j[scheduler-grpc]'",
            file=sys.stderr,
        )
        print(f"  underlying error: {exc}", file=sys.stderr)  # noqa: T201  CLI output
        return 2

    ca_cert_path = Path(args.ca_cert)
    ca_key_path = Path(args.ca_key)
    out_dir = Path(args.out_dir)

    if not ca_cert_path.is_file():
        print(f"z4j: --ca-cert {ca_cert_path!s} not found", file=sys.stderr)  # noqa: T201  CLI output
        return 2
    if not ca_key_path.is_file():
        print(f"z4j: --ca-key {ca_key_path!s} not found", file=sys.stderr)  # noqa: T201  CLI output
        return 2

    try:
        cert_pem, key_pem = mint_scheduler_cert(
            name=args.name,
            ca_cert_pem=ca_cert_path.read_bytes(),
            ca_key_pem=ca_key_path.read_bytes(),
            validity_days=args.validity_days,
        )
        cert_path, key_path = write_minted_cert(
            out_dir=out_dir,
            name=args.name,
            cert_pem=cert_pem,
            key_pem=key_pem,
        )
    except Exception as exc:
        print(f"z4j mint-scheduler-cert failed: {exc}", file=sys.stderr)  # noqa: T201  CLI output
        return 1

    print(f"wrote certificate: {cert_path}")  # noqa: T201  CLI output
    print(f"wrote private key: {key_path}")  # noqa: T201  CLI output
    print(  # noqa: T201  CLI output
        f"\nNext steps:\n"
        f"  1. Add '{args.name}' to Z4J_SCHEDULER_GRPC_ALLOWED_CNS on the brain\n"
        f"  2. Restart the brain so the new allow-list takes effect\n"
        f"  3. scp {cert_path.name} {key_path.name} to the scheduler host\n"
        f"  4. Set Z4J_SCHEDULER_TLS_CERT and Z4J_SCHEDULER_TLS_KEY on the scheduler",
    )
    return 0


def _run_metrics_token(args: argparse.Namespace) -> int:
    """Dispatch ``z4j metrics-token [show|rotate]``.

    Default (no action) is ``show`` for backward compatibility with
    1.0.13's ``z4j metrics-token`` (no subcommand).
    """
    action = getattr(args, "metrics_action", None) or "show"
    if action == "rotate":
        return _run_metrics_token_rotate(args)
    return _run_metrics_token_show(args)


def _run_metrics_token_show(args: argparse.Namespace) -> int:
    """Print the ``/metrics`` bearer token.

    Resolution (first match wins):
      1. ``Z4J_METRICS_AUTH_TOKEN`` env var (operator override).
      2. ``Z4J_METRICS_AUTH_TOKEN`` in ``./.env``.
      3. ``Z4J_METRICS_AUTH_TOKEN`` in ``~/.z4j/config.env``.
      4. ``Z4J_METRICS_AUTH_TOKEN`` line in ``~/.z4j/secret.env``
         (auto-minted by ``z4j serve`` for a fresh packaged SQLite install).
      5. Prints an error to stderr and exits 2.

    Writes ONLY the token to stdout so scripts can use
    ``$(z4j metrics-token)`` safely.
    """
    from z4j_brain.configuration import capture_configuration

    try:
        snapshot = capture_configuration()
    except Exception as exc:
        print(f"z4j metrics-token: configuration refused: {exc}", file=sys.stderr)  # noqa: T201
        return 2
    token = snapshot.values.get("Z4J_METRICS_AUTH_TOKEN")
    if token:
        print(token)  # noqa: T201
        return 0

    print(  # noqa: T201
        "z4j metrics-token: no token found. "
        "A fresh packaged SQLite install mints one during `z4j serve`; "
        "otherwise set Z4J_METRICS_AUTH_TOKEN explicitly.",
        file=sys.stderr,
    )
    return 2


def _run_metrics_token_rotate(args: argparse.Namespace) -> int:
    """Mint a fresh ``/metrics`` bearer token and replace it in
    ``~/.z4j/secret.env``.

    Refuses unless ``secret.env`` is the effective source after normal
    startup precedence (process environment, ``.env``, ``config.env``,
    then ``secret.env``). When eligible, atomically rewrites the file:
    read all lines, replace (or
    append) the ``Z4J_METRICS_AUTH_TOKEN=`` line, write to a temp
    file in the same dir, ``rename()`` over the original. This way
    a concurrent ``z4j serve`` boot reads either the old file or
    the new one, never a half-written one.

    Does NOT touch the running brain process. Operators must
    restart for the new token to take effect (the brain caches
    the env var at startup; FastAPI's ``Settings`` is built once
    per process).

    Prints the new token to stdout (one line, no other noise) so
    scripts can ``new=$(z4j metrics-token rotate)`` and immediately
    push the value to a Prometheus reload.
    """
    import secrets as _secrets

    from z4j_brain.configuration import capture_configuration
    from z4j_brain.secret_store import update_secret_store

    secret_env = z4j_home() / "secret.env"
    try:
        snapshot = capture_configuration()
    except Exception as exc:
        print(  # noqa: T201
            f"z4j metrics-token rotate: configuration refused: {exc}",
            file=sys.stderr,
        )
        return 2
    source = snapshot.source_for_env_key("Z4J_METRICS_AUTH_TOKEN")
    if source != "secret.env":
        print(  # noqa: T201
            "z4j metrics-token rotate: refusing to rewrite secret.env because "
            f"the effective token source is {source}. Rotate that source "
            "instead; the lower-precedence store was not changed.",
            file=sys.stderr,
        )
        return 2

    new_token = _secrets.token_urlsafe(32)
    try:
        winner = update_secret_store(
            secret_env,
            {"Z4J_METRICS_AUTH_TOKEN": new_token},
        )
    except Exception as exc:
        print(f"z4j metrics-token rotate: store update refused: {exc}", file=sys.stderr)  # noqa: T201
        return 2
    if winner.values.get("Z4J_METRICS_AUTH_TOKEN") != new_token:
        print(  # noqa: T201
            "z4j metrics-token rotate: persisted winner mismatch; the new token was not advertised",
            file=sys.stderr,
        )
        return 2

    # Audit log (best-effort): log the rotation to structlog so the
    # operations team can correlate "Prometheus stopped scraping" with
    # "someone rotated the token at 14:32". We deliberately don't
    # write to the DB audit_events table from the CLI rotate path -
    # the brain may not be running, and adding a DB dependency to a
    # CLI hygiene command would be a footgun (rotate would fail when
    # the DB was unreachable).
    import logging as _logging

    _logging.getLogger("z4j.brain.cli").info(
        "metrics_token_rotated",
        extra={
            "secret_env": str(secret_env),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
        },
    )

    print(new_token)  # noqa: T201
    print(  # noqa: T201
        f"z4j metrics-token rotate: new token written to {secret_env}. "
        f"Restart the brain (`systemctl restart z4j` or equivalent) for "
        f"the new token to take effect, and update your Prometheus "
        f"scrape config's authorization.credentials before the restart.",
        file=sys.stderr,
    )
    return 0


def _run_doctor(args: argparse.Namespace) -> int:  # noqa: PLR0915  flat diagnostic inventory
    """Full health + configuration audit.

    Composes ``check`` (DB + migrations) with a set of warnings that
    a plain ``check`` can't raise because they're not failures -
    they're configuration smells the operator should be aware of
    before exposing the brain to the internet.

    Return codes:
      0 = all green, no warnings
      0 = check passed but one or more warnings (operator attention)
      non-zero = same as ``check`` (config invalid / DB unreachable /
                 schema not at head)
    """
    import asyncio
    import os

    # Reuse the existing check to catch config / DB / migration issues
    # up front. If that fails, the rest of doctor is moot.
    rc = _run_check(args)
    if rc != 0:
        return rc

    warnings: list[str] = []

    # Warning 1: dev mode + non-loopback bind = publicly-reachable dev
    # mode, which is the exact footgun we already fixed in the host
    # middleware. Surface it up front so operators see it.
    env = os.environ.get("Z4J_ENVIRONMENT", "").lower()
    # Only flag when Z4J_BIND_HOST is explicitly set to a non-loopback
    # value AND env is dev. Pre-1.0.14 the default fallback was
    # "0.0.0.0", which fired a false positive every time the operator
    # ran `z4j doctor` between sessions (the env var is unset until
    # `z4j serve` sets it during dev-mode auto-defaulting). v1.0.14's
    # _run_serve sets Z4J_BIND_HOST=127.0.0.1 when env=dev and the
    # operator hasn't pinned it - so the only path to this warning is
    # an EXPLICIT Z4J_BIND_HOST != loopback set in the operator's
    # environment, which IS the dangerous combo.
    bind_host = os.environ.get("Z4J_BIND_HOST", "")
    if (
        env == "dev"
        and bind_host
        and bind_host
        not in (
            "127.0.0.1",
            "localhost",
            "[::1]",
        )
    ):
        # As of v1.0.14 `z4j serve` refuses to start with this combo
        # (see _run_serve fail-closed gate). Doctor still flags it as
        # an INFO-level warning so an operator running `z4j doctor`
        # in a CI/IaC pipeline catches the env-var combo before it
        # crashes the systemd unit on the next restart.
        warnings.append(
            f"Z4J_ENVIRONMENT=dev AND Z4J_BIND_HOST={bind_host!r}. "
            f"`z4j serve` will REFUSE to start with this combo "
            f"(fail-closed since v1.0.14). Either set "
            f"Z4J_BIND_HOST=127.0.0.1 for localhost-only dev, or switch "
            f"to Z4J_ENVIRONMENT=production with explicit "
            f"Z4J_PUBLIC_URL=https://... and Z4J_ALLOWED_HOSTS for "
            f"public access. Setting both auto-promotes the environment "
            f"to production. The CLI flag `z4j serve --environment "
            f"production` is the easiest way to flip."
        )

    # Warning 2: Z4J_DEBUG_HOST_ERRORS is on - verbose host rejection
    # responses will leak internal hostnames. Only safe for strictly-
    # localhost installs.
    if os.environ.get("Z4J_DEBUG_HOST_ERRORS", "").lower() in ("1", "true", "yes", "on"):
        warnings.append(
            "Z4J_DEBUG_HOST_ERRORS=1 is set. Rejected Host-header "
            "requests will echo internal allow-list data back to the "
            "caller. Only safe for local-laptop development bound to "
            "127.0.0.1. Turn it off for anything reachable from the "
            "network."
        )

    # Warning 3: auto-minted secrets - the operator should back up
    # the persisted secret.env file off-host.
    secret_env = z4j_home() / "secret.env"
    if secret_env.exists():
        warnings.append(
            f"A brain secret store exists at {secret_env}. Back it up "
            f"off-host (rsync / S3 / password manager) and use `z4j config "
            f"show` to confirm which values are effective. Losing an effective "
            f"Z4J_SECRET breaks agent credentials and stored TOTP secrets; "
            f"losing Z4J_SESSION_SECRET invalidates sessions; losing "
            f"Z4J_AUDIT_CHAIN_SECRET prevents audit-chain verification."
        )

    # Warning 4: /metrics exposed without auth. Prometheus labels
    # expose project IDs, queue names, task names, in-memory state.
    # Fail-secure default was introduced in 1.0.13; before that, every
    # install was public by default.
    metrics_enabled = os.environ.get("Z4J_METRICS_ENABLED", "true").lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    if metrics_enabled and os.environ.get("Z4J_METRICS_PUBLIC", "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        warnings.append(
            "Z4J_METRICS_PUBLIC=1 is set. /metrics is served without "
            "authentication. Prometheus labels leak project IDs, "
            "queue/task names, and in-memory state to anyone who can "
            "reach the endpoint. Only safe on a trusted closed "
            "network. For production, unset Z4J_METRICS_PUBLIC and "
            "use Z4J_METRICS_AUTH_TOKEN (run `z4j metrics-token` to "
            "print the auto-minted value)."
        )

    async def _row_warnings() -> None:
        from sqlalchemy import text

        from z4j_brain.persistence.database import DatabaseManager

        _settings, engine = _build_settings_from_env()
        db = DatabaseManager(engine)
        try:
            async with db.session() as session:
                r_users = await session.execute(text("SELECT COUNT(*) FROM users"))
                users = r_users.scalar_one() or 0
                r_projects = await session.execute(
                    text("SELECT COUNT(*) FROM projects"),
                )
                projects = r_projects.scalar_one() or 0
                # A revoked agent is a historical tombstone, not an available
                # credential. Doctor's warning is operational ("none minted"),
                # unlike ``z4j status``'s explicitly physical row counts.
                # Fall back for a pre-1.9 schema, where the column does not yet
                # exist and every remaining row is necessarily live.
                try:
                    async with session.begin_nested():
                        r_agents = await session.execute(
                            text("SELECT COUNT(*) FROM agents WHERE revoked_at IS NULL"),
                        )
                except Exception:
                    r_agents = await session.execute(
                        text("SELECT COUNT(*) FROM agents"),
                    )
                agents = r_agents.scalar_one() or 0
        finally:
            await engine.dispose()

        if users == 0:
            warnings.append(
                "No users exist yet. Complete first-boot setup at the "
                "/setup URL printed by `z4j serve`, or run "
                "`z4j createsuperuser` directly."
            )
        if users > 0 and projects == 0:
            warnings.append(
                "Users exist but no projects. The first-boot flow normally "
                "creates a default project - investigate (`z4j status`)."
            )
        if projects > 0 and agents == 0:
            warnings.append(
                "Projects exist but no agents minted. Go to "
                "/projects/<slug>/agents in the dashboard and click "
                "'new agent' to issue a token + hmac_secret."
            )

    try:
        asyncio.run(_row_warnings())
    except Exception as exc:
        warnings.append(
            f"could not enumerate users/projects/agents: {type(exc).__name__}: {exc}",
        )

    if warnings:
        print(f"\nz4j doctor: warnings ({len(warnings)}):")  # noqa: T201
        for i, w in enumerate(warnings, 1):
            print(f"  {i}. {w}\n")  # noqa: T201
        return 0

    print("\nz4j doctor: all green, no warnings.")  # noqa: T201
    return 0


def _run_backup(args: argparse.Namespace) -> int:
    """Snapshot the brain DB to a file. Backend auto-detected from DB URL."""
    _bootstrap_env_for_management_commands()
    from z4j_brain.backup import backup
    from z4j_brain.settings import Settings

    settings = Settings()  # type: ignore[call-arg]
    output = Path(args.output)
    try:
        result = backup(settings.database_url, output)
    except FileExistsError as exc:
        print(f"z4j: {exc}")  # noqa: T201
        return 1
    except FileNotFoundError as exc:
        print(f"z4j: {exc}")  # noqa: T201
        return 1
    except Exception as exc:
        print(f"z4j: backup failed: {exc}")  # noqa: T201
        return 1
    size_mb = result["size_bytes"] / (1024 * 1024)
    print(  # noqa: T201
        f"z4j: backup complete\n"
        f"  backend:    {result['backend']}\n"
        f"  output:     {result['path']}\n"
        f"  size:       {size_mb:.2f} MiB",
    )
    print(  # noqa: T201
        "z4j: move this file off-host (scp, rclone, S3, ...) for true disaster recovery.",
    )
    return 0


def _staged_restore_source(database_url: str, operation: str) -> Path:
    """Read one staged operation's own source path, per backend."""

    from z4j_brain.backup import detect_backend

    if detect_backend(database_url) == "postgres":
        from z4j_brain.management_restore_postgres import (
            staged_restore_source,
        )
    else:
        from z4j_brain.management_restore import staged_restore_source

    return staged_restore_source(database_url, operation=operation)


def _run_restore(args: argparse.Namespace) -> int:  # noqa: PLR0911
    """Restore the brain DB from a backup file. Brain MUST be stopped."""
    if not args.force:
        print(  # noqa: T201
            "z4j: restore replaces the live DB. The brain process "
            "MUST be stopped first (`systemctl stop z4j` / `docker compose "
            "down z4j`). Re-run with --force to acknowledge.",
        )
        return 1
    _bootstrap_env_for_management_commands()
    import json

    from z4j_brain.backup import restore, rollback_restore
    from z4j_brain.settings import Settings

    settings = Settings()  # type: ignore[call-arg]
    if args.rollback_operation and args.source is not None:
        print(  # noqa: T201
            "z4j: restore failed: rollback does not accept a source path",
        )
        return 1
    if args.rollback_operation and args.known_head is not None:
        print(  # noqa: T201
            "z4j: restore failed: rollback does not accept --known-head",
        )
        return 1
    if not args.rollback_operation and args.source is None and args.operation is None:
        print(  # noqa: T201
            "z4j: restore failed: PATH, --operation UUID, or --rollback-operation UUID is required",
        )
        return 1
    try:
        if args.rollback_operation:
            result = rollback_restore(
                settings.database_url,
                operation=args.rollback_operation,
            )
            print(  # noqa: T201
                "z4j: restore rollback complete\n"
                f"  backend:    {result['backend']}\n"
                f"  operation:  {result['operation_id']}\n"
                f"  marker:     {result.get('marker_id', 'n/a')}",
            )
            return 0
        # A resume never reopens the operator's file: it takes its source from
        # the durable phase. Asking for a PATH it will not read is how the
        # fence came to advertise a resume command the CLI then rejected.
        src = (
            Path(args.source)
            if args.source is not None
            else _staged_restore_source(settings.database_url, args.operation)
        )
        if args.known_head is None:
            known_head = None
        else:
            try:
                decoded_known_head = json.loads(args.known_head)
            except (TypeError, ValueError):
                decoded_known_head = {"__invalid_json__": True}
            known_head = (
                decoded_known_head
                if isinstance(decoded_known_head, dict)
                else {"__invalid_json__": True}
            )
        result = restore(
            settings.database_url,
            src,
            operation=args.operation,
            expected_sha256=args.expected_sha256,
            stopped_executor_attestation=(args.attest_stopped_executors),
            known_head=known_head,
        )
    except FileNotFoundError as exc:
        print(f"z4j: {exc}")  # noqa: T201
        return 1
    except Exception as exc:
        print(f"z4j: restore failed: {exc}")  # noqa: T201
        return 1
    print(  # noqa: T201
        f"z4j: restore complete\n"
        f"  backend:    {result['backend']}\n"
        f"  source:     {result['source']}\n"
        f"  operation:  {result.get('operation_id', 'n/a')}\n"
        f"  digest:     {result.get('source_digest', 'n/a')}\n"
        f"  rollback:   {result.get('known_head_result', 'n/a')}",
    )
    print(  # noqa: T201
        "z4j: start the brain (`systemctl start z4j` / `docker "
        "compose up -d z4j`) and verify with `z4j check && z4j status`.",
    )
    return 0


def _run_allowed_hosts(args: argparse.Namespace) -> int:
    """Handle ``z4j allowed-hosts {list,add,remove,path}``.

    Thin wrapper over :mod:`z4j_brain.allowed_hosts`. All actions
    operate on the same on-disk file so a `serve` invocation reads
    exactly what an earlier `add` wrote.
    """
    from z4j_brain.allowed_hosts import add, get_path, read_persisted, remove

    action = args.ah_action

    if action == "path":
        print(get_path())  # noqa: T201
        return 0

    if action == "list":
        path = get_path()
        hosts = read_persisted()
        if not hosts:
            print(f"(no persisted hosts in {path})")  # noqa: T201
            print(  # noqa: T201
                "Add one with: z4j allowed-hosts add tasks.example.com",
            )
            return 0
        print(f"# persisted hosts ({path}):")  # noqa: T201
        for h in hosts:
            print(f"  {h}")  # noqa: T201
        print(  # noqa: T201
            "\nThese are merged into the auto-detected hostname/IP set on every `z4j serve` start.",
        )
        return 0

    if action == "add":
        added, skipped = add(args.hosts)
        for h in added:
            print(f"  added:   {h}")  # noqa: T201
        for h in skipped:
            print(f"  skipped: {h} (already present)")  # noqa: T201
        if added:
            print(  # noqa: T201
                f"\nWrote {get_path()}. Restart `z4j serve` for the change to take effect.",
            )
        return 0

    if action == "remove":
        removed, not_found = remove(args.hosts)
        for h in removed:
            print(f"  removed:   {h}")  # noqa: T201
        for h in not_found:
            print(f"  not found: {h}")  # noqa: T201
        if removed:
            print(  # noqa: T201
                f"\nWrote {get_path()}. Restart `z4j serve` for the change to take effect.",
            )
        return 0

    return 2


def _setup_multiprocess_metrics_env(
    workers: int,
    *,
    reload_mode: bool,
) -> str | None:
    """Point prometheus_client at a shared mmap dir for multi-worker serve.

    The default ``z4j serve``
    runs min(4, cpu) uvicorn worker PROCESSES, but the brain's
    Prometheus registry is in-process, so a load-balanced
    ``/metrics`` scrape lands on ONE worker and misses counters
    incremented in the others (agent-offline and automation incident
    counters appear to reset or never fire). prometheus_client's
    multiprocess mode fixes this: with ``PROMETHEUS_MULTIPROC_DIR``
    set, every process writes metric values to mmap files in that
    directory and the scrape handler aggregates across all of them
    (see ``z4j_brain.api.metrics``).

    Import-order guarantee (prometheus_client binds its value
    backend AT IMPORT TIME from this env var):

    - The parent process (this one) does not import
      prometheus_client before ``uvicorn.run``: the serve path
      touches only uvicorn, z4j_core.paths, and z4j_brain's
      ``__init__`` / ``allowed_hosts`` / ``startup`` modules, none of
      which import the metrics module. With ``workers > 1`` uvicorn's
      supervisor never loads the app in the parent either
      (``Config.load`` runs inside ``Server.serve``, i.e. in the
      workers).
    - uvicorn spawns workers with multiprocessing's "spawn" context
      (``uvicorn._subprocess``), so each worker is a FRESH
      interpreter that inherits ``os.environ`` and imports
      prometheus_client with the env var already set. The workers,
      the processes actually serving scrapes, therefore always get
      multiprocess-backed values; even if a future refactor imported
      the metrics module in the parent early, only the parent's
      (non-serving) registry would stay in-process.

    Lifecycle:

    - ``mkdtemp`` mints a fresh per-run directory, so stale value
      files from a previous serve run can never leak into this run's
      aggregation (a stale counter file would resurrect ghost
      increments under a recycled PID).
    - The directory is removed via ``atexit`` on normal shutdown; a
      SIGKILL'd parent leaves it behind for the OS tmp cleaner.
    - Worker-death cleanup: before each aggregate scrape, the metrics
      handler probes worker PIDs and calls
      ``multiprocess.mark_process_dead`` for dead workers. That removes
      their live-gauge files, bounding ordinary gauge staleness to the
      next successful scrape. Counter and histogram files intentionally
      remain so completed work is never un-counted. Reaping is best-effort;
      PID reuse or a failed probe can delay live-gauge cleanup.
    - Operators who export ``PROMETHEUS_MULTIPROC_DIR`` themselves
      own that directory's lifecycle; it is left untouched.

    Returns the directory created, or ``None`` when multiprocess
    mode was not activated here (single worker, ``--reload``, or an
    operator-managed directory).
    """
    if workers <= 1 or reload_mode:
        # Single process serves every scrape, so the in-process
        # registry is already complete. --reload is dev-only and
        # runs a single worker under the reloader regardless of the
        # workers flag; reloader restarts would also churn PIDs and
        # accumulate stale mmap files within one run.
        return None
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        # Operator-managed directory: respect it and its lifecycle.
        return None

    import atexit
    import shutil
    import tempfile

    multiproc_dir = tempfile.mkdtemp(prefix="z4j-prometheus-multiproc-")
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = multiproc_dir
    atexit.register(shutil.rmtree, multiproc_dir, ignore_errors=True)
    print(  # noqa: T201
        f"z4j: multiprocess metrics active for {workers} workers "
        f"(PROMETHEUS_MULTIPROC_DIR={multiproc_dir}); /metrics "
        "scrapes aggregate across all worker processes.",
    )
    return multiproc_dir


def resolve_serve_workers(
    requested: int | None,
    *,
    local_registry: bool,
    cpu_count: int,
    embedded_scheduler: bool = False,
) -> tuple[int, str | None]:
    """Resolve the uvicorn worker count for ``z4j serve``.

    Default is ``min(4, cpu_count)`` (a single worker could not dispatch
    WebSocket PONGs within ping_timeout while ingesting event batches,
    causing agent flap). BUT a LOCAL (in-memory) agent registry cannot be
    shared across worker PROCESSES: each uvicorn worker keeps its own, so
    an agent connected to worker A is invisible to the dashboard served by
    worker B (split-brain), multiple workers on one SQLite file contend on
    writes, and N workers race the first-boot bootstrap (N concurrent
    _auto_bootstrap_admin -> UNIQUE-violation tracebacks + a misleading
    setup-token banner on the flagship quickstart). The SQLite
    auto-detection sets ``Z4J_REGISTRY_BACKEND=local``, so a SQLite
    deployment is single-worker by construction; scaling out workers
    requires Postgres (the shared postgres_notify registry).

    Embedded scheduler supervision is also process-local.  More than one
    uvicorn worker would start one scheduler child per worker, duplicating
    fire loops and making every child contend for the same metrics socket.
    That deployment is therefore single-worker even on PostgreSQL; operators
    who need a multi-worker brain deploy the scheduler as its standalone
    service instead.

    Returns ``(workers, note)`` where ``note`` is an operator-facing line
    to print (or None).
    """
    workers = max(1, min(4, cpu_count)) if requested is None else int(requested)
    if local_registry and workers > 1:
        note = (
            f"z4j: SQLite / in-memory registry detected -- forcing "
            f"--workers=1 (requested {workers}). A multi-worker in-memory "
            f"registry splits agent visibility across processes and "
            f"contends on the single SQLite file. Switch to Postgres "
            f"(Z4J_DATABASE_URL=postgresql+asyncpg://...) to scale out "
            f"workers."
        )
        return 1, note
    if embedded_scheduler and workers > 1:
        note = (
            "z4j: embedded scheduler detected -- forcing --workers=1 "
            f"(requested {workers}). Embedded supervision is process-local; "
            "multiple brain workers would launch competing scheduler children. "
            "Disable Z4J_EMBEDDED_SCHEDULER and deploy the standalone scheduler "
            "to run a multi-worker PostgreSQL brain."
        )
        return 1, note
    return workers, None


def resolve_serve_workers_for_settings(
    requested: int | None,
    *,
    settings: Settings,
    cpu_count: int,
) -> tuple[int, str | None]:
    """Resolve workers from the effective settings, not raw environment.

    Keeping this decision in an executable helper lets startup tests pass a
    real ``Settings`` object (including SQLite's registry coercion) without
    driving the rest of the CLI ceremony.
    """

    return resolve_serve_workers(
        requested,
        local_registry=str(settings.registry_backend).lower() == "local",
        cpu_count=cpu_count,
        embedded_scheduler=bool(settings.embedded_scheduler),
    )


def enforce_cli_admin_password_topology(
    password: str | None,
    *,
    workers: int,
    reload: bool,
) -> None:
    """Refuse an in-process bootstrap password for spawned interpreters."""

    if password and (workers > 1 or reload):
        raise SystemExit(
            "z4j: --admin-password requires a single non-reload "
            f"worker, but the resolved topology is workers={workers}"
            f"{', reload=on' if reload else ''}. uvicorn spawns "
            "fresh worker interpreters that never receive the "
            "in-process password, so the admin would not be "
            "provisioned (a setup-token banner would print instead), "
            "and a forked child would expose the cleartext in memory. "
            "Pass --workers=1 without --reload, set the password via "
            "the Z4J_BOOTSTRAP_ADMIN_PASSWORD env var (eagerly popped "
            "by startup.py and inherited safely), or run "
            "bootstrap-admin separately before serving."
        )


def _sqlite_database_path(database_url: str) -> Path | None:
    """Return the local path for a file-backed SQLite URL."""

    from sqlalchemy.engine import make_url

    try:
        url = make_url(database_url)
    except Exception:
        return None
    if not url.drivername.startswith("sqlite"):
        return None
    if not url.database or url.database == ":memory:":
        return None
    return Path(url.database).expanduser().resolve()


def _sqlite_has_bound_audit_key_state(database_path: Path) -> bool:
    """Refuse a replacement key once preparation or activation is durable."""

    import sqlite3

    if not database_path.exists():
        return False
    try:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
            timeout=2,
        )
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name IN ('audit_chain_preparation','audit_chain_state')",
                )
            }
            probes = {
                "audit_chain_preparation": ("SELECT 1 FROM audit_chain_preparation LIMIT 1"),
                "audit_chain_state": "SELECT 1 FROM audit_chain_state LIMIT 1",
            }
            for table, query in probes.items():
                if table in tables and connection.execute(query).fetchone() is not None:
                    return True
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"cannot safely inspect existing SQLite database {database_path}: {exc}",
        ) from exc
    return False


async def _has_boundary_f_audit_authority(session: Any) -> bool:
    """Return whether preparation or active chain authority is durable."""

    from sqlalchemy import inspect, text

    connection = await session.connection()
    tables = await connection.run_sync(
        lambda sync_connection: set(
            inspect(sync_connection).get_table_names(),
        ),
    )
    probes = {
        "audit_chain_preparation": ("SELECT 1 FROM audit_chain_preparation LIMIT 1"),
        "audit_chain_state": "SELECT 1 FROM audit_chain_state LIMIT 1",
    }
    for table, query in probes.items():
        if table not in tables:
            continue
        if (await session.execute(text(query))).first() is not None:
            return True
    return False


def _capture_serve_configuration(*, preliminary: Any | None = None) -> Any:
    """Capture configuration and safely bootstrap packaged SQLite secrets."""

    import secrets as _secrets

    from z4j_brain.configuration import (
        capture_configuration,
        export_snapshot_environment,
        merge_secret_store_snapshot,
        overlay_runtime_environment,
    )
    from z4j_brain.secret_store import read_secret_store, update_secret_store

    home = z4j_home()
    preliminary = preliminary or capture_configuration(
        home=home,
        include_secret_store=False,
    )
    database_url = preliminary.values.get("Z4J_DATABASE_URL")
    if not database_url:
        data_dir = ensure_z4j_home()
        database_path = data_dir / "z4j.db"
        database_url = f"sqlite+aiosqlite:///{database_path}"
        os.environ["Z4J_DATABASE_URL"] = database_url
        os.environ.setdefault("Z4J_REGISTRY_BACKEND", "local")
        print(  # noqa: T201
            f"z4j: using SQLite at {database_path} (set Z4J_DATABASE_URL for Postgres)",
        )
    preliminary = overlay_runtime_environment(preliminary)

    if not database_url.startswith("sqlite"):
        store_values = read_secret_store(home / "secret.env").values if home.exists() else {}
        snapshot = merge_secret_store_snapshot(preliminary, store_values)
        audit_source = snapshot.source_for_env_key("Z4J_AUDIT_CHAIN_SECRET")
        if snapshot.values.get("Z4J_ENVIRONMENT", "dev").lower() != "dev" and audit_source in {
            "default",
            "secret.env",
        }:
            raise RuntimeError(
                "PostgreSQL production requires an explicitly configured "
                "Z4J_AUDIT_CHAIN_SECRET; packaged secret.env bootstrap is "
                "available only for self-contained SQLite",
            )
        export_snapshot_environment(snapshot)
        return snapshot

    data_dir = ensure_z4j_home()
    secret_path = data_dir / "secret.env"
    database_path = _sqlite_database_path(database_url)
    if database_path is None and database_url != "sqlite+aiosqlite:///:memory:":
        raise RuntimeError(
            "cannot prove the packaged SQLite database path; provide all "
            "secrets explicitly or use a normal file-backed SQLite URL",
        )

    store = read_secret_store(secret_path)
    database_exists = database_path is not None and database_path.exists()
    snapshot = merge_secret_store_snapshot(preliminary, store.values)
    required = {
        "Z4J_SECRET": 48,
        "Z4J_SESSION_SECRET": 48,
        "Z4J_METRICS_AUTH_TOKEN": 32,
        "Z4J_AUDIT_CHAIN_SECRET": 48,
    }
    missing = [key for key in required if not snapshot.values.get(key)]
    # Complete external configuration needs no packaged secret store. In
    # particular, a container may have started its database with env secrets
    # and never created secret.env. Missing authority still fails closed.
    if database_exists and store.file_identity is None and missing:
        raise RuntimeError(
            f"existing SQLite database {database_path} has no verified "
            f"{secret_path}; refusing to mint replacement authentication "
            "or audit keys",
        )

    if missing and database_exists:
        non_audit = [key for key in missing if key != "Z4J_AUDIT_CHAIN_SECRET"]
        if non_audit:
            raise RuntimeError(
                "existing SQLite installation is missing persisted authority "
                f"for {', '.join(non_audit)}; refusing to invent replacements",
            )
        if database_path is None or _sqlite_has_bound_audit_key_state(database_path):
            raise RuntimeError(
                "audit preparation/state already exists but the configured "
                "audit key is missing; restore the original key",
            )

    updates = {
        key: _secrets.token_urlsafe(size) for key, size in required.items() if key in missing
    }
    if updates:
        winner = update_secret_store(secret_path, updates)
        snapshot = merge_secret_store_snapshot(preliminary, winner.values)
        for key in updates:
            if snapshot.source_for_env_key(key) == "secret.env" and snapshot.values.get(
                key
            ) != winner.values.get(key):
                raise RuntimeError(
                    f"persisted {key} winner did not become effective",
                )
        print(  # noqa: T201
            "z4j: safely persisted independent packaged secrets: " + ", ".join(sorted(updates)),
        )

    export_snapshot_environment(snapshot)
    return snapshot


def _run_serve(args: argparse.Namespace) -> int:  # noqa: PLR0912, PLR0915  serve flag handling
    """Run uvicorn programmatically.

    We import uvicorn lazily so ``z4j version`` and
    ``z4j migrate`` do not pay the uvicorn import cost.
    """
    import os

    import uvicorn

    # Hard-fail early if any of the dropped 1.4 path-override env vars
    # (Z4J_RUNTIME_DIR, Z4J_BUFFER_DIR, Z4J_BUFFER_PATH) are set.
    # Silent ignore would leave operators thinking they had relocated
    # state when they hadn't, which is a security footgun. The error
    # text directs them at the single Z4J_HOME variable that 1.5
    # consolidated to.
    reject_deprecated_path_env()

    # Z4J_LOG_FORMAT is the unified env var documented for both the
    # brain and the agent. The brain's structlog setup keys off
    # Z4J_LOG_JSON (boolean) for historical reasons; translate here
    # so operators see one consistent variable name. Explicit
    # Z4J_LOG_JSON wins if both are set (less surprising than the
    # other order).
    raw_format = os.environ.get("Z4J_LOG_FORMAT", "").strip().lower()
    if raw_format and "Z4J_LOG_JSON" not in os.environ:
        if raw_format == "json":
            os.environ["Z4J_LOG_JSON"] = "true"
        elif raw_format == "text":
            os.environ["Z4J_LOG_JSON"] = "false"

    # --environment / --env CLI flag wins over Z4J_ENVIRONMENT env var
    # (CLI > env > auto-detect default). We set it BEFORE the rest of
    # the env-var defaulting below so the auto-promote and bind-host
    # logic see the operator's intent. Removing the env var first is
    # the cleanest way to express "the flag is now authoritative" -
    # otherwise os.environ.setdefault would race against an existing
    # setting from the caller's shell.
    if args.environment:
        os.environ["Z4J_ENVIRONMENT"] = args.environment

    # Auto-setup: pass admin credentials so the brain's first-boot
    # hook creates the admin user + default project and skips the
    # setup-URL banner. Helm / compose manifests set these via env
    # vars directly (read in startup.py); the cli flags below set
    # the email via env (non-secret, useful for debugging) but the
    # password lands in a module-level holder so it never appears
    # in ``os.environ``.
    #
    # The prior version set ``Z4J_BOOTSTRAP_ADMIN_PASSWORD`` in
    # ``os.environ``, which
    # made it readable via ``/proc/<pid>/environ`` by the same UID
    # for the lifetime of the process AND inheritable by every
    # subprocess we fork. The module-global holder pattern keeps
    # the password in process memory only.
    if args.admin_email:
        os.environ["Z4J_BOOTSTRAP_ADMIN_EMAIL"] = args.admin_email
    # NOTE (CX-M18): --admin-password handling -- the multi-worker/reload
    # guard AND stashing the cleartext into the in-process holder -- is
    # DEFERRED to after worker-topology resolution below. Guarding here
    # on the raw flag was unsound: `getattr(args, "workers", None) or 1`
    # treats an UNSET --workers as 1 and passes the guard, but Postgres
    # then resolves the same unset value to min(4, cpu). uvicorn SPAWNS
    # fresh worker interpreters for workers>1 (and for --reload), where
    # the module-global holder is empty -- so the requested admin was
    # never provisioned and a setup-token banner printed instead. The
    # real resolved topology is only known after resolve_serve_workers().

    bootstrap_coordinator = contextlib.ExitStack()
    try:
        from z4j_brain.configuration import capture_configuration
        from z4j_brain.management_retirement import (
            assert_no_pending_installation_retirement,
        )
        from z4j_brain.secret_store import (
            audit_bootstrap_coordinator,
            ensure_secret_store_directory,
        )

        ensure_secret_store_directory(z4j_home())
        assert_no_pending_installation_retirement(z4j_home())
        preliminary = capture_configuration(
            home=z4j_home(),
            include_secret_store=False,
        )
        preliminary_database_url = preliminary.values.get("Z4J_DATABASE_URL")
        if not preliminary_database_url or preliminary_database_url.startswith(
            "sqlite",
        ):
            bootstrap_coordinator.enter_context(
                audit_bootstrap_coordinator(
                    ensure_secret_store_directory(z4j_home()),
                ),
            )
        configuration_snapshot = _capture_serve_configuration(
            preliminary=preliminary,
        )
    except Exception as exc:
        bootstrap_coordinator.close()
        print(f"z4j: configuration bootstrap refused: {exc}", file=sys.stderr)  # noqa: T201
        return 2

    # In dev mode the brain's settings validators expect localhost-friendly
    # values for allowed_hosts + a non-https public_url. Set sane defaults
    # if the operator hasn't pinned them. Mirrors the Docker entrypoint.
    if not os.environ.get("Z4J_DATABASE_URL", "").startswith("postgresql"):
        # Auto-promote to production when the operator's already-declared
        # config shape *is* production-shaped. Two signals taken together
        # (added v1.0.14):
        #   1. Z4J_PUBLIC_URL starts with https:// (operator wired TLS)
        #   2. Z4J_ALLOWED_HOSTS is set explicitly (operator has named
        #      the public hostnames)
        # Either alone is ambiguous; both together prove production
        # intent. Honor it instead of silently shipping dev-mode cookies
        # behind their TLS terminator. Operator can still force dev with
        # an explicit Z4J_ENVIRONMENT=dev (env always wins over our
        # defaulting).
        if "Z4J_ENVIRONMENT" not in os.environ:
            pub = os.environ.get("Z4J_PUBLIC_URL", "")
            has_allowed = "Z4J_ALLOWED_HOSTS" in os.environ
            if pub.startswith("https://") and has_allowed:
                os.environ["Z4J_ENVIRONMENT"] = "production"
                print(  # noqa: T201
                    "z4j: auto-promoting Z4J_ENVIRONMENT=production "
                    "(detected https Z4J_PUBLIC_URL + explicit "
                    "Z4J_ALLOWED_HOSTS). Set Z4J_ENVIRONMENT=dev to override.",
                )
            else:
                os.environ["Z4J_ENVIRONMENT"] = "dev"
        # Smart default allow-list: localhost + the machine's own hostname
        # and FQDN. Lets `pip install z4j && z4j serve` on a remote VM
        # work without the operator having to set Z4J_ALLOWED_HOSTS for
        # the hostname they already know they're reaching. Operator can
        # override by setting Z4J_ALLOWED_HOSTS explicitly (env wins),
        # or by adding --allowed-host flags (merged below).
        if "Z4J_ALLOWED_HOSTS" not in os.environ:
            import json as _json
            import socket as _socket

            auto_hosts: list[str] = ["localhost", "127.0.0.1", "[::1]"]

            # 1) Hostname + FQDN. The hostname is what `uname -n` shows;
            #    the FQDN includes the domain (e.g. Tailscale's
            #    `<host>.<tailnet>.ts.net`).
            for fn_name in ("gethostname", "getfqdn"):
                try:
                    h = getattr(_socket, fn_name)()
                    if h and h.lower() not in {x.lower() for x in auto_hosts}:
                        auto_hosts.append(h)
                except Exception:  # noqa: S110  best-effort hostname discovery
                    pass

            # 2) IPv4 addresses bound on the host. Covers the common
            #    homelab/LAN case where the operator reaches the brain
            #    via the server's LAN IP (e.g. 192.168.x.x). Without
            #    this users hit the host-validation 400 even though
            #    they're on the same network.
            #
            #    Two complementary strategies, both stdlib:
            #    a) gethostbyname_ex(hostname) returns every IP the
            #       resolver knows for the hostname. Picks up multiple
            #       interfaces on machines with proper /etc/hosts.
            #    b) UDP-socket trick: open a datagram socket "to" a
            #       non-routable address; no packet ever leaves, but
            #       the OS picks the source IP it WOULD use for that
            #       destination. That's the box's primary outbound
            #       interface IP, even on systems where (a) only
            #       returns 127.0.1.1 (Debian default).
            try:
                _, _, addrs = _socket.gethostbyname_ex(_socket.gethostname())
                for ip in addrs:
                    if ip and ip.lower() not in {x.lower() for x in auto_hosts}:
                        auto_hosts.append(ip)
            except Exception:  # noqa: S110  best-effort resolver IP discovery
                pass
            try:
                with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
                    # 10.255.255.255 is non-routable; connect() on a UDP
                    # socket just picks the source - no datagram is sent.
                    _s.connect(("10.255.255.255", 1))
                    primary_ip = _s.getsockname()[0]
                    if primary_ip and primary_ip not in auto_hosts:
                        auto_hosts.append(primary_ip)
            except Exception:  # noqa: S110  best-effort primary IP discovery
                pass

            # 3) Merge persisted allow-list from `~/.z4j/allowed-hosts`.
            # Operators add custom domains here once via
            # `z4j allowed-hosts add tasks.example.com`; the file is read
            # on every boot. This is the answer to "where do I put my
            # public DNS name so I don't have to pass --allowed-host
            # every time".
            from z4j_brain.allowed_hosts import read_persisted

            for h in read_persisted():
                if h and h.lower() not in {x.lower() for x in auto_hosts}:
                    auto_hosts.append(h)

            os.environ["Z4J_ALLOWED_HOSTS"] = _json.dumps(auto_hosts)

        # SAFE-BY-DEFAULT BIND (added v1.0.14, breaking from 1.0.13):
        # In dev mode, force the bind host to loopback unless the
        # operator explicitly set Z4J_BIND_HOST. Pre-1.0.14 the default
        # was 0.0.0.0 in dev mode, which silently exposed dev-mode
        # cookies (secure=False, no __Host- prefix, no HSTS) to any
        # caller that could reach the port. Combined with the
        # fail-closed gate in _run_serve, the brain now refuses to
        # accept off-loopback connections without explicit production
        # mode (Z4J_ENVIRONMENT=production + https Z4J_PUBLIC_URL +
        # explicit Z4J_ALLOWED_HOSTS).
        if os.environ.get("Z4J_ENVIRONMENT") == "dev" and "Z4J_BIND_HOST" not in os.environ:
            os.environ["Z4J_BIND_HOST"] = "127.0.0.1"

        # PUBLIC_URL AUTO-DERIVATION (added v1.0.14): when the operator
        # hasn't pinned Z4J_PUBLIC_URL, derive it from the actual bind
        # host:port so the first-boot setup banner prints a URL that
        # actually works. Pre-1.0.14 the banner hard-coded
        # http://localhost:7700/setup?token=... regardless of --port,
        # leaving anyone running on a non-default port staring at a
        # 404 from whatever happened to be on :7700 (or a connection
        # refusal). Production mode requires Z4J_PUBLIC_URL to be
        # set explicitly (see Settings._enforce_security_invariants),
        # so this fires only in dev mode where the default is
        # operator-friendly rather than security-load-bearing.
        if os.environ.get("Z4J_ENVIRONMENT") == "dev" and "Z4J_PUBLIC_URL" not in os.environ:
            # Mirror the precedence uvicorn will use:
            # --host > Z4J_BIND_HOST > settings default.
            # --port > Z4J_BIND_PORT > settings default (7700).
            _bh = args.host or os.environ.get("Z4J_BIND_HOST", "127.0.0.1")
            _bp = args.port or int(os.environ.get("Z4J_BIND_PORT", "7700"))
            # Browsers prefer "localhost" over "127.0.0.1" / "::1" in
            # display (it survives clipboard better and works
            # cross-IPv4/IPv6). For non-loopback binds we keep the
            # actual host so the URL still resolves; non-loopback in
            # dev mode is fail-closed anyway, so this branch is mostly
            # belt-and-suspenders.
            _display = (
                "localhost" if _bh in ("127.0.0.1", "localhost", "[::1]", "::1", "0.0.0.0") else _bh  # noqa: S104  membership check, not a bind
            )
            os.environ["Z4J_PUBLIC_URL"] = f"http://{_display}:{_bp}"

    # --debug-host-errors opt-in: enables verbose host-rejection response
    # bodies, but ONLY in dev mode. Protects against the common footgun
    # where a homelab operator runs the pip/SQLite path (dev mode by
    # default) behind a public reverse proxy - they'd otherwise get
    # internal-hostname leakage on every crawler hit.
    if getattr(args, "debug_host_errors", False):
        if os.environ.get("Z4J_ENVIRONMENT", "").lower() != "dev":
            bootstrap_coordinator.close()
            print(  # noqa: T201
                "z4j: --debug-host-errors refused outside dev mode. "
                "This flag enables verbose 400 responses that leak internal "
                "hostnames; unsafe when the brain is reachable from any "
                "source other than localhost.",
            )
            return 1
        os.environ["Z4J_DEBUG_HOST_ERRORS"] = "1"
        print(  # noqa: T201
            "z4j: WARNING - --debug-host-errors is ON. Rejected "
            "requests will return internal hostnames in the response body. "
            "For local development only.",
        )

    # Merge any --allowed-host CLI flags onto whatever env / auto-detect
    # produced. The CLI flag is a repeatable convenience for ad-hoc hosts
    # ("this VM's DNS name", "an internal load balancer", ...) - it never
    # replaces the env, only extends it.
    if getattr(args, "allowed_host", None):
        import json as _json

        current = os.environ.get("Z4J_ALLOWED_HOSTS", "[]").strip()
        try:
            existing = _json.loads(current) if current else []
            if not isinstance(existing, list):
                existing = []
        except Exception:
            # Tolerate a comma-separated string in the env var - some
            # operators reach for the shell-native form.
            existing = [s.strip() for s in current.split(",") if s.strip()]
        merged = list(existing)
        for h in args.allowed_host:
            if h and h not in merged:
                merged.append(h)
        os.environ["Z4J_ALLOWED_HOSTS"] = _json.dumps(merged)

    from z4j_brain.configuration import (
        export_snapshot_environment,
        overlay_runtime_environment,
    )

    configuration_snapshot = overlay_runtime_environment(configuration_snapshot)
    export_snapshot_environment(configuration_snapshot)

    # Auto-migrate before serve. The bare-metal quickstart used to
    # leave migrations to a manual ``z4j migrate upgrade head``
    # step - easy to forget, and the first request would then blow
    # up with an opaque "relation does not exist" error.
    # Running ``alembic upgrade head`` here is idempotent (no-op
    # when already at head) and fails fast with a clear error if
    # the DB is unreachable. Can be disabled for managed-migration
    # deployments by setting ``Z4J_AUTO_MIGRATE=false`` (Helm /
    # GitOps workflows that want migrations as a separate Job).
    try:
        if os.environ.get("Z4J_AUTO_MIGRATE", "true").lower() != "false":
            try:
                _auto_migrate()
            except _UnknownDBRevisionError as exc:
                # v1.0.19 compat-fix: the DB's ``alembic_version`` row
                # references a revision file this code's package
                # doesn't ship. That happens when an operator
                # downgrades z4j-brain across a migration boundary
                # (DB at head N, code at head N-2). Pre-1.0.19 this
                # was a hard SystemExit which caused systemd flap
                # loops. From 1.0.19 onward we WARN and continue
                # boot - the brain serves the subset of features
                # this code understands; newer migrations' tables
                # are simply unused (workers + repos use the
                # ``_has_table`` defensive pattern). See
                # docs/MIGRATIONS.md for the bidirectional-compat
                # contract. Operators who actually want to clean up
                # the DB to match this code can run
                # ``z4j migrate sync --allow-future-schema``.
                print(  # noqa: T201
                    f"z4j: DB is at a NEWER alembic head "
                    f"({exc.db_head!r}) than this code knows about. "
                    "Continuing boot; this code will serve the subset "
                    "of features it understands. Run `z4j "
                    "migrate sync --allow-future-schema` to roll the "
                    "DB back to this code's head (DESTRUCTIVE - drops "
                    "tables the newer code added).",
                )
            except SystemExit as exc:
                # alembic_main exits on other errors (e.g. DB
                # unreachable, malformed revision file). Translate to
                # a clear message + non-zero return so the operator
                # doesn't have to read a cryptic argparse trace.
                print(  # noqa: T201
                    f"z4j: auto-migrate failed (code {exc.code}). "
                    "Set Z4J_AUTO_MIGRATE=false and run `z4j "
                    "migrate upgrade head` manually if you are managing "
                    "migrations separately.",
                )
                return 1
    finally:
        bootstrap_coordinator.close()

    from z4j_brain.configuration import settings_from_snapshot

    settings = settings_from_snapshot(configuration_snapshot)

    # FAIL-CLOSED dev+public-bind gate (added v1.0.14, breaking from
    # 1.0.13). Refuse to start when the brain is in dev mode AND
    # binding to anything other than loopback. Dev mode relaxes:
    #   - cookies: secure=False, no __Host- prefix
    #   - HSTS header: not sent
    #   - host validation: allowed_hosts can be empty
    #   - public_url: can be plain http://
    # All four are catastrophic if the brain is reachable from the
    # internet, a LAN, Tailscale, or anywhere off-loopback. The
    # Local-SQLite auto-detection above flips an UNSET environment to
    # production when https Z4J_PUBLIC_URL + explicit Z4J_ALLOWED_HOSTS
    # declare production intent. It never overrides explicit dev mode,
    # so this gate also fires when production-shaped values accompany an
    # explicit Z4J_ENVIRONMENT=dev on a non-loopback bind.
    bind = args.host or settings.bind_host
    _loopback = ("127.0.0.1", "localhost", "[::1]", "::1")
    if settings.environment == "dev" and bind not in _loopback:
        print(  # noqa: T201
            "z4j: REFUSING TO START.\n"
            "\n"
            f"  Z4J_ENVIRONMENT=dev + bind {bind!r} is unsafe:\n"
            "  in dev mode the brain skips Secure-cookie / HSTS /\n"
            "  host-header validation, so binding to a non-loopback\n"
            "  address would expose those weakened defaults to\n"
            "  whatever can reach this socket.\n"
            "\n"
            "  Pick one of:\n"
            "\n"
            "  1. Localhost-only dev (the default for ad-hoc work):\n"
            "       z4j serve --host 127.0.0.1\n"
            "\n"
            "  2. Docker / k8s dev stack on an internal network:\n"
            "       Z4J_ENVIRONMENT=production \\\n"
            "       Z4J_PUBLIC_URL=http://localhost:7700 \\\n"
            '       Z4J_ALLOWED_HOSTS=\'["localhost","127.0.0.1"]\' \\\n'
            "       Z4J_ALLOW_HTTP_PUBLIC_URL=true \\\n"
            "       z4j serve --host 0.0.0.0\n"
            "     (Z4J_ALLOW_HTTP_PUBLIC_URL=true is the explicit\n"
            "     opt-in for production-shaped config without TLS;\n"
            "     only safe on a trusted internal network.)\n"
            "\n"
            "  3. Public production with TLS:\n"
            "       Z4J_ENVIRONMENT=production \\\n"
            "       Z4J_PUBLIC_URL=https://tasks.example.com \\\n"
            "       Z4J_ALLOWED_HOSTS='[\"tasks.example.com\"]' \\\n"
            "       z4j serve --host 0.0.0.0\n"
            "\n"
            "  Because Z4J_ENVIRONMENT is explicitly dev here, those\n"
            "  values will not auto-promote it. Set production as above,\n"
            "  or unset Z4J_ENVIRONMENT on the local SQLite serve path\n"
            "  to allow production-shaped auto-detection.\n"
            "\n"
            "  See: https://z4j.dev/operations/dev-vs-production",
            file=sys.stderr,
        )
        return 2

    # Tell the operator exactly which Host headers will be accepted.
    # Without this banner the only way to learn what's whitelisted is to
    # hit the brain with a wrong Host and read the (now improved) 400
    # response, which assumes the operator can reach the brain at all.
    if settings.allowed_hosts:
        from z4j_brain.allowed_hosts import get_path as _ah_path
        from z4j_brain.allowed_hosts import read_persisted as _ah_read

        bind = args.host or settings.bind_host
        port = args.port or settings.bind_port
        joined = ", ".join(settings.allowed_hosts)
        print(  # noqa: T201
            f"z4j: serving on {bind}:{port}, accepting Host headers: {joined}",
        )
        persisted = _ah_read()
        if persisted:
            print(  # noqa: T201
                f"z4j: persisted from {_ah_path()}: {', '.join(persisted)}",
            )
        print(  # noqa: T201
            "z4j: to add more, run `z4j allowed-hosts add <name>` (persists across restarts).",
        )

    # Default workers count is now min(4, cpu) instead
    # of the pre-1.5 hardcoded 1. Single uvicorn worker was unable to
    # dispatch WebSocket PONGs within the 10s ping_timeout while
    # ingesting agent event_batches under load, causing agent flap.
    # Multi-worker spreads connection handling across processes; each
    # process has its own asyncio event loop. The min(4, cpu) cap
    # mirrors the gunicorn convention (2 * cpu + 1 is the canonical
    # web-tier shape; 4 is sufficient for the brain's mostly-async
    # workload without needing per-worker DB pool tuning).
    try:
        cpu = os.cpu_count() or 2
    except Exception:
        cpu = 2
    # H2: detect the local (in-process) agent registry from the RESOLVED
    # settings, not the raw env var. os.environ["Z4J_REGISTRY_BACKEND"]
    # is only set on the auto-SQLite path (when Z4J_DATABASE_URL was
    # unset); an operator who points Z4J_DATABASE_URL at an explicit
    # sqlite:// URL -- or sets registry_backend via ~/.z4j/config.env or
    # ./.env, which Settings reads but os.environ never sees -- still
    # gets registry_backend coerced to "local" by Settings, yet the
    # env-var check missed it and spawned min(4, cpu) workers over one
    # in-memory registry + one SQLite file (the split-brain/contention/
    # bootstrap-race the single-worker guard exists to prevent).
    local_registry = str(settings.registry_backend).lower() == "local"
    workers_resolved, worker_note = resolve_serve_workers_for_settings(
        args.workers,
        settings=settings,
        cpu_count=cpu,
    )
    if worker_note:
        print(worker_note)  # noqa: T201

    # CX-M18: gate --admin-password now that the REAL worker topology is
    # known. uvicorn spawns fresh worker interpreters for workers>1 and
    # for --reload, where the in-process bootstrap-password holder is not
    # inherited (the admin is never provisioned and a setup-token banner
    # prints instead); a forked child would also expose the cleartext in
    # its memory. Only a single, non-reload, in-process worker can carry
    # it safely.
    enforce_cli_admin_password_topology(
        args.admin_password,
        workers=workers_resolved,
        reload=bool(args.reload),
    )
    if args.admin_password:
        from z4j_brain import startup as _startup

        _startup.set_cli_bootstrap_password(args.admin_password)

    if workers_resolved == 1 and not local_registry:
        # Operator explicitly chose --workers=1, OR the host has only
        # 1 CPU. Either way emit an INFO so the trade-off is visible
        # in startup logs - operators investigating agent flap can
        # then connect the dots without grepping the source. (Skipped
        # for the SQLite/local-registry case above, which prints its
        # own reason and where --workers>1 is simply not an option.)
        print(  # noqa: T201
            "z4j: starting with --workers=1. This works fine for "
            "<=5 agents but agent disconnects can be triggered by "
            "event-loop contention at higher counts. Pass "
            "--workers=4 (or --workers=$(nproc)) for production.",
        )

    # With multiple worker processes, per-process Prometheus
    # registries shard the operational counters (a load-balanced
    # scrape sees one worker's view). Flip on prometheus_client
    # multiprocess mode BEFORE uvicorn spawns the workers so the env
    # var is inherited by every fresh worker interpreter; see the
    # helper's docstring for the import-order reasoning and the
    # worker-death cleanup tradeoff.
    _setup_multiprocess_metrics_env(
        workers_resolved,
        reload_mode=bool(args.reload),
    )

    uvicorn.run(
        "z4j_brain.main:create_app",
        host=args.host or settings.bind_host,
        port=args.port or settings.bind_port,
        factory=True,
        workers=workers_resolved,
        reload=args.reload,
        log_config=None,  # we configure structlog ourselves
        # Drop the ``Server: uvicorn`` header. Cosmetic but removes
        # a free piece of fingerprint data (uvicorn version implies
        # cpython version implies known CVE applicability) that an
        # attacker would otherwise get before sending a single
        # payload.
        server_header=False,
        # Widen the brain-side WebSocket PING/PONG cadence so the
        # outbound PING gets plenty of headroom when ingest is
        # bursty. uvicorn's defaults (20s/20s) are too tight under
        # sustained 100 task/s x 10 agent fanout: the underlying
        # ``websockets`` library serializes PING with application
        # sends on the same connection task, and a busy ingest
        # path will starve PING dispatch within the default
        # window. 60s/60s tolerates ~2 minutes of starvation
        # before close. Mirror the agent-side bumps in
        # z4j-bare/transport/websocket.py.
        ws_ping_interval=60.0,
        ws_ping_timeout=60.0,
    )
    return 0


def _find_alembic_config_path() -> Path | None:
    """Resolve the one bundled/source Alembic configuration."""

    candidates: list[Path] = []
    env_path = os.environ.get("Z4J_ALEMBIC_INI")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path.cwd() / "alembic.ini")
    candidates.append(Path(__file__).resolve().parent / "alembic.ini")
    candidates.append(
        Path(__file__).resolve().parent.parent.parent / "alembic.ini",
    )
    return next((path for path in candidates if path.exists()), None)


def _run_migrate(args: argparse.Namespace) -> int:
    """Delegate to alembic with the brain's bundled config.

    Resolution order for ``alembic.ini``:

    1. ``$Z4J_ALEMBIC_INI`` if set (used by the docker image to point
       at ``/app/alembic.ini``).
    2. ``./alembic.ini`` in the current working directory (the
       contributor flow when running from the source tree).
    3. The source-tree location next to ``backend/src/`` (legacy
       fallback for editable installs).
    """
    from alembic.config import main as alembic_main

    # Bootstrap env (DB URL + secrets) so alembic's env.py can
    # instantiate Settings(). Fresh installs don't have these yet.
    _bootstrap_env_for_management_commands()

    if args.action == "prepare-runtime-rollback":
        return _run_migrate_prepare_runtime_rollback(args.rest)

    config_path = _find_alembic_config_path()
    if config_path is None:
        print(  # noqa: T201
            "z4j: alembic.ini not found; set Z4J_ALEMBIC_INI or install "
            "the bundled migration package",
            file=sys.stderr,
        )
        return 2

    if args.action == "sync":
        return _run_migrate_sync(
            config_path,
            allow_future=getattr(args, "allow_future_schema", False),
            confirm_destructive=getattr(
                args,
                "i_know_this_can_corrupt_data",
                False,
            ),
        )

    cli_args = ["-c", str(config_path), args.action, *args.rest]
    alembic_main(argv=cli_args, prog="z4j migrate")
    return 0


def _run_migrate_prepare_runtime_rollback(  # noqa: PLR0911, PLR0915
    rest: Sequence[str],
) -> int:
    """Run the two-phase, image-bound 1.9 -> 1.8.2 preparation ceremony."""

    import asyncio
    import hmac
    import json
    import re as _re
    import uuid
    from datetime import UTC, datetime

    from sqlalchemy import text

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.runtime_rollback import (
        ROLLBACK_COSIGN_PATH,
        ROLLBACK_TARGET,
        ROLLBACK_TARGET_RELEASE,
        SEALED_TARGET_CADENCE_FINGERPRINT,
        RuntimeRollbackRefused,
        build_preview,
        challenge_sha256,
        durable_evidence_sha256,
        load_finalized_production_carrier,
        verify_durable_rollback_evidence,
    )
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories.audit_log import AuditLogRepository
    from z4j_brain.persistence.repositories.schedule_control import (
        ScheduleControlRepository,
    )
    from z4j_brain.schema_transition import RELEASE_MIGRATION_HEAD
    from z4j_brain.settings import Settings

    ceremony = argparse.ArgumentParser(
        prog="z4j migrate prepare-runtime-rollback",
        description=(
            "preview or apply the sealed 1.9.0 -> 1.8.2/Python-3.14.7 schedule preparation"
        ),
    )
    ceremony.add_argument("--target", required=True)
    ceremony.add_argument("--target-image", required=True)
    ceremony.add_argument(
        "--candidate-authority-root",
        required=True,
        help=(
            "read-only production-finalization-attestation-1.9.0 directory; "
            "must contain exactly the signed receipt, bundle, attestation "
            "transcript, and staging index"
        ),
    )
    ceremony.add_argument(
        "--rollback-evidence-root",
        required=True,
        help=(
            "read-only portable OCI evidence graph containing exactly "
            "qualification, finalization, one promotion-or-recovery terminal, "
            "and release-index stage directories"
        ),
    )
    ceremony.add_argument(
        "--stopped-executors-challenge",
        default=None,
        help=(
            "exact challenge emitted by preview; supplying it explicitly "
            "attests that every Brain and scheduler executor is stopped"
        ),
    )
    options = ceremony.parse_args(list(rest))
    if options.target != ROLLBACK_TARGET:
        print(  # noqa: T201
            "z4j migrate prepare-runtime-rollback: unsupported target; "
            f"expected {ROLLBACK_TARGET!r}",
            file=sys.stderr,
        )
        return 2

    source_revision = os.environ.get("Z4J_RELEASE_SOURCE_REVISION", "").strip()
    source_image = os.environ.get("Z4J_RELEASE_IMAGE", "").strip()
    if _re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        print(  # noqa: T201
            "z4j migrate prepare-runtime-rollback: "
            "Z4J_RELEASE_SOURCE_REVISION must bind the candidate's 40-hex "
            "Git revision",
            file=sys.stderr,
        )
        return 2
    if not source_image:
        print(  # noqa: T201
            "z4j migrate prepare-runtime-rollback: Z4J_RELEASE_IMAGE must "
            "bind the candidate image by OCI sha256 digest",
            file=sys.stderr,
        )
        return 2
    try:
        source_authority = load_finalized_production_carrier(
            Path(options.candidate_authority_root),
            asserted_revision=source_revision,
            asserted_image=source_image,
        )
    except RuntimeRollbackRefused as exc:
        print(  # noqa: T201
            "z4j migrate prepare-runtime-rollback: REFUSED: "
            f"production carrier proof failed: {exc}",
            file=sys.stderr,
        )
        return 1
    try:
        durable_evidence = verify_durable_rollback_evidence(
            Path(options.rollback_evidence_root),
            cosign_path=ROLLBACK_COSIGN_PATH,
        )
    except RuntimeRollbackRefused as exc:
        print(  # noqa: T201
            "z4j migrate prepare-runtime-rollback: REFUSED: "
            f"durable rollback evidence failed: {exc}",
            file=sys.stderr,
        )
        return 1
    source_revision = str(source_authority["source_revision"])
    source_image = str(source_authority["source_image"])
    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as exc:
        print(  # noqa: T201
            f"z4j migrate prepare-runtime-rollback: failed to load settings: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    async def _run() -> int:
        engine = create_engine_from_settings(settings)
        database = DatabaseManager(engine)
        try:
            async with database.session(write=True) as session:
                database_head = (
                    await session.execute(
                        text("SELECT version_num FROM alembic_version"),
                    )
                ).scalar_one()
                if database_head != RELEASE_MIGRATION_HEAD:
                    raise RuntimeRollbackRefused(
                        "database must be at exact release head "
                        f"{RELEASE_MIGRATION_HEAD!r}; found {database_head!r}",
                    )
                repository = ScheduleControlRepository(session)
                plan = await repository.plan_runtime_rollback(lock_rows=True)
                preview = build_preview(
                    source_authority=source_authority,
                    durable_evidence=durable_evidence,
                    database_head=database_head,
                    target_image=options.target_image,
                    row_set_digest=plan.row_set_digest,
                    reserved_schedule_count=len(plan.rows),
                    external_schedule_count=plan.external_schedule_count,
                )
                supplied_challenge = options.stopped_executors_challenge
                if supplied_challenge is None:
                    await session.rollback()
                    print(json.dumps(preview, indent=2, sort_keys=True))  # noqa: T201
                    return 0
                expected_challenge = str(preview["stopped_executors_challenge"])
                if not hmac.compare_digest(supplied_challenge, expected_challenge):
                    raise RuntimeRollbackRefused(
                        "stopped-executors challenge does not match the current "
                        "database/image/runtime preview",
                    )
                challenge_digest = challenge_sha256(supplied_challenge)
                operation_id = uuid.UUID(hex=str(preview["operation_id"]))
                target_authority = preview["target_image_authority"]
                preparation = await repository.prepare_runtime_rollback(
                    target_release=ROLLBACK_TARGET_RELEASE,
                    target_image=options.target_image,
                    operation_id=operation_id,
                    expected_row_set_digest=plan.row_set_digest,
                    quiescence_challenge_sha256=challenge_digest,
                    target_durable_evidence_sha256=durable_evidence_sha256(
                        durable_evidence,
                    ),
                    target_release_evidence_index=durable_evidence["release_index"],
                    target_evidence_terminal_stage=str(
                        durable_evidence["terminal_stage"],
                    ),
                    occurred_at=datetime.now(UTC),
                )
                audit_metadata = {
                    "operation_id": str(operation_id),
                    "candidate_source_revision": source_revision,
                    "candidate_image": source_image,
                    "candidate_production_authority": source_authority,
                    "candidate_production_authority_sha256": source_authority["authority_sha256"],
                    "target_release": ROLLBACK_TARGET_RELEASE,
                    "target_image": options.target_image,
                    "target_cadence_runtime_fingerprint": (SEALED_TARGET_CADENCE_FINGERPRINT),
                    "target_image_manifest_sha256": target_authority["manifest_sha256"],
                    "target_image_platforms": target_authority["platforms"],
                    "target_image_release_receipt_sha256": target_authority[
                        "release_receipt_sha256"
                    ],
                    "target_durable_evidence": durable_evidence,
                    "target_durable_evidence_sha256": durable_evidence_sha256(
                        durable_evidence,
                    ),
                    "target_release_evidence_index": durable_evidence["release_index"],
                    "target_evidence_terminal_stage": durable_evidence["terminal_stage"],
                    "changed_count": preparation.changed_count,
                    "noop_count": preparation.noop_count,
                    "block_count": 0,
                    "external_schedule_count": (preparation.external_schedule_count),
                    "schedule_revision_watermark": (preparation.schedule_revision_watermark),
                    "change_log_pruned_through": preparation.change_log_pruned_through,
                    "prepared_schedule_ids": sorted(
                        str(row["schedule_id"]) for row in preparation.rows if row["changed"]
                    ),
                    "noop_schedule_ids": sorted(
                        str(row["schedule_id"]) for row in preparation.rows if not row["changed"]
                    ),
                    "schedule_revisions": {
                        str(row["schedule_id"]): (row["new_revision"] or row["schedule_revision"])
                        for row in preparation.rows
                    },
                    "row_set_digest": preparation.row_set_digest,
                    "quiescence_assertion": ("all Brain and scheduler executors are stopped"),
                    "quiescence_challenge_sha256": challenge_digest,
                    "invoked_via": "cli",
                }
                await AuditService(settings).record(
                    AuditLogRepository(session),
                    action="system.prepare_runtime_rollback",
                    target_type="runtime_rollback",
                    target_id=str(operation_id),
                    result="success",
                    outcome="allow",
                    metadata=audit_metadata,
                )
                receipt = {
                    "format": "z4j-runtime-rollback-preparation-receipt-v1",
                    "preview": preview,
                    "operation_id": str(operation_id),
                    "changed_count": preparation.changed_count,
                    "noop_count": preparation.noop_count,
                    "external_schedule_count": (preparation.external_schedule_count),
                    "schedule_revision_watermark": (preparation.schedule_revision_watermark),
                    "change_log_pruned_through": preparation.change_log_pruned_through,
                    "revisions": [
                        {"schedule_id": str(schedule_id), "revision": revision}
                        for schedule_id, revision in preparation.revisions
                    ],
                    "rows": list(preparation.rows),
                    "audit": audit_metadata,
                }
                await session.commit()
                print(json.dumps(receipt, indent=2, sort_keys=True))  # noqa: T201
                return 0
        finally:
            await database.dispose()

    try:
        return asyncio.run(_run())
    except RuntimeRollbackRefused as exc:
        print(  # noqa: T201
            f"z4j migrate prepare-runtime-rollback: REFUSED: {exc}",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(  # noqa: T201
            "z4j migrate prepare-runtime-rollback: failed before commit: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2


def _run_migrate_sync(  # noqa: PLR0915  one destructive command boundary
    config_path: Path,
    *,
    allow_future: bool,
    confirm_destructive: bool,
) -> int:
    """Operator escape hatch: align the DB to this code's head.

    Three modes:

    - **DB head == code head**: no-op, prints a status line.
    - **DB head < code head**: equivalent to ``migrate upgrade head``.
      Idempotent.
    - **DB head > code head** (downgrade-skew): refuses unless both
      ``--allow-future-schema`` AND
      ``--i-know-this-can-corrupt-data`` are passed. With both,
      stamps the DB ``alembic_version`` row back to this code's
      head and drops identifier-safe tables the newer migrations
      added. It does not remove newer columns from known tables, so
      this is not a complete reverse migration. DESTRUCTIVE - rows in
      dropped tables are lost forever.

    Added v1.0.19 so operators have a documented escape hatch
    instead of editing ``alembic_version`` with sqlite3.
    """
    from alembic.config import Config
    from alembic.config import main as alembic_main
    from alembic.script import ScriptDirectory

    cfg = Config(str(config_path))
    script = ScriptDirectory.from_config(cfg)
    code_head = script.get_current_head()

    db_head = _detect_unknown_db_head(config_path)
    if db_head is None:
        # DB head IS known to this code's scripts. Either matches
        # head or is older - just upgrade-to-head (idempotent).
        print(  # noqa: T201
            f"z4j migrate sync: DB head is known; running "
            f"`alembic upgrade head` (target={code_head!r}).",
        )
        alembic_main(
            argv=["-c", str(config_path), "upgrade", "head"],
            prog="z4j migrate sync",
        )
        return 0

    # DB has a future revision. Refuse without explicit consent.
    print(  # noqa: T201
        f"z4j migrate sync: DB is at FUTURE revision {db_head!r} "
        f"that this code's migrations don't ship (code head: "
        f"{code_head!r}).",
        file=sys.stderr,
    )
    if not (allow_future and confirm_destructive):
        print(  # noqa: T201
            "z4j migrate sync: refusing to proceed. To stamp "
            "the DB back to this code's head AND drop unknown tables "
            "the newer code added (newer columns on known tables remain), "
            "re-run with both:\n"
            "    --allow-future-schema\n"
            "    --i-know-this-can-corrupt-data\n"
            "Recommended alternative: install z4j at the "
            "version that matches your DB head and continue.",
            file=sys.stderr,
        )
        return 1

    try:
        protected_tables = _destructive_sync_protected_tables()
    except Exception as exc:
        print(  # noqa: T201
            "z4j migrate sync: refusing destructive sync because the "
            f"authenticated-transition fence could not be proved: {exc}",
            file=sys.stderr,
        )
        return 1
    if protected_tables:
        print(  # noqa: T201
            "z4j migrate sync: refusing destructive sync because the "
            "authenticated 1.8 transition exists "
            f"({', '.join(protected_tables)}). Provision a matching/new "
            "database or use an authorized restore; do not stamp or drop "
            "this installation.",
            file=sys.stderr,
        )
        return 1

    # Operator confirmed: stamp + drop unknown tables. This deliberately does
    # not attempt to infer or remove columns that newer migrations may have
    # added to tables this code still knows.
    print(  # noqa: T201
        f"z4j migrate sync: STAMPING DB back to {code_head!r} "
        f"and dropping unknown tables (DESTRUCTIVE).",
    )
    # Step 1: stamp ``alembic_version`` to the code's head. This
    # makes alembic stop trying to find the future revision.
    alembic_main(
        argv=["-c", str(config_path), "stamp", code_head or "head"],
        prog="z4j migrate sync (stamp)",
    )
    # Step 2: drop tables that this code's metadata doesn't define
    # but exist in the DB. We compare against the SQLAlchemy
    # ``Base.metadata`` to find what's "extra" beyond this code's
    # known shape.
    from sqlalchemy import create_engine, inspect, text

    from z4j_brain.persistence import models  # noqa: F401
    from z4j_brain.persistence.base import Base
    from z4j_brain.schema_transition import SCHEMA_TRANSITION_ADVISORY_LOCK_KEY

    db_url = os.environ.get("Z4J_DATABASE_URL")
    if db_url:
        sync_url = db_url.replace("+asyncpg", "").replace("+aiosqlite", "")
        engine = create_engine(sync_url, future=True)
        try:
            with engine.connect() as conn:
                if conn.dialect.name == "sqlite":
                    conn.exec_driver_sql("BEGIN EXCLUSIVE")
                elif conn.dialect.name == "postgresql":
                    conn.execute(
                        text("SELECT pg_advisory_xact_lock(:lock_id)"),
                        {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
                    )
                inspector = inspect(conn)
                db_tables = set(inspector.get_table_names())
                known_tables = set(Base.metadata.tables.keys()) | {
                    "alembic_version",
                }
                extra_tables = db_tables - known_tables
                # Defensively validate the table identifier before f-string
                # interpolation. Today ``db_tables`` comes from
                # ``inspect(engine).get_table_names()`` and is therefore
                # operator-controlled, but a future code path that
                # widens the source could introduce SQL-injection if
                # this guard is missing.
                import re as _re

                _ident_re = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
                for tbl in sorted(extra_tables):
                    if not _ident_re.fullmatch(tbl):
                        print(  # noqa: T201
                            f"  refusing to drop table with unsafe identifier: {tbl!r}",
                        )
                        continue
                    print(  # noqa: T201
                        f"  dropping unknown table: {tbl}",
                    )
                    # Use IF EXISTS for safety. SQLite + Postgres
                    # both support this.
                    conn.execute(
                        text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                            f'DROP TABLE IF EXISTS "{tbl}"',
                        ),
                    )
                conn.commit()
        finally:
            engine.dispose()
    print(  # noqa: T201
        "z4j migrate sync: done. Restart the brain.",
    )
    return 0


def _destructive_sync_protected_tables() -> tuple[str, ...]:
    """Fence authenticated/prepared 1.8 databases before any destructive sync."""

    from sqlalchemy import create_engine, inspect, text

    from z4j_brain.schema_transition import SCHEMA_TRANSITION_ADVISORY_LOCK_KEY

    db_url = os.environ.get("Z4J_DATABASE_URL")
    if not db_url:
        raise RuntimeError("Z4J_DATABASE_URL is not configured")
    sync_url = db_url.replace("+asyncpg", "").replace("+aiosqlite", "")
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as connection:
            if connection.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN EXCLUSIVE")
            elif connection.dialect.name == "postgresql":
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_id)"),
                    {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
                )
            tables = set(inspect(connection).get_table_names())
            return tuple(
                sorted(
                    tables
                    & {
                        "audit_chain_preparation",
                        "audit_chain_state",
                    },
                ),
            )
    finally:
        engine.dispose()


class _UnknownDBRevisionError(RuntimeError):
    """Raised by :func:`_auto_migrate` when the DB's
    ``alembic_version`` references a revision this code's package
    doesn't ship (typical of a brain downgrade across a migration
    boundary). v1.0.19 introduced this as a distinct signal so
    the serve caller can warn-and-continue instead of flap-looping.

    Attributes:
        db_head: The unknown revision id present in the DB.
    """

    def __init__(self, db_head: str) -> None:
        super().__init__(
            f"DB alembic_version={db_head!r} not present in this code's migration scripts",
        )
        self.db_head = db_head


def _auto_migrate(
    *,
    retirement_context: dict[str, Any] | None = None,
) -> None:
    """Run ``alembic upgrade head`` against the configured DB.

    Called by :func:`_run_serve` on bare-metal starts so the
    quickstart is one-command: ``z4j serve`` → working
    brain. Idempotent; a no-op when the DB is already at head.

    Raises :class:`_UnknownDBRevisionError` when the DB references
    an alembic revision this code doesn't ship (downgrade-skew).
    Raises :class:`SystemExit` on any other alembic failure
    (DB unreachable, malformed revision, etc.).
    """
    import os

    from alembic import command as alembic_command
    from alembic.config import Config
    from alembic.config import main as alembic_main

    candidates: list[Path] = []
    env_path = os.environ.get("Z4J_ALEMBIC_INI")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path.cwd() / "alembic.ini")
    # pip-install path: alembic.ini is bundled inside the installed
    # package right next to cli.py. This is THE case we care about
    # for ``pip install z4j && z4j serve``.
    candidates.append(Path(__file__).resolve().parent / "alembic.ini")
    # Editable / source-tree fallback: when developing inside the
    # monorepo the ini lives at packages/z4j-brain/backend/alembic.ini
    # i.e. three parents up from this file.
    candidates.append(
        Path(__file__).resolve().parent.parent.parent / "alembic.ini",
    )
    config_path = next((p for p in candidates if p.exists()), None)
    if config_path is None:
        print(  # noqa: T201
            "z4j: auto-migrate failed closed (alembic.ini not found); "
            "set Z4J_ALEMBIC_INI to a readable migration config or install "
            "a complete z4j package. To manage migrations separately, set "
            "Z4J_AUTO_MIGRATE=false explicitly.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    # v1.0.19: pre-flight the DB head against the code's known
    # revisions so we can convert "unknown revision" into a clean
    # _UnknownDBRevisionError instead of letting alembic exit
    # cryptically. Caller (the serve handler) then warn-and-
    # continues. If the pre-flight itself fails (DB unreachable,
    # alembic_version table missing on first boot, etc.) we let
    # alembic's normal path handle it - the upgrade-head call
    # below will surface the same error consistently.
    try:
        unknown = _detect_unknown_db_head(config_path)
    except Exception:
        # Pre-flight is best-effort. Any failure here just falls
        # through to the regular alembic path.
        unknown = None
    if unknown is not None:
        raise _UnknownDBRevisionError(unknown)
    if retirement_context is None:
        alembic_main(
            argv=["-c", str(config_path), "upgrade", "head"],
            prog="z4j migrate (auto)",
        )
    else:
        config = Config(str(config_path))
        config.attributes["z4j_installation_retirement"] = dict(
            retirement_context,
        )
        alembic_command.upgrade(config, "head")
    database_url = os.environ.get("Z4J_DATABASE_URL", "")
    database_path = _sqlite_database_path(database_url)
    if (
        os.name == "posix"
        and database_path is not None
        and database_path == z4j_home() / "z4j.db"
        and database_path.exists()
    ):
        database_path.chmod(0o600)


def _detect_unknown_db_head(config_path: Path) -> str | None:
    """Return the DB's alembic head iff that head is unknown to
    the code's migration scripts. Otherwise return None.

    Used by :func:`_auto_migrate` to detect downgrade-skew
    (DB at head N, code only ships up to head N-K) and convert it
    into a clean :class:`_UnknownDBRevisionError` rather than the
    cryptic ``alembic exit code -1`` flap loop pre-1.0.19
    operators saw.

    Best-effort: if the DB has no ``alembic_version`` table yet
    (fresh install), or the lookup raises for any other reason,
    returns None and lets the regular alembic upgrade run.
    """
    # The DB url comes from the env, which alembic.ini's
    # sqlalchemy.url placeholder reads via env.py. Without it we
    # can't introspect anything, so bail before doing any work that
    # might touch the filesystem (alembic config load).
    import os

    db_url = os.environ.get("Z4J_DATABASE_URL")
    if not db_url:
        return None

    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import create_engine, text

    from z4j_brain.schema_transition import SCHEMA_TRANSITION_ADVISORY_LOCK_KEY

    cfg = Config(str(config_path))
    script = ScriptDirectory.from_config(cfg)
    known_revisions = {rev.revision for rev in script.walk_revisions()}

    # Strip the asyncpg / aiosqlite driver suffix - we just want a
    # sync read of one row.
    sync_url = db_url.replace("+asyncpg", "").replace("+aiosqlite", "")
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as conn:
            if conn.dialect.name == "sqlite":
                conn.exec_driver_sql("BEGIN EXCLUSIVE")
            elif conn.dialect.name == "postgresql":
                conn.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_id)"),
                    {"lock_id": SCHEMA_TRANSITION_ADVISORY_LOCK_KEY},
                )
            result = conn.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1"),
            )
            row = result.first()
    except Exception:
        return None
    finally:
        engine.dispose()
    if row is None:
        return None
    db_head = str(row[0])
    if db_head in known_revisions:
        return None
    return db_head


def _run_audit(args: argparse.Namespace) -> int:  # noqa: PLR0911  flat subcommand dispatch
    """Dispatch ``z4j audit <subcommand>``."""
    if args.audit_command == "verify":
        return _run_audit_verify(args)
    if args.audit_command == "export-head":
        return _run_audit_export_head(args)
    if args.audit_command == "rotate-chain-key":
        return _run_audit_rotate_chain_key(args)
    if args.audit_command == "retire-chain-key":
        return _run_audit_retire_chain_key(args)
    if args.audit_command == "activate-chain-state":
        return _run_audit_activate_chain_state(args)
    if args.audit_command == "export-and-delete-frozen":
        return _run_audit_export_and_delete_frozen(args)
    if args.audit_command == "fork-cleanup":
        return _run_audit_fork_cleanup(args)
    if args.audit_command == "reseal-watermark":
        return _run_audit_reseal_watermark(args)
    print(  # noqa: T201
        f"z4j audit: unknown subcommand {args.audit_command!r}",
        file=sys.stderr,
    )
    return 2


def _run_projects(args: argparse.Namespace) -> int:
    """Dispatch ``z4j projects <subcommand>``."""
    if args.projects_command == "rewrite-scheduler":
        return _run_projects_rewrite_scheduler(args)
    print(  # noqa: T201
        f"z4j projects: unknown subcommand {args.projects_command!r}",
        file=sys.stderr,
    )
    return 2


def _run_projects_rewrite_scheduler(  # noqa: PLR0915 - explicit fail-closed CLI
    args: argparse.Namespace,
) -> int:
    """Preview or finalize one manifest-bound scheduler-owner cutover."""
    import asyncio
    import json
    import uuid
    from datetime import UTC, datetime

    _bootstrap_env_for_management_commands()

    from z4j_brain.configuration import (
        capture_configuration,
        export_snapshot_environment,
        settings_from_snapshot,
    )
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        ProjectRepository,
    )
    from z4j_brain.persistence.repositories.schedule_external import (
        ScheduleExternalRepository,
    )

    try:
        snapshot = capture_configuration()
        export_snapshot_environment(snapshot)
        settings = settings_from_snapshot(snapshot)
    except Exception as exc:
        print(  # noqa: T201
            f"z4j projects rewrite-scheduler: failed to load settings: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    audit_service = AuditService(settings)

    async def _run() -> int:  # noqa: PLR0911, PLR0912, PLR0915
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        try:
            async with db.session(write=True) as session:
                projects_repo = ProjectRepository(session)
                project = await projects_repo.get_by_slug(args.slug)
                if project is None:
                    print(  # noqa: T201
                        f"z4j projects rewrite-scheduler: project {args.slug!r} not found",
                        file=sys.stderr,
                    )
                    return 2

                if args.from_scheduler == args.to_scheduler:
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: --from and --to must name distinct owners",
                        file=sys.stderr,
                    )
                    return 2
                if args.all_sources:
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: --all-sources is "
                        "unsafe and no longer supported; use a complete external "
                        "stream or explicit --schedule-id values",
                        file=sys.stderr,
                    )
                    return 2
                try:
                    schedule_ids = tuple(uuid.UUID(value) for value in args.schedule_id)
                except ValueError:
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: every --schedule-id must be a UUID",
                        file=sys.stderr,
                    )
                    return 2
                repository = ScheduleExternalRepository(session)
                to_reserved = args.to_scheduler == "z4j-scheduler"
                if to_reserved:
                    if args.from_scheduler == "z4j-scheduler":
                        print(  # noqa: T201
                            "z4j projects rewrite-scheduler: reserved-to-reserved "
                            "is not an owner cutover",
                            file=sys.stderr,
                        )
                        return 2
                    if schedule_ids:
                        print(  # noqa: T201
                            "z4j projects rewrite-scheduler: external-source "
                            "cutovers always select the complete sealed stream",
                            file=sys.stderr,
                        )
                        return 2
                    preview = await repository.preview_external_to_reserved_cutover(
                        project_id=project.id,
                        from_owner=args.from_scheduler,
                        source_scope=args.source_scope,
                        cursor_policy=args.cursor_policy,
                    )
                else:
                    missing_target = [
                        name
                        for name, value in (
                            ("--target-source-scope", args.target_source_scope),
                            (
                                "--target-adapter-instance-id",
                                args.target_adapter_instance_id,
                            ),
                            ("--target-agent-id", args.target_agent_id),
                            (
                                "--target-registry-owner-id",
                                args.target_registry_owner_id,
                            ),
                            (
                                "--target-session-generation",
                                args.target_session_generation,
                            ),
                        )
                        if not value
                    ]
                    if missing_target:
                        print(  # noqa: T201
                            "z4j projects rewrite-scheduler: external target "
                            f"requires {', '.join(missing_target)}",
                            file=sys.stderr,
                        )
                        return 2
                    if args.from_scheduler == "z4j-scheduler" and not schedule_ids:
                        print(  # noqa: T201
                            "z4j projects rewrite-scheduler: reserved-source "
                            "cutover requires explicit --schedule-id values",
                            file=sys.stderr,
                        )
                        return 2
                    if args.from_scheduler != "z4j-scheduler" and schedule_ids:
                        print(  # noqa: T201
                            "z4j projects rewrite-scheduler: external-source "
                            "cutovers always select the complete sealed stream",
                            file=sys.stderr,
                        )
                        return 2
                    try:
                        target_agent_id = uuid.UUID(args.target_agent_id)
                        target_registry_owner_id = uuid.UUID(
                            args.target_registry_owner_id,
                        )
                    except ValueError:
                        print(  # noqa: T201
                            "z4j projects rewrite-scheduler: target agent and "
                            "registry-owner ids must be UUIDs",
                            file=sys.stderr,
                        )
                        return 2
                    preview = await repository.preview_to_external_cutover(
                        project_id=project.id,
                        from_owner=args.from_scheduler,
                        source_scope=args.source_scope,
                        to_owner=args.to_scheduler,
                        target_source_scope=args.target_source_scope,
                        schedule_ids=schedule_ids,
                        cursor_policy=args.cursor_policy,
                        target_adapter_instance_id=(args.target_adapter_instance_id),
                        target_executor_agent_id=target_agent_id,
                        target_executor_registry_owner_id=(target_registry_owner_id),
                        target_executor_session_generation=(args.target_session_generation),
                        target_executor_worker_id=args.target_worker_id,
                    )

                preview_output = {
                    "manifest_digest": preview.manifest_digest,
                    "manifest": preview.manifest,
                }
                if args.dry_run:
                    print(  # noqa: T201
                        json.dumps(
                            preview_output,
                            indent=2,
                            sort_keys=True,
                        ),
                    )
                    return 0
                if (
                    not args.operation_id
                    or not args.preview_manifest_digest
                    or not args.attest_all_schedulers_quiesced
                ):
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: finalization requires "
                        "--operation-id, --preview-manifest-digest, and "
                        "--attest-all-schedulers-quiesced",
                        file=sys.stderr,
                    )
                    return 2
                try:
                    operation_id = uuid.UUID(args.operation_id)
                except ValueError:
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: --operation-id must be a UUID",
                        file=sys.stderr,
                    )
                    return 2
                if args.preview_manifest_digest != preview.manifest_digest:
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: preview changed; rerun "
                        "--dry-run and re-attest the new manifest",
                        file=sys.stderr,
                    )
                    return 2

                if to_reserved:
                    stream = preview.manifest["stream"]
                    attestation = {
                        "all_old_and_new_scheduler_replicas_quiesced": True,
                        "preview_manifest_digest": preview.manifest_digest,
                        "stream_id": stream["stream_id"] if stream else None,
                        "epoch_uuid": stream["epoch_uuid"] if stream else None,
                        "sealed_sequence": (stream["sealed_sequence"] if stream else None),
                        "final_snapshot_digest": (
                            stream["last_snapshot_digest"] if stream else None
                        ),
                    }
                    transition = await repository.finalize_external_to_reserved_cutover(
                        operation_id=operation_id,
                        project_id=project.id,
                        from_owner=args.from_scheduler,
                        source_scope=args.source_scope,
                        preview_manifest_digest=preview.manifest_digest,
                        cursor_policy=args.cursor_policy,
                        quiescence_attestation=attestation,
                        occurred_at=datetime.now(UTC),
                    )
                else:
                    source_stream = preview.manifest["source_stream"]
                    attestation = {
                        "all_old_and_new_scheduler_replicas_quiesced": True,
                        "preview_manifest_digest": preview.manifest_digest,
                        "source_stream_id": (source_stream["stream_id"] if source_stream else None),
                        "source_epoch_uuid": (
                            source_stream["epoch_uuid"] if source_stream else None
                        ),
                        "source_sealed_sequence": (
                            source_stream["sealed_sequence"] if source_stream else None
                        ),
                        "source_final_snapshot_digest": (
                            source_stream["last_snapshot_digest"] if source_stream else None
                        ),
                    }
                    transition = await repository.finalize_to_external_cutover(
                        operation_id=operation_id,
                        project_id=project.id,
                        from_owner=args.from_scheduler,
                        source_scope=args.source_scope,
                        to_owner=args.to_scheduler,
                        target_source_scope=args.target_source_scope,
                        schedule_ids=schedule_ids,
                        preview_manifest_digest=preview.manifest_digest,
                        cursor_policy=args.cursor_policy,
                        quiescence_attestation=attestation,
                        target_adapter_instance_id=(args.target_adapter_instance_id),
                        target_executor_agent_id=target_agent_id,
                        target_executor_registry_owner_id=(target_registry_owner_id),
                        target_executor_session_generation=(args.target_session_generation),
                        target_executor_worker_id=args.target_worker_id,
                        occurred_at=datetime.now(UTC),
                    )
                if transition.disposition not in {
                    "completed",
                    "exact_replay",
                }:
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: cutover refused: "
                        f"{transition.disposition}",
                        file=sys.stderr,
                    )
                    return 2

                cutover = transition.cutover
                if cutover is None:
                    print(  # noqa: T201
                        "z4j projects rewrite-scheduler: cutover evidence is missing",
                        file=sys.stderr,
                    )
                    return 2
                if transition.disposition == "completed":
                    await audit_service.record(
                        AuditLogRepository(session),
                        action="schedule.owner_cutover",
                        target_type="schedule_owner_cutover",
                        target_id=str(operation_id),
                        result="success",
                        outcome="allow",
                        project_id=project.id,
                        metadata={
                            "from_owner": args.from_scheduler,
                            "to_owner": args.to_scheduler,
                            "source_scope": args.source_scope,
                            "cursor_policy": args.cursor_policy,
                            "preview_manifest_digest": (preview.manifest_digest),
                            "result_manifest_digest": (cutover.result_manifest_digest),
                            "schedule_count": len(transition.schedules),
                            "invoked_via": "cli",
                        },
                    )
                    await session.commit()
                print(  # noqa: T201
                    json.dumps(
                        {
                            "disposition": transition.disposition,
                            "operation_id": str(operation_id),
                            "preview_manifest_digest": (preview.manifest_digest),
                            "result_manifest_digest": (cutover.result_manifest_digest),
                            "result_manifest": cutover.result_manifest,
                        },
                        indent=2,
                        sort_keys=True,
                    ),
                )
                return 0
        finally:
            await db.dispose()

    return asyncio.run(_run())


def _misfire_cli_record(row: Any) -> dict[str, Any]:
    """Flatten one ``scheduler.misfire_detected`` audit row for CLI output.

    ``target_id`` is the schedule id (the misfire detector writes it as
    such); the remaining fields come from the detector's audit metadata,
    the same shape the REST projection reads.
    """
    meta = row.audit_metadata or {}
    return {
        "schedule_id": str(row.target_id),
        "detected_at": row.occurred_at.isoformat() if row.occurred_at else None,
        "name": meta.get("name"),
        "engine": meta.get("engine"),
        "kind": meta.get("kind"),
        "expected_fire_at": meta.get("expected_fire_at"),
        "lateness_seconds": meta.get("lateness_seconds"),
        "grace_seconds": meta.get("grace_seconds"),
    }


def _print_misfires_table(slug: str, records: list[dict[str, Any]]) -> None:
    """Render the flattened misfire records as an aligned text table.

    Mirrors the column-width computation used by ``z4j upgrade`` so the
    two read-only tables look consistent.
    """
    if not records:
        print(f"z4j misfires: no misfires recorded for project {slug!r}.")  # noqa: T201
        return

    cols: tuple[tuple[str, str], ...] = (
        ("SCHEDULE ID", "schedule_id"),
        ("DETECTED AT", "detected_at"),
        ("NAME", "name"),
        ("ENGINE", "engine"),
        ("KIND", "kind"),
        ("LATE(s)", "lateness_seconds"),
        ("GRACE(s)", "grace_seconds"),
    )

    def _cell(rec: dict[str, Any], key: str) -> str:
        val = rec.get(key)
        return "" if val is None else str(val)

    widths = {
        key: max(len(header), *(len(_cell(rec, key)) for rec in records)) + 2
        for header, key in cols
    }
    header_line = "".join(f"{header:<{widths[key]}}" for header, key in cols)
    print(header_line)  # noqa: T201
    print("-" * len(header_line))  # noqa: T201
    for rec in records:
        print("".join(f"{_cell(rec, key):<{widths[key]}}" for _, key in cols))  # noqa: T201
    print()  # noqa: T201
    print(  # noqa: T201
        f"{len(records)} misfire(s) for project {slug!r} (newest first).",
    )


def _run_misfires(args: argparse.Namespace) -> int:
    """Dispatch ``z4j misfires --project <slug>``.

    Prints the project's ``scheduler.misfire_detected`` history across
    ALL its schedules, newest first -- the shell-side twin of the
    VIEWER-facing REST endpoint. ``--json`` emits a machine-readable
    object (``{"project": <slug>, "misfires": [...]}``) for scripting;
    the default is an aligned text table.

    Exit codes:
        0 - success (including an empty history)
        2 - misconfiguration (bad slug / project not found / DB down)
    """
    import asyncio

    _bootstrap_env_for_management_commands()

    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        ProjectRepository,
    )
    from z4j_brain.settings import Settings

    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as exc:
        print(  # noqa: T201
            f"z4j misfires: failed to load settings: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    # Cap the fetch at the CLI boundary too (the repo caps as well;
    # belt-and-suspenders keeps a scripted --limit from surprising).
    limit = max(1, min(1000, args.limit))

    async def _run() -> int:
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        try:
            async with db.session() as session:
                project = await ProjectRepository(session).get_by_slug(args.project)
                if project is None:
                    print(  # noqa: T201
                        f"z4j misfires: project {args.project!r} not found",
                        file=sys.stderr,
                    )
                    return 2
                rows = await AuditLogRepository(session).list_misfires_for_project(
                    project_id=project.id,
                    limit=limit,
                )
                # Materialise inside the session so attribute access does
                # not touch a closed/expired session after dispose.
                records = [_misfire_cli_record(r) for r in rows]
        finally:
            # ``--json`` is a strict stdout protocol.  The shared manager's
            # informational dispose log may use structlog's pre-configuration
            # stdout fallback in a short-lived CLI process, corrupting that
            # protocol.  Dispose the same engine directly and silently here.
            await engine.dispose()

        if args.json:
            import json as _json

            print(  # noqa: T201
                _json.dumps({"project": args.project, "misfires": records}),
            )
            return 0

        _print_misfires_table(args.project, records)
        return 0

    return asyncio.run(_run())


def _run_audit_reseal_watermark(args: argparse.Namespace) -> int:
    """Re-sign a legacy, unauthenticated prune watermark under the current
    secret (H1). Operator ceremony -- never automatic.

    Returns 0 on success / already-sealed / dry-run, 1 on a refusal the
    operator must resolve, 2 on config / connection failure.
    """
    import asyncio

    _bootstrap_env_for_management_commands()

    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories import AuditLogRepository
    from z4j_brain.persistence.repositories.audit_log import (
        authenticate_prune_watermark,
    )
    from z4j_brain.settings import Settings

    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as exc:
        print(  # noqa: T201
            f"z4j audit reseal-watermark: failed to load settings: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    async def _run() -> int:  # noqa: PLR0911  explicit refusal outcomes
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        try:
            async with db.session() as session:
                if await _has_boundary_f_audit_authority(session):
                    print(  # noqa: T201
                        "z4j audit reseal-watermark: refusing after "
                        "Boundary-F preparation or activation; the legacy "
                        "watermark is no longer mutable authority.",
                        file=sys.stderr,
                    )
                    return 1
                repo = AuditLogRepository(session)
                raw = await repo.get_raw_prune_watermark()
                if raw is None:
                    print(  # noqa: T201
                        "z4j audit reseal-watermark: no prune watermark stored; nothing to reseal.",
                    )
                    return 0
                secrets = settings.all_secrets_for_verification()
                if authenticate_prune_watermark(secrets, raw) is not None:
                    print(  # noqa: T201
                        "z4j audit reseal-watermark: the watermark already "
                        "authenticates under the current secret window; nothing "
                        "to do.",
                    )
                    return 0

                # Unauthenticated. Distinguish a legacy BARE value (no MAC,
                # the 1.7.0->1.7.1 upgrade case) from a TAGGED value that
                # fails to verify (forged, or signed under a fully rotated-out
                # secret -- do NOT bless it without --force-bare).
                row_part, _, mac_part = raw.rpartition(":")
                is_tagged = ":" in raw and bool(row_part) and bool(mac_part)
                if is_tagged and not args.force_bare:
                    print(  # noqa: T201
                        "z4j audit reseal-watermark: REFUSING. The stored "
                        "watermark is tagged but verifies under no current or "
                        "previous secret. That usually means the signing secret "
                        "was rotated fully out of the window -- restore it to "
                        "Z4J_PREVIOUS_SECRETS and re-run `z4j audit verify` -- OR "
                        "the value was forged. Only if you are certain the "
                        "embedded anchor is genuine, re-run with --force-bare "
                        "--i-have-verified-the-chain.",
                        file=sys.stderr,
                    )
                    return 1

                row_hmac = row_part if is_tagged else raw
                if not row_hmac:
                    print(  # noqa: T201
                        "z4j audit reseal-watermark: the stored watermark is "
                        "empty or malformed; refusing to reseal.",
                        file=sys.stderr,
                    )
                    return 1

                shape = "tagged-but-unverifiable" if is_tagged else "legacy bare"
                if not args.chain_verified:
                    print(  # noqa: T201
                        "z4j audit reseal-watermark: DRY RUN (pass "
                        "--i-have-verified-the-chain to write).\n"
                        f"  stored watermark : {shape}\n"
                        f"  would reseal anchor row_hmac: {row_hmac[:16]}...\n"
                        "  under the current Z4J_SECRET.\n\n"
                        "Resealing tells `z4j audit verify` to trust this row as "
                        "the genuine prune anchor. Run `z4j audit verify` first; "
                        "if the chain is intact apart from this watermark, re-run "
                        "with --i-have-verified-the-chain.",
                    )
                    return 0

                current_secret = settings.secret.get_secret_value().encode("utf-8")
                await repo.set_prune_watermark(row_hmac, secret=current_secret)
                await session.commit()
                print(  # noqa: T201
                    "z4j audit reseal-watermark: resealed the prune watermark "
                    "under the current secret. `z4j audit verify` should now "
                    "pass (assuming the rest of the chain is intact).",
                )
                return 0
        finally:
            await engine.dispose()

    return asyncio.run(_run())


def _run_audit_activate_chain_state(  # noqa: PLR0912, PLR0915  offline ceremony
    args: argparse.Namespace,
) -> int:
    """Finalize or apply one manifest-bound Boundary-F activation."""

    import asyncio
    import json

    from alembic import command
    from alembic.config import Config
    from alembic.util import CommandError
    from sqlalchemy import text

    from z4j_brain.configuration import (
        capture_configuration,
        settings_from_snapshot,
    )
    from z4j_brain.domain.audit_activation import (
        build_activation_manifest,
        read_activation_manifest,
        write_activation_manifest,
    )
    from z4j_brain.domain.audit_chain import AuditChainIntegrityError
    from z4j_brain.domain.audit_verifier import verify_active_audit_generation
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories.audit_log import (
        AUDIT_CHAIN_ADVISORY_LOCK_KEY,
    )
    from z4j_brain.secret_store import audit_bootstrap_coordinator

    manifest_path = Path(args.manifest).expanduser().resolve()
    if args.known_head is None:
        known_head: dict[str, Any] | None = None
    else:
        try:
            decoded_known_head = json.loads(args.known_head)
        except (TypeError, ValueError):
            decoded_known_head = {"__invalid_json__": True}
        known_head = (
            decoded_known_head
            if isinstance(decoded_known_head, dict)
            else {"__invalid_json__": True}
        )
    preliminary = capture_configuration(include_secret_store=False)
    database_hint = preliminary.values.get("Z4J_DATABASE_URL", "")
    sqlite_shape = not database_hint or database_hint.startswith("sqlite")
    coordinator = (
        audit_bootstrap_coordinator(z4j_home())
        if sqlite_shape and args.restore_operation is None
        else contextlib.nullcontext()
    )

    try:
        with coordinator:
            snapshot = _bootstrap_env_for_management_commands()
            settings = settings_from_snapshot(snapshot)

            async def _build_manifest() -> dict[str, Any]:
                if args.restore_operation is not None:
                    if settings.database_url.startswith("sqlite"):
                        from z4j_brain.management_restore import (
                            build_restore_activation_manifest,
                        )
                    else:
                        from z4j_brain.management_restore_postgres import (
                            build_restore_activation_manifest,
                        )

                    return await asyncio.to_thread(
                        build_restore_activation_manifest,
                        settings.database_url,
                        operation=args.restore_operation,
                        settings=settings,
                        legacy_key_window_complete=bool(
                            args.legacy_key_window_complete,
                        ),
                        known_head=known_head,
                    )
                engine = create_engine_from_settings(settings)
                try:
                    async with engine.connect() as connection:
                        if connection.dialect.name == "sqlite":
                            await connection.exec_driver_sql("BEGIN EXCLUSIVE")
                        else:
                            await connection.execution_options(
                                isolation_level="REPEATABLE READ",
                            )
                            await connection.begin()
                            await connection.execute(
                                text(
                                    "SELECT pg_advisory_xact_lock(:lock_id)",
                                ),
                                {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_KEY},
                            )
                            await connection.execute(
                                text(
                                    "LOCK TABLE audit_log IN SHARE ROW EXCLUSIVE MODE",
                                ),
                            )
                            await connection.execute(
                                text(
                                    "LOCK TABLE audit_chain_preparation "
                                    "IN SHARE ROW EXCLUSIVE MODE",
                                ),
                            )
                        try:
                            return await connection.run_sync(
                                lambda sync_connection: build_activation_manifest(
                                    sync_connection,
                                    settings,
                                    legacy_key_window_complete=bool(
                                        args.legacy_key_window_complete,
                                    ),
                                    known_head=known_head,
                                ),
                            )
                        finally:
                            await connection.rollback()
                finally:
                    await engine.dispose()

            if not args.apply:
                if args.attest_manifest_digest is not None:
                    raise RuntimeError(  # noqa: TRY301
                        "--attest-manifest-digest is valid only with --apply",
                    )
                manifest = asyncio.run(_build_manifest())
                write_activation_manifest(manifest_path, manifest)
                print(  # noqa: T201
                    "z4j audit activate-chain-state: finalized "
                    f"{manifest_path} (digest={manifest['manifest_digest']}, "
                    f"frozen_rows={manifest['frozen_row_count']}).",
                )
                if manifest["requires_ambiguity_attestation"]:
                    print(  # noqa: T201
                        "z4j audit activate-chain-state: activation is "
                        "ambiguous; inspect classification_failures and apply "
                        "only with --attest-manifest-digest="
                        f"{manifest['manifest_digest']}.",
                    )
                return 0

            manifest = read_activation_manifest(manifest_path)
            if args.known_head is not None:
                raise RuntimeError(  # noqa: TRY301
                    "--known-head is bound while finalizing; omit it when "
                    "applying the finalized manifest",
                )
            requested_complete = args.legacy_key_window_complete
            if (
                requested_complete is not None
                and bool(
                    manifest["legacy_key_window_complete"],
                )
                != requested_complete
            ):
                raise RuntimeError(  # noqa: TRY301
                    "--legacy-key-window-complete differs from the finalized manifest",
                )
            expected_digest = str(manifest["manifest_digest"])
            attestation = args.attest_manifest_digest
            if manifest["requires_ambiguity_attestation"]:
                if attestation != expected_digest:
                    raise RuntimeError(  # noqa: TRY301
                        f"ambiguous activation requires --attest-manifest-digest={expected_digest}",
                    )
            elif attestation is not None and attestation != expected_digest:
                raise RuntimeError(  # noqa: TRY301
                    "supplied attestation does not equal the finalized manifest digest",
                )

            if args.restore_operation is not None:
                from z4j_brain.backup import restore

                if settings.database_url.startswith("sqlite"):
                    from z4j_brain.management_restore import (
                        apply_restore_activation_manifest,
                    )
                else:
                    from z4j_brain.management_restore_postgres import (
                        apply_restore_activation_manifest,
                    )

                activated_phase = apply_restore_activation_manifest(
                    settings.database_url,
                    operation=args.restore_operation,
                    settings=settings,
                    manifest=manifest,
                    attestation=attestation,
                )
                restore_result = restore(
                    settings.database_url,
                    Path(
                        activated_phase["source_provenance"]["supplied_path"],
                    ),
                    operation=args.restore_operation,
                )
                print(  # noqa: T201
                    "z4j audit activate-chain-state: restore-bound "
                    "activation committed, restore verified, and fences "
                    f"cleared (operation={restore_result['operation_id']}).",
                )
                return 0

            config_path = _find_alembic_config_path()
            if config_path is None:
                raise RuntimeError(  # noqa: TRY301
                    "alembic.ini was not found",
                )
            config = Config(str(config_path))
            config.attributes["z4j_configuration_snapshot"] = snapshot
            config.attributes["z4j_audit_activation_manifest"] = manifest
            config.attributes["z4j_audit_activation_attestation"] = attestation
            command.upgrade(config, "head")

            async def _verify_committed_activation() -> tuple[int, int]:
                engine = create_engine_from_settings(settings)
                db = DatabaseManager(engine)
                try:
                    async with db.session(write=True) as session:
                        report = await verify_active_audit_generation(
                            session,
                            settings,
                            page_size=1000,
                        )
                        if not report.clean:
                            raise AuditChainIntegrityError(
                                "post-activation verification is not clean: "
                                + "; ".join(report.mismatches),
                            )
                        await session.rollback()
                        return (
                            report.verified_active_rows,
                            report.verified_frozen_rows,
                        )
                finally:
                    await db.dispose()

            active_rows, frozen_rows = asyncio.run(
                _verify_committed_activation(),
            )
            print(  # noqa: T201
                "z4j audit activate-chain-state: activation committed and "
                f"fully verified ({active_rows} active, {frozen_rows} frozen).",
            )
            return 0
    except (
        AuditChainIntegrityError,
        CommandError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(  # noqa: T201
            f"z4j audit activate-chain-state: refused: {exc}",
            file=sys.stderr,
        )
        return 1


def _run_audit_export_and_delete_frozen(args: argparse.Namespace) -> int:
    """Run/resume the offline frozen-history export/delete ceremony."""

    import asyncio
    import contextlib
    import uuid

    from z4j_core.paths import z4j_home

    from z4j_brain.configuration import (
        capture_configuration,
        settings_from_snapshot,
    )
    from z4j_brain.domain.audit_chain import AuditChainIntegrityError
    from z4j_brain.domain.audit_frozen_export import export_and_delete_frozen
    from z4j_brain.persistence.database import create_engine_from_settings
    from z4j_brain.secret_store import audit_bootstrap_coordinator

    try:
        operation_id = uuid.UUID(args.operation)
        if str(operation_id) != args.operation.lower():
            raise ValueError(  # noqa: TRY301
                "--operation must be a canonical lowercase UUID",
            )
        destination = Path(args.destination).expanduser().resolve()
        preliminary = capture_configuration(include_secret_store=False)
        database_hint = preliminary.values.get("Z4J_DATABASE_URL", "")
        sqlite_shape = not database_hint or database_hint.startswith("sqlite")
        coordinator = (
            audit_bootstrap_coordinator(z4j_home()) if sqlite_shape else contextlib.nullcontext()
        )
        with coordinator:
            snapshot = _bootstrap_env_for_management_commands()
            settings = settings_from_snapshot(snapshot)
            engine = create_engine_from_settings(settings)

            async def _run() -> dict[str, Any]:
                try:
                    return await export_and_delete_frozen(
                        engine=engine,
                        settings=settings,
                        private_root=z4j_home() / "audit-frozen-exports",
                        operation_id=operation_id,
                        destination=destination,
                        acknowledge_destination_digest=(args.acknowledge_destination_digest),
                        cleanup=bool(args.cleanup),
                    )
                finally:
                    await engine.dispose()

            result = asyncio.run(_run())
        print(  # noqa: T201
            "z4j audit export-and-delete-frozen: "
            f"{result['phase']} operation={result['operation_id']} "
            f"digest={result['export_sha256']} "
            f"destination={result['destination']}",
        )
        if result["phase"] == "DATABASE_COMMITTED":
            print(  # noqa: T201
                "z4j audit export-and-delete-frozen: the signed database "
                "transition committed; retain the private spool until "
                "--acknowledge-destination-digest matches the digest above.",
            )
        return 0
    except (
        AuditChainIntegrityError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(  # noqa: T201
            f"z4j audit export-and-delete-frozen: refused: {exc}",
            file=sys.stderr,
        )
        return 1


def _run_audit_rotate_chain_key(  # noqa: PLR0915  two-resource ceremony
    args: argparse.Namespace,
) -> int:
    """Begin/resume the explicit Boundary-F audit-key transition."""

    import asyncio
    import secrets

    from z4j_brain.configuration import (
        apply_secret_store_winner,
        capture_configuration,
        settings_from_snapshot,
    )
    from z4j_brain.domain.audit_chain import (
        AuditChainIntegrityError,
        build_audit_keyring,
    )
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.audit_verifier import verify_active_audit_generation
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories import AuditLogRepository
    from z4j_brain.secret_store import (
        audit_bootstrap_coordinator,
        update_secret_store,
    )

    preliminary = capture_configuration(include_secret_store=False)
    database_hint = preliminary.values.get("Z4J_DATABASE_URL", "")
    sqlite_shape = not database_hint or database_hint.startswith("sqlite")
    coordinator = (
        audit_bootstrap_coordinator(z4j_home()) if sqlite_shape else contextlib.nullcontext()
    )

    try:
        with coordinator:
            snapshot = _bootstrap_env_for_management_commands()
            settings = settings_from_snapshot(snapshot)
            managed = snapshot.source_for_env_key("Z4J_AUDIT_CHAIN_SECRET") == "secret.env"
            if args.begin_managed and not managed:
                raise RuntimeError(  # noqa: TRY301
                    "--begin-managed is valid only when the effective audit key "
                    "is safe-store-managed",
                )
            if managed and not settings.database_url.startswith("sqlite"):
                raise RuntimeError(  # noqa: TRY301
                    "safe-store-managed audit-key rotation is supported only for packaged SQLite",
                )

            async def _preflight() -> tuple[str, dict[str, int]]:
                engine = create_engine_from_settings(settings)
                db = DatabaseManager(engine)
                try:
                    async with db.session(write=True) as session:
                        report = await verify_active_audit_generation(
                            session,
                            settings,
                            page_size=1000,
                        )
                        if not report.clean:
                            raise AuditChainIntegrityError(
                                "audit verification is not clean before rotation",
                            )
                        state = await AuditLogRepository(
                            session,
                        ).get_chain_state_for_update()
                        return state.state_key_id, dict(state.active_key_counts)
                finally:
                    await db.dispose()

            state_key_id, active_counts = asyncio.run(_preflight())
            audit_secrets = settings.all_audit_chain_secrets_for_verification()
            if not audit_secrets:
                raise RuntimeError(  # noqa: TRY301
                    "the dedicated audit-key window is empty",
                )
            current_key_id, keyring = build_audit_keyring(
                audit_secrets[0],
                audit_secrets[1:],
            )
            if state_key_id not in keyring:
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "the configured audit-key window does not contain the authenticated state key",
                )

            if managed and state_key_id == current_key_id:
                if not args.begin_managed:
                    print(  # noqa: T201
                        "z4j audit rotate-chain-key: no pending managed "
                        "rotation; pass --begin-managed to mint a new key.",
                    )
                    return 0
                if len(active_counts) >= 32:
                    raise RuntimeError(  # noqa: TRY301
                        "the active 32-key audit window is full; prune and "
                        "retire an old key before rotating",
                    )
                old_current = (
                    settings.audit_chain_secret.get_secret_value()
                    if settings.audit_chain_secret is not None
                    else ""
                )
                if "," in old_current:
                    raise RuntimeError(  # noqa: TRY301
                        "the managed current audit key cannot be encoded in "
                        "the previous-key window",
                    )
                prior_text = (
                    settings.audit_chain_previous_secrets.get_secret_value()
                    if settings.audit_chain_previous_secrets is not None
                    else ""
                )
                prior = [item.strip() for item in prior_text.split(",") if item.strip()]
                previous = list(dict.fromkeys([old_current, *prior]))
                winner = update_secret_store(
                    z4j_home() / "secret.env",
                    {
                        "Z4J_AUDIT_CHAIN_SECRET": secrets.token_urlsafe(48),
                        "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS": ",".join(previous),
                    },
                )
                snapshot = apply_secret_store_winner(snapshot, winner.values)
                settings = settings_from_snapshot(snapshot)
            elif not managed and state_key_id == current_key_id:
                print(  # noqa: T201
                    "z4j audit rotate-chain-key: authenticated state already "
                    "uses the configured current key; install a new current "
                    "key plus the old key in the explicit previous window first.",
                )
                return 0

            async def _rotate() -> bool:
                engine = create_engine_from_settings(settings)
                db = DatabaseManager(engine)
                try:
                    async with db.session(write=True) as session:
                        marker = await AuditService(settings).rotate_chain_key(
                            AuditLogRepository(session),
                        )
                        await session.commit()
                        return marker is not None
                finally:
                    await db.dispose()

            changed = asyncio.run(_rotate())
            print(  # noqa: T201
                "z4j audit rotate-chain-key: "
                + (
                    "rotation committed and authenticated state re-signed."
                    if changed
                    else "rotation was already committed; resume is complete."
                ),
            )
            return 0
    except (AuditChainIntegrityError, RuntimeError, ValueError) as exc:
        print(  # noqa: T201
            f"z4j audit rotate-chain-key: refused: {exc}",
            file=sys.stderr,
        )
        return 1


def _run_audit_retire_chain_key(  # noqa: PLR0915  state/file retirement
    args: argparse.Namespace,
) -> int:
    """Retire one zero-live-count previous audit key."""

    import asyncio

    from z4j_brain.configuration import (
        capture_configuration,
        settings_from_snapshot,
    )
    from z4j_brain.domain.audit_chain import (
        AuditChainIntegrityError,
        build_audit_keyring,
        canonical_audit_key_id,
        normalize_hmac,
    )
    from z4j_brain.domain.audit_verifier import verify_active_audit_generation
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories import AuditLogRepository
    from z4j_brain.secret_store import (
        audit_bootstrap_coordinator,
        update_secret_store,
    )

    try:
        target_key_id = normalize_hmac(args.key_id, field="key_id")
        assert target_key_id is not None
        preliminary = capture_configuration(include_secret_store=False)
        database_hint = preliminary.values.get("Z4J_DATABASE_URL", "")
        coordinator = (
            audit_bootstrap_coordinator(z4j_home())
            if not database_hint or database_hint.startswith("sqlite")
            else contextlib.nullcontext()
        )
        with coordinator:
            snapshot = _bootstrap_env_for_management_commands()
            settings = settings_from_snapshot(snapshot)

            async def _preflight() -> tuple[str, dict[str, int]]:
                engine = create_engine_from_settings(settings)
                db = DatabaseManager(engine)
                try:
                    async with db.session(write=True) as session:
                        report = await verify_active_audit_generation(
                            session,
                            settings,
                            page_size=1000,
                        )
                        if not report.clean:
                            raise AuditChainIntegrityError(
                                "audit verification is not clean before retirement",
                            )
                        state = await AuditLogRepository(
                            session,
                        ).get_chain_state_for_update()
                        return state.state_key_id, dict(state.active_key_counts)
                finally:
                    await db.dispose()

            state_key_id, active_counts = asyncio.run(_preflight())
            audit_secrets = settings.all_audit_chain_secrets_for_verification()
            if not audit_secrets:
                raise RuntimeError(  # noqa: TRY301
                    "the dedicated audit-key window is empty",
                )
            current_key_id, _keyring = build_audit_keyring(
                audit_secrets[0],
                audit_secrets[1:],
            )
            if state_key_id != current_key_id:
                raise AuditChainIntegrityError(  # noqa: TRY301
                    "audit-key rotation is pending; complete it before retirement",
                )
            if target_key_id == current_key_id:
                raise RuntimeError(  # noqa: TRY301
                    "the authenticated current audit key cannot be retired",
                )
            live_count = active_counts.get(target_key_id, 0)
            if live_count:
                raise RuntimeError(  # noqa: TRY301
                    f"key {target_key_id} still authenticates {live_count} live "
                    "active audit row(s)",
                )

            managed = snapshot.source_for_env_key("Z4J_AUDIT_CHAIN_SECRET") == "secret.env"
            if not managed:
                print(  # noqa: T201
                    "z4j audit retire-chain-key: authenticated live count is "
                    "zero. Remove this key from the explicit "
                    "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS source.",
                )
                return 0
            if not settings.database_url.startswith("sqlite"):
                raise RuntimeError(  # noqa: TRY301
                    "safe-store-managed key retirement is supported only for packaged SQLite",
                )

            previous_text = (
                settings.audit_chain_previous_secrets.get_secret_value()
                if settings.audit_chain_previous_secrets is not None
                else ""
            )
            previous = [item.strip() for item in previous_text.split(",") if item.strip()]
            retained = [
                secret
                for secret in previous
                if canonical_audit_key_id(secret.encode()) != target_key_id
            ]
            if len(retained) == len(previous):
                print(  # noqa: T201
                    "z4j audit retire-chain-key: key is already absent from "
                    "the managed previous-key window.",
                )
                return 0
            if retained:
                update_secret_store(
                    z4j_home() / "secret.env",
                    {
                        "Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS": ",".join(retained),
                    },
                )
            else:
                update_secret_store(
                    z4j_home() / "secret.env",
                    {},
                    remove=("Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS",),
                )
            print(  # noqa: T201
                "z4j audit retire-chain-key: removed the zero-live-count key "
                "from the managed previous-key window.",
            )
            return 0
    except (AuditChainIntegrityError, RuntimeError, ValueError) as exc:
        print(  # noqa: T201
            f"z4j audit retire-chain-key: refused: {exc}",
            file=sys.stderr,
        )
        return 1


def _run_audit_export_head(  # noqa: PLR0915  read, authenticate, then write
    args: argparse.Namespace,
) -> int:
    """Print the authenticated current audit chain head.

    The output is the envelope ``audit verify --known-head`` consumes, so
    ``z4j audit export-head > /secure/last-known-head`` produces a file the
    documented mitigation reads verbatim. Anchoring that file somewhere the
    database role cannot rewrite is what makes a rolled-back log detectable;
    a head kept only in the same database proves nothing, because a writer can
    restore an older copy of it.

    The envelope carries exactly six keys because the verifier's parser is a
    closed allow-list and reports INVALID on a seventh. Nothing is signed or
    timestamped here for that reason. Authentication happens before printing
    instead: the state row is proved against the configured keyring, and a row
    that does not authenticate is refused rather than exported.

    Every human-facing line goes to stderr, so a pipe from stdout carries a
    complete envelope and nothing else. Prefer ``--output`` to a shell redirect
    for a file: ``> file`` truncates before this runs, so a refusal would leave
    the operator with an empty anchor exactly when something is already wrong.
    ``--output`` writes through a temporary file and renames, so an existing
    anchor survives every refusal here.

    Returns 0 when a head was printed, 1 on a refusal the operator has to
    resolve, and 2 on settings or connection failure.
    """
    import asyncio
    import os
    import pathlib
    import tempfile

    # Bootstrap env so fresh / bare-metal installs don't crash with
    # a Settings ValidationError before we even open the DB.
    _bootstrap_env_for_management_commands()

    from sqlalchemy import select

    from z4j_brain.domain.audit_chain import (
        AUDIT_CHAIN_SINGLETON_ID,
        AUDIT_ROW_HMAC_VERSION,
        AuditChainIntegrityError,
        authenticate_state,
        canonical_audit_key_id,
        canonical_json,
        normalize_timestamp,
    )
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.models import AuditChainState
    from z4j_brain.settings import Settings

    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as exc:
        print(  # noqa: T201
            f"z4j audit export-head: failed to load settings: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    if settings.audit_chain_secret is None:
        print(  # noqa: T201
            "z4j audit export-head: no audit-chain key is configured, so the "
            "head cannot be authenticated before export. Set "
            "Z4J_AUDIT_CHAIN_SECRET.",
            file=sys.stderr,
        )
        return 2

    async def _run() -> str | None:
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        try:
            async with db.session() as session:
                # A plain read, deliberately not the repository's
                # get_chain_state_for_update(): its FOR UPDATE would hold the
                # singleton row against the live brain's audit writes for the
                # duration of a read-only print.
                rows = list(
                    (
                        await session.execute(
                            select(AuditChainState).where(
                                AuditChainState.singleton_id == AUDIT_CHAIN_SINGLETON_ID,
                            ),
                        )
                    ).scalars(),
                )
                if len(rows) != 1:
                    print(  # noqa: T201
                        "z4j audit export-head: audit_chain_state holds "
                        f"{len(rows)} rows where exactly one is required.",
                        file=sys.stderr,
                    )
                    return None
                state = rows[0]

                keyring = {
                    canonical_audit_key_id(secret): secret
                    for secret in settings.all_audit_chain_secrets_for_verification()
                }
                try:
                    authenticate_state(state, keyring)
                except AuditChainIntegrityError:
                    print(  # noqa: T201
                        "z4j audit export-head: the audit chain state does not "
                        "authenticate against the configured keys, so its head "
                        "is not evidence of anything. Restore a rotated-out key "
                        "into Z4J_AUDIT_CHAIN_PREVIOUS_SECRETS, or investigate "
                        "the state row.",
                        file=sys.stderr,
                    )
                    return None

                if state.head_row_hmac is None or state.head_id is None:
                    print(  # noqa: T201
                        "z4j audit export-head: this chain has no head yet, so "
                        "there is nothing to anchor. Export one once the log "
                        "has its first row.",
                        file=sys.stderr,
                    )
                    return None

                if args.verify:
                    from z4j_brain.domain.audit_verifier import (
                        verify_active_audit_generation,
                    )

                    report = await verify_active_audit_generation(
                        session,
                        settings,
                        page_size=1_000,
                    )
                    if report.mismatches:
                        print(  # noqa: T201
                            "z4j audit export-head: the active generation did "
                            f"not verify clean ({len(report.mismatches)} "
                            "finding(s)), so this head is not exported. "
                            "Anchoring it would record a compromised chain as "
                            "the trusted state.",
                            file=sys.stderr,
                        )
                        return None

                envelope: dict[str, Any] = {
                    "row_hmac": state.head_row_hmac,
                    "hmac_version": AUDIT_ROW_HMAC_VERSION,
                    "generation": str(state.generation).lower(),
                    "id": str(state.head_id).lower(),
                }
                if state.head_hmac_key_id is not None:
                    envelope["hmac_key_id"] = state.head_hmac_key_id
                if state.head_occurred_at is not None:
                    envelope["occurred_at"] = (
                        normalize_timestamp(state.head_occurred_at)
                        .isoformat(timespec="microseconds")
                        .replace("+00:00", "Z")
                    )
                # canonical_json is the same sorted-keys, no-whitespace form the
                # chain itself canonicalises with, so the exported bytes are
                # stable across runs and diffable in whatever sink holds them.
                # The coroutine's job ends here. Persisting the envelope is
                # the caller's, which keeps a blocking write out of the
                # database session and off the event loop.
                return canonical_json(envelope).decode("utf-8")
        finally:
            # Dispose the engine directly rather than through the manager.
            # stdout here is a strict JSON protocol and the manager's
            # informational dispose log may use structlog's pre-configuration
            # stdout fallback in a short-lived CLI process, corrupting it.
            await engine.dispose()

    payload = asyncio.run(_run())
    if payload is None:
        return 1

    if args.output is None:
        print(payload)  # noqa: T201
        return 0

    # Written through a temporary file in the same directory and renamed, so an
    # existing anchor is replaced only by a complete envelope. Every refusal
    # above returns before this point and leaves the previous file untouched,
    # which a shell redirect could not do: `> file` truncates first.
    target = pathlib.Path(args.output)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(payload + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            staged = pathlib.Path(handle.name)
        staged.replace(target)
    except OSError as exc:
        print(  # noqa: T201
            f"z4j audit export-head: could not write {args.output}: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    print(  # noqa: T201
        f"wrote the authenticated chain head to {args.output}",
        file=sys.stderr,
    )
    return 0


def _run_audit_verify(args: argparse.Namespace) -> int:  # noqa: PLR0915  audit chain verification
    """Verify active row HMACs and the frozen-history aggregate.

    Active rows are walked in keyset pages and each row HMAC/chain link
    is checked. Frozen legacy rows are immutable history represented by
    an authenticated count and canonical snapshot digest; they are loaded
    as one snapshot and verified as that aggregate, not as independent
    per-row HMACs.

    Returns 0 on clean verification, 1 on at least one mismatch,
    2 on configuration / connection failure. Operators wire this
    into a nightly check and page on non-zero exit.
    """
    import asyncio
    import json

    # Bootstrap env so fresh / bare-metal installs don't crash with
    # a Settings ValidationError before we even open the DB.
    _bootstrap_env_for_management_commands()

    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.repositories import AuditLogRepository
    from z4j_brain.settings import Settings

    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as exc:
        print(  # noqa: T201
            f"z4j audit verify: failed to load settings: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    audit = AuditService(settings)
    known_head: dict[str, Any] | None = None
    if args.known_head is not None:
        try:
            decoded = json.loads(args.known_head)
        except (TypeError, ValueError):
            decoded = {"__invalid_json__": True}
        known_head = decoded if isinstance(decoded, dict) else {"__invalid_json__": True}

    async def _run() -> int:  # noqa: PLR0912, PLR0915  chain verification branches
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        verified = 0
        mismatches: list[str] = []
        # Streaming chain walk: each row's prev_row_hmac must equal the
        # PREVIOUS row's row_hmac, and the first row must have
        # prev_row_hmac IS NULL (the genesis anchor). Without these
        # checks the verifier silently re-anchors at whatever row is
        # streamed first, so an operator with DB write access who
        # truncates the chain prefix produces a "valid" trimmed log.
        # (1.6.0 round-3 audit High-1: wires the round-2 H3 fix into
        # the CLI tool operators actually run.)
        first_row = True
        prev_hmac: str | None = None
        # Keyset cursor over the chain order (occurred_at, id). We page
        # through the ENTIRE log so a chain longer than one page is fully
        # verified. Previously this loaded a single fixed slice
        # (stream_for_verify(chunk=--limit)) and every row past the cap
        # went unverified -- a silent gap for any audit log over ~5000
        # rows, i.e. exactly the case a compliance audit cares about.
        cursor_occurred_at = None
        cursor_id = None
        page_size = args.limit
        if not 1 <= page_size <= 5000:
            print(  # noqa: T201  CLI output
                f"z4j audit verify: --limit must be between 1 and 5000 (got {page_size})",
                file=sys.stderr,
            )
            return 2
        if settings.audit_chain_secret is not None:
            from z4j_brain.domain.audit_verifier import (
                verify_active_audit_generation,
            )

            try:
                async with db.session() as session:
                    report = await verify_active_audit_generation(
                        session,
                        settings,
                        page_size=page_size,
                        known_head=known_head,
                    )
            except Exception as exc:
                print(  # noqa: T201
                    "z4j audit verify: Boundary-F integrity verification "
                    f"refused: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                await db.dispose()
                return 1
            await db.dispose()
            print(f"verified active: {report.verified_active_rows}")  # noqa: T201
            print(  # noqa: T201
                f"canonical frozen rows assessed in aggregate: {report.verified_frozen_rows}",
            )
            if report.known_head_result is not None:
                print(f"known-head: {report.known_head_result}")  # noqa: T201
            if report.mismatches:
                # The findings, not the lines. Past the reporting cap the tuple
                # holds a hundred findings plus the line naming the overflow,
                # so measuring it here announced 101 for a chain with 123 wrong
                # rows, on the one screen an operator reads while sizing the
                # damage.
                print(f"MISMATCHES ({report.mismatch_count}):")  # noqa: T201
                for mismatch in report.mismatches:
                    print(f"  {mismatch}")  # noqa: T201
            return 0 if report.clean else 1
        try:
            async with db.session() as session:
                repo = AuditLogRepository(session)
                # Retention prune boundary: after the sweeper deletes the
                # genesis row, the first surviving row legitimately
                # anchors on this stored watermark rather than a NULL
                # prev_row_hmac. Absent a prune it is None and the
                # NULL-genesis anchor is required exactly as before.
                # (1.7 audit.)
                # M1: authenticate the watermark against the whole rotation
                # window (current + previous secrets), mirroring how row
                # HMACs verify -- so a watermark minted before a Z4J_SECRET
                # rotation still authenticates instead of false-alarming
                # "chain truncation".
                prune_watermark = await repo.get_prune_watermark(
                    secrets=settings.all_secrets_for_verification(),
                )
                while True:
                    rows = await repo.stream_for_verify(
                        chunk=page_size,
                        after_occurred_at=cursor_occurred_at,
                        after_id=cursor_id,
                    )
                    if not rows:
                        break
                    for row in rows:
                        if first_row:
                            first_row = False
                            if (
                                row.prev_row_hmac is not None
                                and row.prev_row_hmac != prune_watermark
                            ):
                                mismatches.append(
                                    f"{row.id} (chain truncation: first "
                                    f"row has non-null prev_row_hmac; "
                                    f"genesis anchor missing)",
                                )
                        elif row.prev_row_hmac != prev_hmac:
                            saw = row.prev_row_hmac[:12] if row.prev_row_hmac else "None"
                            want = prev_hmac[:12] if prev_hmac else "None"
                            mismatches.append(
                                f"{row.id} (chain break: prev_row_hmac={saw}, expected={want})",
                            )
                        if audit.verify_row(row):
                            verified += 1
                        else:
                            mismatches.append(str(row.id))
                        prev_hmac = row.row_hmac
                    cursor_occurred_at = rows[-1].occurred_at
                    cursor_id = rows[-1].id
                    if len(rows) < page_size:
                        break
        finally:
            await db.dispose()
        print(f"verified: {verified}")  # noqa: T201
        if mismatches:
            print(f"MISMATCHES ({len(mismatches)}):")  # noqa: T201
            for mid in mismatches:
                print(f"  {mid}")  # noqa: T201
            return 1
        return 0

    return asyncio.run(_run())


def _verify_fork_cleanup_backup(
    path: Path,
    expected_duplicates: Sequence[tuple[str, int]],
) -> None:
    """Fsync and prove the standalone SQLite recovery contains the forks."""

    import sqlite3
    import stat
    from urllib.parse import quote

    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError("fork-cleanup backup is not a regular file")
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError("fork-cleanup backup identity changed")
        if os.name == "posix":
            if opened.st_uid != os.getuid():
                raise RuntimeError("fork-cleanup backup is not owner-owned")
            os.fchmod(fd, 0o600)
        os.fsync(fd)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    final_path = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size) != (
        final_path.st_dev,
        final_path.st_ino,
        final_path.st_size,
    ):
        raise RuntimeError("fork-cleanup backup pathname changed")
    # Flushing the parent directory is what makes the new directory entry
    # itself durable, and only POSIX lets you open a directory to flush it:
    # on Windows ``os.open`` on one raises PermissionError, and no supported
    # substitute exists (SQLite's own Windows VFS skips the directory sync
    # for the same reason). The file fsync above is the whole guarantee
    # available there, so skip the entry flush rather than fail the fence.
    if os.name == "posix":
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    uri = f"file:{quote(str(path))}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity != ("ok",):
            raise RuntimeError(
                f"fork-cleanup backup integrity_check failed: {integrity!r}",
            )
        observed = [
            (str(row[0]), int(row[1]))
            for row in connection.execute(
                "SELECT prev_row_hmac, COUNT(*) FROM audit_log "
                "WHERE prev_row_hmac IS NOT NULL "
                "GROUP BY prev_row_hmac HAVING COUNT(*) > 1",
            )
        ]
    finally:
        connection.close()
    if sorted(observed) != sorted(expected_duplicates):
        raise RuntimeError(
            "fork-cleanup backup does not contain the scanned duplicate set",
        )


def _run_audit_fork_cleanup(  # noqa: PLR0911, PLR0915  quarantine dispatch
    args: argparse.Namespace,
) -> int:
    """Quarantine duplicate ``prev_row_hmac`` rows so the v1.1.0
    UNIQUE chain index can apply.

    Shipped in 1.1.1 after the migration ``2026_04_28_0012_audit_unique``
    crashed live deployments that had pre-existing chain forks: rows
    sharing a non-NULL prev_row_hmac, produced by older releases
    (race in AuditService.record), test fixtures, or replay artefacts.

    What it does, in order:

    1. Connects to the configured DB via Settings.
    2. SELECTs duplicate prev_row_hmac groups + the rows in them.
    3. Prints the duplicate set so the operator can eyeball it.
    4. Auto-backs up the DB (SQLite: file copy with timestamp suffix;
       Postgres: warns to use ``pg_dump`` and refuses unless
       ``--no-backup``).
    5. Prompts ``[y/N]`` unless ``--apply``.
    6. CREATE TABLE IF NOT EXISTS ``audit_log_legacy_forks`` with
       the same shape as ``audit_log``, copies fork rows into it
       (preserving every byte for forensic review), then DELETEs
       them from ``audit_log``. The earliest row per group (by id
       lexicographic order) is kept as the canonical chain link.
    7. Verifies no remaining duplicates.
    8. Returns 0 on clean state, 1 on residual duplicates, 2 on
       configuration / connection failure.

    Operator workflow after running this:
       z4j serve         # migration applies cleanly, brain boots
    """
    import asyncio
    import sys
    import time

    _bootstrap_env_for_management_commands()

    from sqlalchemy import text

    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.settings import Settings

    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as exc:
        print(  # noqa: T201
            f"z4j audit fork-cleanup: failed to load settings: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2

    db_url = settings.database_url
    is_sqlite = "sqlite" in db_url

    async def _scan() -> list[tuple[str, int]] | None:
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        try:
            async with db.session() as session:
                if await _has_boundary_f_audit_authority(session):
                    print(  # noqa: T201
                        "z4j audit fork-cleanup: refusing after Boundary-F "
                        "preparation or activation; use the manifest-bound "
                        "activation/export ceremonies instead.",
                        file=sys.stderr,
                    )
                    return None
                result = await session.execute(
                    text(
                        "SELECT prev_row_hmac, COUNT(*) AS cnt "
                        "FROM audit_log "
                        "WHERE prev_row_hmac IS NOT NULL "
                        "GROUP BY prev_row_hmac "
                        "HAVING COUNT(*) > 1"
                    )
                )
                return [(str(r[0]), int(r[1])) for r in result.fetchall()]
        finally:
            await db.dispose()

    dups = asyncio.run(_scan())
    if dups is None:
        return 1
    if not dups:
        print(  # noqa: T201
            "z4j audit fork-cleanup: no duplicate prev_row_hmac "
            "rows found. Audit chain is fork-free; nothing to do."
        )
        return 0

    fork_rows = sum(c for _, c in dups)
    fork_groups = len(dups)
    rows_to_quarantine = fork_rows - fork_groups

    print(  # noqa: T201
        f"\nFound {fork_rows} rows in {fork_groups} duplicate "
        f"prev_row_hmac groups. The cleanup will:\n"
        f"  - keep the earliest row in each group as the canonical chain link\n"
        f"  - move the remaining {rows_to_quarantine} fork row(s) to "
        f"`audit_log_legacy_forks` (every byte preserved for forensic review)\n"
    )

    print("Duplicate groups:")  # noqa: T201
    for prev_hmac, count in dups:
        prefix = prev_hmac[:16] if len(prev_hmac) > 16 else prev_hmac
        print(f"  prev_row_hmac={prefix}... count={count}")  # noqa: T201
    print()  # noqa: T201

    if not args.apply:
        try:
            answer = (
                input(
                    "Proceed with quarantine? [y/N] ",
                )
                .strip()
                .lower()
            )
        except EOFError:
            answer = ""
        if answer != "y":
            print("Aborted; no changes made.")  # noqa: T201
            return 0

    # Backup before any write.
    if is_sqlite:
        from z4j_brain.backup import backup_sqlite

        sqlite_path = _sqlite_database_path(db_url)
        if sqlite_path is None:
            print(  # noqa: T201
                "z4j audit fork-cleanup: cannot prove the SQLite path; refusing before mutation.",
                file=sys.stderr,
            )
            return 2
        backup_path = sqlite_path.with_name(
            f"{sqlite_path.name}.pre-fork-cleanup.{int(time.time())}",
        )
        try:
            backup_sqlite(db_url, backup_path)
            _verify_fork_cleanup_backup(backup_path, dups)
            print(f"Backup written and verified: {backup_path}")  # noqa: T201
        except (OSError, RuntimeError, ValueError) as exc:
            print(  # noqa: T201
                f"Backup failed verification: {exc}. SQLite fork cleanup "
                "requires a coherent verified backup; --no-backup cannot "
                "bypass this fence.",
                file=sys.stderr,
            )
            return 2
    elif not args.no_backup:
        print(  # noqa: T201
            "Postgres detected: this command does not run pg_dump "
            "for you. Take a backup with `pg_dump` BEFORE re-running, "
            "or pass --no-backup if you already have one.",
            file=sys.stderr,
        )
        if not args.apply:
            return 2

    async def _cleanup() -> int:
        engine = create_engine_from_settings(settings)
        db = DatabaseManager(engine)
        try:
            async with db.session(write=True) as session:
                if await _has_boundary_f_audit_authority(session):
                    print(  # noqa: T201
                        "z4j audit fork-cleanup: Boundary-F authority "
                        "appeared before mutation; refusing.",
                        file=sys.stderr,
                    )
                    await session.rollback()
                    return 1
                # Create legacy table (CREATE TABLE AS / WHERE 0
                # copies the schema without rows on both engines).
                await session.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS audit_log_legacy_forks "
                        "AS SELECT * FROM audit_log WHERE 1=0"
                    )
                )

                # Identify fork rows: in a duplicate group, AND not
                # the earliest by id.
                ins = await session.execute(
                    text(
                        "INSERT INTO audit_log_legacy_forks "
                        "SELECT * FROM audit_log "
                        "WHERE prev_row_hmac IS NOT NULL "
                        "  AND prev_row_hmac IN ("
                        "    SELECT prev_row_hmac FROM audit_log "
                        "    WHERE prev_row_hmac IS NOT NULL "
                        "    GROUP BY prev_row_hmac "
                        "    HAVING COUNT(*) > 1"
                        "  )"
                        "  AND id NOT IN ("
                        "    SELECT MIN(id) FROM audit_log "
                        "    WHERE prev_row_hmac IS NOT NULL "
                        "    GROUP BY prev_row_hmac"
                        "  )"
                    )
                )
                quarantined = ins.rowcount or 0

                deleted = await session.execute(
                    text(
                        "DELETE FROM audit_log "
                        "WHERE id IN ("
                        "  SELECT id FROM audit_log_legacy_forks"
                        ")"
                    )
                )
                deleted_count = deleted.rowcount or 0
                await session.commit()

                # Verify
                check = await session.execute(
                    text(
                        "SELECT COUNT(*) FROM ("
                        "  SELECT prev_row_hmac FROM audit_log "
                        "  WHERE prev_row_hmac IS NOT NULL "
                        "  GROUP BY prev_row_hmac "
                        "  HAVING COUNT(*) > 1"
                        ") AS dup"
                    )
                )
                remaining = int(check.scalar() or 0)

            print(  # noqa: T201
                f"\nQuarantined {quarantined} row(s) to "
                f"audit_log_legacy_forks; deleted {deleted_count} row(s) "
                f"from audit_log."
            )
            if remaining > 0:
                print(  # noqa: T201
                    f"WARNING: {remaining} duplicate group(s) still present. "
                    "Re-run, or inspect the data manually.",
                    file=sys.stderr,
                )
                return 1
            print("Audit chain is fork-free. Run `z4j serve` to apply the migration.")  # noqa: T201
            return 0
        finally:
            await db.dispose()

    return asyncio.run(_cleanup())


def _run_reset_setup(args: argparse.Namespace) -> int:
    """Wipe pending first-boot tokens and append signed reset evidence.

    Existing setup audit rows remain intact so the next ``serve`` mints a
    fresh token without erasing the history that explains the reset.

    Refuses if any user already exists (that's a security hole,
    not a recovery path - someone is trying to reset onboarding for
    a configured brain). Use the dashboard's account-recovery flow
    or restore from backup instead.

    Use case: operator restarted the brain, the browser still has a
    stale URL with the old token, every retry is failing with
    "invalid_token", and the per-IP rate limit triggered a 15-minute
    lockout. Run this command, then restart the brain.
    """
    import asyncio
    import sys

    # Resolve the effective database before deciding whether there is anything
    # to reset.  The old shortcut always inspected ``Z4J_HOME/z4j.db`` and
    # therefore returned success without contacting a configured PostgreSQL
    # database (or a SQLite database at a non-default path).
    snapshot = _bootstrap_env_for_management_commands(
        allow_absent_file_sqlite_without_secrets=True,
    )
    database_url = str(snapshot.values.get("Z4J_DATABASE_URL", ""))
    db_path = _sqlite_database_path(database_url)
    if db_path is not None and not db_path.exists():
        print(  # noqa: T201
            f"z4j reset-setup: no DB found at {db_path}. "
            "Nothing to reset - run `z4j serve` to bootstrap.",
            file=sys.stderr,
        )
        return 0

    from sqlalchemy import delete, func, select

    from z4j_brain.configuration import settings_from_snapshot
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.persistence.models import (
        AuditLog,
        FirstBootToken,
        User,
    )
    from z4j_brain.persistence.repositories import AuditLogRepository

    settings = settings_from_snapshot(snapshot)
    engine = create_engine_from_settings(settings)
    db = DatabaseManager(engine)

    async def _run() -> int:
        try:
            async with db.session(write=True) as session:
                existing_user = (await session.execute(select(User).limit(1))).scalars().first()
                if existing_user is not None:
                    print(  # noqa: T201
                        "z4j reset-setup: REFUSED - a user already exists. "
                        "Reset-setup is only for the "
                        "pre-first-boot state. Use the dashboard's "
                        "account-recovery flow or restore from backup "
                        "if you need to regain access.",
                        file=sys.stderr,
                    )
                    return 2

                if not args.force:
                    print(  # noqa: T201
                        "About to wipe:\n"
                        "  - all pending first-boot tokens\n"
                        "  - no audit evidence (a signed reset record is "
                        "appended)\n"
                        "Pass --force to proceed without this prompt. "
                        "Cancelled (no --force).",
                        file=sys.stderr,
                    )
                    return 1

                tokens_deleted = (await session.execute(delete(FirstBootToken))).rowcount
                setup_evidence = int(
                    (
                        await session.execute(
                            select(func.count(AuditLog.id)).where(
                                AuditLog.action.like("setup.%"),
                            ),
                        )
                    ).scalar_one(),
                )
                await AuditService(settings).record(
                    AuditLogRepository(session),
                    action="setup.tokens_reset",
                    target_type="first_boot",
                    result="success",
                    outcome="allow",
                    metadata={
                        "tokens_deleted": int(tokens_deleted or 0),
                        "prior_setup_evidence_preserved": setup_evidence,
                    },
                )
                await session.commit()

                print(  # noqa: T201
                    f"z4j reset-setup: wiped {tokens_deleted} "
                    "pending token(s), preserved all prior audit evidence, "
                    "and appended setup.tokens_reset. Run `z4j serve` to "
                    "mint a fresh setup URL.",
                )
                return 0
        finally:
            await db.dispose()

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# Full-DB reset, user mgmt, health checks, status
# ---------------------------------------------------------------------------

_TABLES_TO_WIPE_ORDER: tuple[str, ...] = (
    # Child rows first (FK constraints). Schema stays intact; only
    # the rows vanish. If you add a new table in a migration, append
    # it here so `reset` stays complete.
    "audit_log",
    "sessions",
    "first_boot_tokens",
    "password_reset_tokens",
    "api_keys",
    "commands",
    "events",
    "task_annotations",
    "tasks",
    "schedules",
    "queues",
    "workers",
    "agents",
    "notification_deliveries",
    "user_notifications",
    "user_subscriptions",
    "user_channels",
    "user_preferences",
    "notification_channels",
    "project_default_subscriptions",
    "project_config",
    "memberships",
    "invitations",
    "projects",
    "export_jobs",
    "extension_store",
    "feature_flags",
    "saved_views",
    "users",
    "z4j_meta",
)


def _bootstrap_env_for_management_commands(
    *,
    allow_absent_file_sqlite_without_secrets: bool = False,
) -> Any:
    """Set Z4J_* env vars so Settings() and alembic's env.py can
    construct. Mirrors the early part of ``_run_serve`` but stops
    before instantiating anything - callers that need Settings +
    engine use :func:`_build_settings_from_env` which wraps this.

    Idempotent: safe to call multiple times.

    Management commands READ an existing secret.env if present,
    but REFUSE to mint the installation/session authority when
    missing - they exit with a clear error pointing the operator
    at ``z4j serve`` (which mints + prints the visible setup
    banner).  The sole compatibility exception is an existing
    packaged SQLite installation whose verified pre-1.8 store has
    every legacy secret but no audit-chain key.  The documented
    offline activation ceremony persists that one new independent
    key under the same bootstrap coordinator used by ``serve``.

    ``reset-setup`` alone opts into returning the captured snapshot for an
    absent file-backed SQLite database before this secret fence. There is no
    database to mutate in that state. PostgreSQL, in-memory SQLite, and every
    existing file-backed SQLite database still require installation secrets.
    """
    from z4j_brain.configuration import (
        capture_configuration,
        export_snapshot_environment,
        overlay_runtime_environment,
    )
    from z4j_brain.management_retirement import (
        assert_no_pending_installation_retirement,
    )
    from z4j_brain.secret_store import (
        audit_bootstrap_coordinator,
        ensure_secret_store_directory,
    )

    # A fresh packaged management entry (notably the Compose migration
    # command) can legitimately run before Z4J_HOME exists.  Establish only
    # the empty owner-private directory so the retirement fence can inspect
    # its stable journal location.  No secret, database, or metadata is
    # created before the fence.
    home = ensure_secret_store_directory(z4j_home())
    assert_no_pending_installation_retirement(home)

    snapshot = capture_configuration()
    if not snapshot.values.get("Z4J_DATABASE_URL"):
        db_path = home / "z4j.db"
        os.environ["Z4J_DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
        os.environ.setdefault("Z4J_REGISTRY_BACKEND", "local")
        snapshot = overlay_runtime_environment(snapshot)

    database_url = str(snapshot.values.get("Z4J_DATABASE_URL", ""))
    if allow_absent_file_sqlite_without_secrets:
        database_path = _sqlite_database_path(database_url)
        if database_path is not None and not database_path.exists():
            return snapshot

    legacy_secret_keys = (
        "Z4J_SECRET",
        "Z4J_SESSION_SECRET",
        "Z4J_METRICS_AUTH_TOKEN",
    )
    if (
        database_url.startswith("sqlite")
        and all(snapshot.values.get(key) for key in legacy_secret_keys)
        and not snapshot.values.get("Z4J_AUDIT_CHAIN_SECRET")
    ):
        preliminary = capture_configuration(
            home=home,
            include_secret_store=False,
        )
        with audit_bootstrap_coordinator(home):
            snapshot = _capture_serve_configuration(
                preliminary=preliminary,
            )

    if not snapshot.values.get("Z4J_SECRET"):
        raise SystemExit(
            "z4j: refusing to mint Z4J_SECRET from a management "
            "command; run `z4j serve` once first or configure the "
            "existing installation secrets explicitly",
        )

    os.environ.setdefault("Z4J_ENVIRONMENT", "dev")
    os.environ.setdefault(
        "Z4J_ALLOWED_HOSTS",
        '["localhost","127.0.0.1"]',
    )
    snapshot = overlay_runtime_environment(snapshot)
    export_snapshot_environment(snapshot)
    return snapshot


def _build_settings_from_env() -> tuple[Any, Any]:
    """Shared bootstrap for commands that need a DB engine.

    Calls :func:`_bootstrap_env_for_management_commands` then
    constructs ``Settings`` + an ``AsyncEngine``.
    """
    snapshot = _bootstrap_env_for_management_commands()

    from z4j_brain.configuration import settings_from_snapshot
    from z4j_brain.persistence.database import create_engine_from_settings

    settings = settings_from_snapshot(snapshot)
    engine = create_engine_from_settings(settings)
    return settings, engine


def _run_reset(args: argparse.Namespace) -> int:
    """Reset the authenticated generation or retire a packaged install.

    The ordinary reset deletes domain data (users, projects, agents,
    tasks, events, schedules, notifications, and prior audit history)
    while retaining the schema, authenticated installation identity,
    monotonic schedule namespaces, and one signed reset genesis.

    After this, the brain is in pre-first-boot state: the next
    ``serve`` mints a fresh setup token and prints a new admin-
    creation URL. It is intentionally not a byte-for-byte brand-new
    installation.

    ``--nuke-secrets`` takes a separate packaged-SQLite retirement
    path. It creates a fresh replacement and retains the prior
    database/key pair in a recoverable bundle until an explicitly
    authenticated destroy command removes it.

    Use when:
      - starting over on a dev / evaluation machine
      - recovering from a test that left junk data
      - cleaning a staging environment between runs

    Do NOT use on production without a DB backup. Ordinary-reset domain
    rows have no CLI undo; retirement-bundle recovery is a different,
    explicitly managed workflow.
    """
    import asyncio
    import sys

    import structlog

    if not args.force:
        print(  # noqa: T201
            "z4j reset: REQUIRED --force flag missing.\n"
            "\n"
            "The ordinary reset deletes domain rows (users, projects,\n"
            "agents, tasks, events, sessions, and prior audit history)\n"
            "while preserving installation identity, monotonic namespaces,\n"
            "and a signed reset genesis. Deleted domain data needs a backup\n"
            "to restore. --nuke-secrets uses recoverable retirement instead.\n"
            "\n"
            "If you really mean it:\n"
            "  z4j reset --force\n"
            "  z4j reset --force --nuke-secrets   # also resets HMAC keys",
            file=sys.stderr,
        )
        return 1

    if args.nuke_secrets:
        from z4j_brain.configuration import settings_from_snapshot
        from z4j_brain.management_retirement import (
            InstallationRetirementRefused,
            retire_packaged_sqlite_installation,
        )

        def _bootstrap_replacement(
            retirement_context: dict[str, Any],
        ) -> Any:
            snapshot = _capture_serve_configuration()
            _auto_migrate(retirement_context=retirement_context)
            return settings_from_snapshot(snapshot)

        try:
            result = retire_packaged_sqlite_installation(
                z4j_home(),
                bootstrap=_bootstrap_replacement,
            )
        except Exception as exc:
            label = "refused" if isinstance(exc, InstallationRetirementRefused) else "failed"
            print(  # noqa: T201
                f"z4j reset: packaged installation retirement {label}: {exc}",
                file=sys.stderr,
            )
            return 1
        print(  # noqa: T201
            "z4j reset: complete fresh installation created; the old "
            "database/key pair remains in a recoverable retirement bundle.\n"
            f"  operation:       {result['operation_id']}\n"
            f"  bundle:          {result['bundle']}\n"
            f"  manifest digest: {result['manifest_digest']}\n"
            "Destroy it later only with `z4j recovery "
            "destroy-retired-installation` and the exact digest above.",
        )
        return 0

    settings, engine = _build_settings_from_env()

    async def _wipe() -> int:
        from z4j_brain.domain.audit_activation import (
            write_activation_manifest,
        )
        from z4j_brain.domain.audit_chain import AuditChainIntegrityError
        from z4j_brain.management_reset import (
            GenerationResetRefused,
            build_generation_reset_preview,
            perform_generation_reset,
        )
        from z4j_brain.persistence.database import DatabaseManager

        db = DatabaseManager(engine)
        try:
            try:
                async with db.session(write=True) as session:
                    if args.preview_manifest:
                        preview = await build_generation_reset_preview(
                            session,
                            settings,
                        )
                        await session.rollback()
                        write_activation_manifest(
                            Path(args.preview_manifest),
                            preview,
                        )
                        print(  # noqa: T201
                            "z4j reset: finalized non-mutating preview "
                            f"{args.preview_manifest} "
                            "(stopped-executor challenge="
                            f"{preview['stopped_executor_attestation_challenge']}, "
                            "required="
                            f"{preview['requires_stopped_executor_attestation']}).",
                        )
                        return 0
                    result = await perform_generation_reset(
                        session,
                        settings,
                        stopped_executor_attestation=(args.attest_stopped_executors),
                    )
                    await session.commit()
            except (AuditChainIntegrityError, GenerationResetRefused) as exc:
                print(  # noqa: T201
                    f"z4j reset: REFUSED before commit - {exc}",
                    file=sys.stderr,
                )
                return 1
            else:
                print(  # noqa: T201
                    "z4j reset: authenticated generation reset committed "
                    f"(domain rows={result['wiped_domain_rows']:,}, "
                    f"revision={result['new_revision']}, "
                    f"external epoch={result['new_epoch']}, "
                    f"manifest={result['manifest_digest']}).",
                )
        finally:
            await db.dispose()

        print(  # noqa: T201
            "z4j reset: done. Run `z4j serve` to see the new first-boot setup URL.",
        )
        return 0

    # Silence structlog's boot-time warnings during reset.
    structlog.reset_defaults()
    return asyncio.run(_wipe())


def _run_recovery(args: argparse.Namespace) -> int:
    """Dispatch explicit packaged-installation recovery actions."""

    import sys

    if args.recovery_action != "destroy-retired-installation":
        print(  # noqa: T201
            "z4j recovery: an action is required",
            file=sys.stderr,
        )
        return 1
    from z4j_brain.management_retirement import (
        InstallationRetirementRefused,
        destroy_retired_installation,
    )

    try:
        result = destroy_retired_installation(
            z4j_home(),
            operation=args.operation,
            confirm_manifest_digest=args.confirm_manifest_digest,
        )
    except Exception as exc:
        label = "refused" if isinstance(exc, InstallationRetirementRefused) else "failed"
        print(  # noqa: T201
            f"z4j recovery: destroy-retired-installation {label}: {exc}",
            file=sys.stderr,
        )
        return 1
    print(  # noqa: T201
        "z4j recovery: logical removal complete\n"
        f"  operation: {result['operation_id']}\n"
        f"  manifest:  {result['manifest_digest']}\n"
        "  note: unlink does not guarantee physical secure erasure on "
        "snapshots, copy-on-write filesystems, SSDs, or external backups.",
    )
    return 0


def _run_changepassword(args: argparse.Namespace) -> int:
    """Reset a user's password from the CLI.

    Explicitly revokes every existing session and removes trusted-device
    records in the same transaction as the password change. The
    ``password_changed_at`` anchor remains defense in depth; it is not the
    revocation boundary because SQLite timestamps have a one-second grace.
    """
    import asyncio
    import sys
    from datetime import UTC, datetime

    from sqlalchemy import select

    password = _read_password_from_args(args)
    if password is None:
        return 2

    settings, engine = _build_settings_from_env()

    async def _run() -> int:
        from z4j_brain.auth.passwords import PasswordHasher
        from z4j_brain.domain.audit_service import AuditService
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.models import User
        from z4j_brain.persistence.repositories import (
            AuditLogRepository,
            SessionRepository,
            TrustedDeviceRepository,
        )

        hasher = PasswordHasher(settings)
        try:
            hasher.validate_policy(password)
        except Exception as exc:
            print(  # noqa: T201
                f"z4j changepassword: password rejected: {exc}",
                file=sys.stderr,
            )
            return 3

        db = DatabaseManager(engine)
        try:
            async with db.session(write=True) as session:
                user = (
                    (
                        await session.execute(
                            select(User).where(User.email == args.email.lower()),
                        )
                    )
                    .scalars()
                    .first()
                )
                if user is None:
                    print(  # noqa: T201
                        f"z4j changepassword: no user with email {args.email!r}",
                        file=sys.stderr,
                    )
                    return 4
                user.password_hash = hasher.hash(password)
                user.password_changed_at = datetime.now(UTC)
                user.failed_login_count = 0
                user.locked_until = None
                revoked_sessions = await SessionRepository(
                    session,
                ).revoke_all_for_user(user.id, reason="password_changed")
                await TrustedDeviceRepository(session).delete_all_for_user(user.id)
                await AuditService(settings).record(
                    AuditLogRepository(session),
                    action="user.password.changed_by_cli",
                    target_type="user",
                    target_id=str(user.id),
                    result="success",
                    outcome="allow",
                    metadata={
                        "operator_uid": (os.getuid() if hasattr(os, "getuid") else None),
                        "revoked_sessions": revoked_sessions,
                    },
                )
                await session.commit()
                print(  # noqa: T201
                    f"z4j changepassword: password updated for "
                    f"{user.email}. All existing sessions are now invalid.",
                )
                return 0
        finally:
            await db.dispose()

    return asyncio.run(_run())


def _run_reset_mfa(args: argparse.Namespace) -> int:
    """Operator escape hatch: clear a user's MFA state from the CLI.

    Sets ``users.mfa_secret_encrypted = NULL`` and
    ``users.mfa_enrolled_at = NULL``, deletes every row in
    ``mfa_recovery_codes`` and ``trusted_devices`` for the user, and
    flips ``sessions.mfa_verified_at = NULL`` for the user's live
    sessions. The user can log in with their password as usual; the
    sensitive-action gate treats their session as un-verified until
    they enroll again.

    Writes a ``user.mfa_reset_by_admin`` audit row attributed to the
    OS user running the CLI (best-effort: ``os.getlogin()``). There
    is intentionally no REST surface for this -- an attacker who has
    only the dashboard cannot trigger it.
    """
    import asyncio
    import getpass
    import os as _os
    import sys
    from datetime import UTC, datetime

    from sqlalchemy import select, update

    settings, engine = _build_settings_from_env()
    email = args.email.lower()

    if not args.confirm:
        prompt = (
            f"Clear MFA + recovery codes + trusted devices for "
            f"{email!r}? Type the email to confirm: "
        )
        try:
            response = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("z4j reset-mfa: aborted", file=sys.stderr)  # noqa: T201
            return 2
        if response != email:
            print(  # noqa: T201
                "z4j reset-mfa: confirmation did not match; aborted",
                file=sys.stderr,
            )
            return 2

    try:
        operator_label = getpass.getuser() or "unknown"
    except (OSError, KeyError):
        operator_label = _os.environ.get("USER") or "unknown"

    async def _run() -> int:
        from z4j_brain.domain.audit_service import AuditService
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.models import (
            MfaRecoveryCode,
            TrustedDevice,
            User,
        )
        from z4j_brain.persistence.models import (
            Session as SessionRow,
        )
        from z4j_brain.persistence.repositories import AuditLogRepository

        db = DatabaseManager(engine)
        try:
            async with db.session(write=True) as db_session:
                user = (
                    (
                        await db_session.execute(
                            select(User).where(User.email == email),
                        )
                    )
                    .scalars()
                    .first()
                )
                if user is None:
                    print(  # noqa: T201
                        f"z4j reset-mfa: no user with email {email!r}",
                        file=sys.stderr,
                    )
                    return 4
                if user.mfa_secret_encrypted is None and user.mfa_enrolled_at is None:
                    print(  # noqa: T201
                        f"z4j reset-mfa: {email} has no MFA enrolled; nothing to do",
                    )
                    return 0

                from sqlalchemy import delete

                await db_session.execute(
                    update(User)
                    .where(User.id == user.id)
                    .values(
                        mfa_secret_encrypted=None,
                        mfa_enrolled_at=None,
                        updated_at=datetime.now(UTC),
                    ),
                )
                await db_session.execute(
                    delete(MfaRecoveryCode).where(
                        MfaRecoveryCode.user_id == user.id,
                    ),
                )
                await db_session.execute(
                    delete(TrustedDevice).where(
                        TrustedDevice.user_id == user.id,
                    ),
                )
                await db_session.execute(
                    update(SessionRow)
                    .where(SessionRow.user_id == user.id)
                    .values(mfa_verified_at=None),
                )

                await AuditService(settings).record(
                    AuditLogRepository(db_session),
                    action="user.mfa_reset_by_admin",
                    target_type="user",
                    target_id=str(user.id),
                    result="success",
                    outcome="allow",
                    user_id=user.id,
                    source_ip="127.0.0.1",
                    metadata={"reset_via": "cli", "operator": operator_label},
                )
                await db_session.commit()
                print(  # noqa: T201
                    f"z4j reset-mfa: cleared MFA for {email}. They can "
                    "log in with their password; the sensitive-action "
                    "gate will require a fresh enrollment.",
                )
                return 0
        finally:
            await db.dispose()

    return asyncio.run(_run())


def _read_password_from_args(args: argparse.Namespace) -> str | None:
    """Shared helper for password reading (stdin vs flag)."""
    import sys

    if getattr(args, "password_stdin", False):
        password = sys.stdin.read().strip()
        if not password:
            print(  # noqa: T201
                "error: empty password from stdin",
                file=sys.stderr,
            )
            return None
        return password
    if getattr(args, "password", None):
        print(  # noqa: T201
            "WARNING: password passed on the command line is visible "
            "in shell history and `ps`. Prefer --password-stdin.",
            file=sys.stderr,
        )
        return args.password
    print(  # noqa: T201
        "error: must provide --password or --password-stdin",
        file=sys.stderr,
    )
    return None


def _run_check(args: argparse.Namespace) -> int:
    """Validate config + DB connectivity, and REPORT the stamped revision.

    It does not compare that revision against this build's head. Use
    ``z4j migrate current --check-heads`` for that; a database two minors
    behind still exits 0 here. This docstring claimed a head check for
    several releases while the code never performed one, which is how the
    same false claim reached the CLI help and three documentation pages.

    Non-destructive. Returns:
      0 = config loads, DB answers (whatever revision, including none)
      1 = config invalid
      2 = DB unreachable
      3 = alembic_version exists but is EMPTY (no revision stamped at all)
    """
    import asyncio
    import sys

    from sqlalchemy import text

    checks: list[tuple[str, str]] = []

    try:
        settings, engine = _build_settings_from_env()
        checks.append(("config", "OK"))
        # Surface the active environment so operators don't have to
        # infer it from a warning further down (added v1.0.14).
        # Marked production-mode rows with the secure-default tag,
        # dev-mode rows with the relaxed-defaults tag.
        env_tag = (
            "dev (loopback-only, relaxed cookies, no HSTS)"
            if settings.is_dev
            else "production (TLS-required, host validation, secure cookies)"
        )
        checks.append(("environment", f"{settings.environment}  -  {env_tag}"))
    except Exception as exc:
        print(  # noqa: T201
            f"z4j check: config INVALID: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    async def _db_check() -> int:
        from z4j_brain.persistence.database import DatabaseManager

        db = DatabaseManager(engine)
        try:
            try:
                async with db.session() as session:
                    await session.execute(text("SELECT 1"))
                checks.append(("database connectivity", "OK"))
            except Exception as exc:
                print(  # noqa: T201
                    f"z4j check: DB unreachable: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                return 2

            try:
                async with db.session() as session:
                    row = (
                        await session.execute(
                            text(
                                "SELECT version_num FROM alembic_version",
                            ),
                        )
                    ).first()
                    if row is None:
                        checks.append(("alembic version", "NOT INITIALIZED"))
                        print(  # noqa: T201
                            "z4j check: alembic_version table empty "
                            "(run `z4j migrate upgrade head`)",
                            file=sys.stderr,
                        )
                        return 3
                    checks.append(
                        ("alembic version", f"at {row[0]}"),
                    )
            except Exception as exc:
                # alembic_version table missing = fresh DB, not an error.
                checks.append(
                    ("alembic version", f"not present ({exc})"),
                )
        finally:
            await db.dispose()
        return 0

    rc = asyncio.run(_db_check())
    for name, status in checks:
        print(f"  {name:30s}  {status}")  # noqa: T201
    if rc == 0:
        print("z4j check: all green.")  # noqa: T201
    return rc


def _run_status(args: argparse.Namespace) -> int:
    """Print a high-level summary of brain state.

    Intended for quick "what's going on" visibility - not a full
    health check (see `check` for that). Counts rows across the
    user-visible tables and shows the revision currently stamped in
    ``alembic_version``. It does not claim that stamp equals this build's
    migration head.
    """
    import asyncio

    from sqlalchemy import func, select, text

    settings, engine = _build_settings_from_env()

    async def _run() -> int:
        from z4j_brain.persistence.database import DatabaseManager
        from z4j_brain.persistence.models import (
            Agent,
            AuditLog,
            Project,
            Task,
            User,
        )
        from z4j_brain.persistence.models import (
            Session as SessionModel,
        )

        db = DatabaseManager(engine)
        try:
            async with db.session() as session:

                async def _count(model: type) -> int | str:
                    """Return row count, or 'n/a' if the table doesn't
                    exist yet (fresh DB, never migrated). Each call uses
                    a SAVEPOINT so a missing table on one model doesn't
                    poison the session for the others.
                    """
                    try:
                        async with session.begin_nested():
                            row = (
                                await session.execute(
                                    select(func.count()).select_from(model),
                                )
                            ).scalar_one()
                            return int(row or 0)
                    except Exception:
                        return "n/a"

                users = await _count(User)
                projects = await _count(Project)
                agents = await _count(Agent)
                tasks = await _count(Task)
                sessions = await _count(SessionModel)
                audit_rows = await _count(AuditLog)

                try:
                    rev_row = (
                        await session.execute(
                            text(
                                "SELECT version_num FROM alembic_version",
                            ),
                        )
                    ).first()
                    rev = rev_row[0] if rev_row else "(none)"
                except Exception:
                    rev = "(alembic_version missing)"

            def _fmt(v: int | str) -> str:
                return f"{v:>8,}" if isinstance(v, int) else f"{v:>8}"

            env_tag = (
                "(loopback-only, relaxed cookies, no HSTS)"
                if settings.is_dev
                else "(TLS-required, host validation, secure cookies)"
            )
            print("z4j status")  # noqa: T201
            print(f"  version             {__version__}")  # noqa: T201
            print(f"  alembic revision    {rev}")  # noqa: T201
            print(f"  environment         {settings.environment}  {env_tag}")  # noqa: T201
            print(f"  database            {settings.database_url.split('@')[-1]}")  # noqa: T201
            print("")  # noqa: T201
            print("  row counts:")  # noqa: T201
            print(f"    users             {_fmt(users)}")  # noqa: T201
            print(f"    projects          {_fmt(projects)}")  # noqa: T201
            print(f"    agents            {_fmt(agents)}")  # noqa: T201
            print(f"    tasks             {_fmt(tasks)}")  # noqa: T201
            print(f"    sessions          {_fmt(sessions)}")  # noqa: T201
            print(f"    audit rows        {_fmt(audit_rows)}")  # noqa: T201
            if any(v == "n/a" for v in (users, projects, agents, tasks, sessions, audit_rows)):
                print("")  # noqa: T201
                print(  # noqa: T201
                    "  (n/a = table not present yet; run `z4j migrate upgrade head`)",
                )
            return 0
        finally:
            await db.dispose()

    return asyncio.run(_run())


def _canonical_admin_lookup(raw: str) -> str:
    """RM13: the canonical email the bootstrap store used, for the post-provision
    re-check lookup. Mirrors startup.py's validate_admin_email(); falls back to
    the raw value if the address no longer validates, so the re-check never
    crashes on an odd input."""
    from z4j_brain.domain.auth_service import validate_admin_email

    try:
        return validate_admin_email(raw)
    except Exception:
        return raw


async def _requested_admin_exists(users: Any, email: str) -> bool:
    """RM13 + cli:4265: does the SPECIFIC requested admin exist after bootstrap,
    as an ACTIVE ADMIN?

    The admin row is stored under validate_admin_email(email) (NFKC + casefold +
    IDNA punycode; see startup.py). get_by_email only strip()+casefold()s its
    argument, so looking up the RAW email would MISS a just-created non-ASCII /
    IDN-domain admin and the CLI would falsely report "not created" despite a
    successful provision. Look up the same canonical form the store used.

    cli:4265: an existence-only check reports success for a row that is not the
    provisioned admin -- an INACTIVE row, or a pre-existing NON-admin row under
    that email. Require ``is_admin`` AND ``is_active`` so only a real, usable
    admin counts. (The residual case a concurrent bootstrap picked a DIFFERENT
    password cannot be distinguished here without the password; the error message
    calls it out and the operator re-runs.)
    """
    user = await users.get_by_email(_canonical_admin_lookup(email))
    if user is None:
        return False
    return bool(getattr(user, "is_admin", False)) and bool(getattr(user, "is_active", False))


def _run_bootstrap_admin(args: argparse.Namespace) -> int:
    """Imperatively create the first admin user + default project.

    Fails with a clear message (exit 3) if the brain is already
    past first-boot. This command is for the narrow case where
    someone needs to provision an admin without running uvicorn -
    e.g. a Kubernetes ``Job`` running before the brain Deployment,
    or a CI step setting up a test environment.

    Password handling: ``--password-stdin`` is the recommended
    path (nothing visible in ``ps`` or shell history). The
    ``--password`` flag is available for non-interactive scripts
    that already handle secrets elsewhere but comes with a
    printed warning.
    """
    import asyncio
    import getpass
    import os

    from z4j_brain.auth.passwords import PasswordHasher
    from z4j_brain.domain.audit_service import AuditService
    from z4j_brain.domain.setup_service import SetupService
    from z4j_brain.persistence.database import (
        DatabaseManager,
        create_engine_from_settings,
    )
    from z4j_brain.settings import Settings
    from z4j_brain.startup import run_first_boot_check

    # Password source. Either stdin (preferred) or --password.
    if args.password_stdin:
        if sys.stdin.isatty():
            password = getpass.getpass("z4j admin password: ")
        else:
            password = sys.stdin.read().rstrip("\n")
    else:
        print(  # noqa: T201
            "warning: --password is visible in ps/shell-history; "
            "use --password-stdin in production scripts",
            file=sys.stderr,
        )
        password = args.password

    if not password:
        print("error: empty password", file=sys.stderr)  # noqa: T201
        return 2

    # Bootstrap env (DB URL + secrets) so Settings() + alembic can
    # construct. Fresh-install supported.
    _bootstrap_env_for_management_commands()

    # Auto-migrate so tables exist on a truly fresh install.
    # Idempotent: no-op if already at head.
    try:
        _auto_migrate()
    except SystemExit:
        print(  # noqa: T201
            "z4j bootstrap-admin: migrations failed. "
            "Run `z4j migrate upgrade head` manually first.",
            file=sys.stderr,
        )
        return 2

    # Thread the env-var path inside run_first_boot_check so the
    # CLI and the env-var mode produce byte-identical outcomes.
    # Password lands in the in-process holder instead of os.environ.
    # See cli.py serve
    # path comment + startup.py::set_cli_bootstrap_password for the
    # full rationale (avoids /proc/<pid>/environ leakage and
    # subprocess inheritance).
    os.environ["Z4J_BOOTSTRAP_ADMIN_EMAIL"] = args.email
    from z4j_brain import startup as _startup

    _startup.set_cli_bootstrap_password(password)
    if args.display_name:
        os.environ["Z4J_BOOTSTRAP_ADMIN_DISPLAY_NAME"] = args.display_name

    async def _bootstrap() -> int:
        settings = Settings()  # type: ignore[call-arg]
        db = DatabaseManager(create_engine_from_settings(settings))
        hasher = PasswordHasher(settings)
        audit = AuditService(settings)
        setup_service = SetupService(
            settings=settings,
            hasher=hasher,
            audit=audit,
        )

        # Detect "already set up" so we can return a distinct exit
        # code (3) instead of the generic 1. The shared
        # ``run_first_boot_check`` is idempotent and will simply
        # log + return in that case.
        from z4j_brain.persistence.repositories import UserRepository

        async with db.session() as session:
            users = UserRepository(session)
            if not await setup_service.is_first_boot(users):
                print(  # noqa: T201
                    "error: brain is already initialised; use the admin UI to manage users",
                    file=sys.stderr,
                )
                return 3

        await run_first_boot_check(
            db=db,
            setup_service=setup_service,
            settings=settings,
        )
        # M13: run_first_boot_check swallows validate-policy / DB errors (weak
        # password, connectivity) and may create NO admin. Re-check that an
        # admin now exists before reporting success, so a failed provision
        # does not exit 0 with a misleading "provisioned" line.
        async with db.session() as session:
            users = UserRepository(session)
            # RM13: confirm the SPECIFIC requested admin exists, not merely that
            # some user does. is_first_boot counts ANY user, so a concurrent
            # bootstrap that created a DIFFERENT admin would let this process
            # falsely report the requested one as provisioned.
            #
            if not await _requested_admin_exists(users, args.email):
                print(  # noqa: T201
                    f"error: admin {args.email} was not created (check the log "
                    "above for a weak-password or database error, or a "
                    "concurrent bootstrap that created a different admin), "
                    "then retry.",
                    file=sys.stderr,
                )
                return 1
        print(f"z4j: admin {args.email} provisioned")  # noqa: T201
        return 0

    return asyncio.run(_bootstrap())


_CONFIG_ENV_TEMPLATE = """\
# z4j runtime tunables.
# Loaded by the brain at startup via Pydantic Settings.
#
# Precedence (highest to lowest):
#   1. process environment variables (Z4J_*)
#   2. ./.env in the brain's working directory (dev convenience)
#   3. THIS FILE
#   4. code defaults
#
# Edit any value below to change runtime behavior. Restart the brain
# to pick up changes; see `z4j config show` for the effective values.
#
# Bootstrap settings (database URL, secrets, listen address, log
# format) live in $Z4J_HOME/secret.env or your environment - they
# are intentionally not in this file because the operator usually
# wants them sourced from a secret manager.
# Do not put credentials, tokens, or secrets in this 0644 tunables file.

# How long to retain task events before the periodic sweeper purges
# them. Increase for forensic / compliance environments. Decrease to
# reduce DB size if you only care about recent state.
# Z4J_EVENT_RETENTION_DAYS=30

# Audit-log retention. Independent from event retention because the
# audit log is required by SOC 2 / ISO 27001 controls; you typically
# want it longer.
# Z4J_AUDIT_RETENTION_DAYS=365

# How long the brain waits for a command frame to receive its
# command_ack before timing out. Bump if you have intentionally slow
# command handlers (e.g. a custom retry that holds the connection).
# Z4J_COMMAND_TIMEOUT_SECONDS=30

# How long an agent can be silent before the brain considers it
# disconnected. Drives the dashboard's online/offline indicator.
# Z4J_AGENT_OFFLINE_TIMEOUT_SECONDS=60

# Per-IP rate limit for the public setup endpoint (unauthenticated
# first-boot URL). Tighten if you suspect token-guessing attempts.
# Z4J_FIRST_BOOT_ATTEMPTS_PER_IP=30

# Maximum size of a single inbound payload (events, commands, etc.).
# Defaults to 8192 bytes. Increase only for environments that ship larger task
# arguments, but be aware of memory implications.
# Z4J_MAX_PAYLOAD_SIZE_BYTES=8192

# WebSocket frame limits. The smaller value is effective, so change both when
# increasing the default 1 MiB cap. Each must remain at least as large as the
# payload limit for WebSocket event frames to reach the payload validator.
# Z4J_MAX_WS_FRAME_BYTES=1048576
# Z4J_WS_MAX_FRAME_BYTES=1048576
"""


def _run_init(args: argparse.Namespace) -> int:
    """Scaffold ``$Z4J_HOME/config.env`` from a documented template.

    Idempotent: refuses to overwrite an existing file unless
    ``--force`` is passed. Mirrors the ``cargo init`` / ``git init``
    UX. Useful for homelab and dev installs; production deploys
    typically render their config.env from a Helm template or
    Ansible role.
    """
    config_env = z4j_home() / "config.env"
    if config_env.exists() and not args.force:
        print(  # noqa: T201
            f"z4j init: {config_env} already exists. Pass --force to "
            "overwrite, or edit the file directly. Run `z4j config show` "
            "to see the effective settings.",
            file=sys.stderr,
        )
        return 1

    ensure_z4j_home()
    config_env.write_text(_CONFIG_ENV_TEMPLATE, encoding="utf-8")
    with contextlib.suppress(OSError):
        config_env.chmod(0o644)
    print(  # noqa: T201
        f"z4j init: created {config_env} with the documented "
        "tunables template. Edit it to change runtime behavior, "
        "then restart `z4j serve`. Run `z4j config show` to see "
        "the effective settings any time.",
    )
    return 0


_CONFIG_SECRET_NAME_SUFFIXES: tuple[str, ...] = (
    "_secret",
    "_password",
    "_token",
    "_api_key",
    "_private_key",
    "_credential",
    "_credentials",
)
_CONFIG_SECRET_NAME_EXACT: frozenset[str] = frozenset(
    {
        "api_key",
        "credential",
        "credentials",
        "database_url",
        "password",
        "private_key",
        "secret",
        "token",
    }
)


def _config_field_looks_secret(field: str) -> bool:
    """Recognize plain-string credential carriers defensively.

    Most Settings secrets use ``SecretStr``. The name check closes the
    remaining gap for ``database_url`` and for a future field that carries a
    credential as plain ``str``. Suffix-only matching avoids masking benign
    counters such as ``first_boot_token_ttl_seconds``.
    """

    normalized = field.lower()
    return normalized in _CONFIG_SECRET_NAME_EXACT or any(
        normalized.endswith(suffix) for suffix in _CONFIG_SECRET_NAME_SUFFIXES
    )


def _config_source(field: str, settings: object, env: dict[str, str]) -> str:
    """Identify where a setting's effective value came from.

    Thin wrapper around :func:`z4j_brain.config_introspect.config_source`
    that preserves the original kwargs shape used by ``z4j config show``.
    The shared introspector reads immutable captured provenance and may
    therefore report ``secret.env`` for a secret field without reopening it.
    """
    from z4j_brain.config_introspect import config_source as _shared

    is_secret = False
    try:
        from pydantic import SecretStr

        value = getattr(settings, field, None)
        is_secret = isinstance(value, SecretStr) or _config_field_looks_secret(field)
    except Exception:  # noqa: S110  best-effort secret-field detection
        pass
    return _shared(field, env=env, is_secret_field=is_secret)


def _run_config_show(args: argparse.Namespace) -> int:
    """Print the brain's effective settings + their source.

    Useful for diagnosing "why isn't my change taking effect" without
    grepping log files. Secrets are masked unless --reveal-secrets is
    passed; the flag exists for one-off debugging and should never be
    redirected to a file or piped to a logging system.
    """
    import os

    from pydantic import SecretStr

    from z4j_brain.configuration import (
        capture_configuration,
        export_snapshot_environment,
        settings_from_snapshot,
    )

    try:
        snapshot = capture_configuration()
        export_snapshot_environment(snapshot)
        settings = settings_from_snapshot(snapshot)
    except Exception as exc:
        print(  # noqa: T201
            f"z4j config show: failed to load Settings: {exc}",
            file=sys.stderr,
        )
        return 2

    env = {k: v for k, v in os.environ.items() if k.startswith("Z4J_")}

    print(  # noqa: T201
        f"z4j config show: effective settings (Z4J_HOME={z4j_home()})\n",
    )
    field_width = max(
        (len(f) for f in settings.model_fields),
        default=20,
    )
    for field_name in sorted(settings.model_fields):
        value: Any = getattr(settings, field_name)
        is_secret = isinstance(value, SecretStr) or _config_field_looks_secret(field_name)
        if is_secret and not args.reveal_secrets:
            display = "***"
        elif isinstance(value, SecretStr):
            display = value.get_secret_value()
        elif isinstance(value, list) and not value:
            display = "[]"
        elif isinstance(value, dict) and not value:
            display = "{}"
        else:
            display = str(value)
        source = _config_source(field_name, settings, env)
        print(  # noqa: T201
            f"  {field_name:<{field_width}}  {display}  ({source})",
        )
    return 0


def _run_config_validate(args: argparse.Namespace) -> int:
    """Pre-flight a candidate config file before deploying it.

    Captures the file through the same identity-stable reader used at
    startup, then attempts to construct :class:`Settings`. Exits 0 if
    the captured document would build a valid Settings.
    """

    candidate = Path(args.path) if args.path else (z4j_home() / "config.env")
    from z4j_brain.configuration import (
        ConfigurationCaptureError,
        capture_explicit_configuration_file,
        configuration_snapshot_from_values,
        settings_from_snapshot,
        supported_settings_environment_keys,
        validate_non_settings_tunable_values,
    )

    try:
        parsed = capture_explicit_configuration_file(candidate)
    except ConfigurationCaptureError as exc:
        print(  # noqa: T201
            f"z4j config validate: cannot safely capture {candidate}: {exc}",
            file=sys.stderr,
        )
        return 2

    supported = supported_settings_environment_keys()
    unsupported = sorted(key for key in parsed if key not in supported)
    if unsupported:
        print(  # noqa: T201
            f"z4j config validate: unsupported setting key(s): {unsupported!r}",
            file=sys.stderr,
        )
        return 1

    try:
        validate_non_settings_tunable_values(parsed)
    except ConfigurationCaptureError as exc:
        print(  # noqa: T201
            f"z4j config validate: {candidate} failed validation: {exc}",
            file=sys.stderr,
        )
        return 1

    # ``config.env`` is a tunables-only layer. Supply inert bootstrap
    # placeholders for required values that normally come from secret.env or
    # the process environment, then use the exact startup decoder so list and
    # mapping values are parsed as JSON rather than passed as raw strings.
    bootstrap = {
        "Z4J_SECRET": "x" * 48,
        "Z4J_SESSION_SECRET": "y" * 48,
        "Z4J_AUDIT_CHAIN_SECRET": "z" * 48,
        "Z4J_ALLOWED_HOSTS": '["localhost"]',
        "Z4J_PUBLIC_URL": "https://localhost",
    }
    structured_database = {
        "Z4J_DATABASE_HOST",
        "Z4J_DATABASE_PORT",
        "Z4J_DATABASE_USER",
        "Z4J_DATABASE_PASSWORD",
        "Z4J_DATABASE_NAME",
    }
    if "Z4J_DATABASE_URL" not in parsed and not (structured_database & parsed.keys()):
        bootstrap["Z4J_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
    candidate_values = bootstrap | parsed

    try:
        snapshot = configuration_snapshot_from_values(
            candidate_values,
            source=str(candidate),
        )
        settings_from_snapshot(snapshot)
    except Exception as exc:
        print(  # noqa: T201
            f"z4j config validate: {candidate} failed validation: {exc}",
            file=sys.stderr,
        )
        return 1

    print(  # noqa: T201
        f"z4j config validate: {candidate} tunables are valid "
        f"({len(parsed)} setting(s) parsed; runtime bootstrap sources not checked).",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
