"""Per-cert project-binding enforcement for ``SchedulerService`` RPCs.

Audit fix M-5 (Apr 2026 security audit). The
:class:`SchedulerAllowlistInterceptor` validates that the peer cert's
CN appears on the operator-configured allow-list, but the original
design left every allow-listed CN with cross-project authority - one
scheduler cert could drive RPCs against any project the brain knew
about. For multi-tenant deployments that's a real authorization gap.

This module narrows that authority. Operators populate
``Z4J_SCHEDULER_GRPC_CN_PROJECT_BINDINGS`` with a CN → list-of-slugs
map; each handler that has a project context (FireSchedule,
AcknowledgeFireResult, ListSchedules, WatchSchedules) calls
:func:`enforce_cn_project_binding` after resolving the request's
project. A bound CN whose request targets an unbound project is
rejected with ``PERMISSION_DENIED``.

CNs absent from the binding map keep their legacy cross-project
authority - the binding is opt-in per-cert so a single configuration
change doesn't break fleet-wide schedulers.

Project lookup is by ``project_id`` (UUID) → ``slug``. Slug
resolution caches at process scope because slugs are immutable in
practice; if an operator renames a project the cache is bounded by
process lifetime.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID

import grpc

if TYPE_CHECKING:  # pragma: no cover
    from z4j_brain.persistence.database import DatabaseManager

from z4j_brain.scheduler_grpc.auth import _normalise_cn

logger = logging.getLogger("z4j.brain.scheduler_grpc.binding")


def extract_peer_cns(context: grpc.aio.ServicerContext) -> set[str]:
    """Pull every CN/SAN string off the peer cert as a normalised set.

    Mirrors :func:`z4j_brain.scheduler_grpc.auth._enforce_cn`'s logic
    so the binding check sees the same identities the allow-list
    interceptor saw. Duplicated rather than imported to keep the
    interceptor module a single-purpose surface.
    """
    auth_ctx = context.auth_context()
    candidates: set[str] = set()

    def _entries(key: str) -> list:
        return list(auth_ctx.get(key, [])) + list(
            auth_ctx.get(key.encode(), []),
        )

    for key in ("x509_subject_alternative_name", "x509_common_name"):
        for entry in _entries(key):
            try:
                candidates.add(
                    entry.decode() if isinstance(entry, bytes) else str(entry),
                )
            except UnicodeDecodeError:
                continue

    return {_normalise_cn(c) for c in candidates}


async def resolve_project_slug(
    *,
    project_id: UUID,
    db: DatabaseManager,
) -> str | None:
    """Look up a project's slug by id. Returns ``None`` if not found.

    A small per-process LRU cache would help here, but slug lookups
    happen at most once per FireSchedule - and the project row is
    almost always already in the connection pool's hot set. Skip the
    cache for v1 simplicity.
    """
    from sqlalchemy import select  # noqa: PLC0415

    from z4j_brain.persistence.models import Project  # noqa: PLC0415

    async with db.session() as session:
        result = await session.execute(
            select(Project.slug).where(Project.id == project_id),
        )
        row = result.scalar_one_or_none()
    return row


async def enforce_cn_project_binding(
    *,
    context: grpc.aio.ServicerContext,
    project_id: UUID,
    bindings: dict[str, list[str]],
    db: DatabaseManager,
) -> None:
    """Abort the RPC if the peer's CN is bound and the project isn't.

    No-op when ``bindings`` is empty (legacy mode) or when none of the
    peer's CNs appears in ``bindings`` (this CN is unbound and keeps
    cross-project authority).

    When at least one of the peer's CNs IS bound, the request's
    project slug must appear in the union of every bound CN's slug
    list. This handles the case where one cert carries multiple SANs:
    if any SAN maps to a binding that includes the project, the RPC
    is allowed.
    """
    if not bindings:
        return

    peer_cns = extract_peer_cns(context)
    bound_for_peer = [cn for cn in peer_cns if cn in bindings]
    if not bound_for_peer:
        # None of the peer's CNs are bound - keep cross-project
        # authority for unbound certs.
        return

    project_slug = await resolve_project_slug(project_id=project_id, db=db)
    if project_slug is None:
        # Project doesn't exist. Don't reveal that distinction at the
        # auth boundary; treat as denied.
        logger.warning(
            "z4j.brain.scheduler_grpc.binding: rejected RPC for "
            "unknown project_id=%s from CN(s)=%r",
            project_id, sorted(bound_for_peer),
        )
        await context.abort(
            grpc.StatusCode.PERMISSION_DENIED,
            "scheduler not authorised for this project",
        )

    allowed_slugs: set[str] = set()
    for cn in bound_for_peer:
        allowed_slugs.update(bindings.get(cn, []))

    if project_slug not in allowed_slugs:
        logger.warning(
            "z4j.brain.scheduler_grpc.binding: rejected RPC; CN(s)=%r "
            "are bound but project %r is not in their binding "
            "list (allowed=%r)",
            sorted(bound_for_peer), project_slug, sorted(allowed_slugs),
        )
        await context.abort(
            grpc.StatusCode.PERMISSION_DENIED,
            "scheduler not authorised for this project",
        )


async def filter_project_ids_by_binding(
    *,
    context: grpc.aio.ServicerContext,
    bindings: dict[str, list[str]],
    db: DatabaseManager,
) -> set[UUID] | None:
    """Resolve the bound project_ids for the peer's CN(s).

    Used by ListSchedules / WatchSchedules when the request omits
    ``project_id`` - the handler narrows its query to only the bound
    projects so a bound CN never sees rows it doesn't own.

    Returns:
        - ``None`` when ``bindings`` is empty OR when none of the
          peer's CNs is bound (cross-project authority preserved).
        - A set of project_ids when at least one CN is bound. The
          handler must restrict its query to ``Schedule.project_id IN
          (set)``. An empty set means "bound but no projects exist
          for any of these slugs" → return zero rows.
    """
    if not bindings:
        return None
    peer_cns = extract_peer_cns(context)
    bound_for_peer = [cn for cn in peer_cns if cn in bindings]
    if not bound_for_peer:
        return None

    allowed_slugs: set[str] = set()
    for cn in bound_for_peer:
        allowed_slugs.update(bindings.get(cn, []))
    if not allowed_slugs:
        return set()

    from sqlalchemy import select  # noqa: PLC0415

    from z4j_brain.persistence.models import Project  # noqa: PLC0415

    async with db.session() as session:
        result = await session.execute(
            select(Project.id).where(Project.slug.in_(allowed_slugs)),
        )
        return {row for row in result.scalars().all()}


__all__ = [
    "enforce_cn_project_binding",
    "extract_peer_cns",
    "filter_project_ids_by_binding",
    "resolve_project_slug",
]
