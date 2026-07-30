"""Boundary-F transaction-ownership guards for non-request audit writers.

SQLite cannot safely upgrade a deferred read transaction into the serialized
writer transaction required by the authenticated audit chain.  Request
dependencies already open write requests correctly, but background workers,
WebSocket/gRPC handlers, GET-side audit logging, and CLI commands own their
sessions directly.  Keep that ownership inventory explicit and
mutation-sensitive here.
"""

from __future__ import annotations

import ast
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

SOURCE_ROOT = Path(__file__).parents[2] / "src" / "z4j_brain"

# Each entry names a source-level owner that performs an authenticated audit
# write directly or calls a service (dispatcher/automation executor) that does.
# The value is the exact number of DatabaseManager write sessions the owner
# must open.  Reverting any one of these ``write=True`` arguments makes its
# parametrized case fail.
IMMEDIATE_WRITER_OWNERS = {
    ("api/openapi_route.py", "_audit_schema_access"): 1,
    ("cli.py", "_run_projects_rewrite_scheduler"): 1,
    ("cli.py", "_run_reset_mfa"): 1,
    ("domain/workers/agent_health.py", "AgentHealthWorker._alert_offline"): 1,
    ("domain/workers/agent_health.py", "AgentHealthWorker._fire_automation"): 1,
    (
        "domain/workers/automation_outbox.py",
        "AutomationOutboxDrainWorker._replay_one",
    ): 1,
    ("domain/workers/misfire_detector.py", "MisfireDetector._alert_misfire"): 1,
    ("domain/workers/misfire_detector.py", "MisfireDetector._fire_automation"): 1,
    ("domain/workers/pending_fires.py", "PendingFiresReplayWorker.tick"): 1,
    ("domain/workers/reconciliation.py", "ReconciliationWorker.tick"): 1,
    (
        "domain/workers/schedule_circuit_breaker.py",
        "ScheduleCircuitBreakerWorker._disable_and_audit",
    ): 1,
    ("middleware/_audit_queue.py", "AuditQueue._write_one"): 1,
    (
        "scheduler_grpc/handlers.py",
        "SchedulerServiceImpl.AcknowledgeFireResult",
    ): 1,
    ("scheduler_grpc/handlers.py", "SchedulerServiceImpl.FireSchedule"): 1,
    ("websocket/frame_router.py", "FrameRouter._dispatch_automation"): 1,
    ("websocket/frame_router.py", "FrameRouter._run_control_persist"): 1,
    ("websocket/gateway.py", "ws_agent"): 1,
}


def _function_nodes(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def visit(
        node: ast.AST,
        parents: tuple[str, ...] = (),
    ) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, (*parents, child.name))
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = ".".join((*parents, child.name))
                found[qualname] = child
                # Nested functions are intentionally included.  The CLI
                # command owners contain their async transaction body in a
                # nested ``_run`` function.
                visit(child, (*parents, child.name))
                continue
            visit(child, parents)

    visit(tree)
    return found


def _immediate_session_count(node: ast.AST) -> int:
    count = 0
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Call):
            continue
        if not (isinstance(candidate.func, ast.Attribute) and candidate.func.attr == "session"):
            continue
        write = next(
            (keyword.value for keyword in candidate.keywords if keyword.arg == "write"),
            None,
        )
        if isinstance(write, ast.Constant) and write.value is True:
            count += 1
    return count


@pytest.mark.parametrize(
    ("relative_path", "qualname", "expected_count"),
    [(*owner, count) for owner, count in sorted(IMMEDIATE_WRITER_OWNERS.items())],
)
def test_non_request_audit_writer_starts_immediate_sqlite_transaction(
    relative_path: str,
    qualname: str,
    expected_count: int,
) -> None:
    tree = ast.parse((SOURCE_ROOT / relative_path).read_text(encoding="utf-8"))
    functions = _function_nodes(tree)

    assert qualname in functions, (
        f"{relative_path}:{qualname} disappeared; reclassify its audit write owner"
    )
    assert _immediate_session_count(functions[qualname]) == expected_count


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "expected_write"),
    [
        ("GET", False),
        ("HEAD", False),
        ("OPTIONS", False),
        ("POST", True),
        ("PUT", True),
        ("PATCH", True),
        ("DELETE", True),
    ],
)
async def test_api_request_dependency_owns_the_whole_sqlite_write_unit(
    method: str,
    expected_write: bool,
) -> None:
    """Mutation requests reserve the writer before any dependency DB read."""
    from starlette.requests import Request
    from z4j_brain.api.deps import get_session

    writes: list[bool] = []
    yielded = object()

    class _Database:
        @asynccontextmanager
        async def session(self, *, write: bool = False):  # type: ignore[no-untyped-def]
            writes.append(write)
            yield yielded

    request = Request(
        {
            "type": "http",
            "method": method,
            "path": "/api/v1/test",
            "headers": [],
            "app": SimpleNamespace(
                state=SimpleNamespace(db=_Database()),
            ),
        },
    )
    dependency: Any = get_session(request)
    assert await anext(dependency) is yielded
    await dependency.aclose()

    assert writes == [expected_write]
