"""Executable gates for the event loop the PostgreSQL backup ceremony runs on.

psycopg refuses to run against Windows' ProactorEventLoop, and a console entry
point gets exactly that from a bare ``asyncio.run``. ``z4j backup`` against
PostgreSQL therefore could not reach the server at all on Windows, while an
operator whose entry point happened to supply a selector loop (uvicorn does)
saw nothing wrong.

The loop is chosen per operation rather than by installing a process-wide
policy, because z4j is a library as well as a CLI and the selector loop the
backup needs has no subprocess support. Both halves get a gate here: the
ceremony really runs on the loop backup.py picked, and picking it leaves the
ambient loop of the embedding process alone.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from z4j_brain import backup, management_restore_postgres

_WINDOWS_ONLY = pytest.mark.skipif(
    os.name != "nt",
    reason="only Windows has a ProactorEventLoop for psycopg to refuse",
)


def _default_loop_type() -> type[asyncio.AbstractEventLoop]:
    """Report the loop type an unaware caller would get right now."""

    loop = asyncio.new_event_loop()
    try:
        return type(loop)
    finally:
        loop.close()


def test_the_ceremony_runs_on_the_loop_backup_chose(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The dump must not be driven by a loop nobody vetted.

    Going back through the ceremony module's own synchronous wrapper would
    hand the work to whatever loop ``asyncio.run`` builds from the ambient
    policy, which is the defect. Runs on every platform: the loop identity
    is checked, not the loop's flavour.
    """

    created: list[asyncio.AbstractEventLoop] = []
    observed: list[asyncio.AbstractEventLoop] = []

    def factory() -> asyncio.AbstractEventLoop:
        loop = asyncio.SelectorEventLoop()
        created.append(loop)
        return loop

    async def fake_run_backup(database_url: str, output: Path) -> None:
        observed.append(asyncio.get_running_loop())

    monkeypatch.setattr(
        management_restore_postgres,
        "_pinned_client_loop_factory",
        lambda: factory,
    )
    monkeypatch.setattr(
        management_restore_postgres,
        "_run_backup",
        fake_run_backup,
    )

    backup.backup_postgres(
        "postgresql+asyncpg://z4j:pw@127.0.0.1:5432/z4j",
        tmp_path / "z4j.dump",
    )

    assert len(created) == 1
    assert observed == created


@_WINDOWS_ONLY
def test_the_backup_loop_is_one_psycopg_accepts() -> None:
    """Assert the exact predicate psycopg applies before it will connect."""

    proactor = getattr(asyncio, "ProactorEventLoop", None)
    assert proactor is not None

    async def running_loop() -> asyncio.AbstractEventLoop:
        return asyncio.get_running_loop()

    loop = management_restore_postgres._run_pinned_client(running_loop())

    assert not isinstance(loop, proactor)


@_WINDOWS_ONLY
def test_choosing_the_loop_leaves_the_embedding_process_alone() -> None:
    """A process-wide policy would fix the CLI and break its embedders.

    An application that embeds z4j gets its loop from the same ambient
    default, and the selector loop this backup needs cannot spawn
    subprocesses, so the choice has to stay inside the operation. The
    check runs mid-ceremony as well as after it, because a policy swapped
    in and restored around the call would look clean from the outside.
    """

    during: list[type[asyncio.AbstractEventLoop]] = []

    async def observe() -> None:
        during.append(_default_loop_type())

    before = _default_loop_type()
    management_restore_postgres._run_pinned_client(observe())
    after = _default_loop_type()

    assert during == [before]
    assert after is before


def test_management_backup_entrypoint_delegates_to_pinned_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Execute the second public backup wrapper and observe its runner."""

    marker = object()
    observed: list[object] = []

    def capture(operation: object) -> None:
        observed.append(operation)

    monkeypatch.setattr(
        management_restore_postgres,
        "_run_backup",
        lambda database_url, output: marker,
    )
    monkeypatch.setattr(
        management_restore_postgres,
        "_run_pinned_client",
        capture,
    )

    management_restore_postgres.backup_postgres_database(
        "postgresql+asyncpg://z4j:pw@127.0.0.1:5432/z4j",
        tmp_path / "z4j.dump",
    )

    assert observed == [marker]
