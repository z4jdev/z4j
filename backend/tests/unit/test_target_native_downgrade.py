"""A downgrade is admissible when no row was written since the target wrote it.

The container ceremony rewrites cursors and asserts the target will agree with
them, which is a claim strong enough to need an image, a registry and a
signature. This path makes no such claim, because it rewrites nothing. It admits
the downgrade only when every reserved row still carries the identity the target
itself wrote, in which case going back restores exactly the state the target
last saw.

That is the ordinary case rather than an exotic one. Nothing in this release
re-stamps a row: the write sites are creation and owner cutover, and neither the
fire path nor the cursor path touches the column. So an installation that
upgraded and then merely ran is admissible.

These tests hold the two paths apart. Without the declaration the container
ceremony is reached unchanged, and its refusal is the one that fires. With it,
the container ceremony is not consulted at all.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import create_engine, text

from .test_previous_release_restore import (  # type: ignore[import-not-found]
    _PREVIOUS_RELEASE_HEAD,
    _alembic_config,
    _populate,
    previous_release_install,
)

# Re-exported so pytest resolves it here. Importing the fixture is what makes it
# visible in this module; the name is otherwise unused.
__all__ = ["previous_release_install"]

_ENV = "Z4J_ROLLBACK_TARGET_FINGERPRINT"
# Stands in for whatever the release being returned to computes. Its only
# required property is that it is a well-formed digest that is not this
# release's, which is exactly the property a real target's value has.
_TARGET = "0d62d10e3a145979ce69ba4460d12725a01cd0a653daff81b8be711871a6c8bd"


def _upgrade_and_populate(
    async_url: str,
    config,
    *,
    names: tuple[str, ...],
    written_by: str,
) -> None:
    """Create rows carrying the identity a different release would have written.

    A real upgrade adds columns and rewrites nothing, so rows keep the older
    release's identity. That state cannot be faked afterwards: the schedules
    table is guarded and a raw UPDATE is refused by z4j_schedule_guard, which
    is Boundary-D working correctly. So the closure is substituted at write
    time instead, which reproduces the same rows through the same guarded path
    rather than going around it.
    """

    from z4j_brain.persistence.repositories import schedule_control as control

    command.upgrade(config, "head")
    original = control.cadence_runtime_fingerprint
    control.cadence_runtime_fingerprint = lambda: written_by
    try:
        asyncio.run(
            _populate(
                async_url,
                project_id=uuid.uuid4(),
                slug="target-native",
                schedule_names=names,
                with_external_executor=False,
            ),
        )
    finally:
        control.cadence_runtime_fingerprint = original


def _reserved_fingerprints(sync_url: str) -> set[str]:
    engine = create_engine(sync_url)
    with engine.begin() as connection:
        rows = connection.execute(
            text(
                "SELECT cadence_runtime_fingerprint FROM schedules "
                "WHERE scheduler = 'z4j-scheduler'",
            ),
        ).scalars()
        observed = {str(value) for value in rows}
    engine.dispose()
    return observed


def _head(sync_url: str) -> str:
    engine = create_engine(sync_url)
    with engine.begin() as connection:
        head = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    engine.dispose()
    return str(head)


def test_untouched_rows_admit_the_downgrade(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ordinary case: upgraded, ran, never re-saved a schedule."""

    config, sync_url, async_url = previous_release_install
    _upgrade_and_populate(async_url, config, written_by=_TARGET, names=("alpha", "beta"))
    assert _reserved_fingerprints(sync_url) == {_TARGET}

    monkeypatch.setenv(_ENV, _TARGET)
    command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)

    assert _head(sync_url) == _PREVIOUS_RELEASE_HEAD


def test_without_the_declaration_the_container_ceremony_still_governs(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absent the declaration nothing changed, including the refusal."""

    config, _sync_url, async_url = previous_release_install
    _upgrade_and_populate(async_url, config, written_by=_TARGET, names=("alpha",))

    monkeypatch.delenv(_ENV, raising=False)
    with pytest.raises(
        CommandError,
        match="rollback compatibility image authority is not finalized",
    ):
        command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)


def test_a_row_written_by_this_release_refuses(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One re-saved schedule is enough, and the refusal says which way out."""

    config, sync_url, async_url = previous_release_install
    _upgrade_and_populate(async_url, config, written_by=_TARGET, names=("alpha",))
    # A second schedule saved under THIS release, which is exactly what an
    # operator editing a schedule after upgrading produces.
    asyncio.run(
        _populate(
            async_url,
            project_id=uuid.uuid4(),
            slug="edited-here",
            schedule_names=("beta",),
            with_external_executor=False,
        ),
    )
    assert len(_reserved_fingerprints(sync_url)) == 2

    monkeypatch.setenv(_ENV, _TARGET)
    with pytest.raises(CommandError, match="different cadence identities"):
        command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)


def test_a_declaration_that_disagrees_with_the_rows_refuses(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Declaring a target the rows were not written for is the dangerous case.

    Handing those rows to that target disables every schedule it cannot agree
    with, so this refuses rather than proceeding.
    """

    config, _sync_url, async_url = previous_release_install
    _upgrade_and_populate(async_url, config, written_by=_TARGET, names=("alpha",))

    monkeypatch.setenv(_ENV, "c" * 64)
    with pytest.raises(CommandError, match="but Z4J_ROLLBACK_TARGET_FINGERPRINT declares"):
        command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)


def test_declaring_this_releases_own_fingerprint_refuses(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """That describes staying here, not going back, so it cannot be a target."""

    from z4j_brain.domain.schedule_cadence import cadence_runtime_fingerprint

    config, _sync_url, async_url = previous_release_install
    _upgrade_and_populate(async_url, config, written_by=_TARGET, names=("alpha",))

    monkeypatch.setenv(_ENV, cadence_runtime_fingerprint())
    with pytest.raises(CommandError, match="does not describe a downgrade"):
        command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)


@pytest.mark.parametrize("bad", ["", "   ", "not-a-digest", "abc", "0" * 63, "0" * 65])
def test_a_malformed_declaration_refuses(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
    bad: str,
) -> None:
    """An empty value falls through to the container path; the rest refuse."""

    config, _sync_url, async_url = previous_release_install
    _upgrade_and_populate(async_url, config, written_by=_TARGET, names=("alpha",))

    monkeypatch.setenv(_ENV, bad)
    expected = (
        "rollback compatibility image authority is not finalized"
        if not bad.strip()
        else "is not a sha256 digest"
    )
    with pytest.raises(CommandError, match=expected):
        command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)


def test_no_reserved_schedules_needs_no_declaration(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An install with nothing to disagree about was always admissible."""

    config, sync_url, _async_url = previous_release_install
    command.upgrade(config, "head")

    monkeypatch.delenv(_ENV, raising=False)
    command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)
    assert _head(sync_url) == _PREVIOUS_RELEASE_HEAD


def test_an_uppercase_declaration_is_accepted_and_still_compared(
    previous_release_install: tuple[object, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hex is case-insensitive, so case must not decide whether a rollback runs.

    It is normalized rather than rejected, and the comparison that matters
    still happens: an uppercase digest of the WRONG value is still refused.
    """

    config, sync_url, async_url = previous_release_install
    _upgrade_and_populate(async_url, config, written_by=_TARGET, names=("alpha",))

    monkeypatch.setenv(_ENV, _TARGET.upper())
    command.downgrade(_alembic_config(), _PREVIOUS_RELEASE_HEAD)
    assert _head(sync_url) == _PREVIOUS_RELEASE_HEAD
