"""The declared PostgreSQL restore contract for the configured prior head.

These unit tests exercise head classification, manifest derivation, and schema
digest tables.  They do not execute an artifact from an earlier release and are
therefore contract tests, not previous-binary compatibility evidence.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from z4j_brain import management_restore as sqlite_restore_module
from z4j_brain import management_restore_postgres as postgres_restore_module
from z4j_brain.management_restore import (
    _LEGACY_SOURCE_HEAD,
    _PREVIOUS_RELEASE_HEAD,
    _SQLITE_SOURCE_SCHEMA_DIGESTS,
    DatabaseRestoreRefused,
)
from z4j_brain.management_restore import (
    _assert_activated_boundary_singleton as _sqlite_assert_activated,
)
from z4j_brain.schema_transition import RELEASE_MIGRATION_HEAD

_ARCHIVE = Path("/nonexistent/previous-release-head.dump")
_TOOL = postgres_restore_module._Tool(
    name="pg_restore",
    path=Path("/nonexistent/pg_restore"),
    digest="0" * 64,
    identity=(1, 2, 3),
    version="pg_restore (PostgreSQL) 18.0",
    major=18,
)


def _write_flat_migration_layout(
    package_directory: Path,
    *,
    missing: str | None = None,
) -> Path:
    """Model the flat ``site-packages/z4j_brain`` wheel layout."""

    package_directory.mkdir(parents=True)
    module_path = package_directory / "management_restore.py"
    module_path.write_text("# installed module\n", encoding="utf-8")
    if missing != "alembic.ini":
        (package_directory / "alembic.ini").write_text(
            "[alembic]\nscript_location = must-be-overridden\n",
            encoding="utf-8",
        )
    if missing != "migrations":
        migrations = package_directory / "migrations"
        migrations.mkdir()
        if missing != "migrations/env.py":
            (migrations / "env.py").write_text("# migration environment\n", encoding="utf-8")
        if missing != "migrations/versions":
            (migrations / "versions").mkdir()
    return module_path


def test_restore_migrations_resolve_from_flat_installed_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restore never reaches back into the source-tree ``backend/src`` layout."""

    package_directory = tmp_path / "site-packages" / "z4j_brain"
    module_path = _write_flat_migration_layout(package_directory)
    monkeypatch.setattr(sqlite_restore_module, "__file__", str(module_path))

    config = sqlite_restore_module._restore_migration_config()

    assert Path(config.config_file_name) == package_directory / "alembic.ini"
    assert config.get_main_option("script_location") == str(package_directory / "migrations")
    assert postgres_restore_module._restore_migration_config is (
        sqlite_restore_module._restore_migration_config
    )


@pytest.mark.parametrize(
    "missing",
    ("alembic.ini", "migrations", "migrations/env.py", "migrations/versions"),
)
def test_restore_migrations_refuse_incomplete_installed_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    """An incomplete wheel cannot fall back to coincidental checkout assets."""

    package_directory = tmp_path / "site-packages" / "z4j_brain"
    module_path = _write_flat_migration_layout(package_directory, missing=missing)
    monkeypatch.setattr(sqlite_restore_module, "__file__", str(module_path))

    with pytest.raises(DatabaseRestoreRefused, match="bundled restore migration asset is missing"):
        sqlite_restore_module._restore_migration_config()


def _install_extraction(
    monkeypatch: pytest.MonkeyPatch,
    tables: dict[str, list[dict[str, str | None]]],
) -> None:
    def fake_extract(
        pg_restore: Any,
        archive: Path,
        table_name: str,
    ) -> list[dict[str, str | None]]:
        return [dict(row) for row in tables.get(table_name, [])]

    monkeypatch.setattr(
        postgres_restore_module,
        "_extract_table",
        fake_extract,
    )


def _copy_stream(
    table_name: str,
    rows: list[dict[str, str | None]],
) -> bytes:
    """Render rows the way ``pg_restore --data-only`` emits them."""

    if not rows:
        return b""
    columns = list(rows[0])
    lines = [f"COPY public.{table_name} ({', '.join(columns)}) FROM stdin;"]
    lines.extend(
        "\t".join("\\N" if row[column] is None else str(row[column]) for column in columns)
        for row in rows
    )
    lines.append("\\.")
    return ("\n".join(lines) + "\n").encode()


def _install_copy_extraction(
    monkeypatch: pytest.MonkeyPatch,
    tables: dict[str, list[dict[str, str | None]]],
) -> None:
    """Feed real COPY text through the real extraction and ordering path.

    Stubbing ``_extract_table`` itself would skip the very code that decides
    row order, so a determinism claim made over that stub proves nothing.
    """

    def fake_run(
        tool: Any,
        arguments: list[str],
        *,
        environment: dict[str, str],
        text_output: bool,
    ) -> subprocess.CompletedProcess[Any]:
        requested = [
            argument.removeprefix("--table=")
            for argument in arguments
            if argument.startswith("--table=")
        ]
        assert len(requested) == 1
        return subprocess.CompletedProcess(
            args=list(arguments),
            returncode=0,
            stdout=_copy_stream(requested[0], tables.get(requested[0], [])),
            stderr=b"",
        )

    monkeypatch.setattr(
        postgres_restore_module,
        "_run_identity_bound",
        fake_run,
    )


def _boundary_d_tables(
    *,
    revision: str = "41",
    epoch: str = "7",
) -> dict[str, list[dict[str, str | None]]]:
    return {
        "alembic_version": [{"version_num": _PREVIOUS_RELEASE_HEAD}],
        "schedule_revision_state": [
            {
                "singleton_id": "schedule-revision",
                "current_revision": revision,
                "change_log_pruned_through": "12",
                "guard_version": "1",
            },
        ],
        "schedule_external_epoch_allocator": [
            {
                "singleton_id": "schedule-external-epoch",
                "current_epoch_number": epoch,
                "guard_version": "1",
            },
        ],
        "schedule_external_streams": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "current_epoch_uuid": "22222222-2222-2222-2222-222222222222",
                "current_epoch_number": "3",
                "phase": "ACTIVE",
                "authorized_adapter_instance_id": "adapter-a",
                "executor_agent_id": "33333333-3333-3333-3333-333333333333",
                "executor_registry_owner_id": "owner-a",
                "executor_session_generation": "4",
                "executor_worker_id": "worker-a",
            },
        ],
        "schedule_external_stream_epochs": [
            {
                "stream_id": "11111111-1111-1111-1111-111111111111",
                "epoch_uuid": "22222222-2222-2222-2222-222222222222",
                "epoch_number": "3",
                "phase": "ACTIVE",
                "authorized_adapter_instance_id": "adapter-a",
                "executor_agent_id": "33333333-3333-3333-3333-333333333333",
                "executor_registry_owner_id": "owner-a",
                "executor_session_generation": "4",
                "executor_worker_id": "worker-a",
            },
        ],
        "schedule_external_control_operations": [],
    }


def _stream(index: int) -> dict[str, str | None]:
    marker = str(index) * 2
    return {
        "id": f"{marker * 4}-{marker * 2}-{marker * 2}-{marker * 2}-{marker * 6}",
        "current_epoch_uuid": (f"{marker * 4}-{marker * 2}-{marker * 2}-{marker * 2}-{marker * 6}"),
        "current_epoch_number": str(index),
        "phase": "ACTIVE",
        "authorized_adapter_instance_id": f"adapter-{index}",
        "executor_agent_id": (f"{marker * 4}-{marker * 2}-{marker * 2}-{marker * 2}-{marker * 6}"),
        "executor_registry_owner_id": f"owner-{index}",
        "executor_session_generation": str(index),
        "executor_worker_id": f"worker-{index}",
    }


def _epoch(number: int) -> dict[str, str | None]:
    marker = f"{number:02d}"
    return {
        "stream_id": (f"{marker * 4}-{marker * 2}-{marker * 2}-{marker * 2}-{marker * 6}"),
        "epoch_uuid": (f"{marker * 4}-{marker * 2}-{marker * 2}-{marker * 2}-{marker * 6}"),
        "epoch_number": str(number),
        "phase": "ACTIVE",
        "authorized_adapter_instance_id": f"adapter-{number}",
        "executor_agent_id": (f"{marker * 4}-{marker * 2}-{marker * 2}-{marker * 2}-{marker * 6}"),
        "executor_registry_owner_id": f"owner-{number}",
        "executor_session_generation": str(number),
        "executor_worker_id": f"worker-{number}",
    }


def _operation(index: int, *, status: str) -> dict[str, str | None]:
    marker = f"{index:02d}"
    identifier = f"{marker * 4}-{marker * 2}-{marker * 2}-{marker * 2}-{marker * 6}"
    return {
        "id": identifier,
        "command_id": identifier,
        "stream_id": identifier,
        "epoch_uuid": identifier,
        "epoch_number": str(index),
        "status": status,
        "adapter_instance_id": f"adapter-{index}",
        "agent_id": identifier,
        "registry_owner_id": f"owner-{index}",
        "session_generation": str(index),
        "dispatch_lease": identifier,
    }


def _multi_row_boundary_d_tables() -> dict[str, list[dict[str, str | None]]]:
    """A previous-head archive whose stream tables hold more than one row.

    One row per table cannot expose an ordering defect, so every table that
    feeds the manifest carries several here, including epoch numbers that sort
    differently as text than as numbers.
    """

    tables = _boundary_d_tables()
    tables["schedule_external_streams"] = [_stream(index) for index in (1, 2, 3)]
    tables["schedule_external_stream_epochs"] = [_epoch(number) for number in (2, 9, 10)]
    tables["schedule_external_control_operations"] = [
        _operation(1, status="PENDING"),
        _operation(2, status="CLAIMED"),
        _operation(3, status="RESOLVED"),
    ]
    return tables


def test_configured_prior_head_is_a_supported_postgres_restore_source() -> None:
    """The configured prior head remains in the declared restore contract."""

    assert _PREVIOUS_RELEASE_HEAD in (postgres_restore_module._SUPPORTED_SOURCE_HEADS)
    assert _PREVIOUS_RELEASE_HEAD in (postgres_restore_module._BOUNDARY_D_SOURCE_HEADS)
    assert _LEGACY_SOURCE_HEAD not in (postgres_restore_module._BOUNDARY_D_SOURCE_HEADS)
    assert set(postgres_restore_module._SUPPORTED_SOURCE_HEADS) == {
        RELEASE_MIGRATION_HEAD,
        _PREVIOUS_RELEASE_HEAD,
        _LEGACY_SOURCE_HEAD,
    }


def test_previous_release_head_schema_contract_covers_supported_majors() -> None:
    """Each supported major needs its own derived previous-head contract."""

    previous = postgres_restore_module._PREVIOUS_SCHEMA_DEFINITIONS_DIGESTS
    assert set(previous).issuperset({16, 17, 18})
    for major, digest in previous.items():
        # A previous-head digest that equals the release or legacy value for
        # the same major was copied, not derived: the schema text differs at
        # every one of these heads.
        assert digest != (postgres_restore_module._RELEASE_SCHEMA_DEFINITIONS_DIGESTS.get(major))
        assert digest != (postgres_restore_module._LEGACY_SCHEMA_DEFINITIONS_DIGESTS.get(major))
        assert len(digest) == 64
        assert set(digest) <= set("0123456789abcdef")
    assert postgres_restore_module._SCHEMA_DEFINITIONS_DIGESTS_BY_HEAD[_PREVIOUS_RELEASE_HEAD] is (
        previous
    )


def test_archive_source_head_accepts_the_previous_release_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The head gate is what refused a previous-release archive outright."""

    _install_extraction(
        monkeypatch,
        {"alembic_version": [{"version_num": _PREVIOUS_RELEASE_HEAD}]},
    )

    head = postgres_restore_module._archive_source_head(_TOOL, _ARCHIVE)

    assert head == _PREVIOUS_RELEASE_HEAD


def test_archive_source_head_still_refuses_an_unknown_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Widening the gate must not turn it into a pass-through."""

    _install_extraction(
        monkeypatch,
        {"alembic_version": [{"version_num": "v2_0_something_else"}]},
    )

    with pytest.raises(
        DatabaseRestoreRefused,
        match="cannot restore a backup taken at migration head",
    ):
        postgres_restore_module._archive_source_head(_TOOL, _ARCHIVE)


def test_archive_source_head_still_refuses_a_malformed_version_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two rows in alembic_version is not a head, whatever they say."""

    _install_extraction(
        monkeypatch,
        {
            "alembic_version": [
                {"version_num": _PREVIOUS_RELEASE_HEAD},
                {"version_num": RELEASE_MIGRATION_HEAD},
            ],
        },
    )

    with pytest.raises(
        DatabaseRestoreRefused,
        match="malformed migration head",
    ):
        postgres_restore_module._archive_source_head(_TOOL, _ARCHIVE)


def test_previous_head_authority_is_derived_never_stubbed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reusing the pre-D shortcut here would skip a stopped-executor ceremony."""

    _install_extraction(monkeypatch, _boundary_d_tables())

    authority = postgres_restore_module._archive_source_authority(
        _TOOL,
        _ARCHIVE,
        source_head=_PREVIOUS_RELEASE_HEAD,
        archive_digest="a" * 64,
        toc_digest="b" * 64,
    )

    external = authority["external_authority_manifest"]
    assert authority["source_head"] == _PREVIOUS_RELEASE_HEAD
    assert authority["revision"] == 41
    assert authority["epoch"] == 7
    assert "revision_classification" not in authority
    assert external["stream_count"] == 1
    assert external["epoch_count"] == 1
    assert external["requires_stopped_executor_attestation"] is True
    assert external["executor_authority"]["streams"][0]["adapter_instance_id"] == "adapter-a"
    empty = postgres_restore_module.release_manifest_digest([])
    assert external["allocator_digest"] != empty
    assert external["stream_digest"] != empty


def test_extracted_archive_rows_land_in_one_canonical_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pg_restore replays physical order, so extraction has to impose one."""

    tables = _multi_row_boundary_d_tables()
    shuffled = {name: list(reversed(rows)) for name, rows in tables.items()}
    _install_copy_extraction(monkeypatch, shuffled)

    streams = postgres_restore_module._extract_table(
        _TOOL,
        _ARCHIVE,
        "schedule_external_streams",
    )
    epochs = postgres_restore_module._extract_table(
        _TOOL,
        _ARCHIVE,
        "schedule_external_stream_epochs",
    )

    assert [row["id"] for row in streams] == [
        row["id"] for row in tables["schedule_external_streams"]
    ]
    # Epoch order is numeric, matching the integer column the SQLite backend
    # sorts on: read as text, 10 would sort ahead of 2 and the two backends
    # would describe the same logical database differently.
    assert [row["epoch_number"] for row in epochs] == ["2", "9", "10"]


def test_previous_head_authority_manifest_is_row_order_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resume re-derives the challenge, so the manifest cannot drift.

    The same rows are fed twice in two different physical orders, which is
    what a dump taken after a row rewrite looks like.
    """

    tables = _multi_row_boundary_d_tables()
    shuffled = {name: list(reversed(rows)) for name, rows in tables.items()}
    assert shuffled["schedule_external_streams"] != (tables["schedule_external_streams"])

    _install_copy_extraction(monkeypatch, tables)
    first = postgres_restore_module._archive_source_authority(
        _TOOL,
        _ARCHIVE,
        source_head=_PREVIOUS_RELEASE_HEAD,
        archive_digest="a" * 64,
        toc_digest="b" * 64,
    )
    _install_copy_extraction(monkeypatch, shuffled)
    second = postgres_restore_module._archive_source_authority(
        _TOOL,
        _ARCHIVE,
        source_head=_PREVIOUS_RELEASE_HEAD,
        archive_digest="a" * 64,
        toc_digest="b" * 64,
    )

    external = first["external_authority_manifest"]
    assert external["stream_count"] == 3
    assert external["epoch_count"] == 3
    # The resolved operation carries no live executor authority, so only the
    # unresolved two reach the manifest.
    assert external["operation_count"] == 2
    assert list(first) == list(second)
    assert first == second
    assert first["manifest_digest"] == second["manifest_digest"]

    source_snapshot = {
        "manifest_digest": first["manifest_digest"],
        "external_authority_manifest": first["external_authority_manifest"],
    }
    target_snapshot = {
        "manifest_digest": "c" * 64,
        "external_authority_manifest": {
            "requires_stopped_executor_attestation": False,
        },
    }
    _, challenge, required = postgres_restore_module._attestation_envelope(
        source_snapshot=source_snapshot,
        target_snapshot=target_snapshot,
    )
    _, repeated_challenge, repeated_required = postgres_restore_module._attestation_envelope(
        source_snapshot={
            "manifest_digest": second["manifest_digest"],
            "external_authority_manifest": (second["external_authority_manifest"]),
        },
        target_snapshot=target_snapshot,
    )
    assert challenge == repeated_challenge
    # The executor rows in this archive are exactly why the ceremony must not
    # be skipped for a previous-head source.
    assert required is True
    assert repeated_required is True


@pytest.mark.parametrize(
    "table_name",
    ["schedule_revision_state", "schedule_external_epoch_allocator"],
)
def test_unactivated_boundary_d_source_is_refused_before_anything_runs(
    monkeypatch: pytest.MonkeyPatch,
    table_name: str,
) -> None:
    """An unactivated D singleton has to be caught while the target is intact.

    The archive is otherwise well formed, so nothing else in preflight stops
    it. Without this refusal the operation runs on to ``pg_restore --clean``
    and the live database is gone before the unactivated state is noticed.
    """

    tables = _boundary_d_tables()
    tables[table_name] = [{**tables[table_name][0], "guard_version": "0"}]
    _install_copy_extraction(monkeypatch, tables)

    with pytest.raises(
        DatabaseRestoreRefused,
        match=f"{table_name} is not Boundary-D activated",
    ):
        postgres_restore_module._archive_source_authority(
            _TOOL,
            _ARCHIVE,
            source_head=_PREVIOUS_RELEASE_HEAD,
            archive_digest="a" * 64,
            toc_digest="b" * 64,
        )


@pytest.mark.parametrize(
    "table_name",
    ["schedule_revision_state", "schedule_external_epoch_allocator"],
)
def test_boundary_d_source_without_a_guard_column_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    table_name: str,
) -> None:
    """An archive with no guard column at all proves nothing about D."""

    tables = _boundary_d_tables()
    row = dict(tables[table_name][0])
    del row["guard_version"]
    tables[table_name] = [row]
    _install_copy_extraction(monkeypatch, tables)

    with pytest.raises(
        DatabaseRestoreRefused,
        match=f"{table_name} is not Boundary-D activated",
    ):
        postgres_restore_module._archive_source_authority(
            _TOOL,
            _ARCHIVE,
            source_head=_PREVIOUS_RELEASE_HEAD,
            archive_digest="a" * 64,
            toc_digest="b" * 64,
        )


def test_an_activated_boundary_d_source_still_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal above must not be a refusal of every previous-head source."""

    _install_copy_extraction(monkeypatch, _boundary_d_tables())

    authority = postgres_restore_module._archive_source_authority(
        _TOOL,
        _ARCHIVE,
        source_head=_PREVIOUS_RELEASE_HEAD,
        archive_digest="a" * 64,
        toc_digest="b" * 64,
    )

    assert authority["revision"] == 41
    assert authority["epoch"] == 7


@pytest.mark.parametrize(
    "table_name",
    ["schedule_revision_state", "schedule_external_epoch_allocator"],
)
def test_both_backends_refuse_the_same_unactivated_source(
    monkeypatch: pytest.MonkeyPatch,
    table_name: str,
) -> None:
    """The two backends describe one logical database, so they must agree.

    A source either is Boundary-D activated or is not; a refusal on one
    backend and an accepted restore on the other is the disagreement that
    costs an operator their live database.
    """

    tables = _boundary_d_tables()
    tables[table_name] = [{**tables[table_name][0], "guard_version": "0"}]
    _install_copy_extraction(monkeypatch, tables)

    with pytest.raises(DatabaseRestoreRefused):
        postgres_restore_module._archive_source_authority(
            _TOOL,
            _ARCHIVE,
            source_head=_PREVIOUS_RELEASE_HEAD,
            archive_digest="a" * 64,
            toc_digest="b" * 64,
        )
    # The SQLite reader types the same column as an integer, so its unactivated
    # row is 0 rather than the archive's "0".
    with pytest.raises(DatabaseRestoreRefused):
        _sqlite_assert_activated([{"guard_version": 0}], table_name)


def test_head_evidence_guard_accepts_the_shipped_heads() -> None:
    """The positive control for every refusal below."""

    postgres_restore_module._assert_source_head_evidence_is_current()


@pytest.mark.parametrize(
    "moving_name",
    ["RELEASE_MIGRATION_HEAD", "_PREVIOUS_RELEASE_HEAD"],
)
def test_a_head_bump_without_re_derived_evidence_fails_at_import(
    monkeypatch: pytest.MonkeyPatch,
    moving_name: str,
) -> None:
    """Hardcoded per-major digests describe one head, and heads move.

    Bumping the release head re-points these imported names at a head nobody
    measured, and every restore of the displaced head is then refused for a
    schema mismatch whose cause is invisible.
    """

    monkeypatch.setattr(
        postgres_restore_module,
        moving_name,
        "v2_0_a_head_nobody_measured",
    )

    with pytest.raises(RuntimeError, match="re-derive"):
        postgres_restore_module._assert_source_head_evidence_is_current()


def test_an_unconfirmed_boundary_d_head_fails_at_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reading D authority out of an archive is a claim about a shipped head.

    A head added here without confirming its release shipped D activated would
    make the archive's revision, epoch and executor authority authoritative on
    a database that never had any.
    """

    monkeypatch.setattr(
        postgres_restore_module,
        "_BOUNDARY_D_SOURCE_HEADS",
        frozenset({*postgres_restore_module._BOUNDARY_D_SOURCE_HEADS, "v2_0_unconfirmed"}),
    )

    with pytest.raises(RuntimeError, match="no confirmed activated release"):
        postgres_restore_module._assert_source_head_evidence_is_current()


def test_a_drifted_cross_backend_allowlist_fails_at_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One backend promising a restore the other refuses is not a restore."""

    monkeypatch.setattr(
        postgres_restore_module,
        "_SUPPORTED_SOURCE_HEADS",
        frozenset({*postgres_restore_module._SUPPORTED_SOURCE_HEADS, "v2_0_postgres_only"}),
    )

    with pytest.raises(RuntimeError, match="allowlists disagree"):
        postgres_restore_module._assert_source_head_evidence_is_current()


def test_the_two_backends_ship_the_same_source_allowlist() -> None:
    """The state the guard above defends, asserted directly."""

    assert frozenset(_SQLITE_SOURCE_SCHEMA_DIGESTS) == (
        postgres_restore_module._SUPPORTED_SOURCE_HEADS
    )
