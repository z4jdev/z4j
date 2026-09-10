"""Focused invariants for exact SQLite and PostgreSQL schema normalization."""

from __future__ import annotations

from typing import Any

import pytest
from z4j_brain.management_reset import (
    _normalize_sqlite_schema_definition,
    _postgres_exact_schema_contract,
    release_manifest_digest,
)


def test_appended_column_physical_line_does_not_change_table_contract() -> None:
    fresh = """CREATE TABLE example (
        id INTEGER NOT NULL,
        payload TEXT DEFAULT ('a,b'),
        revoked_at DATETIME,
        CONSTRAINT ck_payload CHECK (instr(payload, ',') >= 0)
    )"""
    upgraded = """CREATE TABLE example (
        id INTEGER NOT NULL,
        payload TEXT DEFAULT ('a,b'), revoked_at DATETIME,
        CONSTRAINT ck_payload CHECK (instr(payload, ',') >= 0)
    )"""

    assert _normalize_sqlite_schema_definition("table", fresh) == (
        _normalize_sqlite_schema_definition("table", upgraded)
    )


def test_top_level_split_preserves_commas_inside_sql_literals_and_expressions() -> None:
    definition = """CREATE TABLE example (
        id INTEGER NOT NULL,
        quoted TEXT DEFAULT 'it''s,a,value',
        pair TEXT DEFAULT (printf('%s,%s', 'left', 'right')),
        CONSTRAINT ck_pair CHECK (pair IN ('left,right', 'right,left'))
    )"""

    normalized = _normalize_sqlite_schema_definition("table", definition)

    assert isinstance(normalized, dict)
    assert normalized["columns"] == [
        "id INTEGER NOT NULL",
        "quoted TEXT DEFAULT 'it''s,a,value'",
        "pair TEXT DEFAULT (printf('%s,%s', 'left', 'right'))",
    ]
    assert normalized["constraints"] == [
        "CONSTRAINT ck_pair CHECK (pair IN ('left,right', 'right,left'))",
    ]


def test_sqlite_table_rebuild_spelling_does_not_change_contract() -> None:
    original = """CREATE TABLE projects (
        id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
    )"""
    rebuilt = """CREATE TABLE "projects" (
        id INTEGER NOT NULL,
        created_at DATETIME DEFAULT (CURRENT_TIMESTAMP) NOT NULL
    )"""

    assert _normalize_sqlite_schema_definition("table", original) == (
        _normalize_sqlite_schema_definition("table", rebuilt)
    )


def test_unreviewed_table_rebuild_spelling_remains_exact() -> None:
    original = """CREATE TABLE audit_log (
        id INTEGER NOT NULL,
        occurred_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
    )"""
    changed = """CREATE TABLE "audit_log" (
        id INTEGER NOT NULL,
        occurred_at DATETIME DEFAULT (CURRENT_TIMESTAMP) NOT NULL
    )"""

    assert _normalize_sqlite_schema_definition("table", original) != (
        _normalize_sqlite_schema_definition("table", changed)
    )


class _CatalogResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> _CatalogResult:
        return self

    def all(self) -> list[dict[str, Any]]:
        return list(self._rows)


class _ColumnCatalogSession:
    """Answer the exact contract's column query; every other section is empty."""

    def __init__(self, columns: list[dict[str, Any]]) -> None:
        self._columns = columns

    async def execute(self, statement: Any) -> _CatalogResult:
        sql = " ".join(str(statement).split())
        if "JOIN pg_attribute attribute ON" in sql:
            # The canned rows are keyed by the alias the real query selects.
            assert "attribute.attnum AS attnum," in sql
            return _CatalogResult(self._columns)
        return _CatalogResult([])


_AUDIT_STATE_COLUMNS = (
    {"column_name": "singleton_id", "data_type": "character varying(32)"},
    {"column_name": "active_row_count", "data_type": "bigint"},
    {"column_name": "observed_active_row_count", "data_type": "bigint"},
)


def _column_rows(
    attnums: tuple[int, ...],
    order: tuple[int, ...] = (0, 1, 2),
) -> list[dict[str, Any]]:
    """Live pg_attribute rows as the column query returns them, by attnum."""

    rows = [
        {
            "table_name": "audit_chain_state",
            "attnum": attnum,
            **_AUDIT_STATE_COLUMNS[index],
            "not_null": True,
            "default_expression": None,
            "identity_kind": "",
            "generated_kind": "",
            "collation": "",
        }
        for attnum, index in zip(attnums, order, strict=True)
    ]
    # A second table is numbered from one on its own.
    rows.append(
        {
            "table_name": "commands",
            "attnum": 1,
            "column_name": "id",
            "data_type": "uuid",
            "not_null": True,
            "default_expression": None,
            "identity_kind": "",
            "generated_kind": "",
            "collation": "",
        },
    )
    return rows


async def _column_contract(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return await _postgres_exact_schema_contract(
        _ColumnCatalogSession(rows),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "attnums",
    [
        pytest.param((1, 2, 4), id="dropped-and-re-added-last-column"),
        pytest.param((2, 3, 4), id="dropped-leading-column"),
        pytest.param((1, 3, 6), id="several-dropped-slots"),
    ],
)
async def test_postgres_dropped_column_slots_do_not_change_schema_contract(
    attnums: tuple[int, ...],
) -> None:
    """PostgreSQL never reuses a dropped attnum, so the contract must not see it.

    The first case is the audit tally downgrade and re-upgrade: the re-added
    column lands after the slot its dropped predecessor still occupies.
    """

    clean = await _column_contract(_column_rows((1, 2, 3)))
    slotted = await _column_contract(_column_rows(attnums))

    assert slotted == clean
    assert release_manifest_digest(slotted) == release_manifest_digest(clean)
    # Without a dropped slot a column keeps its physical number under the
    # historical key set, so the pinned digests and every manifest an earlier
    # build recorded still match an installation that never dropped a column.
    positions = [
        (row["table_name"], row["column_name"], row["ordinal"]) for row in clean["columns"]
    ]
    assert positions == [
        ("audit_chain_state", "singleton_id", 1),
        ("audit_chain_state", "active_row_count", 2),
        ("audit_chain_state", "observed_active_row_count", 3),
        ("commands", "id", 1),
    ]
    assert all("attnum" not in row for row in clean["columns"])
    # Control: the same physical history with two live columns traded is a
    # real schema difference and must still be refused.
    reordered = await _column_contract(_column_rows(attnums, order=(0, 2, 1)))
    assert release_manifest_digest(reordered) != release_manifest_digest(clean)
