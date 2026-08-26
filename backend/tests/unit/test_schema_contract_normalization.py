"""Focused invariants for exact SQLite schema normalization."""

from __future__ import annotations

from z4j_brain.management_reset import _normalize_sqlite_schema_definition


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
