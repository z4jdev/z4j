"""Task exports must keep attacker-controlled cells as spreadsheet text."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from types import SimpleNamespace

import pytest
from z4j_brain.api import _export as generic_export
from z4j_brain.api.tasks import (
    _SPREADSHEET_FORMULA_PREFIXES,
    _export_csv,
    _export_xlsx,
    _neutralise_formula,
)


async def _stream_body(response) -> bytes:
    chunks: list[bytes] = []
    async for chunk in response.body_iterator:
        chunks.append(chunk.encode() if isinstance(chunk, str) else chunk)
    return b"".join(chunks)


class TestNeutraliseFormula:
    @pytest.mark.parametrize(
        "raw",
        [
            "=IMPORTXML(...)",
            "=1+1",
            "+cmd|'/c calc'!",
            "-2+HYPERLINK(...)",
            "@SUM(A1:A10)",
            "\tleading tab",
            "\rcarriage",
        ],
    )
    def test_prefixes_neutralised(self, raw: str) -> None:
        assert _neutralise_formula(raw) == "'" + raw

    @pytest.mark.parametrize(
        "raw",
        ["normal task name", "app.tasks.send_email", "", "worker@host", "/path/to/x"],
    )
    def test_safe_strings_passthrough(self, raw: str) -> None:
        assert _neutralise_formula(raw) == raw

    def test_non_string_passthrough(self) -> None:
        assert _neutralise_formula(None) is None
        assert _neutralise_formula(42) == 42
        assert _neutralise_formula(True) is True

    def test_prefix_set_complete(self) -> None:
        assert set(_SPREADSHEET_FORMULA_PREFIXES) >= {"=", "+", "-", "@", "\t"}


def test_generic_export_contract_scopes_formula_neutralisation_to_spreadsheets() -> None:
    contract = " ".join((generic_export.__doc__ or "").split())
    assert "CSV and XLSX helpers" in contract
    assert "JSON preserves the source value" in contract
    response = generic_export.export_json(
        [SimpleNamespace(name="=literal-json-value")],
        [("name", lambda row: row.name)],
        "values.json",
    )
    assert b'"name": "=literal-json-value"' in response.body


@pytest.mark.asyncio
async def test_csv_export_neutralises_the_emitted_cell() -> None:
    response = _export_csv(
        [SimpleNamespace(name='=HYPERLINK("https://attacker.invalid")')],
        "project",
        selected_fields=["name"],
    )

    body = (await _stream_body(response)).decode()

    assert body.splitlines()[0] == "name"
    assert body.splitlines()[1].startswith("\"'=HYPERLINK")


@pytest.mark.asyncio
async def test_xlsx_export_emits_text_and_no_formula_node() -> None:
    response = _export_xlsx(
        [SimpleNamespace(name="=1+1")],
        "project",
        selected_fields=["name"],
    )
    archive = zipfile.ZipFile(io.BytesIO(await _stream_body(response)))

    worksheet_roots = [
        ET.fromstring(archive.read(name))
        for name in archive.namelist()
        if name.startswith("xl/worksheets/") and name.endswith(".xml")
    ]
    assert not any(
        element.tag.rsplit("}", 1)[-1] == "f" for root in worksheet_roots for element in root.iter()
    )
    shared = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    strings = [node.text for node in shared.iter() if node.tag.rsplit("}", 1)[-1] == "t"]
    assert "'=1+1" in strings
