"""Generic CSV / JSON / XLSX export helpers.

Shared by routers that need to stream query results as file
downloads (today: ``/audit``; ``/tasks`` has inlined equivalents
that will migrate here in a follow-up cleanup).

Security: the CSV and XLSX helpers route attacker-controllable strings
through :func:`neutralise_formula` before they reach spreadsheet cells.
Task names, audit ``action`` values, ``user_agent`` headers, and exception
strings are all operator-visible in Excel / Google Sheets / LibreOffice;
without the apostrophe prefix a crafted value starting with ``=``, ``+``,
``-``, ``@``, tab, or CR becomes a live formula. JSON preserves the source
value because it is a data interchange format rather than a spreadsheet
cell format. Same rationale as ``tasks.py``.
"""

from __future__ import annotations

import csv
import io
import json as _json
from collections.abc import Callable, Iterable
from typing import Any

import xlsxwriter  # type: ignore[import-untyped]
from fastapi.responses import Response, StreamingResponse

from z4j_brain.errors import ValidationError

#: First-character prefixes that Excel / Google Sheets / LibreOffice
#: interpret as formulas when a cell starts with one. Attacker-
#: controlled task names / exceptions / args / audit metadata can
#: otherwise become live formulas in the operator's spreadsheet.
_SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

#: Hard cap on rows per xlsx export. ``in_memory=True`` builds the
#: whole workbook in RAM; past ~25 000 rows we force operators to
#: switch to CSV (which streams).
XLSX_ROW_CAP = 25_000

#: A field definition used by every export format: the column name
#: plus a callable that extracts the value from a row.
FieldDef = tuple[str, Callable[[Any], Any]]


def neutralise_formula(value: Any) -> Any:
    """Return a spreadsheet-safe form of ``value``.

    If ``value`` is a string starting with one of the formula
    trigger characters, prefix an apostrophe so the cell renders
    as text instead of being evaluated. Non-strings (int, float,
    bool, None, dict, list) pass through unchanged - they cannot
    introduce formula injection.
    """
    if isinstance(value, str) and value.startswith(_SPREADSHEET_FORMULA_PREFIXES):
        return "'" + value
    return value


def export_csv(
    rows: list[Any],
    field_defs: list[FieldDef],
    filename: str,
) -> Any:
    """Stream ``rows`` as a CSV file download.

    Args:
        rows: Pre-fetched list of domain objects to serialise.
        field_defs: Column name + value-extractor pairs. Order is
            preserved in the output header row.
        filename: Value for ``Content-Disposition: attachment;
            filename="..."``. Should NOT include quotes.

    Returns:
        A :class:`fastapi.responses.StreamingResponse` the caller
        can return directly from a route handler.
    """
    headers = [name for name, _ in field_defs]

    def generate() -> Any:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
        for row in rows:
            writer.writerow(
                [neutralise_formula(fn(row)) for _, fn in field_defs],
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


def export_json(
    rows: list[Any],
    field_defs: list[FieldDef],
    filename: str,
) -> Any:
    """Return ``rows`` as a JSON array file download.

    Shape: ``[ {col1: value, col2: value, ...}, ... ]``. Non-JSON-
    native values (datetimes, UUIDs, enum members) are coerced via
    :func:`str` - callers wanting stricter serialisation should
    stringify inside their field extractors.
    """
    data = []
    for row in rows:
        item = {}
        for name, fn in field_defs:
            item[name] = fn(row)
        data.append(item)

    body = _json.dumps(data, indent=2, default=str, ensure_ascii=False)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


def export_xlsx(
    rows: list[Any],
    field_defs: list[FieldDef],
    filename: str,
    sheet_name: str,
) -> Any:
    """Generate ``rows`` as an XLSX (Excel) file download.

    Uses ``xlsxwriter`` (pure Python, write-only, no native deps).
    ``strings_to_formulas=False`` disables xlsxwriter's auto-
    conversion of strings starting with ``=`` into formulas -
    first line of defence against spreadsheet-formula injection.
    :func:`neutralise_formula` handles ``+`` / ``-`` / ``@`` /
    tab / CR prefixes that the flag does not cover.

    Raises:
        ValidationError: When ``len(rows) > XLSX_ROW_CAP``. The
            cap keeps memory bounded because ``in_memory=True``
            builds the whole workbook in RAM.
    """
    if len(rows) > XLSX_ROW_CAP:
        raise ValidationError(
            f"xlsx export is capped at {XLSX_ROW_CAP} rows; use CSV for larger result sets",
            details={"row_count": len(rows), "cap": XLSX_ROW_CAP},
        )

    headers = [name for name, _ in field_defs]

    buf = io.BytesIO()
    wb = xlsxwriter.Workbook(
        buf,
        {"in_memory": True, "strings_to_formulas": False},
    )
    try:
        ws = wb.add_worksheet(sheet_name)
        header_fmt = wb.add_format({"bold": True, "bg_color": "#f1f5f9"})

        for col, h in enumerate(headers):
            ws.write(0, col, h, header_fmt)
        for r, row in enumerate(rows, start=1):
            for col, (_, fn) in enumerate(field_defs):
                value = neutralise_formula(fn(row))
                if value is None or value == "":
                    ws.write_blank(r, col, None)
                elif isinstance(value, (str, int, float, bool)):
                    ws.write(r, col, value)
                else:
                    ws.write_string(r, col, str(value))

        ws.freeze_panes(1, 0)
    finally:
        wb.close()
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# ---------------------------------------------------------------------------
# Streaming encoders for background export jobs
#
# The helpers above take a list, which is what the synchronous export
# path has after its capped query. A background job never has the whole
# result in memory: it pages the query and hands each page to one of the
# encoders below, which return bytes for that page only. The byte layout
# is the one the synchronous path produces (same header, same quoting,
# same two-space JSON indentation), so a file written by a job and a file
# downloaded synchronously for the same filter are the same bytes.
# ---------------------------------------------------------------------------

#: Rows per worksheet an xlsx job may write. Excel's sheet holds 1 048 576
#: rows and one is the header. Constant-memory mode spools rows to a
#: temporary file as they are written, so this is the file format's
#: limit, not a memory one.
XLSX_JOB_ROW_CAP = 1_048_575


def encode_csv_header(field_defs: list[FieldDef]) -> bytes:
    """The header line, UTF-8, as the synchronous export writes it."""
    buf = io.StringIO()
    csv.writer(buf).writerow([name for name, _ in field_defs])
    return buf.getvalue().encode("utf-8")


def encode_csv_rows(rows: Iterable[Any], field_defs: list[FieldDef]) -> bytes:
    """One CSV line per row, UTF-8, formula-neutralised."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in rows:
        writer.writerow([neutralise_formula(fn(row)) for _, fn in field_defs])
    return buf.getvalue().encode("utf-8")


class JsonArrayEncoder:
    """Emit a JSON array one item at a time, matching ``json.dumps(indent=2)``.

    ``json.dumps(list_of_dicts, indent=2)`` renders ``[\\n  {...},\\n  {...}\\n]``
    and ``[]`` for nothing. This encoder produces the same bytes without
    holding the list: call :meth:`start` once, :meth:`rows` per page and
    :meth:`finish` once.
    """

    def __init__(self, field_defs: list[FieldDef]) -> None:
        self._field_defs = field_defs
        self._count = 0

    def start(self) -> bytes:
        return b"["

    def rows(self, rows: Iterable[Any]) -> bytes:
        pieces: list[str] = []
        for row in rows:
            item = {name: fn(row) for name, fn in self._field_defs}
            text = _json.dumps(item, indent=2, default=str, ensure_ascii=False)
            indented = "\n".join("  " + line for line in text.splitlines())
            pieces.append(("\n" if self._count == 0 else ",\n") + indented)
            self._count += 1
        return "".join(pieces).encode("utf-8")

    def finish(self) -> bytes:
        return b"]" if self._count == 0 else b"\n]"


class XlsxStreamWriter:
    """Write an xlsx workbook row by row to a path in constant memory.

    ``constant_memory`` makes xlsxwriter flush each row to a spool file as
    it is written instead of assembling the sheet in RAM, which is what
    lets a job write a sheet the synchronous export would refuse. Rows
    must arrive in order, which a paged query guarantees.
    """

    def __init__(self, path: str, field_defs: list[FieldDef], sheet_name: str) -> None:
        self._field_defs = field_defs
        self._workbook = xlsxwriter.Workbook(
            path,
            {"constant_memory": True, "strings_to_formulas": False},
        )
        self._sheet = self._workbook.add_worksheet(sheet_name)
        header_fmt = self._workbook.add_format({"bold": True, "bg_color": "#f1f5f9"})
        for col, (name, _) in enumerate(field_defs):
            self._sheet.write(0, col, name, header_fmt)
        self._sheet.freeze_panes(1, 0)
        self._next_row = 1

    @property
    def rows_written(self) -> int:
        return self._next_row - 1

    def write_rows(self, rows: Iterable[Any]) -> int:
        """Append ``rows``; raise :class:`ValidationError` past the sheet cap."""
        for row in rows:
            if self._next_row > XLSX_JOB_ROW_CAP:
                raise ValidationError(
                    f"xlsx export is capped at {XLSX_JOB_ROW_CAP} rows by the "
                    "worksheet format; use CSV or JSON for larger result sets",
                    details={"cap": XLSX_JOB_ROW_CAP, "format": "xlsx"},
                )
            for col, (_, fn) in enumerate(self._field_defs):
                value = neutralise_formula(fn(row))
                if value is None or value == "":
                    self._sheet.write_blank(self._next_row, col, None)
                elif isinstance(value, (str, int, float, bool)):
                    self._sheet.write(self._next_row, col, value)
                else:
                    self._sheet.write_string(self._next_row, col, str(value))
            self._next_row += 1
        return self.rows_written

    def close(self) -> None:
        self._workbook.close()


__all__ = [
    "XLSX_JOB_ROW_CAP",
    "XLSX_ROW_CAP",
    "FieldDef",
    "JsonArrayEncoder",
    "XlsxStreamWriter",
    "encode_csv_header",
    "encode_csv_rows",
    "export_csv",
    "export_json",
    "export_xlsx",
    "neutralise_formula",
]
