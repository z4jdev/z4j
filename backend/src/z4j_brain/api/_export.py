"""Generic CSV / JSON / XLSX export helpers.

Shared by routers that need to stream query results as file
downloads (today: ``/audit``; ``/tasks`` has inlined equivalents
that will migrate here in a follow-up cleanup).

Security: every helper routes attacker-controllable strings
through :func:`neutralise_formula` before they reach the client's
spreadsheet. Task names, audit ``action`` values, ``user_agent``
headers, and exception strings are all operator-visible in Excel /
Google Sheets / LibreOffice; without the apostrophe prefix a
crafted value starting with ``=``, ``+``, ``-``, ``@``, tab, or CR
becomes a live formula (external audit High #4, same rationale as
``tasks.py``).
"""

from __future__ import annotations

import csv
import io
import json as _json
from collections.abc import Callable
from typing import Any

import xlsxwriter
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


__all__ = [
    "XLSX_ROW_CAP",
    "FieldDef",
    "export_csv",
    "export_json",
    "export_xlsx",
    "neutralise_formula",
]
