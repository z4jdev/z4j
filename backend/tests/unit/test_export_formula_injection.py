"""External-audit High #4 regression tests - task export must not
execute attacker-controlled strings as spreadsheet formulas."""

from __future__ import annotations

import pytest

from z4j_brain.api.tasks import (
    _SPREADSHEET_FORMULA_PREFIXES,
    _neutralise_formula,
)


class TestNeutraliseFormula:
    """Unit contract on the neutraliser itself."""

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
        """Every formula-trigger prefix must get an apostrophe."""
        out = _neutralise_formula(raw)
        assert isinstance(out, str)
        assert out.startswith("'")
        assert out[1:] == raw

    @pytest.mark.parametrize(
        "raw",
        [
            "normal task name",
            "app.tasks.send_email",
            "",
            "worker@host",  # @ mid-string is fine - only leading @ triggers
            "/path/to/x",
            "hello=world",  # = mid-string is fine
        ],
    )
    def test_safe_strings_passthrough(self, raw: str) -> None:
        assert _neutralise_formula(raw) == raw

    def test_non_string_passthrough(self) -> None:
        assert _neutralise_formula(None) is None
        assert _neutralise_formula(42) == 42
        assert _neutralise_formula(3.14) == 3.14
        assert _neutralise_formula(True) is True

    def test_prefix_set_complete(self) -> None:
        """Pin the prefix tuple - OWASP + Google guidance require
        these five (=, +, -, @, tab). CR is defence in depth."""
        assert set(_SPREADSHEET_FORMULA_PREFIXES) >= {
            "=", "+", "-", "@", "\t",
        }


class TestXlsxFormulaDisabled:
    """xlsxwriter must be invoked with ``strings_to_formulas=False``
    so even an un-neutralised ``=`` string cannot become a formula.
    We verify by inspecting the call path."""

    def test_xlsx_uses_strings_to_formulas_false(self) -> None:
        """Smoke: read the source of ``_export_xlsx`` and confirm
        the Workbook flag is set. A regression would re-enable the
        xlsxwriter default and open the attack back up."""
        import inspect

        from z4j_brain.api import tasks

        src = inspect.getsource(tasks._export_xlsx)
        assert '"strings_to_formulas": False' in src or (
            "'strings_to_formulas': False" in src
        ), "xlsxwriter default auto-converts '='-prefixed strings to formulas"

    def test_csv_runs_neutraliser_on_every_cell(self) -> None:
        """Every row write in ``_export_csv`` must route through
        ``_neutralise_formula``. Regression guard."""
        import inspect

        from z4j_brain.api import tasks

        src = inspect.getsource(tasks._export_csv)
        assert "_neutralise_formula" in src, (
            "CSV exporter must neutralise every cell against formula injection"
        )
