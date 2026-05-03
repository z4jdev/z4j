"""Tests for ``z4j upgrade`` (1.2.2+).

The command compares installed z4j package versions against
PyPI's JSON API. Tests use httpx ``MockTransport`` so we never
hit the real PyPI from CI.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import httpx
import pytest


def _patch_pypi(
    monkeypatch: pytest.MonkeyPatch, responses: dict[str, dict],
) -> None:
    """Make every httpx.Client return canned PyPI responses by URL."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for marker, payload in responses.items():
            if marker in url:
                if payload.get("status", 200) >= 400:
                    return httpx.Response(payload["status"], json={})
                return httpx.Response(200, json=payload)
        return httpx.Response(404, json={})

    real_client = httpx.Client

    def make_client(*args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", make_client)


def _patch_installed(
    monkeypatch: pytest.MonkeyPatch, versions: dict[str, str],
) -> None:
    """Replace importlib.metadata.version inside the cli module."""
    from importlib.metadata import PackageNotFoundError

    def fake_version(name: str) -> str:
        if name in versions:
            return versions[name]
        raise PackageNotFoundError(name)

    # The CLI imports lazily inside _run_upgrade, so we patch on
    # importlib.metadata directly.
    import importlib.metadata as md

    monkeypatch.setattr(md, "version", fake_version)


class TestUpgradeCheck:
    def test_all_current_returns_zero(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _patch_installed(monkeypatch, {"z4j": "1.2.2", "z4j-brain": "1.2.2"})
        _patch_pypi(monkeypatch, {
            "/pypi/z4j/json": {"info": {"version": "1.2.2"}},
            "/pypi/z4j-brain/json": {"info": {"version": "1.2.2"}},
        })

        from z4j_brain.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["upgrade"])
        assert rc == 0
        assert "current" in buf.getvalue()

    def test_behind_returns_one(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _patch_installed(monkeypatch, {"z4j": "1.2.1", "z4j-brain": "1.2.1"})
        _patch_pypi(monkeypatch, {
            "/pypi/z4j/json": {"info": {"version": "1.2.2"}},
            "/pypi/z4j-brain/json": {"info": {"version": "1.2.2"}},
        })

        from z4j_brain.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["upgrade"])
        assert rc == 1
        assert "behind" in buf.getvalue()

    def test_json_output(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _patch_installed(monkeypatch, {"z4j": "1.2.1"})
        _patch_pypi(monkeypatch, {
            "/pypi/z4j/json": {"info": {"version": "1.2.2"}},
        })

        from z4j_brain.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["upgrade", "--json"])
        assert rc == 1
        payload = json.loads(buf.getvalue())
        assert payload["ok"] is False
        assert payload["behind_count"] == 1
        assert payload["rows"][0]["package"] == "z4j"
        assert payload["rows"][0]["behind"] is True

    def test_uninstalled_packages_skipped(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Only z4j is installed; the other adapters are not.
        _patch_installed(monkeypatch, {"z4j": "1.2.2"})
        _patch_pypi(monkeypatch, {
            "/pypi/z4j/json": {"info": {"version": "1.2.2"}},
        })

        from z4j_brain.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["upgrade", "--json"])
        assert rc == 0
        payload = json.loads(buf.getvalue())
        assert len(payload["rows"]) == 1

    def test_pypi_404_marked_unpublished(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _patch_installed(monkeypatch, {"z4j-bare": "1.2.0"})
        _patch_pypi(monkeypatch, {
            "/pypi/z4j-bare/json": {"status": 404},
        })

        from z4j_brain.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["upgrade", "--json"])
        # Not on PyPI is not "behind"; should not flip the exit code.
        assert rc == 0
        payload = json.loads(buf.getvalue())
        assert payload["rows"][0]["latest"] == "(not on PyPI)"
        assert payload["rows"][0]["behind"] is False
