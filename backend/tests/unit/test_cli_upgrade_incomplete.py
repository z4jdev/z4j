"""Malformed/unavailable index metadata cannot authorize an upgrade."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from z4j_brain.cli import main

from tests.unit.test_cli_upgrade import _patch_installed


@pytest.mark.parametrize("apply", [False, True])
@pytest.mark.parametrize(
    "metadata", ["invalid_json", "list", "info_list", "missing", "null", "number", "404"]
)
def test_incomplete_index_scan_is_structured_and_never_runs_pip(
    monkeypatch, capsys, metadata, apply
):
    _patch_installed(monkeypatch, {"z4j": "1.2.2"})
    payloads = {
        "list": [],
        "info_list": {"info": []},
        "missing": {},
        "null": {"info": {"version": None}},
        "number": {"info": {"version": 123}},
    }

    def handler(request):
        if metadata == "invalid_json":
            return httpx.Response(200, text="<html>not metadata</html>")
        if metadata == "404":
            return httpx.Response(404, json={})
        return httpx.Response(200, json=payloads[metadata])

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    pip = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr("subprocess.run", pip)
    monkeypatch.setattr("shutil.which", lambda value: value)
    assert main(["upgrade", "--json", *(["--apply"] if apply else [])]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False
    assert output["network_error"]
    assert output["rows"][0]["package"] == "z4j"
    pip.assert_not_called()


@pytest.mark.parametrize("latest, expected", [("1.2.2", 0), ("1.2.3", 1)])
def test_valid_metadata_still_compares_versions(monkeypatch, capsys, latest, expected):
    _patch_installed(monkeypatch, {"z4j": "1.2.2"})
    real_client = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"info": {"version": latest}})
    )
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs)
    )
    assert main(["upgrade", "--json"]) == expected
    output = json.loads(capsys.readouterr().out)
    assert output["network_error"] is None
    assert output["rows"][0]["latest"] == latest
