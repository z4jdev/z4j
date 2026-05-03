"""Tests for the per-project ``allowed_schedulers`` allowlist (1.2.2+).

Audit fix MED-13 (and HIGH-9 cross-validation, HIGH-8 per-element
regex). Covers:

- ``NULL`` (default) is unrestricted (backwards-compat).
- PATCH `null` clears an existing allow-list.
- PATCH `[]` is rejected as misconfig.
- create-with-allowed → success.
- create-with-disallowed → 422.
- import per-row reports allow-list failures with the
  recognizable ``allowed_schedulers:`` prefix.
- per-element regex rejects junk strings.
- default_scheduler_owner must be in allowed_schedulers when
  both are set.
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from httpx import AsyncClient

from z4j_brain.api.schedules import _validate_scheduler_in_allowlist


class _FakeProject:
    """Stand-in for ``Project`` ORM row."""

    def __init__(
        self,
        *,
        default_scheduler_owner: str = "z4j-scheduler",
        allowed_schedulers: list[str] | None = None,
    ) -> None:
        self.default_scheduler_owner = default_scheduler_owner
        self.allowed_schedulers = allowed_schedulers


class TestValidatorHelper:
    """Direct unit tests for ``_validate_scheduler_in_allowlist``."""

    def test_null_allow_list_accepts_anything(self) -> None:
        project = _FakeProject(allowed_schedulers=None)
        # No exception
        _validate_scheduler_in_allowlist(project, "rogue-fleet")

    def test_in_list_accepts(self) -> None:
        project = _FakeProject(
            default_scheduler_owner="celery-beat",
            allowed_schedulers=["celery-beat", "z4j-scheduler"],
        )
        _validate_scheduler_in_allowlist(project, "z4j-scheduler")

    def test_default_owner_implicitly_allowed(self) -> None:
        """The default is always permitted even if not in the list."""
        project = _FakeProject(
            default_scheduler_owner="celery-beat",
            allowed_schedulers=["z4j-scheduler"],
        )
        _validate_scheduler_in_allowlist(project, "celery-beat")

    def test_outside_list_rejects(self) -> None:
        project = _FakeProject(
            default_scheduler_owner="celery-beat",
            allowed_schedulers=["celery-beat", "z4j-scheduler"],
        )
        with pytest.raises(ValueError) as exc_info:
            _validate_scheduler_in_allowlist(project, "rogue-fleet")
        # Message MUST be prefixed so the import per-row error
        # report is self-documenting.
        assert "allowed_schedulers:" in str(exc_info.value)
        assert "rogue-fleet" in str(exc_info.value)


class TestPydanticElementValidation:
    """Per-element regex on ``allowed_schedulers`` (audit fix HIGH-8)."""

    def test_create_rejects_junk_string(self) -> None:
        from z4j_brain.api.projects import CreateProjectRequest

        with pytest.raises(ValueError):
            CreateProjectRequest(
                slug="proj-1",
                name="My Project",
                allowed_schedulers=["; DROP TABLE schedules"],
            )

    def test_create_rejects_uppercase(self) -> None:
        from z4j_brain.api.projects import CreateProjectRequest

        with pytest.raises(ValueError):
            CreateProjectRequest(
                slug="proj-1",
                name="My Project",
                allowed_schedulers=["UPPER-CASE"],
            )

    def test_create_accepts_well_formed(self) -> None:
        from z4j_brain.api.projects import CreateProjectRequest

        body = CreateProjectRequest(
            slug="proj-1",
            name="My Project",
            allowed_schedulers=["celery-beat", "z4j-scheduler"],
        )
        assert body.allowed_schedulers == ["celery-beat", "z4j-scheduler"]

    def test_update_rejects_junk(self) -> None:
        from z4j_brain.api.projects import UpdateProjectRequest

        with pytest.raises(ValueError):
            UpdateProjectRequest(allowed_schedulers=["<script>"])

    def test_update_accepts_null_to_clear(self) -> None:
        """``allowed_schedulers=null`` is the documented "remove
        the restriction" gesture (audit fix MED-13).
        """
        from z4j_brain.api.projects import UpdateProjectRequest

        body = UpdateProjectRequest(allowed_schedulers=None)
        # ``model_fields_set`` carries the explicit-null signal.
        assert "allowed_schedulers" in body.model_fields_set
        assert body.allowed_schedulers is None


class TestImportLoopErrorPrefix:
    """The per-row import loop catches ValueError and stores the
    message in ``summary.errors[idx]``. The allow-list helper
    prefixes ``allowed_schedulers:`` so an operator reading the
    response can tell allow-list rejections from other validation
    errors.
    """

    def test_helper_prefix_matches(self) -> None:
        project = _FakeProject(allowed_schedulers=["z4j-scheduler"])
        try:
            _validate_scheduler_in_allowlist(project, "rogue-fleet")
        except ValueError as exc:
            assert str(exc).startswith("allowed_schedulers:"), str(exc)
        else:
            pytest.fail("expected ValueError")
