"""Malformed stored rules fail closed and malformed HTTP actions return 422."""

from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from z4j_brain.domain.automation.evaluator import (
    actions_are_destructive,
    evaluate_conditions,
    matching_rules,
    validate_actions,
    validate_conditions,
)
from z4j_brain.persistence.enums import ProjectRole
from z4j_brain.persistence.models import AutomationRule

from tests.unit import test_automation_rules_endpoint as endpoints

brain_app = endpoints.brain_app
settings = endpoints.settings


@pytest.mark.parametrize(
    "conditions",
    [
        {"all": []},
        {"all": [{}], "unknown": "ignored"},
        {"runtime_ms_gt": -1},
        {"exception": ""},
        {"any": [{}] * 21},
        [],
        None,
        "",
    ],
)
def test_invalid_stored_conditions_cannot_match(conditions):
    fields = {"runtime_ms": 0, "exception": "any exception"}
    assert validate_conditions(conditions)
    assert evaluate_conditions(conditions, fields) is False
    rule = SimpleNamespace(is_enabled=True, trigger="task.failed", conditions=conditions)
    assert matching_rules([rule], "task.failed", fields) == []


@pytest.mark.parametrize("value", [{}, [], None, 1, True, "unknown"])
def test_malformed_action_type_is_rejected_and_classified_conservatively(value):
    actions = [{"type": value}]
    assert validate_actions(actions)
    assert actions_are_destructive(actions) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [{}, []])
async def test_malformed_action_http_returns_422_without_writing(brain_app, settings, value):
    actor = await endpoints._seed_actor(brain_app, settings, role=ProjectRole.OPERATOR)
    async with endpoints._client(brain_app, settings, actor) as client:
        response = await client.post(
            endpoints._BASE,
            headers=endpoints._hdr(actor),
            json={
                "name": "malformed",
                "trigger": "task.failed",
                "conditions": {},
                "actions": [{"type": value}],
            },
        )
    assert response.status_code == 422, response.text
    async with brain_app.state.db.session() as session:
        assert await session.scalar(select(func.count()).select_from(AutomationRule)) == 0
