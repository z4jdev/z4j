"""The ``z4j init`` tunables template shows the defaults the brain really uses.

The template documents each tunable as a commented ``# Z4J_NAME=value`` line.
Three of them had drifted from ``Settings`` (audit retention 365 against 90,
command timeout 30 against 60, agent offline timeout 60 against 30), so an
operator who uncommented a line to "keep the default" changed the behaviour.
"""

from __future__ import annotations

import re

from z4j_brain.cli import _CONFIG_ENV_TEMPLATE
from z4j_brain.settings import Settings

_COMMENTED_SETTING = re.compile(r"^# (Z4J_[A-Z0-9_]+)=(\S+)$", re.MULTILINE)


def test_every_commented_setting_shows_the_settings_default() -> None:
    lines = _COMMENTED_SETTING.findall(_CONFIG_ENV_TEMPLATE)
    assert lines, "the template lists no commented settings"
    checked = 0
    for env_name, shown in lines:
        field = Settings.model_fields.get(env_name.removeprefix("Z4J_").lower())
        if field is None or field.default is None:
            continue
        default = field.default
        if isinstance(default, bool):
            expected = "true" if default else "false"
            assert shown.lower() == expected, (env_name, shown, default)
        else:
            assert shown == str(default), (env_name, shown, default)
        checked += 1
    # The three that drifted are among the values checked.
    assert checked >= 3
