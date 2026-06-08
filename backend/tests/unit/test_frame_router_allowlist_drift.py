"""R7-H1 / R8 cross-package drift detector.

The brain re-applies the SAME worker_conf allowlist as defense in
depth before persisting heartbeat payloads to the Postgres JSONB
column. The two sets MUST stay byte-identical or one side's filter
becomes the other side's bypass:

* Adapter source: ``packages/z4j-celery/src/z4j_celery/engine.py::_CONF_ALLOWLIST``
* Brain twin:     ``packages/z4j/backend/src/z4j_brain/websocket/frame_router.py::_WORKER_CONF_ALLOWLIST``

Pre-1.6.7 this invariant was only enforced by a comment cross-
reference; the audit follow-up that landed in 1.6.6 introduced the
twin but no CI gate caught drift. This test closes that loop.

The test uses :func:`pytest.importorskip` so it stays a clean no-op
in any brain-only CI lane that does not install ``z4j-celery``.
That keeps the package-dependency direction one-way (brain does NOT
depend on the celery adapter) while still failing loudly in the
polyrepo dev environment + the all-engines docker e2e where both
packages are present.
"""

from __future__ import annotations

import pytest


class TestWorkerConfAllowlistDrift:
    def test_brain_allowlist_matches_celery_adapter_source_r7_h1(self) -> None:
        """The brain's defense-in-depth allowlist must equal the
        canonical celery-adapter source list. Failure message names
        the specific drifting keys so the next maintainer knows
        exactly which side to update."""
        pytest.importorskip("z4j_celery.engine")
        from z4j_celery.engine import _CONF_ALLOWLIST as ADAPTER_SET
        from z4j_brain.websocket.frame_router import (
            _WORKER_CONF_ALLOWLIST as BRAIN_SET,
        )

        only_in_adapter = ADAPTER_SET - BRAIN_SET
        only_in_brain = BRAIN_SET - ADAPTER_SET
        assert not only_in_adapter, (
            "R7-H1 DRIFT: keys live in z4j-celery adapter allowlist but "
            "are missing from the brain twin. The adapter would ship them; "
            "the brain would drop them, so operators silently lose "
            f"visibility on these tuning knobs: {sorted(only_in_adapter)}. "
            "Add them to _WORKER_CONF_ALLOWLIST in "
            "z4j_brain.websocket.frame_router."
        )
        assert not only_in_brain, (
            "R7-H1 DRIFT: keys live in the brain twin but are missing "
            "from the z4j-celery adapter source. The adapter would strip "
            "them before shipping (so they never arrive from celery), but "
            "the brain would accept them if some OTHER adapter sent them, "
            "potentially leaking credentialed config: "
            f"{sorted(only_in_brain)}. Add them to _CONF_ALLOWLIST in "
            "z4j_celery.engine."
        )
        assert ADAPTER_SET == BRAIN_SET
