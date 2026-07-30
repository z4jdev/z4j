"""Regression: brain MUST strip server-owned keys from the
inbound bulk_retry filter.

CVE shape: an authenticated operator (Project.OPERATOR role) submits
``POST /api/v1/projects/<slug>/commands/bulk-retry`` with
``filter.task_names = {<known_rq_job_id>: "os.system"}`` and an
absent or non-RQ ``filter.engine``. Before the brain copied
``filter`` verbatim into ``enriched_filter`` and only conditionally
overwrote ``task_names`` when ``filter.engine in KNOWN_ENGINES``.
The agent's bulk_retry path then trusted ``filter["task_names"][jid]``
and called ``queue.enqueue_call(func="os.system", ...)`` -> arbitrary
importable callable invocation on the agent host.

The fix:
- ``SERVER_OWNED_FILTER_KEYS`` declares the keys that must be
  brain-populated only: ``task_names``, ``task_priorities``,
  ``overrides``.
- The endpoint strips them up front; client attempts to seed them
  are reported in ``rejected_client_supplied_filter_keys`` for audit.
- For RQ explicit-IDs, DB resolution of ``task_names`` is REQUIRED
  for every targeted id; a partial DB match fails the whole batch
  with 400 rather than silently retrying the resolved ones."""

from __future__ import annotations


class TestServerOwnedFilterKeys:
    """The constant that documents 's policy."""

    def test_task_names_is_server_owned(self) -> None:
        from z4j_brain.api.commands import SERVER_OWNED_FILTER_KEYS

        assert "task_names" in SERVER_OWNED_FILTER_KEYS, (
            " regression: task_names must remain server-owned. "
            "Removing it would let an authenticated operator spoof "
            "the RQ adapter's queue.enqueue_call(func=...) target "
            "via filter.task_names, bypassing the brain's DB lookup."
        )

    def test_overrides_is_server_owned(self) -> None:
        from z4j_brain.api.commands import SERVER_OWNED_FILTER_KEYS

        assert "overrides" in SERVER_OWNED_FILTER_KEYS, (
            " regression: overrides (per-job args/kwargs) is "
            "brain-populated; client must not seed it."
        )

    def test_task_priorities_is_server_owned(self) -> None:
        from z4j_brain.api.commands import SERVER_OWNED_FILTER_KEYS

        assert "task_priorities" in SERVER_OWNED_FILTER_KEYS, (
            " regression: task_priorities is populated by the "
            "TaskRepository priority lookup; client must not seed."
        )

    def test_set_shape_is_immutable(self) -> None:
        """Defense against accidental list-not-frozenset drift."""
        from z4j_brain.api.commands import SERVER_OWNED_FILTER_KEYS

        assert isinstance(SERVER_OWNED_FILTER_KEYS, frozenset), (
            "SERVER_OWNED_FILTER_KEYS must be a frozenset so the "
            "module-level membership check stays O(1) and the set "
            "cannot drift at runtime."
        )


class TestClientFilterAllowlist:
    """CX-H5: the client filter is a selection-only allowlist.

    The Dramatiq ``bulk_retry_action`` reads ``actors`` / ``args`` /
    ``kwargs`` / ``queues`` from the filter and invokes the named actor
    with them. The old denylist stripped only three keys, so those
    executable maps rode straight through -> an OPERATOR could invoke an
    arbitrary registered actor with attacker-chosen arguments. The
    allowlist refuses every non-selection key.
    """

    EXECUTABLE_KEYS = ("actors", "args", "kwargs", "queues", "func", "overrides", "task_names")
    SELECTION_KEYS = ("task_ids", "engine", "state", "queue", "name", "since", "until")

    def test_executable_keys_are_not_allowlisted(self) -> None:
        from z4j_brain.api.commands import CLIENT_ALLOWED_BULK_FILTER_KEYS

        for key in self.EXECUTABLE_KEYS:
            assert key not in CLIENT_ALLOWED_BULK_FILTER_KEYS, (
                f"CX-H5 regression: {key!r} is an executable/server-owned "
                "field and must NOT be client-supplyable via the bulk "
                "filter. Allowlisting it re-opens the Dramatiq "
                "arbitrary-actor-invocation primitive."
            )

    def test_selection_keys_are_allowlisted(self) -> None:
        from z4j_brain.api.commands import CLIENT_ALLOWED_BULK_FILTER_KEYS

        for key in self.SELECTION_KEYS:
            assert key in CLIENT_ALLOWED_BULK_FILTER_KEYS, (
                f"{key!r} is a benign selection filter and should remain "
                "client-supplyable; dropping it breaks legitimate "
                "narrowing of a bulk retry."
            )

    def test_server_owned_keys_are_a_strict_subset_of_rejected(self) -> None:
        """Every server-owned key is also rejected by the allowlist,
        so the allowlist strictly supersedes the old denylist."""
        from z4j_brain.api.commands import (
            CLIENT_ALLOWED_BULK_FILTER_KEYS,
            SERVER_OWNED_FILTER_KEYS,
        )

        assert SERVER_OWNED_FILTER_KEYS.isdisjoint(CLIENT_ALLOWED_BULK_FILTER_KEYS), (
            "server-owned keys must never be allowlisted for client input"
        )


class TestEndpointStripsServerOwnedKeys:
    """Structural invariant: issue_bulk_retry references the constant.

    The endpoint runs inside FastAPI with non-trivial dependency
    injection (auth, project lookup, throttle, dispatcher); the
    full-stack endpoint test lives in the integration suite. This
    unit test asserts the structural shape that any future refactor
    must preserve: the function uses SERVER_OWNED_FILTER_KEYS to
    derive enriched_filter from the inbound body.filter, NOT the
    other way around.
    """

    def test_issue_bulk_retry_uses_client_allowlist(self) -> None:
        import inspect

        from z4j_brain.api import commands

        src = inspect.getsource(commands.issue_bulk_retry)
        # 1.7.1 CX-H5: the endpoint now enforces a SELECTION-ONLY
        # allowlist (strictly stronger than the old server-owned
        # denylist -- it strips the server-owned keys AND every
        # executable field). The enriched_filter must be derived by
        # KEEPING only allowlisted keys, not by excluding a denylist.
        assert "CLIENT_ALLOWED_BULK_FILTER_KEYS" in src, (
            "CX-H5 regression: issue_bulk_retry must reference "
            "CLIENT_ALLOWED_BULK_FILTER_KEYS to keep only selection "
            "filters. The endpoint source no longer mentions the "
            "allowlist -- did a refactor drop the sanitization or "
            "revert to a denylist (which lets a client smuggle "
            "executable keys like actors/args/kwargs to an adapter)?"
        )
        assert "if k in CLIENT_ALLOWED_BULK_FILTER_KEYS" in src, (
            "CX-H5 regression: enriched_filter must be derived via a "
            "comprehension that KEEPS only allowlisted keys "
            "(`if k in CLIENT_ALLOWED_BULK_FILTER_KEYS`), not by "
            "excluding a denylist. A denylist re-opens the "
            "confused-deputy class for any executable key not "
            "explicitly enumerated."
        )

    def test_issue_bulk_retry_fails_closed_on_partial_name_resolution_h4(
        self,
    ) -> None:
        """H4 (generalizes): the endpoint refuses the whole batch if
        get_names_for_ids resolves fewer rows than the targeted id set, for
        ANY engine (not just RQ), and requires an explicit known engine. This
        stops an operator mislabeling foreign ids (or omitting the engine) to
        skip the project-scoped ownership check and requeue another project's
        tasks on shared infrastructure."""
        import inspect

        from z4j_brain.api import commands

        src = inspect.getsource(commands.issue_bulk_retry)
        assert "len(task_names) != len(capped_ids)" in src, (
            "H4/ regression: missing the partial-DB-resolution check. "
            "Without it a client could cherry-pick which ids land in the "
            "batch, or requeue foreign ids, by manipulating the input set."
        )
        assert 'filter_engine == "rq"' not in src, (
            "H4 regression: the partial-resolution guard is RQ-only again. "
            "It must fail closed for celery/dramatiq too, else a foreign id "
            "labeled engine=celery skips the project-scoped ownership check."
        )
        assert "filter_engine not in KNOWN_ENGINES" in src, (
            "H4 regression: a bulk retry with task_ids must reject a missing "
            "or unknown engine (an omitted engine previously skipped the "
            "ownership lookup entirely)."
        )
        assert "HTTPException" in src and "status_code=400" in src, (
            " regression: the partial-resolution guard must raise "
            "HTTP 400 rather than silently dropping ids."
        )
