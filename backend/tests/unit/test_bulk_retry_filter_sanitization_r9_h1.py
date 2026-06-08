"""R9-H1 regression: brain MUST strip server-owned keys from the
inbound bulk_retry filter.

CVE shape: an authenticated operator (Project.OPERATOR role) submits
``POST /api/v1/projects/<slug>/commands/bulk-retry`` with
``filter.task_names = {<known_rq_job_id>: "os.system"}`` and an
absent or non-RQ ``filter.engine``. Before R9-H1 the brain copied
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
  with 400 rather than silently retrying the resolved ones.
"""

from __future__ import annotations


class TestServerOwnedFilterKeys:
    """The constant that documents R9-H1's policy."""

    def test_task_names_is_server_owned(self) -> None:
        from z4j_brain.api.commands import SERVER_OWNED_FILTER_KEYS
        assert "task_names" in SERVER_OWNED_FILTER_KEYS, (
            "R9-H1 regression: task_names must remain server-owned. "
            "Removing it would let an authenticated operator spoof "
            "the RQ adapter's queue.enqueue_call(func=...) target "
            "via filter.task_names, bypassing the brain's DB lookup."
        )

    def test_overrides_is_server_owned(self) -> None:
        from z4j_brain.api.commands import SERVER_OWNED_FILTER_KEYS
        assert "overrides" in SERVER_OWNED_FILTER_KEYS, (
            "R9-H1 regression: overrides (per-job args/kwargs) is "
            "brain-populated; client must not seed it."
        )

    def test_task_priorities_is_server_owned(self) -> None:
        from z4j_brain.api.commands import SERVER_OWNED_FILTER_KEYS
        assert "task_priorities" in SERVER_OWNED_FILTER_KEYS, (
            "R9-H1 regression: task_priorities is populated by the "
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

    def test_issue_bulk_retry_uses_server_owned_filter_keys(self) -> None:
        import inspect
        from z4j_brain.api import commands

        src = inspect.getsource(commands.issue_bulk_retry)
        # The set is referenced by name inside the endpoint body.
        # If a future refactor removes the strip step or inlines a
        # different set, this test fails fast.
        assert "SERVER_OWNED_FILTER_KEYS" in src, (
            "R9-H1 regression: issue_bulk_retry must reference "
            "SERVER_OWNED_FILTER_KEYS to strip server-owned keys "
            "from the inbound filter. The endpoint source no longer "
            "mentions the constant - did a refactor inline a different "
            "set or remove the sanitization?"
        )
        # The endpoint must derive enriched_filter from a filtered
        # comprehension that excludes the server-owned keys, not by
        # copying the raw filter and overwriting conditionally
        # (which was the pre-R9-H1 shape).
        assert (
            "k not in SERVER_OWNED_FILTER_KEYS" in src
            or "k for k in" in src and "if k not in SERVER" in src
        ), (
            "R9-H1 regression: enriched_filter must be derived via "
            "a comprehension that excludes SERVER_OWNED_FILTER_KEYS, "
            "not by `dict(body.filter)` followed by conditional "
            "overwrite. The previous shape let client-supplied keys "
            "ride through when the engine field was omitted."
        )

    def test_issue_bulk_retry_fails_closed_on_partial_rq_name_resolution(
        self,
    ) -> None:
        """The endpoint must refuse the whole batch if the DB's
        get_names_for_ids returns fewer rows than the targeted id set
        when filter_engine == 'rq'. The pre-R9-H1 shape would have
        silently retried the resolved ids; the fix raises HTTP 400
        with the missing-id list."""
        import inspect
        from z4j_brain.api import commands

        src = inspect.getsource(commands.issue_bulk_retry)
        assert "len(task_names) != len(capped_ids)" in src, (
            "R9-H1 regression: missing the partial-DB-resolution check "
            "for RQ. Without it, a client could cherry-pick which ids "
            "land in the retry batch by manipulating the input set "
            "against the DB's coverage."
        )
        assert 'filter_engine == "rq"' in src, (
            "R9-H1 regression: the partial-resolution guard must be "
            "RQ-specific because RQ is the engine where missing "
            "task_name triggers RCE-class behavior (the agent's "
            "queue.enqueue_call needs a callable string)."
        )
        assert "HTTPException" in src and "status_code=400" in src, (
            "R9-H1 regression: the partial-resolution guard must raise "
            "HTTP 400 rather than silently dropping ids."
        )
