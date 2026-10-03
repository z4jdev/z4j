"""Pin operational documentation to the behavior its implementations provide."""

from __future__ import annotations

import z4j_brain.domain as domain_package
from z4j_brain import audit_retention, backup
from z4j_brain.domain import audit_forwarder, audit_frozen_export


def _normalized(value: str | None) -> str:
    return " ".join((value or "").split())


def test_retention_docs_distinguish_transaction_and_lock_scopes() -> None:
    module_contract = _normalized(audit_retention.__doc__)
    audit_contract = _normalized(audit_retention.AuditRetentionSweeper._do_sweep.__doc__)
    agent_contract = _normalized(
        audit_retention.AuditRetentionSweeper._do_sweep_agent_status.__doc__
    )

    assert "one outer transaction for the capped" in module_contract
    assert "individual batches are SAVEPOINTs" in audit_contract
    assert "does not take the audit sweep's advisory lock" in module_contract
    assert "does not acquire the audit sweep advisory lock" in agent_contract
    assert "ONE transaction per batch" not in module_contract


def test_sqlite_backup_docs_disclose_normal_lock_contention() -> None:
    module_contract = _normalized(backup.__doc__)
    helper_contract = _normalized(backup.backup_sqlite.__doc__)

    assert "is not lock-free" in module_contract
    assert "not a lock-free online-backup protocol" in helper_contract
    assert "normal SQLite read/write locks still apply" in helper_contract


def test_domain_package_disclaims_a_strict_dependency_boundary() -> None:
    contract = _normalized(domain_package.__doc__)

    assert "not a strict clean-architecture dependency boundary" in contract
    assert "brain persistence, authentication, settings" in contract


def test_forwarder_docs_state_at_least_once_and_the_cursor_limit() -> None:
    contract = _normalized(audit_forwarder.__doc__)

    assert "Delivery is at least once" in contract
    assert "the receiver de-duplicates on the row id" in contract
    assert "Nothing is dropped" in contract
    # The cursor lives beside the log, so the forwarder still is not the
    # out-of-band anchor; the docstring has to keep saying so.
    assert "a role that can delete audit rows can also move the cursor past them" in contract
    assert "bounded and in-memory" not in contract
    assert not hasattr(audit_forwarder.AuditForwarder, "stop")


def test_frozen_export_docs_bound_pathname_cleanup_operations() -> None:
    contract = _normalized(audit_frozen_export.__doc__)

    assert "Cleanup is not wholly pathname-free" in contract
    assert "final empty-directory removal by pathname" in contract
    assert "never falls back to pathname-only operations" not in contract
