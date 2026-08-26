"""Shared retry-safety rules for Boundary A.

Two independent proofs are required:

* Polyfill engines need both operator override halves because the brain stores
  original arguments redacted.
* Every delivered retry must target the exact live session whose loaded adapter
  advertises the versioned by-reference contract. Sticky Agent metadata and the
  z4j-bare package version are observability only.

The dispatcher derives the required engine below every issuer. WebSocket
registries bind adapter capabilities to immutable session generations;
long-poll checks the adapter-derived header on the request that claims the row.
"""

from __future__ import annotations

from typing import Any

from z4j_core.transport import RETRY_BY_REFERENCE_CAPABILITY

#: Engines the current brain is allowed to target with retry commands.
#:
#: Ingest remains forward-compatible with arbitrary engine names, but command
#: dispatch is authority-bearing. Keeping this set in the domain boundary makes
#: unknown engines unsatisfiable even for internal and future issuers that do
#: not pass through the REST validators.
RETRY_COMMAND_ENGINES: frozenset[str] = frozenset({"celery", "rq", "dramatiq"})

#: Engines whose current adapters implement ``retry_task`` natively / by
#: reference. This answers only whether argument reconstruction is safe. It
#: does not authorize delivery: the exact connected adapter session must also
#: advertise :data:`RETRY_BY_REFERENCE_CAPABILITY` through the versioned
#: session contract below.
NATIVE_RETRY_ENGINES: frozenset[str] = frozenset({"celery", "rq", "dramatiq"})


def engine_is_native_retry(engine: Any) -> bool:
    """Whether the current adapter retries by reference (broker-held).

    A true result means operator argument overrides are unnecessary. It says
    nothing about a connected session's authority to receive the retry; every
    delivery path separately checks that session's advertised v1 contract.
    """
    return isinstance(engine, str) and engine in NATIVE_RETRY_ENGINES


def polyfill_retry_has_operator_overrides(override_args: Any, override_kwargs: Any) -> bool:
    """True iff BOTH operator override halves are present.

    The only safe inputs for a polyfill (re-submit) retry, since the brain's
    stored arguments are redacted. Requires both halves: supplying only one and
    pairing it with an empty other half would silently drop the untouched half.
    A caller uses this to decide whether a non-native retry may be dispatched at
    all -- there is no runtime-version escape hatch.
    """
    return override_args is not None and override_kwargs is not None


#: Actions that can re-run work and therefore require authority from the exact
#: loaded adapter session that will receive them.
RETRY_FAMILY_ACTIONS: frozenset[str] = frozenset({"retry_task", "bulk_retry"})


def required_retry_engine(action: Any, payload: Any) -> str | None:
    """Return the engine whose session contract a command requires.

    ``None`` means the action is not in the retry family. The empty string is an
    intentionally unsatisfiable requirement: a retry-family payload that cannot
    name its engine must fail closed rather than become unrestricted.
    """
    if action not in RETRY_FAMILY_ACTIONS:
        return None
    if not isinstance(payload, dict):
        return ""
    engine: Any
    if action == "retry_task":
        engine = payload.get("engine")
    else:
        selection = payload.get("filter")
        engine = selection.get("engine") if isinstance(selection, dict) else None
    if not isinstance(engine, str) or engine not in RETRY_COMMAND_ENGINES:
        return ""
    return engine


def retry_contracts_from_capabilities(capabilities: Any) -> dict[str, int]:
    """Extract versioned retry contracts from one session's capability map."""
    if not isinstance(capabilities, dict):
        return {}
    contracts: dict[str, int] = {}
    for engine, advertised in capabilities.items():
        if (
            isinstance(engine, str)
            and engine
            and isinstance(advertised, (list, tuple, set, frozenset))
            and RETRY_BY_REFERENCE_CAPABILITY in advertised
        ):
            contracts[engine] = 1
    return contracts


def session_supports_retry_engine(contracts: Any, engine: str | None) -> bool:
    """Whether one immutable session satisfies ``engine``'s v1 contract."""
    if engine is None:
        return True
    if not engine or not isinstance(contracts, dict):
        return False
    return contracts.get(engine) == 1
