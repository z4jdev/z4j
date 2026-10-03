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

Which engines may receive a command is not a list the brain carries. An engine
is dispatchable for an action when the target agent's current session
advertises that engine together with the action's capability token (see
:func:`dispatch_refusal`). The brain validates only the *shape* of an engine
name, so an engine string that no connected agent advertises is refused with a
message saying so and is never rewritten to a default (LATENT-1: an unknown
engine once fell back silently to ``"celery"`` in two repository helpers).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any, Protocol

from z4j_core.models.dead_letter import DLQ_LIST_ACTION, LIST_DEAD_LETTERS_CAPABILITY
from z4j_core.transport import RETRY_BY_REFERENCE_CAPABILITY

#: Longest engine name the brain accepts anywhere (matches the ``engine``
#: bound on every z4j-core model: ``Field(min_length=1, max_length=40)``).
ENGINE_NAME_MAX_LENGTH = 40

#: Shape of an adapter name: a leading letter or digit, then letters, digits,
#: ``.``, ``_`` or ``-``. This bounds the string; it authorizes nothing.
_ENGINE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")

#: Engines whose current adapters implement ``retry_task`` natively / by
#: reference: the broker or result backend still holds the original job, so a
#: retry needs no operator arguments. This is a property of the engine, not of
#: a session, which is why it stays a static set: huey attests the safe retry
#: contract yet still needs complete operator replacements because Huey keeps
#: no arguments after completion. It answers only whether argument
#: reconstruction is safe. It does not authorize delivery: the exact connected
#: adapter session must also advertise :data:`RETRY_BY_REFERENCE_CAPABILITY`
#: through the versioned session contract below.
NATIVE_RETRY_ENGINES: frozenset[str] = frozenset({"celery", "rq", "dramatiq"})

#: Capability token an agent must advertise for an engine before the brain
#: dispatches the action to it. Every token is one the adapters already list in
#: their ``DEFAULT_CAPABILITIES`` (and the dashboard reads the same map).
CAPABILITY_FOR_ACTION: Mapping[str, str] = {
    "retry_task": "retry_task",
    "cancel_task": "cancel_task",
    "requeue_dead_letter": "requeue_dead_letter",
    "bulk_retry": "bulk_retry",
    # The read side of the dead-letter store. The action is a wire command
    # name and the token names the adapter method, which is why they differ.
    DLQ_LIST_ACTION: LIST_DEAD_LETTERS_CAPABILITY,
}


class AdvertisedInventory(Protocol):
    """The handshake fields of an Agent row that the dispatch rule reads."""

    @property
    def name(self) -> str: ...

    @property
    def engine_adapters(self) -> list[str]: ...

    @property
    def capabilities(self) -> dict[str, Any]: ...

    @property
    def last_connect_at(self) -> datetime | None: ...


def engine_name_error(value: Any) -> str | None:
    """Return why ``value`` is not a well-formed engine name, or ``None``.

    Shape only. A well-formed name still needs a connected agent that
    advertises it before any command is dispatched for it.
    """
    if not isinstance(value, str) or not value:
        return f"engine must be a non-empty adapter name, got {value!r}"
    if len(value) > ENGINE_NAME_MAX_LENGTH or _ENGINE_NAME_RE.fullmatch(value) is None:
        return (
            "engine must be an adapter name of at most "
            f"{ENGINE_NAME_MAX_LENGTH} characters (letters, digits, '.', '_' "
            f"and '-'), got {value!r}"
        )
    return None


def is_engine_name(value: Any) -> bool:
    """Whether ``value`` has the shape of an adapter name."""
    return engine_name_error(value) is None


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
    name a well-formed engine must fail closed rather than become unrestricted.
    A well-formed name is returned as is; whether any session satisfies it is
    decided by that session's advertised contract, never by a list here.
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
    if not is_engine_name(engine):
        return ""
    return str(engine)


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


def agent_reports_inventory(agent: AdvertisedInventory) -> bool:
    """Whether the brain holds this agent's adapter inventory.

    Only a WebSocket ``hello`` records ``engine_adapters``, ``capabilities`` and
    ``last_connect_at``. The long-poll transport sends no hello, so its row
    keeps the empty inventory it was minted with: unreported, not "no engines".
    A connected agent that listed no engines has reported, and is excluded from
    task commands.
    """
    return agent.last_connect_at is not None or bool(agent.engine_adapters)


def advertised_actions(capabilities: Any, engine: str) -> frozenset[str]:
    """Capability tokens one agent advertises for ``engine``."""
    if not isinstance(capabilities, dict):
        return frozenset()
    advertised = capabilities.get(engine)
    if not isinstance(advertised, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(token for token in advertised if isinstance(token, str))


def dispatch_refusal(agent: AdvertisedInventory, *, engine: Any, action: str) -> str | None:
    """Why ``agent`` may not receive ``action`` for ``engine``, or ``None``.

    The rule: the agent's current session must advertise ``engine`` in its
    engine list and the action's capability token for that engine; a
    retry-family action also needs the adapter's attested safe retry contract,
    which is the same marker every delivery path admits on. An agent whose
    inventory is unreported (long-poll) is not refused here: its claim admits
    each command against the contracts it states on that poll, and its
    dispatcher fails closed on an engine it has not loaded.

    The engine string is never rewritten. A name nothing advertises is a
    refusal that names the engine, not a fallback to another engine.
    """
    shape_error = engine_name_error(engine)
    if shape_error is not None:
        return shape_error
    token = CAPABILITY_FOR_ACTION.get(action)
    if token is None:
        return f"action {action!r} is not an engine command"
    if not agent_reports_inventory(agent):
        return None
    return _inventory_refusal(agent, engine=str(engine), action=action, token=token)


def _inventory_refusal(
    agent: AdvertisedInventory,
    *,
    engine: str,
    action: str,
    token: str,
) -> str | None:
    """The reported-inventory half of :func:`dispatch_refusal`."""
    engines = [name for name in (agent.engine_adapters or []) if isinstance(name, str)]
    if engine not in engines:
        return (
            f"no connected agent advertises engine {engine!r}: agent "
            f"{agent.name!r} advertises {sorted(engines)}"
        )
    actions = advertised_actions(agent.capabilities, engine)
    if token not in actions:
        return (
            f"agent {agent.name!r} does not advertise {token!r} for engine "
            f"{engine!r}; it advertises {sorted(actions)}"
        )
    if action in RETRY_FAMILY_ACTIONS and RETRY_BY_REFERENCE_CAPABILITY not in actions:
        return (
            f"agent {agent.name!r} advertises {token!r} for engine {engine!r} but "
            f"its adapter does not attest the safe retry contract "
            f"({RETRY_BY_REFERENCE_CAPABILITY}); upgrade the adapter"
        )
    return None


def project_engine_authority(
    agents: Iterable[AdvertisedInventory],
    *,
    action: str,
) -> Callable[[str], bool]:
    """Predicate: some agent in ``agents`` may receive ``action`` for an engine.

    Used where no single target is named (a bulk retry whose children bind to
    a compatible session at send time). An agent with an unreported inventory
    counts as able, for the reason given in :func:`dispatch_refusal`.
    """
    candidates = list(agents)

    def _can_dispatch(engine: str) -> bool:
        return any(
            dispatch_refusal(agent, engine=engine, action=action) is None for agent in candidates
        )

    return _can_dispatch


__all__ = [
    "CAPABILITY_FOR_ACTION",
    "ENGINE_NAME_MAX_LENGTH",
    "NATIVE_RETRY_ENGINES",
    "RETRY_FAMILY_ACTIONS",
    "AdvertisedInventory",
    "advertised_actions",
    "agent_reports_inventory",
    "dispatch_refusal",
    "engine_is_native_retry",
    "engine_name_error",
    "is_engine_name",
    "polyfill_retry_has_operator_overrides",
    "project_engine_authority",
    "required_retry_engine",
    "retry_contracts_from_capabilities",
    "session_supports_retry_engine",
]
