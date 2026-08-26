"""Known-answer vectors for every authenticated audit-chain construction.

The audit chain is the compliance claim this product makes to regulated
buyers, and until these vectors existed that claim was asserted rather than
verified. The suite had 355 audit tests and every one of them computed the
expected value with the same code it was checking, so three separate semantic
mutations to the MAC construction passed the entire suite unchanged:

  * dropping ``id`` from the row envelope, which is the exact defence
    ``audit_service`` relies on to make duplicate rows detectable
  * dropping ``prev_row_hmac``, which is what chains a row to its predecessor
    and is the reason a deleted suffix is supposed to be visible
  * dropping the domain separator, which is what stops a MAC computed for one
    construction being replayed as another

A vector is different in kind from a round-trip test. It pins the bytes, so a
change to the canonical form, the field set, the field order, the separator or
the digest cannot be absorbed by recomputing both sides. If one of these fails,
the wire format changed: either that was intended, in which case
``AUDIT_ROW_HMAC_VERSION`` and the affected domain separator must change with
it and existing chains need a documented transition, or it was not, in which
case the change silently broke every chain already written.

Every digest below was produced by the implementation at the commit that
introduced this file and then transcribed as a literal. Do not regenerate them
from the code under test.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from z4j_brain.domain import audit_chain as ac

# 32 bytes, chosen so the vector is reproducible by hand: bytes(range(32)).
_SECRET = bytes(range(32))
_KEY_ID = "8d1fbf6ac33d3c31dc5a80a7bf61ac8909ae2e1b38e43360cd77e28f9f49d939"
_GENERATION = uuid.UUID("77777777-7777-4777-8777-777777777777")
_ROW_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")

_FULL_ROW_JSON = (
    '{"action":"schedule.pause",'
    '"api_key_id":"55555555-5555-4555-8555-555555555555",'
    '"chain_generation":"77777777-7777-4777-8777-777777777777",'
    '"event_id":"33333333-3333-4333-8333-333333333333",'
    '"hmac_key_id":"8d1fbf6ac33d3c31dc5a80a7bf61ac8909ae2e1b38e43360cd77e28f9f49d939",'
    '"id":"11111111-1111-4111-8111-111111111111",'
    '"metadata":{"n":1,"nested":{"a":null,"b":true},"reason":"known-answer"},'
    '"occurred_at":"2026-03-08T06:59:59.123456+00:00",'
    '"outcome":"paused",'
    '"prev_row_hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"project_id":"66666666-6666-4666-8666-666666666666",'
    '"result":"success",'
    '"source_ip":"203.0.113.7",'
    '"target_id":"22222222-2222-4222-8222-222222222222",'
    '"target_type":"schedule",'
    '"user_agent":"z4j-test/1.0",'
    '"user_id":"44444444-4444-4444-8444-444444444444",'
    '"version":2}'
)
_FULL_ROW_MAC = "3a351a7c61f1dd164928e492213054115c9660efd40010bdb6c1c85a51a58c10"
_NULL_ROW_MAC = "31277a6b25a0dfa5cb77e90438e14c6d2dd9a76c56352d714848c8dd59977087"
_PREPARATION_MAC = "b979f6ec1e5d96cd5ff44eb32658e03652fa40d68053ebea187a7f13a0f4ccea"
_FROZEN_DIGEST = "bba947db85568c2eacf2144224a92f9143cb2a8201d3b8ed650ad61d05921223"

# Every field the v2 row envelope carries. Losing one silently is the failure
# this set exists to make loud, so it is written out rather than derived.
_ROW_FIELDS = frozenset(
    {
        "version",
        "id",
        "action",
        "target_type",
        "target_id",
        "result",
        "outcome",
        "event_id",
        "user_id",
        "api_key_id",
        "project_id",
        "source_ip",
        "user_agent",
        "metadata",
        "occurred_at",
        "prev_row_hmac",
        "hmac_key_id",
        "chain_generation",
    }
)


def _full_row() -> dict[str, object]:
    return ac.canonical_row_payload(
        row_id=_ROW_ID,
        action="schedule.pause",
        target_type="schedule",
        target_id="22222222-2222-4222-8222-222222222222",
        result="success",
        outcome="paused",
        event_id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
        user_id=uuid.UUID("44444444-4444-4444-8444-444444444444"),
        api_key_id=uuid.UUID("55555555-5555-4555-8555-555555555555"),
        project_id=uuid.UUID("66666666-6666-4666-8666-666666666666"),
        source_ip="203.0.113.7",
        user_agent="z4j-test/1.0",
        metadata={"reason": "known-answer", "n": 1, "nested": {"b": True, "a": None}},
        occurred_at=datetime.datetime(2026, 3, 8, 6, 59, 59, 123456, tzinfo=datetime.UTC),
        prev_row_hmac="a" * 64,
        hmac_key_id=_KEY_ID,
        chain_generation=_GENERATION,
    )


def _null_row() -> dict[str, object]:
    return ac.canonical_row_payload(
        row_id=_ROW_ID,
        action="user.login",
        target_type="user",
        target_id=None,
        result="failure",
        outcome=None,
        event_id=None,
        user_id=None,
        api_key_id=None,
        project_id=None,
        source_ip=None,
        user_agent=None,
        metadata={},
        occurred_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        prev_row_hmac=None,
        hmac_key_id=_KEY_ID,
        chain_generation=_GENERATION,
    )


def test_row_hmac_version_is_pinned() -> None:
    """The version travels inside the MAC, so it cannot move quietly."""

    assert ac.AUDIT_ROW_HMAC_VERSION == 2
    assert _full_row()["version"] == 2


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("_KEY_ID_DOMAIN", b"z4j/audit-chain/key-id/v1\x00"),
        ("_ROW_MAC_DOMAIN", b"z4j/audit-chain/row/v2\x00"),
        ("_STATE_MAC_DOMAIN", b"z4j/audit-chain/state/v1\x00"),
        ("_PREPARATION_MAC_DOMAIN", b"z4j/audit-chain/preparation/v1\x00"),
        ("_FROZEN_SNAPSHOT_DOMAIN", b"z4j/audit-chain/frozen-snapshot/v1\x00"),
    ],
)
def test_domain_separators_are_pinned(name: str, expected: bytes) -> None:
    """Separation is what stops one construction's MAC being replayed as another."""

    assert getattr(ac, name) == expected


def test_row_envelope_carries_every_canonical_field() -> None:
    """A dropped field is a silent chain break, so the set is asserted whole."""

    assert set(_full_row()) == _ROW_FIELDS
    assert set(_null_row()) == _ROW_FIELDS


def test_canonical_row_json_is_byte_exact() -> None:
    """Pins field order, separators, unicode handling and null encoding."""

    assert ac.canonical_json(_full_row()).decode("utf-8") == _FULL_ROW_JSON


def test_audit_key_id_vector() -> None:
    assert ac.canonical_audit_key_id(_SECRET) == _KEY_ID


def test_row_hmac_vectors() -> None:
    assert ac.compute_row_hmac(_SECRET, _full_row()) == _FULL_ROW_MAC
    assert ac.compute_row_hmac(_SECRET, _null_row()) == _NULL_ROW_MAC


def test_preparation_mac_vector() -> None:
    payload = ac.canonical_preparation_payload(
        preparation_id=uuid.UUID("88888888-8888-4888-8888-888888888888"),
        audit_key_id=_KEY_ID,
        preparation_revision="v1_9_a",
        target_activation_revision="v1_9_b",
    )
    assert ac.compute_preparation_mac(_SECRET, payload) == _PREPARATION_MAC


def test_frozen_snapshot_digest_vector() -> None:
    assert ac.frozen_snapshot_digest([_full_row(), _null_row()]) == _FROZEN_DIGEST
    assert ac.frozen_snapshot_digest([]) is None


def test_frozen_snapshot_digest_is_order_and_length_bound() -> None:
    """Length framing is what stops two rows concatenating into one."""

    forward = ac.frozen_snapshot_digest([_full_row(), _null_row()])
    assert ac.frozen_snapshot_digest([_null_row(), _full_row()]) != forward


def test_row_mac_changes_when_any_canonical_field_changes() -> None:
    """Every field must reach the MAC, including the ones nothing else reads."""

    baseline = ac.compute_row_hmac(_SECRET, _full_row())
    for field in sorted(_ROW_FIELDS):
        mutated = dict(_full_row())
        current = mutated[field]
        if field == "version":
            mutated[field] = 99
        elif field == "metadata":
            mutated[field] = {"reason": "different"}
        elif isinstance(current, str):
            mutated[field] = ("b" * 64) if len(current) == 64 else current + "-x"
        else:
            mutated[field] = "changed"
        assert ac.compute_row_hmac(_SECRET, mutated) != baseline, field


def test_row_mac_is_key_bound() -> None:
    other = bytes(range(1, 33))
    assert ac.compute_row_hmac(other, _full_row()) != _FULL_ROW_MAC
