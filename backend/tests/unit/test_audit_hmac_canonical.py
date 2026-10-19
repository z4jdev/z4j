"""Audit identity fields must encode exactly 32 bytes without whitespace."""

import pytest
from z4j_brain.domain.audit_chain import AuditChainIntegrityError, normalize_hmac


@pytest.mark.parametrize("value", [" " * 64, "\t" * 64, "00 " * 21 + " ", "ab" * 31 + "  "])
def test_whitespace_cannot_stand_in_for_hmac_bytes(value):
    assert len(value) == 64
    with pytest.raises(AuditChainIntegrityError, match="hexadecimal"):
        normalize_hmac(value, field="prev_row_hmac")


@pytest.mark.parametrize("value", ["00" * 32, "ab" * 32, "0123456789abcdef" * 4])
def test_canonical_hmac_is_retained(value):
    assert normalize_hmac(value, field="prev_row_hmac") == value


def test_absent_genesis_hmac_is_retained():
    assert normalize_hmac(None, field="prev_row_hmac") is None
