"""Tests for ``z4j_brain.auth.ip.TrustedProxyResolver``."""

from __future__ import annotations

import pytest

from z4j_brain.auth.ip import TrustedProxyResolver


class TestNoTrustedProxies:
    def test_returns_peer_ip(self) -> None:
        r = TrustedProxyResolver([])
        assert r.resolve(peer_ip="1.2.3.4", xff_header="9.9.9.9") == "1.2.3.4"

    def test_xff_ignored_without_trust(self) -> None:
        r = TrustedProxyResolver([])
        assert r.resolve(peer_ip="10.0.0.1", xff_header="6.6.6.6") == "10.0.0.1"


class TestTrustedSingleHop:
    def test_trusted_peer_returns_xff(self) -> None:
        r = TrustedProxyResolver(["10.0.0.0/8"])
        assert r.resolve(peer_ip="10.1.2.3", xff_header="9.9.9.9") == "9.9.9.9"

    def test_untrusted_peer_ignores_xff(self) -> None:
        r = TrustedProxyResolver(["10.0.0.0/8"])
        assert r.resolve(peer_ip="5.5.5.5", xff_header="9.9.9.9") == "5.5.5.5"


class TestTrustedChain:
    def test_walks_chain_right_to_left(self) -> None:
        r = TrustedProxyResolver(["10.0.0.0/8"])
        # Real client → outer proxy → inner proxy → peer
        # Trust: only 10.0.0.0/8. Walk from right: 10.0.0.6 (trusted),
        # 10.0.0.5 (trusted), 1.2.3.4 (untrusted) → 1.2.3.4 wins.
        result = r.resolve(
            peer_ip="10.0.0.1",
            xff_header="1.2.3.4, 10.0.0.5, 10.0.0.6",
        )
        assert result == "1.2.3.4"

    def test_all_trusted_returns_leftmost(self) -> None:
        r = TrustedProxyResolver(["10.0.0.0/8"])
        result = r.resolve(
            peer_ip="10.0.0.1",
            xff_header="10.0.0.4, 10.0.0.5, 10.0.0.6",
        )
        assert result == "10.0.0.4"

    def test_no_xff_falls_back_to_peer(self) -> None:
        r = TrustedProxyResolver(["10.0.0.0/8"])
        assert r.resolve(peer_ip="10.0.0.1", xff_header=None) == "10.0.0.1"


class TestEdgeCases:
    def test_invalid_cidr_raises_at_construction(self) -> None:
        with pytest.raises(ValueError, match="not a valid CIDR"):
            TrustedProxyResolver(["bad cidr"])

    def test_ipv6_in_chain(self) -> None:
        r = TrustedProxyResolver(["fc00::/7"])
        assert r.resolve(
            peer_ip="fc00::1",
            xff_header="2001:db8::1, fc00::5",
        ) == "2001:db8::1"

    def test_zone_id_stripped(self) -> None:
        r = TrustedProxyResolver(["fe80::/10"])
        result = r.resolve(
            peer_ip="fe80::1%eth0",
            xff_header="2001:db8::1",
        )
        assert result == "2001:db8::1"

    def test_empty_xff_header(self) -> None:
        r = TrustedProxyResolver(["10.0.0.0/8"])
        assert r.resolve(peer_ip="10.0.0.1", xff_header="   ") == "10.0.0.1"

    def test_no_peer_no_xff(self) -> None:
        r = TrustedProxyResolver([])
        assert r.resolve(peer_ip=None, xff_header=None) == ""
