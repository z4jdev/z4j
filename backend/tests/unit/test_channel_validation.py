"""External-audit High #2 + #3 regression tests - unified channel
validation covers telegram + email on BOTH the project-admin and
user-managed channel paths."""

from __future__ import annotations

import pytest

from z4j_brain.domain.notifications.channels import (
    _SMTP_PORT_ALLOWLIST,
    validate_smtp_config,
    validate_telegram_config,
)


class TestTelegramValidation:
    """Block the ``@`` / userinfo-smuggling SSRF on the bot_token."""

    @pytest.mark.parametrize(
        "token",
        [
            "123:abc@attacker.internal",  # userinfo-smuggle
            "1/2:ok",                       # slash - path break
            "12.34:ok",                     # dot in id
            "abc:def",                       # id must be digits
            "12345",                         # missing secret
            "12345:",                        # empty secret
            ":abc",                          # empty id
            " 12345:abc",                   # leading whitespace
            "12345:abc\n",                  # trailing newline
            "12345:abc#fragment",           # hash
        ],
    )
    def test_malformed_bot_token_rejected(self, token: str) -> None:
        err = validate_telegram_config({"bot_token": token})
        assert err is not None, f"{token!r} should be rejected"

    @pytest.mark.parametrize(
        "token",
        [
            "123456:ABCdef_ghi-jkl",
            "987654321:aaaaaaaaaaaaaa",
            "1:a",  # minimal valid shape
        ],
    )
    def test_valid_bot_token_accepted(self, token: str) -> None:
        assert validate_telegram_config({"bot_token": token}) is None

    @pytest.mark.parametrize(
        "chat",
        [
            "evil@attacker",
            "path/traversal",
            "spaces in id",
            "",
            "@-bad-handle",   # handle must start alpha-num
        ],
    )
    def test_malformed_chat_id_rejected(self, chat: str) -> None:
        err = validate_telegram_config({"chat_id": chat})
        assert err is not None

    @pytest.mark.parametrize(
        "chat",
        [
            "12345",
            "-1001234567",
            "@channel_handle",
            "@ch123",
        ],
    )
    def test_valid_chat_id_accepted(self, chat: str) -> None:
        assert validate_telegram_config({"chat_id": chat}) is None

    def test_integer_chat_id_coerced(self) -> None:
        """The API layer may send an int from JSON - we coerce
        before regex."""
        assert validate_telegram_config({"chat_id": -1001234}) is None


class TestSmtpValidation:
    """Block blind SMTP egress to private IPs and non-allowlist ports."""

    def test_port_allowlist_is_standard_smtp(self) -> None:
        """Document + pin the allowlist so a regression can't
        silently open port 22 / 6379 / etc."""
        assert _SMTP_PORT_ALLOWLIST == frozenset({25, 465, 587, 2525})

    @pytest.mark.parametrize(
        "port",
        [22, 80, 443, 6379, 5432, 8080, 8443, 9200, 27017, 3306],
    )
    @pytest.mark.asyncio
    async def test_non_allowlisted_ports_rejected(self, port: int) -> None:
        # Literal public IP so the DNS step is skipped (we're only
        # testing the port check here; other tests cover the
        # hostname path).
        err = await validate_smtp_config(
            {"smtp_host": "93.184.216.34", "smtp_port": port},
        )
        assert err is not None
        assert "allowlist" in err.lower() or "port" in err.lower()

    @pytest.mark.parametrize("port", [25, 465, 587, 2525])
    @pytest.mark.asyncio
    async def test_allowlisted_ports_accepted(self, port: int) -> None:
        # smtp.example.com resolves (via our DNS cache) to a public
        # IP; no block. We can't reliably hit DNS in all test
        # environments - so use a literal IP that we know is
        # public and not blocked.
        err = await validate_smtp_config(
            {"smtp_host": "93.184.216.34", "smtp_port": port},
        )
        assert err is None, f"port {port} should be allowlisted; err={err}"

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "::1",
            "169.254.169.254",   # AWS / cloud metadata
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "0.0.0.0",
        ],
    )
    @pytest.mark.asyncio
    async def test_private_ip_literals_rejected(self, host: str) -> None:
        err = await validate_smtp_config(
            {"smtp_host": host, "smtp_port": 587},
        )
        assert err is not None
        assert "block" in err.lower() or "private" in err.lower() or (
            "IP" in err
        )

    @pytest.mark.asyncio
    async def test_empty_host_rejected(self) -> None:
        err = await validate_smtp_config({"smtp_host": "   "})
        assert err is not None

    @pytest.mark.asyncio
    async def test_non_int_port_rejected(self) -> None:
        err = await validate_smtp_config(
            {"smtp_host": "93.184.216.34", "smtp_port": "notanumber"},
        )
        assert err is not None
        assert "integer" in err.lower() or "int" in err.lower()
