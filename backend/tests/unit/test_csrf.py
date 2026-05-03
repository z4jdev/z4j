"""Tests for ``z4j_brain.auth.csrf``."""

from __future__ import annotations

from z4j_brain.auth.csrf import (
    CSRF_COOKIE_NAME_DEV,
    CSRF_COOKIE_NAME_PROD,
    csrf_cookie_kwargs,
    csrf_cookie_name,
    is_safe_method,
    tokens_match,
)


class TestSafeMethods:
    def test_get_is_safe(self) -> None:
        assert is_safe_method("GET")

    def test_head_is_safe(self) -> None:
        assert is_safe_method("HEAD")

    def test_options_is_safe(self) -> None:
        assert is_safe_method("OPTIONS")

    def test_post_is_not_safe(self) -> None:
        assert not is_safe_method("POST")

    def test_method_case_insensitive(self) -> None:
        assert is_safe_method("get")
        assert not is_safe_method("post")


class TestTokensMatch:
    def test_equal(self) -> None:
        assert tokens_match("abc", "abc")

    def test_different_value_same_length(self) -> None:
        assert not tokens_match("abc", "abd")

    def test_different_length(self) -> None:
        assert not tokens_match("abc", "abcd")

    def test_missing_supplied(self) -> None:
        assert not tokens_match("abc", None)

    def test_empty_supplied(self) -> None:
        assert not tokens_match("abc", "")


class TestCookieNames:
    def test_prod_uses_host_prefix(self) -> None:
        assert csrf_cookie_name(environment="production") == CSRF_COOKIE_NAME_PROD
        assert csrf_cookie_name(environment="production").startswith("__Host-")

    def test_dev_drops_host_prefix(self) -> None:
        assert csrf_cookie_name(environment="dev") == CSRF_COOKIE_NAME_DEV


class TestCsrfCookieKwargs:
    def test_dev_secure_false(self) -> None:
        kw = csrf_cookie_kwargs(environment="dev", max_age_seconds=3600)
        assert kw["secure"] is False
        assert kw["httponly"] is False  # JS must be able to read it
        assert kw["samesite"] == "strict"

    def test_prod_secure_true(self) -> None:
        kw = csrf_cookie_kwargs(environment="production", max_age_seconds=3600)
        assert kw["secure"] is True
        assert kw["httponly"] is False
