"""Compact "weak password" denylist.

A small in-memory frozenset of obvious bad-choice passwords. This is
NOT a substitute for the Have-I-Been-Pwned k-Anonymity check (which
ships in Phase 1.1 as an opt-in network call) - it just catches the
top tier of "wouldn't even need a botnet" guesses without any IO.

The list is intentionally short. Bigger lists are mostly garbage
duplicates and inflate import time and memory for marginal benefit.
For real coverage, enable :data:`Settings.hibp_check_enabled` once
that ships.

Source: composite of OWASP, NIST 800-63B Appendix A guidance, and
the SecLists project's top-100 list, lower-cased and de-duplicated.
"""

from __future__ import annotations

#: Frozen set of common passwords. ``in`` membership is O(1).
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456",
        "123456789",
        "qwerty",
        "password",
        "12345",
        "qwerty123",
        "1q2w3e",
        "12345678",
        "111111",
        "1234567890",
        "1234567",
        "qwerty1",
        "abc123",
        "iloveyou",
        "password1",
        "password123",
        "admin",
        "admin123",
        "administrator",
        "welcome",
        "welcome1",
        "welcome123",
        "letmein",
        "letmein123",
        "monkey",
        "dragon",
        "master",
        "trustno1",
        "sunshine",
        "princess",
        "shadow",
        "azerty",
        "michael",
        "football",
        "baseball",
        "starwars",
        "passw0rd",
        "p@ssw0rd",
        "p@ssword",
        "pa$$w0rd",
        "changeme",
        "changeme123",
        "default",
        "root",
        "toor",
        "test",
        "test123",
        "guest",
        "user",
        "user123",
        "secret",
        "secret123",
        "qazwsx",
        "qwertyuiop",
        "1qaz2wsx",
        "zaq12wsx",
        "qwer1234",
        "asdfghjkl",
        "z4j",
        "z4jadmin",
        "celery",
        "celery123",
        "django",
        "django123",
        "fastapi",
        "redis",
        "postgres",
        "postgres123",
        "rabbitmq",
        "default-password",
        "changeme-please-replace",
        # Long-enough variants that satisfy the policy length +
        # letter + digit rules. These are the ones a careless user
        # types when our 12-char minimum forces them to make their
        # password longer.
        "password1234",
        "password12345",
        "welcome12345",
        "qwerty123456",
        "admin1234567",
        "letmein12345",
        "passw0rd1234",
        "p@ssw0rd1234",
        "changeme1234",
        "changeme12345",
        "iloveyou1234",
    },
)


def _generate_patterns() -> frozenset[str]:
    """Seasonal + year + product-name variants.

    These are passwords that satisfy 3-of-4 character classes +
    length and would otherwise slip past our denylist. Generated
    programmatically so we don't have to hand-maintain thousands
    of `Summer2024` / `Winter2025` / `Z4j2024!` / `Celery123!`
    variants.

    Audit A3: expands the denylist from ~90 entries to ~1,500
    including the "bad but technically meets policy" tail.
    """
    out: set[str] = set()
    seasons = ("spring", "summer", "autumn", "fall", "winter")
    bases = (
        "welcome", "password", "pass", "admin", "letmein", "qwerty",
        "monkey", "dragon", "master", "hello", "login",
        "z4j", "celery", "rq", "dramatiq", "django", "flask",
        "fastapi", "postgres", "postgresql", "redis", "rabbitmq",
        "worker", "brain", "agent", "company", "corp",
    )
    years = tuple(str(y) for y in range(2015, 2030))
    symbols = ("", "!", "!!", "#", "$", "*", "@")

    # Seasonal + year + optional symbol: Spring2024, summer24!, ...
    for s in seasons:
        for y in years:
            for sym in symbols:
                out.add(s + y + sym)
                out.add(s.capitalize() + y + sym)
                out.add(s + y[-2:] + sym)

    # base + year + optional symbol: welcome2024!, z4j2026, admin2024
    for b in bases:
        for y in years:
            for sym in symbols:
                out.add(b + y + sym)
                out.add(b + y[-2:] + sym)
                out.add(b.capitalize() + y + sym)

    # base + keyboard-walk + year: "qwerty123abc"
    for b in ("qwerty", "asdf", "zxcv", "1234"):
        for y in years[-5:]:
            out.add(b + y)

    return frozenset(p.casefold() for p in out)


_PATTERN_SET: frozenset[str] = _generate_patterns()


def is_common_password(plaintext: str) -> bool:
    """Return True if ``plaintext`` matches the denylist (case-folded).

    Checks the curated top-tier set AND the programmatically-
    generated pattern set (seasonal + year + product-name variants)
    - audit A3 expansion.

    Both lookups are O(1) set membership. Case-fold is not
    constant-time but the password is already in our process
    memory at that point; no oracle to leak.
    """
    folded = plaintext.casefold()
    return folded in COMMON_PASSWORDS or folded in _PATTERN_SET


__all__ = ["COMMON_PASSWORDS", "is_common_password"]
