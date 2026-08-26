"""Every security decision reads dev from one place.

The brain's posture is meant to be "exactly ``dev`` relaxes, everything else is
production". Three gates were written as ``== "production"`` instead, which
inverts that for any other label: a deployment tagged ``staging`` got production
cookies, production host validation and production startup invariants, and then
silently lost HSTS, kept a soft-fail on a scheduler-gRPC startup failure, and
was told by ``z4j doctor`` it was in dev mode. A fourth, the MFA trust cookie,
relaxed for ``dev``, ``development`` and ``test``.

The lexical checks below are deliberately narrow tripwires for direct, single-line
spellings.  They do not claim to discover aliases, data flow, or every future
security decision.  The final tests execute the two production predicates and
pin the actual posture rule.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Every shipped package, not just the brain.
#:
#: This guard scanned ``z4j_brain`` alone, and the two gates it was written to
#: catch were ALSO live in z4j-scheduler the whole time: a metrics fail-fast
#: skipped for every label but "production", so a scheduler tagged "staging"
#: served an unauthenticated /metrics carrying project labels, schedule names
#: and leadership state; and an insecure-gRPC refusal with the same shape. The
#: regex flagged both. Nothing pointed it at them.
#:
#: A guard scoped to where the last defect happened to be found is a guard that
#: only ever catches that one. Walk everything that ships.
PACKAGES = Path(__file__).resolve().parents[4]

#: Any comparison of the environment against a literal other than ``dev``.
#:
#: The first version of this pattern required the comparison to follow the
#: attribute directly, and so passed while ``scheduler_grpc/server.py`` compared
#: ``environment.strip().lower()`` to "production" and opened an
#: unauthenticated schedule-control listener for every label but that one. A
#: guard a near miss slips past is decoration, which is the exact thing this
#: file exists to prevent, so arbitrary method chaining is allowed between the
#: attribute and the operator.
#:
#: ``settings.is_dev`` (or ``is_dev_environment`` in the cookie module) is the
#: supported form. Comparing against the literal "dev" is tolerated in the
#: modules that take a bare string rather than a Settings instance.
_BANNED = re.compile(
    r'environment(?:\s*\.\s*\w+\s*\([^)]*\))*\s*(?:==|!=)\s*"(?!dev")[^"]*"',
)
#: Any membership test against a literal set of environment names.
#:
#: The banned-comparison pattern above only models ``==`` and ``!=``, so the
#: obvious next gate, ``settings.environment in STRICT_ENVIRONMENTS``, was
#: invisible to both checks. It has the same defect: a label the tuple does not
#: list takes the wrong branch while every other subsystem, asking is_dev,
#: treats it as production.
_MEMBERSHIP_TEST = re.compile(
    r"environment(?:\s*\.\s*\w+\s*\([^)]*\))*\s+(?:not\s+)?in\s+"
    r"[\(\[{A-Z_]",
)

#: The narrower original: a hand-rolled dev set with more than one name in it.
_MULTI_VALUE_DEV = re.compile(r'environment\s+in\s+\(\s*"dev"\s*,\s*"development"')


def _sources() -> list[Path]:
    return [path for path in PACKAGES.rglob("src/**/*.py") if "__pycache__" not in path.parts]


def test_no_direct_single_line_non_dev_environment_comparison() -> None:
    offenders: list[str] = []
    for path in _sources():
        for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            if _BANNED.search(line):
                offenders.append(f"{path.relative_to(PACKAGES).as_posix()}:{ln}  {line.strip()}")
    assert offenders == [], (
        "these decide posture by comparing the environment to a literal other "
        "than 'dev', so every label except that one takes the wrong branch "
        "while the rest of the brain treats it as production. Use "
        "settings.is_dev:\n  " + "\n  ".join(offenders)
    )


def test_no_direct_single_line_environment_membership_test() -> None:
    """``environment in (...)`` is the same defect wearing different syntax.

    Neither of the other two checks models it: one matches ``==``/``!=``, the
    other matches one specific hand-rolled dev tuple. A new gate written as
    ``environment in STRICT_ENVIRONMENTS`` would pass both while silently
    dropping HSTS, or a cookie flag, for every label the tuple forgot.
    """
    offenders: list[str] = []
    for path in _sources():
        for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if _MEMBERSHIP_TEST.search(line):
                offenders.append(f"{path.relative_to(PACKAGES).as_posix()}:{ln}  {stripped}")
    assert offenders == [], (
        "these decide posture by membership in a literal set of environment "
        "names, so any label the set omits takes the wrong branch. Use "
        "settings.is_dev:" + chr(10) + "  " + (chr(10) + "  ").join(offenders)
    )


def test_no_direct_single_line_multi_value_dev_tuple() -> None:
    offenders: list[str] = []
    for path in _sources():
        for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            if _MULTI_VALUE_DEV.search(line):
                offenders.append(f"{path.relative_to(PACKAGES).as_posix()}:{ln}  {line.strip()}")
    assert offenders == [], (
        "these relax for more names than 'dev', so an operator who sets "
        "Z4J_ENVIRONMENT=development gets production strictness everywhere else "
        "and a relaxed security control here:\n  " + "\n  ".join(offenders)
    )


def test_trusted_device_predicate_accepts_only_exact_dev() -> None:
    from z4j_brain.auth.trusted_device import is_dev_environment

    assert is_dev_environment("dev") is True
    for near_miss in ("development", "test", "Dev", "DEV", "dev ", "staging", "production", ""):
        assert is_dev_environment(near_miss) is False, f"{near_miss!r} was treated as dev"


def test_settings_predicate_accepts_only_exact_dev(brain_settings) -> None:
    assert brain_settings.model_copy(update={"environment": "dev"}).is_dev is True
    for near_miss in ("development", "test", "Dev", "DEV", "dev ", "staging", "production", ""):
        configured = brain_settings.model_copy(update={"environment": near_miss})
        assert configured.is_dev is False, f"{near_miss!r} was treated as dev"
