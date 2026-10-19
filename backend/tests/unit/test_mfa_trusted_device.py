import pytest


@pytest.mark.parametrize("environment", ["production", "staging", "development", "dev"])
def test_trust_cookie_deletion_keeps_prefix_required_attributes(environment):
    from http.cookies import SimpleCookie

    from starlette.responses import Response
    from z4j_brain.auth import trusted_device as td

    response = Response()
    td.clear_trust_cookie(response, environment=environment)
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[td.cookie_name(environment=environment)]
    assert cookie["max-age"] == "0"
    assert cookie["path"] == "/"
    assert not cookie["domain"]
    assert bool(cookie["secure"]) is (environment != "dev")
    assert cookie["httponly"]
    assert cookie["samesite"] == "strict"


def test_only_the_exact_string_dev_relaxes_the_trust_cookie() -> None:
    """A near miss on the environment name must not drop a security flag.

    This predicate used to relax for ``dev``, ``development`` and ``test``,
    while every other check in the brain (sessions, csrf, the startup
    invariants) compares against exactly ``dev``. An operator who set
    ``Z4J_ENVIRONMENT=development`` therefore got production strictness
    everywhere, reasonably concluded they were in production, and shipped the
    one cookie that lets a browser skip an MFA challenge without ``Secure``.

    Also asserts the two predicates agree, because a ``__Host-`` prefixed
    cookie is only valid when Secure is set: if the name and the flags could
    disagree, the result is either a cookie browsers reject or a plaintext one
    in a deployment that believes it is hardened.
    """
    from z4j_brain.auth import trusted_device as td

    assert td.cookie_kwargs(environment="dev", max_age_seconds=60)["secure"] is False
    assert td.cookie_name(environment="dev") == td.COOKIE_NAME_DEV

    for environment in ("development", "test", "staging", "production", "prod-eu", ""):
        kwargs = td.cookie_kwargs(environment=environment, max_age_seconds=60)
        name = td.cookie_name(environment=environment)
        assert kwargs["secure"] is True, f"{environment!r} dropped Secure"
        assert name == td.COOKIE_NAME_PROD, f"{environment!r} got the dev cookie name"

    for environment in ("dev", "development", "test", "production", ""):
        kwargs = td.cookie_kwargs(environment=environment, max_age_seconds=60)
        name = td.cookie_name(environment=environment)
        if name.startswith("__Host-"):
            assert kwargs["secure"] is True, (
                f"{environment!r} emits a __Host- cookie without Secure, which "
                f"browsers refuse to store"
            )
