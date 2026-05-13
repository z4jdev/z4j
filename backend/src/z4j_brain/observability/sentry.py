"""Optional Sentry integration.

Sentry is a fully optional dependency. The brain ships fine without
``sentry-sdk`` installed; setting :attr:`Settings.sentry_dsn` is what
enables capture, and the SDK is loaded lazily so a misconfiguration
or import failure cannot prevent the brain from booting.

Design choices the operator should know about:

- **Off by default.** No DSN, no init. Even with the package
  installed, an unset ``Z4J_SENTRY_DSN`` is a complete no-op.
- **Errors first, traces opt-in.** ``traces_sample_rate`` and
  ``profiles_sample_rate`` default to 0.0 so a fresh enablement
  only ships unhandled exceptions until the operator deliberately
  turns on perf.
- **PII off by default.** ``send_default_pii`` is False. Even with
  it flipped on, :func:`scrub_event` strips the headers and query
  params the brain treats as sensitive (Authorization, cookies,
  webhook signatures, OAuth-style ``token`` query strings, etc.).
- **Idempotent.** Calling :func:`init_sentry` twice is safe; the
  second call logs a debug message and returns ``True`` if the
  first init succeeded.

Threat model. An attacker who can sniff outbound traffic to
``sentry.io`` (or whichever instance the operator points at) must
not learn session cookies, API tokens, MFA recovery codes, or
webhook URLs from a captured error. The scrubber is the load-bearing
piece of that promise; tests in ``tests/unit/test_sentry.py`` pin it.

The brain does not init Sentry in its CLI / migration / scheduler
subcommands by default. ``z4j serve`` calls :func:`init_sentry` from
:func:`create_app`; the one-shot CLI paths (``z4j init``,
``z4j audit verify``, ``z4j reset-mfa``, etc.) do not, because:

- A crash in those commands lands on the operator's terminal and
  is already actionable. Sentry would add network egress and an
  init cost to every short-lived CLI.
- The audit-log row written by the command captures the failure
  for post-hoc analysis; Sentry duplicates that without adding
  signal.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

logger = logging.getLogger("z4j.brain.observability.sentry")


# Module-level state. ``_initialised`` flips to True after a
# successful call so the second call is a noisy no-op rather than a
# silent re-init that double-registers SDK integrations.
_initialised: bool = False


# ---------------------------------------------------------------------------
# Scrubbing rules.
# ---------------------------------------------------------------------------
#
# Sensitive-header names. Lowercased; we lowercase incoming names
# before comparison. Anything that grants authentication, identifies
# a session, or carries a delivery signature lives here.
_SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-z4j-signature",
    "x-z4j-audit-signature",
    "x-z4j-api-key",
    "x-api-key",
    "x-auth-token",
    "x-csrftoken",
    "x-csrf-token",
    # IP-chain headers carry the real client IP behind a trusted
    # proxy. The brain's "user.ip_address" promise (line below) is
    # honoured only if we ALSO strip these. (Round 2 H5.)
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "cf-connecting-ip",
    "true-client-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
    "remote-user",
})

#: Query-parameter names whose VALUES are stripped from Sentry events.
#: The names themselves stay so the operator can still see "a token
#: was on this request" without seeing the token itself.
_SENSITIVE_QUERY_KEYS: frozenset[str] = frozenset({
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "code",            # OAuth + MFA verification codes
    "signature",
    "sig",
    "session",
    "csrf",
})

#: Setting / env-style key patterns whose values are scrubbed when they
#: appear in ``extra`` / ``tags`` / ``contexts``. Substring match,
#: case-insensitive, so ``DATABASE_PASSWORD`` and ``mfa_secret`` both
#: hit. Aligns with the redaction patterns the brain already enforces
#: on event payloads (``z4j_core.redaction``).
_SENSITIVE_VALUE_KEY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"password",
        r"passwd",
        # ``smtp_pass`` (and similar snake-case suffixes) is the
        # z4j-native form: require a start-or-underscore prefix +
        # end-or-non-alpha suffix so this matches ``smtp_pass`` and
        # ``db_pass`` but NOT ``passed_at`` / ``passing``.
        r"(?:^|_)pass(?:wd|word|phrase)?(?:$|[^a-z])",
        r"secret",
        r"token",
        r"api[_-]?key",
        r"auth",
        r"signature",
        r"private[_-]?key",
        r"bot[_-]?token",
        r"webhook[_-]?url",       # webhook URLs often embed tokens in path
        r"integration[_-]?key",
        r"recovery[_-]?code",
        r"mfa[_-]?secret",
    )
)

#: Marker put in place of redacted values. Keeps the event structurally
#: useful (Sentry still shows the header / param name) without leaking
#: bytes.
_REDACTED: str = "[REDACTED by z4j]"


#: Maximum depth ``_redact_mapping`` recurses into nested data.
#: A hostile event with extra/contexts nested 1000 deep would blow
#: Python's recursion limit and the scrubber would raise back into
#: the SDK -- which would then ship the UNSCRUBBED event. Cap at 32
#: and replace deeper subtrees with the inert marker. (Round 2 M4.)
_REDACT_MAX_DEPTH: int = 32


def _redact_list(items: list[Any], *, _depth: int = 0) -> list[Any]:
    """Walk a list, recursing into nested dicts AND nested lists so
    a shape like ``[[{"api_key": "leak"}]]`` does not bypass the
    scrubber. (Round 3 Crit-3.) Bounded by ``_REDACT_MAX_DEPTH``."""
    if _depth >= _REDACT_MAX_DEPTH:
        return [_REDACTED]
    out: list[Any] = []
    for item in items:
        if isinstance(item, dict):
            out.append(_redact_mapping(item, _depth=_depth + 1))
        elif isinstance(item, list):
            out.append(_redact_list(item, _depth=_depth + 1))
        else:
            out.append(item)
    return out


def _redact_mapping(
    mapping: dict[str, Any], *, _depth: int = 0,
) -> dict[str, Any]:
    """Walk ``mapping`` and redact any key matching the value-key
    patterns. Nested dicts are recursed. Lists are walked deeply
    (lists-of-lists-of-dicts no longer bypass via the previous
    one-level recursion). (Round 3 Crit-3.) Bounded by
    ``_REDACT_MAX_DEPTH`` so a hostile event cannot crash the
    scrubber and bypass redaction by recursion."""
    if _depth >= _REDACT_MAX_DEPTH:
        return {"_z4j_truncated": _REDACTED}
    out: dict[str, Any] = {}
    for k, v in mapping.items():
        if isinstance(k, str) and any(
            p.search(k) for p in _SENSITIVE_VALUE_KEY_PATTERNS
        ):
            out[k] = _REDACTED
            continue
        if isinstance(v, dict):
            out[k] = _redact_mapping(v, _depth=_depth + 1)
        elif isinstance(v, list):
            out[k] = _redact_list(v, _depth=_depth + 1)
        else:
            out[k] = v
    return out


def _scrub_headers(headers: Any) -> Any:
    """Headers in a Sentry event can arrive as a dict or as a list
    of ``[name, value]`` pairs depending on the integration. Handle
    both shapes; preserve the input shape on output."""
    if isinstance(headers, dict):
        return {
            name: (_REDACTED if name.lower() in _SENSITIVE_HEADERS else value)
            for name, value in headers.items()
        }
    if isinstance(headers, list):
        scrubbed: list[Any] = []
        for entry in headers:
            if (
                isinstance(entry, (list, tuple))
                and len(entry) == 2
                and isinstance(entry[0], str)
                and entry[0].lower() in _SENSITIVE_HEADERS
            ):
                scrubbed.append([entry[0], _REDACTED])
            else:
                scrubbed.append(entry)
        return scrubbed
    return headers


def _scrub_query_string(qs: str) -> str:
    """Replace values of sensitive query keys; keep the key visible.
    Tolerates malformed query strings (returns them unchanged).
    """
    if not qs:
        return qs
    try:
        pairs = parse_qsl(qs, keep_blank_values=True)
    except Exception:  # noqa: BLE001
        return qs
    if not pairs:
        return qs
    out_pairs: list[tuple[str, str]] = []
    for key, value in pairs:
        if key.lower() in _SENSITIVE_QUERY_KEYS:
            out_pairs.append((key, _REDACTED))
        else:
            out_pairs.append((key, value))
    return urlencode(out_pairs, doseq=False)


def _scrub_url(url: str) -> str:
    """Strip sensitive query params from a URL and replace the path
    for known token-bearing hosts. Calling this on a string that is
    not a URL returns it unchanged.

    Round 3 H1: previously only the query string was scrubbed; URLs
    of the form ``https://hooks.slack.com/T0/B0/SECRETPATH`` (token
    embedded in path, no ``?``) shipped verbatim. Now if the host
    matches a known credential-in-path family, the path AND query
    are replaced with the inert marker.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except Exception:  # noqa: BLE001
        return url
    host = (parts.hostname or "").lower().rstrip(".")
    # Drop tokens-in-path for known credential-bearing hosts.
    if host and _is_token_path_host(host):
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                "/[REDACTED by z4j]",
                "",
                "",
            ),
        )
    if "?" not in url:
        return url
    if not parts.query:
        return url
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            _scrub_query_string(parts.query),
            "",  # fragment dropped: OAuth implicit flow puts tokens here
        ),
    )


#: Hosts that routinely embed credentials in the URL PATH. The
#: ``_scrub_url`` function strips the path AND query for these
#: hosts rather than only the query. (Round 3 H1.)
_TOKEN_PATH_HOST_SUFFIXES: tuple[str, ...] = (
    ".webhook.office.com",
    ".logic.azure.com",
    ".slack.com",
    ".discordapp.com",
    ".discord.com",
    ".pagerduty.com",
)
_TOKEN_PATH_HOSTS_EXACT: frozenset[str] = frozenset({
    "outlook.office.com",
    "hooks.slack.com",
    "events.pagerduty.com",
    "discord.com",
    "discordapp.com",
})


def _is_token_path_host(host: str) -> bool:
    """True iff this host's URL path typically contains a credential."""
    lower = host.lower().rstrip(".")
    if lower in _TOKEN_PATH_HOSTS_EXACT:
        return True
    return any(lower.endswith(s) for s in _TOKEN_PATH_HOST_SUFFIXES)


#: Token-in-path hosts. The breadcrumb / log scrubber spots URLs
#: that have no ``?`` but DO embed credentials in the path (Slack,
#: Discord, Teams workflow webhooks). Catch them with a regex on
#: ``str``-typed message fields where ``_scrub_url`` short-circuits.
_PATH_TOKEN_HOST_RE: re.Pattern[str] = re.compile(
    r"https?://[^\s]*?"
    r"(hooks\.slack\.com|discord(?:app)?\.com|webhook\.office\.com"
    r"|logic\.azure\.com|outlook\.office\.com|events\.pagerduty\.com)"
    r"[^\s]*",
    re.IGNORECASE,
)


def _scrub_inline_urls(text: str) -> str:
    """Replace token-in-path URLs in arbitrary free-form text with
    the scheme+host only. Catches ``logger.info(url)`` lines that
    embed credentials in a webhook URL's path (no ``?`` so
    ``_scrub_url`` skips them)."""
    if not isinstance(text, str) or not text:
        return text
    def _sub(m: re.Match[str]) -> str:
        host = m.group(1)
        scheme = m.group(0).split(":", 1)[0]
        return f"{scheme}://{host}/[REDACTED by z4j]"
    return _PATH_TOKEN_HOST_RE.sub(_sub, text)


def _scrub_env_mapping(env: Any) -> Any:
    """Scrub a CGI-style env-var dict in the Sentry event's
    ``request.env`` block. The ASGI/WSGI integration writes
    ``HTTP_AUTHORIZATION``, ``HTTP_COOKIE``, ``HTTP_X_API_KEY``, etc.
    as keys; strip the ``HTTP_`` prefix for the header allowlist
    comparison, AND run the value-key pattern matcher so a custom
    middleware that drops ``Z4J_SECRET`` into env still has its
    value redacted.
    """
    if not isinstance(env, dict):
        return env
    out: dict[str, Any] = {}
    for key, value in env.items():
        if not isinstance(key, str):
            out[key] = value
            continue
        # CGI-style: HTTP_<header_name_uppercased_underscores>
        if key.startswith("HTTP_"):
            header_name = key[5:].lower().replace("_", "-")
            if header_name in _SENSITIVE_HEADERS:
                out[key] = _REDACTED
                continue
        # Value-key pattern (catches HTTP_AUTHORIZATION via the `auth`
        # pattern, plus custom env like DATABASE_PASSWORD).
        if any(p.search(key) for p in _SENSITIVE_VALUE_KEY_PATTERNS):
            out[key] = _REDACTED
            continue
        out[key] = value
    return out


def _scrub_stacktrace_frames(frames: list[Any]) -> list[Any]:
    """Walk stacktrace frame dicts and scrub source-code context
    lines, local-variable dicts, and path-like fields that may
    embed credentials (e.g., ``/tmp/run-abc123token/file.py`` from
    tempfile-named runs)."""
    if not isinstance(frames, list):
        return frames
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        # Local variables (when include_local_variables=True at
        # init OR a future Sentry version flips the default). The
        # vars dict's keys often ARE the credential names.
        if isinstance(frame.get("vars"), dict):
            frame["vars"] = _redact_mapping(frame["vars"])
        # Source-code surrounding the failing line. May contain
        # `SECRET = "abc"` style literals or webhook URLs.
        for ctx_key in ("context_line",):
            val = frame.get(ctx_key)
            if isinstance(val, str):
                frame[ctx_key] = _scrub_inline_urls(_scrub_url(val))
        for ctx_list_key in ("pre_context", "post_context"):
            ctx = frame.get(ctx_list_key)
            if isinstance(ctx, list):
                frame[ctx_list_key] = [
                    _scrub_inline_urls(_scrub_url(line))
                    if isinstance(line, str) else line
                    for line in ctx
                ]
        # Path-like fields. Sentry uses these to render filenames in
        # the issue UI; a path containing a token is a recon leak.
        for path_key in ("filename", "abs_path", "module"):
            val = frame.get(path_key)
            if isinstance(val, str) and any(
                p.search(val) for p in _SENSITIVE_VALUE_KEY_PATTERNS
            ):
                frame[path_key] = _REDACTED
    return frames


def scrub_event(
    event: Any,
    hint: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Sentry ``before_send`` hook.

    Returns the event after redacting sensitive surfaces. The hint
    argument is ignored; it is part of the SDK contract and may carry
    the original exception object, which we do not need to inspect to
    decide what to redact.

    The function is pure (no Sentry SDK calls); the tests exercise it
    directly with fixture events so they run without ``sentry-sdk``
    installed.

    Defensive: if ``event`` is not a dict (None, primitive), the
    SDK contract is preserved by passing it through unchanged. A
    real Sentry SDK never passes a non-dict, but this guards against
    a future SDK version or a test rig that calls the hook directly.
    """
    del hint  # see docstring

    if not isinstance(event, dict):
        # Sentry SDK before_send contract: return Event-dict or None
        # to drop the event. Returning a non-dict crashes the SDK's
        # downstream envelope serialiser. (Round 5 F4.)
        return None

    # Request block (most of the leak surface).
    request = event.get("request")
    if isinstance(request, dict):
        if "headers" in request:
            request["headers"] = _scrub_headers(request["headers"])
        if "cookies" in request:
            request["cookies"] = _REDACTED
        if "query_string" in request:
            qs = request["query_string"]
            if isinstance(qs, str):
                request["query_string"] = _scrub_query_string(qs)
            elif isinstance(qs, list):
                request["query_string"] = [
                    (k, _REDACTED if k.lower() in _SENSITIVE_QUERY_KEYS else v)
                    for k, v in qs
                ]
        if "url" in request and isinstance(request["url"], str):
            request["url"] = _scrub_url(request["url"])
        # The request body is uncapped by Sentry's defaults. Webhook
        # dispatchers serialise payloads through this codepath and the
        # outbound body can carry a workflow token. Strip wholesale.
        if "data" in request:
            request["data"] = _REDACTED
        # WSGI/ASGI integrations attach a CGI-style env dict that
        # carries HTTP_AUTHORIZATION, HTTP_COOKIE, HTTP_X_API_KEY,
        # plus any custom middleware-attached keys. (Audit H2.)
        if "env" in request:
            request["env"] = _scrub_env_mapping(request["env"])

    # User block. The FastAPI integration attaches
    # ``user.ip_address`` / ``user.id`` / ``user.email`` /
    # ``user.username`` when ``send_default_pii`` is True. The brain's
    # promise is "credentials redacted even when PII flag is on" --
    # email/username/IP are credential-adjacent so strip them.
    # (Audit H3.)
    user = event.get("user")
    if isinstance(user, dict):
        for sensitive_key in ("email", "username", "ip_address"):
            if sensitive_key in user:
                user[sensitive_key] = _REDACTED
        # Keep user.id (uuid; not a credential) so issue grouping
        # still works, and apply the value-key matcher for any
        # custom field a future integration adds.
        event["user"] = _redact_mapping(user)

    # logentry / message: ``logger.error("token=%s", t)`` lands in
    # ``logentry.message`` / ``logentry.formatted`` / ``logentry.params``
    # plus top-level ``message``. The LoggingIntegration ships these
    # by default. (Audit H4.)
    logentry = event.get("logentry")
    if isinstance(logentry, dict):
        for str_key in ("message", "formatted"):
            val = logentry.get(str_key)
            if isinstance(val, str):
                logentry[str_key] = _scrub_url(val)
        params = logentry.get("params")
        if isinstance(params, dict):
            logentry["params"] = _redact_mapping(params)
        elif isinstance(params, list):
            # The params are positional %s slots; we cannot identify
            # which one was a credential by key. Strip wholesale.
            logentry["params"] = [_REDACTED for _ in params]
    top_message = event.get("message")
    if isinstance(top_message, str):
        event["message"] = _scrub_url(top_message)

    # Breadcrumbs commonly include logged outbound HTTP URLs. Walk
    # each breadcrumb's ``data`` for a URL and scrub it.
    breadcrumbs = event.get("breadcrumbs")
    if isinstance(breadcrumbs, dict):
        values = breadcrumbs.get("values")
        if isinstance(values, list):
            for bc in values:
                if not isinstance(bc, dict):
                    continue
                data = bc.get("data")
                if isinstance(data, dict):
                    if isinstance(data.get("url"), str):
                        data["url"] = _scrub_url(data["url"])
                    bc["data"] = _redact_mapping(data)
                if isinstance(bc.get("message"), str):
                    # Best-effort URL scrub inside free-form messages.
                    bc["message"] = _scrub_url(bc["message"])

    # ``extra``, ``tags``, ``contexts`` all carry operator-supplied
    # values. The value-key scrubber catches keys named password /
    # secret / token / api_key etc. ``contexts["trace"]["data"]``
    # carries ``http.url`` for FastAPI server spans, so post-walk
    # we also URL-scrub known URL attribute keys.
    for top_key in ("extra", "tags", "contexts"):
        block = event.get(top_key)
        if isinstance(block, dict):
            event[top_key] = _redact_mapping(block)
    # Spans (Sentry tracing) carry per-span data attributes that
    # mirror the trace-context block. Same scrub applies.
    spans = event.get("spans")
    if isinstance(spans, list):
        for span in spans:
            if not isinstance(span, dict):
                continue
            sdata = span.get("data")
            if isinstance(sdata, dict):
                # URL attributes leak query tokens; scrub before the
                # key-pattern walk because the URL is a single string,
                # not a key whose name matches a pattern.
                for url_key in ("http.url", "url.full", "url.query"):
                    if isinstance(sdata.get(url_key), str):
                        sdata[url_key] = _scrub_url(sdata[url_key])
                span["data"] = _redact_mapping(sdata)
    # Same URL-key scrub on contexts.trace.data (already key-walked
    # above; this is a defence-in-depth pass for the URL specifically).
    contexts = event.get("contexts")
    if isinstance(contexts, dict):
        trace = contexts.get("trace")
        if isinstance(trace, dict):
            tdata = trace.get("data")
            if isinstance(tdata, dict):
                for url_key in ("http.url", "url.full", "url.query"):
                    if isinstance(tdata.get(url_key), str):
                        tdata[url_key] = _scrub_url(tdata[url_key])

    # Exception value + stacktrace frames + mechanism block.
    # ``str(exc)`` routinely includes the offending URL. aiohttp /
    # httpx / custom integrations also attach the failing URL to
    # ``mechanism.data`` (Round 3 Crit-4). Walk every exception in
    # the chain.
    exception_block = event.get("exception")
    if isinstance(exception_block, dict):
        values = exception_block.get("values")
        if isinstance(values, list):
            for entry in values:
                if not isinstance(entry, dict):
                    continue
                if isinstance(entry.get("value"), str):
                    entry["value"] = _scrub_inline_urls(
                        _scrub_url(entry["value"]),
                    )
                st = entry.get("stacktrace")
                if isinstance(st, dict):
                    st["frames"] = _scrub_stacktrace_frames(st.get("frames"))
                # Mechanism block: aiohttp puts the failing URL into
                # ``mechanism.data``; HTTP integrations + custom
                # mechanisms can stash credentials under arbitrary
                # keys. Walk through the value-key scrubber and
                # URL-scrub any string fields that look like URLs.
                mech = entry.get("mechanism")
                if isinstance(mech, dict):
                    if isinstance(mech.get("data"), dict):
                        mech["data"] = _redact_mapping(mech["data"])
                    if isinstance(mech.get("meta"), dict):
                        mech["meta"] = _redact_mapping(mech["meta"])
                    help_link = mech.get("help_link")
                    if isinstance(help_link, str):
                        mech["help_link"] = _scrub_url(help_link)

    # Thread block (non-exception events; same stacktrace shape).
    threads_block = event.get("threads")
    if isinstance(threads_block, dict):
        tvalues = threads_block.get("values")
        if isinstance(tvalues, list):
            for entry in tvalues:
                if not isinstance(entry, dict):
                    continue
                st = entry.get("stacktrace")
                if isinstance(st, dict):
                    st["frames"] = _scrub_stacktrace_frames(st.get("frames"))

    # Transaction string. Usually a route template (safe) but on
    # unmatched routes it can be the raw URL with embedded
    # credentials. Scrub if it looks like a URL. (Round 2 H1.)
    tx = event.get("transaction")
    if isinstance(tx, str) and tx.startswith(("http://", "https://")):
        event["transaction"] = _scrub_inline_urls(_scrub_url(tx))

    return event


def init_sentry(settings: Any) -> bool:
    """Initialise the Sentry SDK if and only if a DSN is configured.

    Returns ``True`` on successful init, ``False`` otherwise (no DSN,
    already initialised, ``sentry-sdk`` not installed, or the SDK
    refused the configuration). Never raises; a failure is logged
    at WARNING and the brain continues to boot.
    """
    global _initialised

    dsn_secret = getattr(settings, "sentry_dsn", None)
    if dsn_secret is None:
        return False
    dsn_value = (
        dsn_secret.get_secret_value()
        if hasattr(dsn_secret, "get_secret_value")
        else str(dsn_secret)
    )
    if not dsn_value or not dsn_value.strip():
        return False

    if _initialised:
        logger.debug("z4j observability.sentry: init_sentry called twice; ignoring")
        return True

    try:
        import sentry_sdk
    except ImportError:
        logger.warning(
            "z4j observability.sentry: Z4J_SENTRY_DSN is set but the "
            "'sentry-sdk' package is not installed. Run `pip install "
            "z4j[sentry]` or `pip install sentry-sdk` to enable error "
            "capture. The brain will continue without Sentry.",
        )
        return False

    environment = (
        getattr(settings, "sentry_environment", None)
        or getattr(settings, "environment", None)
    )
    release = _detect_release()

    try:
        sentry_sdk.init(
            dsn=dsn_value,
            environment=environment,
            release=release,
            traces_sample_rate=float(
                getattr(settings, "sentry_traces_sample_rate", 0.0),
            ),
            profiles_sample_rate=float(
                getattr(settings, "sentry_profiles_sample_rate", 0.0),
            ),
            send_default_pii=bool(
                getattr(settings, "sentry_send_default_pii", False),
            ),
            before_send=scrub_event,
            # The SDK's FastAPI integration picks itself up via the
            # ``starlette`` auto-discovery, so we do not enumerate
            # integrations here -- letting Sentry handle the version
            # matrix is more robust across SDK upgrades.
            attach_stacktrace=True,
            include_local_variables=False,
            # We log via stdlib logging; the LoggingIntegration ships by
            # default and turns ``logger.exception(...)`` into a Sentry
            # event. Operators who do not want that flip it off through
            # the SDK's own knobs; we do not override here.
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "z4j observability.sentry: sentry_sdk.init failed; the "
            "brain will continue without Sentry. Check the DSN and "
            "any pinned SDK version.",
            exc_info=True,
        )
        return False

    _initialised = True
    logger.info(
        "z4j observability.sentry: Sentry initialised "
        "(environment=%s, release=%s, traces=%.3f, profiles=%.3f)",
        environment,
        release or "unset",
        float(getattr(settings, "sentry_traces_sample_rate", 0.0)),
        float(getattr(settings, "sentry_profiles_sample_rate", 0.0)),
    )
    return True


def _detect_release() -> str | None:
    """Best-effort release tag (z4j package version).

    Used to map a Sentry issue back to a specific z4j build. Falls
    back to ``None`` if metadata is unavailable (editable installs
    in some packaging modes); Sentry handles that fine.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover (Python<3.8)
        return None
    for candidate in ("z4j", "z4j-brain"):
        try:
            return f"{candidate}@{version(candidate)}"
        except PackageNotFoundError:
            continue
    return None


def _reset_for_tests() -> None:
    """Test hook: clear the module's idempotency flag so a test that
    asserts on init behaviour can run init twice."""
    global _initialised
    _initialised = False


__all__ = [
    "init_sentry",
    "scrub_event",
    "_reset_for_tests",
    "_REDACTED",
    "_SENSITIVE_HEADERS",
    "_SENSITIVE_QUERY_KEYS",
]
