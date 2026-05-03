"""First-boot setup endpoints.

Three routes:

- ``GET  /api/v1/setup/status``  → ``{first_boot: bool}``. No auth.
- ``GET  /setup``                → tiny inline HTML form. Only
  served while first-boot mode is active. Strict CSP, no JS,
  no external assets.
- ``POST /api/v1/setup/complete`` → consume the token, create the
  bootstrap admin + default project, set the session cookie.

The HTML form is served from ``/setup`` (NOT under ``/api/v1``)
because the dashboard mounts under ``/`` in production and the
operator needs a memorable URL to paste from the printed banner.

There is NO `Depends(require_csrf)` on the complete endpoint -
the token-in-body IS the auth, and there is no session yet.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from z4j_brain.auth.sessions import generate_csrf_token
from z4j_brain.persistence.repositories import SessionRepository

from z4j_brain.api.auth import (
    UserPublic,
    _set_session_cookies,
    _user_payload,
)
from z4j_brain.api.deps import (
    get_audit_log_repo,
    get_client_ip,
    get_first_boot_token_repo,
    get_membership_repo,
    get_project_repo,
    get_session,
    get_settings,
    get_setup_service,
    get_user_repo,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from z4j_brain.domain.setup_service import SetupService
    from z4j_brain.persistence.repositories import (
        AuditLogRepository,
        FirstBootTokenRepository,
        MembershipRepository,
        ProjectRepository,
        UserRepository,
    )
    from z4j_brain.settings import Settings


router_api = APIRouter(prefix="/setup", tags=["setup"])
router_html = APIRouter(tags=["setup"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class StatusResponse(BaseModel):
    first_boot: bool


class CompleteRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    email: EmailStr
    display_name: str | None = Field(default=None, max_length=200)
    password: str = Field(min_length=8, max_length=256)


class CompleteResponse(BaseModel):
    user: UserPublic
    project_id: uuid.UUID


# ---------------------------------------------------------------------------
# JSON endpoints
# ---------------------------------------------------------------------------


@router_api.get("/status", response_model=StatusResponse)
async def status_endpoint(
    setup_service: "SetupService" = Depends(get_setup_service),
    users: "UserRepository" = Depends(get_user_repo),
) -> StatusResponse:
    """Return whether the brain is in first-boot mode.

    Public - no auth required. The dashboard chrome calls this on
    every page load to decide whether to show the setup CTA.
    """
    return StatusResponse(first_boot=await setup_service.is_first_boot(users))


@router_api.post(
    "/complete",
    response_model=CompleteResponse,
    status_code=status.HTTP_200_OK,
)
async def complete(
    request_body: CompleteRequest,
    response: Response,
    settings: "Settings" = Depends(get_settings),
    setup_service: "SetupService" = Depends(get_setup_service),
    users: "UserRepository" = Depends(get_user_repo),
    projects: "ProjectRepository" = Depends(get_project_repo),
    memberships: "MembershipRepository" = Depends(get_membership_repo),
    tokens: "FirstBootTokenRepository" = Depends(get_first_boot_token_repo),
    audit_log: "AuditLogRepository" = Depends(get_audit_log_repo),
    db_session: "AsyncSession" = Depends(get_session),
    ip: str = Depends(get_client_ip),
) -> CompleteResponse:
    """Verify the setup token and bootstrap the brain."""
    result = await setup_service.complete(
        users=users,
        projects=projects,
        memberships=memberships,
        tokens=tokens,
        audit_log=audit_log,
        token=request_body.token,
        email=request_body.email,
        display_name=request_body.display_name,
        password=request_body.password,
        ip=ip,
        user_agent=None,
    )

    # DATA-03: mint the session row BEFORE the single commit so the
    # whole bootstrap (user + project + membership + default_sub +
    # materialize + audit + token-consume + session) is atomic. If
    # this commit fails, the token stays valid and nothing is
    # persisted, so the operator can simply retry.
    sessions = SessionRepository(db_session)
    csrf = generate_csrf_token()
    expires_at = datetime.now(UTC) + timedelta(
        seconds=settings.session_absolute_lifetime_seconds,
    )
    session_row = await sessions.create(
        user_id=result.user.id,
        csrf_token=csrf,
        expires_at=expires_at,
        ip_at_issue=ip,
        user_agent_at_issue=None,
    )
    await db_session.commit()

    _set_session_cookies(
        response,
        settings=settings,
        session_id=session_row.id,
        csrf_token=session_row.csrf_token,
    )
    return CompleteResponse(
        user=_user_payload(result.user),
        project_id=result.project_id,
    )


# ---------------------------------------------------------------------------
# HTML form
# ---------------------------------------------------------------------------


# NOTE: this is a plain string, NOT a .format() template - the
# token is read client-side from window.location.search, the
# server never substitutes anything in. Use single braces.
_FORM_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>z4j first-boot setup</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f8fafc;
      --card: #ffffff;
      --border: #e2e8f0;
      --border-strong: #cbd5e1;
      --fg: #0f172a;
      --fg-muted: #475569;
      --fg-subtle: #94a3b8;
      --primary: #0f172a;
      --primary-hover: #1e293b;
      --primary-fg: #ffffff;
      --danger: #b91c1c;
      --ring: rgba(15, 23, 42, 0.10);
      --shadow:
        0 1px 2px rgba(15, 23, 42, 0.04),
        0 8px 24px rgba(15, 23, 42, 0.06);
      --hover-bg: #f1f5f9;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0b1120;
        --card: #0f172a;
        --border: #1e293b;
        --border-strong: #334155;
        --fg: #f1f5f9;
        --fg-muted: #94a3b8;
        --fg-subtle: #64748b;
        --primary: #f8fafc;
        --primary-hover: #e2e8f0;
        --primary-fg: #0f172a;
        --danger: #f87171;
        --ring: rgba(248, 250, 252, 0.16);
        --shadow:
          0 1px 2px rgba(0, 0, 0, 0.4),
          0 12px 32px rgba(0, 0, 0, 0.5);
        --hover-bg: #1e293b;
      }
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      font-family:
        ui-sans-serif, system-ui, -apple-system, "Segoe UI",
        Roboto, "Helvetica Neue", Arial, sans-serif;
      font-feature-settings: "cv11", "ss01";
      background: var(--bg);
      color: var(--fg);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem 1rem;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 2.25rem 2rem 1.75rem;
      box-shadow: var(--shadow);
    }
    .brand {
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--fg-subtle);
      margin-bottom: 1.25rem;
    }
    h1 {
      margin: 0 0 0.4rem;
      font-size: 1.5rem;
      font-weight: 600;
      letter-spacing: -0.01em;
    }
    p.lead {
      margin: 0 0 1.75rem;
      color: var(--fg-muted);
      font-size: 0.9rem;
    }
    label {
      display: block;
      margin-top: 1.1rem;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--fg);
      letter-spacing: 0;
    }
    input {
      display: block;
      width: 100%;
      margin-top: 0.45rem;
      padding: 0.65rem 0.85rem;
      font-size: 0.92rem;
      font-family: inherit;
      color: var(--fg);
      background: var(--card);
      border: 1px solid var(--border-strong);
      border-radius: 8px;
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    input::placeholder { color: var(--fg-subtle); }
    input:hover { border-color: #94a3b8; }
    input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px var(--ring);
    }
    input[aria-invalid="true"] {
      border-color: var(--danger);
      box-shadow: 0 0 0 3px rgba(185, 28, 28, 0.12);
    }
    .password-wrap {
      display: block;
      position: relative;
    }
    .password-wrap input {
      padding-right: 2.75rem;
    }
    .toggle {
      position: absolute;
      top: 50%;
      right: 0.4rem;
      transform: translateY(-50%);
      width: 2rem;
      height: 2rem;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0;
      margin: 0;
      background: transparent;
      border: none;
      border-radius: 6px;
      color: var(--fg-subtle);
      cursor: pointer;
      transition: color 0.15s, background 0.15s;
    }
    .toggle:hover {
      color: var(--fg);
      background: var(--hover-bg);
    }
    .toggle:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: 1px;
    }
    .toggle svg { width: 18px; height: 18px; display: block; }
    .toggle .icon-eye-off { display: none; }
    .toggle[aria-pressed="true"] .icon-eye { display: none; }
    .toggle[aria-pressed="true"] .icon-eye-off { display: block; }
    .hint {
      margin: 0.45rem 0 0;
      font-size: 0.75rem;
      color: var(--fg-muted);
    }
    .hint.bad { color: var(--danger); }
    .hint.ok { color: #047857; }
    @media (prefers-color-scheme: dark) {
      .hint.ok { color: #34d399; }
    }
    button[type="submit"] {
      margin-top: 1.75rem;
      width: 100%;
      padding: 0.75rem 1rem;
      font-size: 0.92rem;
      font-weight: 600;
      font-family: inherit;
      color: var(--primary-fg);
      background: var(--primary);
      border: 1px solid var(--primary);
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s;
    }
    button[type="submit"]:hover {
      background: var(--primary-hover);
      border-color: var(--primary-hover);
    }
    button[type="submit"]:focus-visible {
      outline: none;
      box-shadow: 0 0 0 3px var(--ring);
    }
    button[type="submit"]:disabled {
      opacity: 0.55;
      cursor: not-allowed;
    }
    .error {
      color: var(--danger);
      margin: 0.85rem 0 0;
      min-height: 1.2rem;
      font-size: 0.82rem;
    }
    .footer {
      margin-top: 1.5rem;
      padding-top: 1.25rem;
      border-top: 1px solid var(--border);
      font-size: 0.72rem;
      color: var(--fg-subtle);
      text-align: center;
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="brand">z4j</div>
    <h1>First-boot setup</h1>
    <p class="lead">Create the first administrator account for this brain.</p>
    <form id="setup-form" autocomplete="off">
      <input type="hidden" name="token" id="token-field">
      <label>Email
        <input type="email" name="email" autocomplete="email" required>
      </label>
      <label>Display name
        <input type="text" name="display_name" autocomplete="name">
      </label>
      <label>Password
        <span class="password-wrap">
          <input type="password" id="password" name="password" autocomplete="new-password" minlength="8" required>
          <button type="button" class="toggle" id="toggle-password" aria-label="Show password" aria-pressed="false">
            <svg class="icon-eye" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg class="icon-eye-off" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" y1="2" x2="22" y2="22"/></svg>
          </button>
        </span>
      </label>
      <p class="hint" id="password-hint">At least 8 characters, with letters and digits.</p>
      <label>Confirm password
        <span class="password-wrap">
          <input type="password" id="password_confirm" name="password_confirm" autocomplete="new-password" minlength="8" required>
          <button type="button" class="toggle" id="toggle-confirm" aria-label="Show password" aria-pressed="false">
            <svg class="icon-eye" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg class="icon-eye-off" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" y1="2" x2="22" y2="22"/></svg>
          </button>
        </span>
      </label>
      <p class="hint" id="match-hint" aria-live="polite"></p>
      <button type="submit" id="submit">Create admin</button>
      <p class="error" id="error" role="alert" aria-live="polite"></p>
    </form>
    <p class="footer">Single-use token. Restart the brain to regenerate.</p>
  </main>
  <script>
    (function() {
      var params = new URLSearchParams(window.location.search);
      var tokenFromUrl = params.get('token') || '';
      document.getElementById('token-field').value = tokenFromUrl;

      var form = document.getElementById('setup-form');
      var err = document.getElementById('error');
      var btn = document.getElementById('submit');
      var pw = document.getElementById('password');
      var pw2 = document.getElementById('password_confirm');
      var matchHint = document.getElementById('match-hint');

      if (!tokenFromUrl) {
        err.textContent = 'Setup token missing. Open the URL printed in the z4j logs (docker compose logs z4j).';
        btn.disabled = true;
      }

      function extractError(j) {
        // FastAPI 422: {detail: [{msg, loc}, ...]}
        if (j && Array.isArray(j.detail)) {
          return j.detail.map(function(d) {
            var field = Array.isArray(d.loc) ? d.loc[d.loc.length - 1] : '';
            return field ? field + ': ' + d.msg : d.msg;
          }).join('; ');
        }
        // Brain ProblemDetails: {detail: {code, message}}
        if (j && j.detail && typeof j.detail === 'object' && j.detail.message) {
          return j.detail.message;
        }
        // Brain flat: {message: "..."} or {detail: "..."}
        if (j && j.message) return j.message;
        if (j && typeof j.detail === 'string') return j.detail;
        return 'Failed.';
      }

      function bindToggle(toggleId, inputEl) {
        var t = document.getElementById(toggleId);
        t.addEventListener('click', function() {
          var visible = inputEl.type === 'text';
          inputEl.type = visible ? 'password' : 'text';
          t.setAttribute('aria-pressed', visible ? 'false' : 'true');
          t.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
          inputEl.focus();
        });
      }
      bindToggle('toggle-password', pw);
      bindToggle('toggle-confirm', pw2);

      function checkMatch() {
        if (!pw2.value) {
          matchHint.textContent = '';
          matchHint.className = 'hint';
          pw2.removeAttribute('aria-invalid');
          return pw.value.length >= 8;
        }
        if (pw.value === pw2.value) {
          matchHint.textContent = 'Passwords match.';
          matchHint.className = 'hint ok';
          pw2.removeAttribute('aria-invalid');
          return pw.value.length >= 8;
        }
        matchHint.textContent = 'Passwords do not match.';
        matchHint.className = 'hint bad';
        pw2.setAttribute('aria-invalid', 'true');
        return false;
      }
      pw.addEventListener('input', checkMatch);
      pw2.addEventListener('input', checkMatch);

      form.addEventListener('submit', function(ev) {
        ev.preventDefault();
        err.textContent = '';
        if (!form.token.value) {
          err.textContent = 'Setup token missing from URL.';
          return;
        }
        if (pw.value !== pw2.value) {
          err.textContent = 'Passwords do not match.';
          pw2.focus();
          return;
        }
        btn.disabled = true;
        var data = {
          token: form.token.value,
          email: form.email.value,
          display_name: form.display_name.value || null,
          password: pw.value,
        };
        fetch('/api/v1/setup/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(data),
        }).then(function(r) {
          if (r.ok) { window.location = '/'; return; }
          return r.json().then(function(j) {
            err.textContent = extractError(j);
            btn.disabled = false;
          }).catch(function() {
            err.textContent = 'Request failed (HTTP ' + r.status + ').';
            btn.disabled = false;
          });
        }).catch(function() {
          err.textContent = 'Network error.';
          btn.disabled = false;
        });
      });
    })();
  </script>
</body>
</html>
"""


@router_html.get("/setup")
async def setup_form(
    token: str = Query(default=""),  # noqa: ARG001 - read by JS, not server
    setup_service: "SetupService" = Depends(get_setup_service),
    users: "UserRepository" = Depends(get_user_repo),
    tokens: "FirstBootTokenRepository" = Depends(get_first_boot_token_repo),
) -> HTMLResponse:
    """Serve the inline HTML form.

    Only available while ``users`` is empty. After the bootstrap
    admin exists, returns 404 - the form has no business existing
    after first boot. The token query parameter is intentionally
    NOT used by the server; the JS reads it from
    ``window.location.search`` and stuffs it into the hidden form
    field. The server's only job is to gate visibility on the
    first-boot flag.

    Round-8 audit fix R8-Bootstrap-MED (Apr 2026): also require
    that an active token row exists. Pre-fix, between a successful
    ``complete()`` commit and the user row becoming visible to a
    parallel reader (Postgres replica lag), ``users.count() == 0``
    could still be True even though the setup is conceptually done.
    The form would render referencing a stale URL, confusing UX
    and a small information leak about install state. Tying
    visibility to "active token AND users empty" closes the gap.
    """
    if not await setup_service.is_first_boot(users):
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8><title>Not found</title><p>404</p>",
            status_code=404,
        )
    active_token = await tokens.get_active(lock=False)
    if active_token is None:
        # No mintable token, operator hasn't restarted the brain
        # since the prior token expired or was consumed. Render 404
        # so the page doesn't claim "first boot" with no path
        # forward.
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8><title>Not found</title><p>404</p>",
            status_code=404,
        )
    return HTMLResponse(content=_FORM_HTML)


__all__ = ["router_api", "router_html"]
