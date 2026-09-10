# Changelog

## 1.11.0 (2026-09-10)

- Require `aiosmtplib>=5.1.3` for email delivery. This excludes STARTTLS
  response injection (CVE-2026-55558) and includes the additional ESMTP
  address-validation fixes in 5.1.3. The tested release already uses 5.1.3;
  the change prevents constrained installations from retaining an older SMTP
  client while continuing to allow newer versions.

- Keep PostgreSQL audit append cost stable as history grows with exact
  transactional accounting, independent full audit verification, and indexed
  schedule-receipt lookups. Preserve signed history through migration,
  downgrade and supported backup restoration.

- This release changes the schema. Migration `v1_11_audit_append_tally` runs
  on the first `z4j serve` after upgrading, or through
  `z4j migrate upgrade head` when `Z4J_AUTO_MIGRATE=false`. It adds
  `audit_chain_state.observed_active_row_count` and the
  `ix_commands_schedule_fire_receipt` index on `commands`. On PostgreSQL it
  also takes the audit signing lock and an `EXCLUSIVE` lock on `audit_log` and
  `audit_chain_state`, counts the existing active audit history to seed the
  tally, installs the tally triggers, and builds the index without
  `CONCURRENTLY`. Until it commits, the starting Brain does not serve, and
  audited actions and command writes from any other process wait. The
  duration grows with audit history and command volume, so schedule the
  upgrade for a quiet window. On SQLite it only adds the column and the index.

- Add the Agent Health API,
  `GET /api/v1/projects/{slug}/agents/{agent_id}/health`, and a Health dialog
  on the dashboard's Agents page. Project viewers can read an agent's latest
  100 retained status samples, each with its structured telemetry-loss
  counters and authenticated worker identity; revoked or foreign agents
  return 404. A sample's time is when the agent sent it, so a report buffered
  through an outage carries its delivery time. Missing reports, older agents
  and disabled status history show as unavailable accounting, never as zero
  loss. A heartbeat that reports changed, positive loss also produces a
  rate-bounded Brain warning.

- Keep Celery and RQ task submission responsive during broker stalls by moving
  blocking publishes to the dedicated broker pool. A publish timeout retains
  an explicit indeterminate outcome because the task may still be enqueued.

- Preserve a failed or timed-out fire's original outcome when an operator
  resolves its hold. Resolution is recorded separately, resumes the selected
  cadence safely, and no longer raises a database transition error.

- Synchronize timeout sweeps through the database, avoiding an ORM timestamp
  comparison crash after a SQLite command refresh.

- Canonicalize PostgreSQL network-address values when preparing restore/reset
  manifests, so backups containing real IPv4 or IPv6 login sessions restore
  successfully without relaxing the manifest type checks.

- Keep PostgreSQL reset and restore available after a supported downgrade and
  re-upgrade. PostgreSQL never reuses a dropped column's number, so the schema
  signature binds the order of live columns instead of physical column numbers;
  databases without dropped-column slots keep their existing signatures.

- Preserve externally configured SQLite authority across restarts and upgrades:
  a complete set of supplied secrets no longer requires a local secret store.
  Existing databases with missing keys still refuse replacement keys.

- Refresh locked scheduler delivery commands before claiming them, so concurrent
  registry delivery paths cannot reuse a stale pending state or replace another
  claim. PostgreSQL regression coverage reproduces the competing-reader race.

- Accept a command for a live long-poll agent as pending on brains that use the
  local command registry (SQLite and other single-process installations). The
  request reported "agent is not connected" while the agent still claimed and
  ran the command, inviting a second attempt that could run it twice.

* Align runtime version metadata and sibling dependency floors with the coordinated 1.11.0 release.
* Refresh the dashboard with consistent page controls, sortable record columns, restrained light/dark palettes, clearer settings navigation and responsive layouts.
* Add personal Saved Views for task-history filters with membership, CSRF, uniqueness and quota checks.
* Show filtered result totals and correct all-matching bulk selection; improve search, tooltip and dialog keyboard behavior.
* Keep long-poll agents as task command targets: they report no engine inventory, so the task detail page and bulk retry treat an unreported inventory as unknown rather than empty, while a token that never connected is not offered. Bulk retry and revoke send each task to an agent that can act on its engine (revoke no longer uses the project's first agent) and send nothing when a selected task has no such agent.
* Recognize canonical PyPI prerelease versions in agent freshness and compatibility warnings.
* Keep a saved schedule's kind and expression in the schedule Edit dialog. A run-once (`clocked`) or `solar` schedule that the form does not offer for its engine no longer opens as a cron schedule whose save the Brain refuses.

## 1.10.0 (2026-08-28)

* The dashboard shows a schedule's recent history as a picture. Each row of
  the schedules table carries a strip of the last twenty fires, oldest on the
  left, coloured by outcome, so a schedule that flaps, one that fails in
  bursts, and one that has been dead for a week look different rather than
  sharing a number. The same strip, fifty fires wide, sits above the
  fire-history table on the schedule detail page, and a twenty-wide one sits
  in a new "Schedules needing attention" panel on the
  project overview, which lists schedules whose most recent fires are an
  unbroken run of failures, worst first, and stays silent when everything is
  healthy.
* A schedule that is failing is visible before the circuit breaker disables
  it. The brain counted every schedule's run of consecutive failures on each
  breaker tick and kept nothing but the disable. The schedules list and the
  single-schedule read now report `consecutive_failures` (0 means the newest
  fire is not a failure; responses to mutations do not recount and carry
  `null`), the list reports the operator's `circuit_breaker_threshold`, and
  the table shows a Health badge reading, for example, "3 of 5 failing" while
  the schedule is still enabled. With the breaker switched off the count is
  still reported, over the newest twenty fires.
* `GET /projects/{slug}/schedules/runs` returns the last N fires for many
  schedules in one request. It is the endpoint the strips read; the dashboard
  asks for at most a hundred schedules per request and the route refuses more
  than five hundred.
* Both circuit-breaker reads of fire history are bounded and cheap. On
  PostgreSQL the bulk read is a per-schedule top-N (`LATERAL`), so its cost is
  schedules times the limit rather than every fire of every schedule in the
  retention window numbered and then discarded. Both reads are bounded by the
  retention cutoff on `fired_at`, which is what the prune worker deletes by,
  so the bound excludes nothing that still exists: a fire caught up for an
  old slot, or replayed from the buffer, has a recent `fired_at` and stays
  visible to the breaker and the grid alike.
* The canvas tree separates queue wait from execution. A task that ran for
  40ms after four minutes in the queue and a task that ran for four minutes
  used to look identical; each node now carries a two-segment bar, and the
  legend says the wait is measured from when the brain observed the task, so
  it is a close lower bound rather than an exact figure. The tree node shape
  gains `started_at` to make that possible.
* Wide tables scroll instead of losing columns. The table wrapper clipped its
  overflow, so at common widths the schedules table silently dropped Last run,
  Next run, Runs, Enabled and its row actions while provenance columns took
  the space. Tables now open on a chosen column set with a Columns chooser in
  the footer, header labels never wrap, dates in dense tables render on one
  line with the absolute timestamp on hover, and counts get thousands
  separators. Schedule rows are roughly half their previous height.
* The public demo matches the API again. It showed every schedule as held,
  because its fixtures omit `paused_at` and the badge tested strictly for
  null; every schedule detail page showed a blank fire-history card, because
  the mock answered with a paginated envelope where the real route returns a
  list; and the overview's five recent tasks were sixty, because the mock
  ignored `limit`. All three are fixed and the demo carries fire history for
  every schedule.
* Every node workspace moves to its newest release that clears the three-day
  minimum age, with one deliberate hold: the dashboard's TypeScript stays on
  the 5.9 line. The 6.0 line clears the age gate and the linter's peer range,
  and the 7.0 line does not; the compiler major is held until its tsconfig
  changes are reviewed on their own, not folded into a release wave.
* The Workers page's configuration lint panel is readable and cannot take the
  page down. Its finding text used a background colour token and was
  invisible, and a payload without a `workers` array crashed the page; the
  panel now uses the foreground token and renders nothing on an unexpected
  shape. The trend chart's axis is labelled in round steps and its last time
  label is no longer clipped, and the workers table shows the three load
  averages on one line.
* The published container image carries no package installer. pip, its
  vendored-library inventory, ensurepip's bundled wheel and the pip launchers
  are removed, as are `grpcio-tools` and `setuptools`, which the runtime
  never imports (the gRPC gencode is committed and needs only `grpcio` and
  `protobuf`). The inventory alone produced two false HIGH scanner findings
  in the previous image. A derived image that installs extra packages must
  add an installer first.

## 1.9.1 (2026-08-27)

* The published image takes the security updates its Debian base was behind
  on, and pins the base by digest as well as by tag.
* The 1.9.0 container images are published. Every 1.9.0 feature was reachable
  only from a pip install until now, which left schedule hold, the worker lint,
  the deep health probe, the scheduled chain verifier, connection-pool sizing
  and previous-release restore invisible to anyone running the published image.
* `z4j audit export-head` prints the authenticated chain head as the envelope
  `audit verify --known-head` accepts. The documentation has always named that
  check as the defence against a database role that can rewrite history, but
  nothing in the product would tell an operator what their head was, so the
  advice could only be followed by reading the state row out of the database and
  assembling the JSON by hand. The state is authenticated before anything is
  printed, `--verify` refuses to export a head from a chain that did not verify
  clean, and the envelope carries only the keys the verifier accepts.
* Schedule hold is visible and controllable from the dashboard. The brain has
  enforced it in six places and projects it onto the scheduler wire, but the
  dashboard had no pause or resume control at all and gave a held schedule no
  mark, because `is_enabled` means retired rather than held and was correctly
  showing enabled.
* A user blocked by MFA enrollment enforcement is told so, and given the route
  to enroll. Previously the brain answered every non-exempt route with a 403 the
  dashboard rendered as "your role doesn't have access", which is both wrong and
  a dead end. The status response's `enrollment_required` and
  `enrollment_deadline` had been sent all along and were missing from the
  dashboard's hand-written type.
* The worker configuration lint has a panel on the Workers page and a
  documentation page. It reports what it did not evaluate separately from a
  clean result, because a worker whose engine has no rules has not been judged.
* Dead-letter requeue is reachable. The adapter implementation, the policy
  action, the agent handler and the wire contract all existed; no endpoint ever
  issued the command. Engines without a safe dead-letter primitive refuse at the
  adapter and report why.
* The scheduler no longer loses a fire to its own dispatch latency. A slot the
  leader had already seen as due could be reclassified as missed by the time a
  retry ran, and under the default `catch_up="skip"` it was then advanced past
  and recorded as fired without ever being dispatched. A slot judged on-time now
  stays on-time across retries, for a bounded window rather than indefinitely;
  one that genuinely elapsed while the scheduler was down is unchanged, and
  `skip` still discards it. Slots a `catch_up` policy
  does drop are now logged and counted rather than dropped in silence, the
  on-time grace is configurable, and an unexpected error in one tick no longer
  takes the whole scheduler process down. See the `z4j-scheduler` changelog.
* Documentation corrections: the settings reference stated that the connection
  pool is not configurable, which stopped being true when it became configurable;
  the threat model scoped both database-boundary weaknesses to PostgreSQL when
  only the schedule guard is engine-specific, leaving SQLite operators reading
  that the audit-log weakness did not apply to them.

## 1.9.0 (2026-08-25)

* **Dashboard dependency refresh:** The bundled dashboard is rebuilt against
  current stable frontend dependencies (TanStack Query, react-hook-form,
  ESLint, Testing Library user-event, jsdom) and the repository-wide pnpm
  release authority moves to 11.24.0. `pnpm audit` reports no known
  vulnerabilities in this tree. TypeScript stays on the 5.9 line: 7.0 is
  available and both the production build and the type check pass on it, but
  typescript-eslint does not support TypeScript 7 yet, so adopting it would
  mean shipping with linting switched off.
* **Dependency security floors:** Fresh installs now refuse vulnerable
  cryptography (<50.0.0), protobuf (<6.33.5), and optional Sentry SDK
  (<2.8.0) releases. The test extra requires pytest 9.1.1 or newer within
  the supported pytest 9 line.
* **Upgrade sequence:** Take a backup, stop every 1.8 brain process, run
  `z4j migrate upgrade head`, and then start only 1.9 processes. This is not a
  rolling upgrade: Kubernetes' default `RollingUpdate` can overlap old and new
  processes even at `replicas: 1`, so use `strategy: { type: Recreate }` and
  turn off `Z4J_AUTO_MIGRATE` on runtime replicas. The five-revision chain adds
  `schedules.overlap_policy`, `schedules.paused_at`, and `agents.revoked_at`,
  deduplicates and enforces one legacy NULL-worker slot per agent, installs
  exact rolling-window admissions and monotonic configuration epochs, preserves
  notification delivery owners after subscription deletion, and adds the audit
  action-prefix index; `overlap_policy` is groundwork and only `allow` is
  accepted in 1.9.
* **Rollback:** A 1.9 database cannot be started directly with the ordinary
  1.8.2 image: pre-existing rows carry the Python 3.14.6 cadence fingerprint
  and 1.9-created rows carry Python 3.14.7. Stop every Brain and scheduler
  executor, then use the exact 1.9 candidate carrier to run the two-phase
  `z4j migrate prepare-runtime-rollback` ceremony. It binds a human quiescence
  challenge to the complete row set and the separately published
  `1.8.2-py3.14.7-rollback-1.9.0` compatibility image. Consume that image only
  by the finalized index digest in the signed release receipt; mutable
  `1.8.2`, `1.8`, and `latest` tags are forbidden. Preparation restamps every
  reserved row through authenticated Boundary-D revisions, recomputes target
  cursors from retained legitimate anchors, and preserves definitions, control
  tokens, execution counters, and fire evidence. Externally owned rows remain
  on their legitimate external repository upsert/promotion path. Only after
  preparation succeeds may the exact 1.9 carrier run
  `z4j migrate downgrade v1_8_schedule_cursor_repair`, after which unchanged
  1.8.2 code runs from the compatibility digest. The migration environment
  checks every state-dependent preflight before the first downgrade revision.
  It refuses an unfinalized compatibility manifest, any post-preparation row
  change, paused or quarantined schedules, any agent tombstone, or a delivery
  retaining its owner only through `recipient_user_id` after subscription
  deletion. Resume paused schedules; export or clear those delivery rows, or
  restore a backup from before the subscription deletion. Revocation destroys
  the original token hash, so a database containing a tombstone must be
  replaced from the backup taken before that revocation. Offline `--sql`
  across these live-state guards fails closed.
  When the checks pass, exact automation admissions are conservatively collapsed
  into the legacy aggregate breaker state. The daily stale-agent worker can
  create tombstones automatically after
  `Z4J_AGENT_STALE_PRUNE_DAYS` (30 days by default); set it to `0` before the
  upgrade if that automatic behavior is unwanted.
* **Schedule controls and diagnostics:** Pause and resume now provide an
  incident hold distinct from destructive disable and enable. Schedules owned
  by an external scheduler are refused because z4j cannot enforce their hold.
  This release also adds authenticated per-subsystem deep health, worker
  configuration lint, and opt-in scheduled audit-chain verification.
* **PostgreSQL liveness:** `Z4J_DATABASE_POOL_SIZE` and
  `Z4J_DATABASE_MAX_OVERFLOW` are configurable. Startup refuses a configured
  total below the derived floor of one connection per leader-gated worker, one
  for an enabled embedded scheduler, and one spare; the default configuration's
  floor is four. This is a deadlock-prevention floor, not a sizing
  recommendation.
* **Backup and restore:** A backup from 1.8 can be restored, migrated, and
  finalized under 1.9. New SQLite backups are created owner-only on POSIX and
  refuse an existing destination; audit older backups and rotate API keys and
  sessions if a world-readable copy was exposed. PostgreSQL backups previously
  taken on Windows may be truncated, so take a fresh backup after upgrading and
  confirm `pg_restore --list` reads it. On Windows, place PostgreSQL client
  binaries in an owner-private directory first on `PATH`.
* **Adapter capability safety:** Celery no longer advertises the unsafe
  `requeue_dead_letter` action; direct calls fail without publishing. Dramatiq
  no longer advertises operations that stock Dramatiq cannot satisfy safely,
  rq-scheduler no longer advertises an `enable` operation that cannot restore a
  removed definition, and TaskIQ rejects unsupported non-default queue, ETA,
  and priority overrides instead of silently ignoring them. TaskIQ broker and
  custom schedule-source operations now require the correct owner event loop
  and fail closed when it is unavailable.
* **Environment security:** Only the exact value `dev` selects relaxed behavior.
  Other `Z4J_ENVIRONMENT` and `Z4J_SCHEDULER_ENVIRONMENT` values now take the
  production path, including authenticated metrics, protected scheduler gRPC,
  production cookies and host validation, and fail-fast scheduler-listener
  startup.
* **Reliability:** Schedule fires now submit the locally computed cadence
  identity, preventing dependency or Python patch changes from stalling every
  existing schedule. Unsupported agents back off instead of reconnecting
  forever, paused schedules no longer generate false misfire incidents, audit
  verification cannot omit unexamined rows, and failed restores are refused
  before they strand the startup fence.

## 1.8.0 (2026-07-23)

* **Retry safety**: adapter proof is bound to the exact worker session that receives a retry; sticky per-agent metadata and automation can no longer authorize a different old worker, and coordinated 1.8.0 package floors prevent the reverse old-runtime/current-adapter pairing.
* **Deploy**: the default `docker compose up -d` refused to start (dev-mode + 0.0.0.0 bind gate); the default compose now runs the production posture pinned to loopback. The postgres+Caddy health check was 400-rejected by host validation (Caddy then never started); the health subtree is now exempt. SQLite deployments are now forced single-worker (a multi-worker in-memory agent registry split agent visibility across processes and raced the first-boot bootstrap into noisy UNIQUE-violation tracebacks); Postgres keeps the multi-worker default except when embedded scheduler mode is enabled, which safely forces one brain worker so each process cannot launch a competing scheduler child. Multi-worker Postgres uses the standalone scheduler deployment. The embedded child inherits the brain's resolved environment unless explicitly overridden, preventing a dev brain from silently launching a production-default child that crash-loops on metrics exposure. The Caddy overlay's `deploy/Caddyfile` now actually ships (it was referenced by the compose mount but absent from the released repo and sdist, so the auto-HTTPS quickstart always failed); and the Postgres compose now forwards `Z4J_BOOTSTRAP_ADMIN_*` so zero-log-exposure admin seeding works there too (previously only the SQLite compose passed the variables through). The default and Postgres compose kits now use a split-safe Dockerfile that is included in the sdist and installs that exact released source tree; they no longer invoke a monorepo Dockerfile whose sibling-package inputs are absent. The packaged Postgres kit persists `/data` in `z4j_brain_state`, so the mandatory 1.7-to-1.8 manifest survives between separate one-off preparation and apply containers. A packaged `.dockerignore` keeps compose secrets and local build state out of image layers while preserving the compiled dashboard.
* **Upgrade safety**: 1.7 sub-second schedule cursors are normalized during Boundary-D activation, and `v1_8_schedule_cursor_repair` gives already-activated pre-release databases a guarded immutable repair path; previously, an enabled schedule could show moving cursors while silently executing nothing forever. Upgrade verification now requires `total_runs` to increase after the ceremony. The packaged SQLite management path safely tightens an owned legacy 0755 `/data` directory to 0700 and persists exactly the missing independent audit-chain key in a verified pre-1.8 secret store. The documented PostgreSQL rollback now recreates an empty target database, restores with fail-fast SQL handling, and requires exactly the 1.7 migration head before restarting the previous image; it can no longer report success while leaving a mixed 1.7/1.8 schema.
* **Security**: authenticated the audit prune-watermark (a DB-write adversary could otherwise silently truncate the HMAC chain); closed a second-factor bypass on the dashboard WebSocket; wrong recovery codes now count toward the MFA lockout; denial-audit rows now carry the real client IP + user id; hardened the predictable `/tmp` buffer fallback (CWE-377); security headers are now stamped on early 413/400 responses.
* **Reliability**: the scheduler no longer fires the entire backlog for `fire_one_missed` on recovery (a duplicate-side-effects storm); destructive engine/scheduler actions (cancel/purge/retry/trigger_now across celery/rq/dramatiq + scheduler adapters) offload their broker I/O so a broker incident can't freeze the agent, and a bulk retry against a hung broker (celery/rq/dramatiq) aborts early instead of grinding through every id; agent events buffered during an outage are recovered on restart instead of orphaned, and a `post_fork` hook fixes the agent under gunicorn/uWSGI `--preload`.
* **Correctness**: Dramatiq retry + Celery DLQ requeue now thread the task/actor name (were dead); pagination fixes for the home feed, the schedules cursor (hung on a `|` in a name), and pending-task visibility; huey lock-contention is no longer a false failure; taskiq stops double-counting failures + hands events across loops safely; `celery beat` behind value-taking flags installs the agent.

* **Connection pool sizing is now configurable** via `Z4J_DATABASE_POOL_SIZE` (default 20) and `Z4J_DATABASE_MAX_OVERFLOW` (default 10); both were hardcoded. Size this before you deploy: each uvicorn worker builds its own engine and `z4j serve` defaults to `max(1, min(4, cpu_count))` workers, so worst-case demand is `workers x (pool_size + max_overflow)`. At the defaults on a 4-core host that is 120, which exceeds a stock PostgreSQL `max_connections` of 100 on its own, leaving no room for a second brain, a standalone scheduler, or a spare superuser slot. Defaults are unchanged so nothing shifts on upgrade; `docs/DATABASE.md` has the formula and four ways to fit it.
* **Critical fix**: a malformed `Host` header (`[::1]extra`, `[::1`) raised an unhandled error on Python 3.14 instead of the 400 host validation exists to return. Python 3.14 made `urlsplit` raise on exactly those hosts, and two middlewares reached for `request.url`, which rebuilds a URL from the client-supplied `Host` and parses it lazily; the security-headers middleware runs outermost, ahead of host validation, and host validation itself read it before its own malformed-host check. Both now read the path from the ASGI scope, which no header can poison. No request reached the application either way, so this was robustness rather than a bypass, but it was reachable with an attacker-controlled header on a supported runtime.
* **Critical fix**: triggering a schedule with no agent online returned 500 instead of the 404 that names the cause ("no online agent for this project; start the agent and retry"), which 1.7 returned. The endpoint was correct: the best-effort denial audit ran first and read the actor id off a request-scoped ORM instance whose session had already closed, and the resulting `DetachedInstanceError` escaped the structured-error handler and became a generic 500. The actor id is now captured at authentication time so the error path never touches the ORM, and no failure while recording a denial can change the response the caller receives. Denial rows are still written and still attributed.
* **Critical fix**: enabling MFA could lock a user out. The request-time second-factor gate matched its escape-route allowlist against the router-local path instead of the mounted `/api/v1/...` path, so a password-only session was refused even at the verify route it needed, and only `z4j reset-mfa` could recover the account. The gate now matches the request's real path; the identical latent bug in the enrollment gate is fixed by the same change.
* Fixed: Celery retries ignored the brain-supplied task name (falling back to the off-by-default `result_extended` metadata) so retries of a finished task failed to resolve; the in-worker agent started on `worker_init` and could wedge a worker's prefork pool after a restart (now `worker_ready`); the periodic health refresh could overrun its cap and emit a synthetic-error health blob every cycle; under `celery beat` the Django integration installed no agent so the scheduler showed as unknown; schedules with the same name on two different schedulers (for example a huey and an arq `cleanup`) clobbered each other because the upsert keyed on `(project, name)` instead of `(project, scheduler, name)`; and fresh installs warned about `0755` home directories the agent itself created (now `0700`).
* Added: an Issues dashboard page (browse failure-fingerprint groups with status filters), scheduler misfires surfaced on the Schedules page, a bundled `THIRD-PARTY-NOTICES.txt`, and an Automation REST reference in the docs.

## 1.7.0 (2026-07-11)

* **Automation rule engine**: governed per-project rules (notify / retry / cancel) with a rolling-window circuit breaker, per-project kill switch, dry-run mode, and an HMAC-chained audit of every firing; destructive rules require ADMIN, browser-session mutations require fresh MFA, bearer-authenticated callers follow API-key authority, and fire time rechecks the creator's current ADMIN membership. New dashboard Automation area.
* **Issues** (failure fingerprinting), **brain-side misfire detection**, **per-operator fire attribution**, a **durable automation firing outbox**, and Postgres RANGE-partitioning of the fire-history table.
* Purge confirmation is now a keyed HMAC derived from the project secret and verified server-side.
* The long-poll routes advertise the canonical agent/project UUIDs (`X-Z4J-Agent-Id` / `X-Z4J-Project-Id` response headers) so a slug-configured agent can bind the correct frame-HMAC identity; pre-1.7 the long-poll transport could never pass frame verification.
* Fixed: Microsoft Teams notification channels were un-creatable (channel-type validation excluded `teams`); `z4j audit verify` silently verified only the first 5,000 rows (now pages the whole chain); default redaction missed camelCase secrets (`accessToken` / `refreshToken`) and `hmac_secret`; `fire_one_missed` catch-up re-fired the same missed occurrences every replay tick; an ingest deadlock could roll back an entire accepted event batch; `alembic downgrade base` orphaned every enum type on Postgres; the shipped `deploy/Caddyfile` proxied to a pre-1.4 service name (guaranteed 502).
* **Security hardening** (four-round internal audit, all eight findings closed): request-time second-factor enforcement so a password-only session cannot reach the control plane; MFA re-enrollment now requires a fresh second factor; a per-account MFA lockout (NIST 800-63B); TOTP single-use / anti-replay; the login enumeration timing oracle removed; password reset now wipes trusted-device rows; the audit-chain prune anchor fixed so `z4j audit verify` stops false-alarming after retention; and failed password-reset attempts are audited. `click` bumped to 8.4.2 (CVE-2026-7246).
* Added the project-wide misfire view `GET /projects/{slug}/schedules/misfires` and the `z4j misfires --project <slug>` CLI.
* The thirteen development-time 1.7 migrations were consolidated into a single `v1_7_schema` revision (the in-place 1.6.x -> 1.7 upgrade is unchanged) plus a `v1_7_security_hardening` revision; the 1.6.x -> 1.7 upgrade is verified data-safe on Postgres and SQLite.
* See the root CHANGELOG for the full detail of this release.
* Python 3.11 is now the minimum supported version (3.10 dropped).
* Part of the coordinated 1.7.0 fleet release (unified fleet version, green lint/format/import-boundary gate).

## 1.4.0 (2026-05-02)

Initial 1.4.0 release: the consolidated z4j control plane. Server, dashboard, REST API, audit log, and reconciliation all ship in this distribution (pre-1.4.0 they shipped under the `z4j` PyPI name; that name is now a metadata-only compatibility shim). Engine and framework adapters available via extras: `pip install z4j[django,celery]`.
