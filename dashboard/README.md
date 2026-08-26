# z4j dashboard

The z4j brain's web dashboard. Built with TanStack Router, React,
Tailwind CSS, and shadcn/ui. Compiles to plain static HTML/CSS/JS - no Node
runtime in production.

License: AGPL v3 (same as the brain).

## Stack

| Layer              | Tech                                                     |
| ------------------ | -------------------------------------------------------- |
| Build / dev server | Vite                                                     |
| Routing            | TanStack Router (file-based)                             |
| UI                 | React and TypeScript                                     |
| Styling            | Tailwind CSS, shadcn/ui (new-york)                       |
| Data fetching      | TanStack Query                                           |
| Tables             | TanStack Table                                           |
| Forms              | React Hook Form + Zod                                    |
| Icons              | lucide-react                                             |
| Toasts             | sonner                                                   |
| Theme              | Local class-based dark, light, and system theme provider |

## Pages

| Route                                   | What                                                            |
| --------------------------------------- | --------------------------------------------------------------- |
| `/login`                                | Email + password form, posts to the brain                       |
| `/setup`                                | Served by the brain itself (HTML form) on first boot            |
| `/projects/:slug`                       | Overview - stat cards + recent task list                        |
| `/projects/:slug/tasks`                 | Task list with state / name / queue filters + cursor pagination |
| `/projects/:slug/tasks/:engine/:taskId` | Task detail with events timeline + retry / cancel actions       |
| `/projects/:slug/workers`               | Worker list                                                     |
| `/projects/:slug/queues`                | Queue list                                                      |
| `/projects/:slug/schedules`             | Schedule list with enable / disable / trigger toggles           |
| `/projects/:slug/commands`              | Command list with detail panel                                  |
| `/projects/:slug/agents`                | Agent list with mint-token modal                                |
| `/projects/:slug/audit`                 | Audit log (admin only)                                          |

## Local development

You have three options:

### Option 1 - Pure local (fastest iteration)

Requires a Node and pnpm version supported by `package.json`, plus a brain
running somewhere.

```bash
cd packages/z4j/dashboard
pnpm install
pnpm dev
```

`pnpm dev` generates and validates the tracked TanStack route tree before
Vite starts, so a clean checkout cannot build a stale optimized module graph.
The Vite dev server then starts on `http://localhost:5173` and proxies
`/api/v1`, `/setup`, `/metrics`, and `/ws/agent` to
`http://127.0.0.1:7700` (the default brain bind). If your brain is
elsewhere, set `VITE_BRAIN_URL`, for example
`VITE_BRAIN_URL=http://brain.internal:7700 pnpm dev`.

### Option 2 - Docker compose (one command, full stack)

From the repo root:

Set Z4J_REDIS_8_10_1_INDEX_SHA256 in the current shell from the reviewed Redis
8.10.1 Docker Hub OCI index registry receipt. No digest is committed.

```bash
export Z4J_REDIS_8_10_1_INDEX_SHA256
bash scripts/require-redis-image-authority.sh Z4J_REDIS_8_10_1_INDEX_SHA256
docker compose -f docker-compose.dev.yml up
```

This brings up Postgres, the brain (with `--reload`), the dashboard
(Vite + HMR), and the dev-sandbox Django app + Celery workers.

- Dashboard: <http://localhost:5173>
- Brain backend: <http://localhost:7700>
- Sandbox Django: <http://localhost:8000>

### Option 3 - Production preview

Build the unified brain image (which bakes the dashboard dist into
`/app/dashboard/dist` and serves it from FastAPI):

```bash
docker build -f packages/z4j/backend/Dockerfile -t z4j .
docker run --rm -p 8080:7700 \
    -e Z4J_DATABASE_URL='postgresql+asyncpg://user:password@db/z4j?sslmode=require' \
    -e Z4J_SECRET="$(openssl rand -hex 48)" \
    -e Z4J_SESSION_SECRET="$(openssl rand -hex 48)" \
    -e Z4J_AUDIT_CHAIN_SECRET="$(openssl rand -hex 48)" \
    -e Z4J_PUBLIC_URL='http://localhost:8080' \
    -e Z4J_ALLOWED_HOSTS='["localhost","127.0.0.1"]' \
    -e Z4J_ALLOW_HTTP_PUBLIC_URL=true \
    -e Z4J_ENVIRONMENT=production \
    z4j
```

The dashboard is served by the brain itself at <http://localhost:8080/>.
`Z4J_ALLOW_HTTP_PUBLIC_URL` is only appropriate for this local preview. Use
HTTPS and remove that exception in a reachable deployment.

The preview's `sslmode=require` encrypts the PostgreSQL connection but does not
authenticate the database server unless `sslrootcert` is also supplied. For a
remote database, mount the provider CA in the container and prefer
`sslmode=verify-full&sslrootcert=/run/secrets/postgres-ca.pem`; `verify-full`
validates both the certificate chain and the hostname. z4j translates these
libpq-style URL parameters into asyncpg's SSL configuration before SQLAlchemy
connects.

## Project layout

```
dashboard/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.ts        # most config is in globals.css
├── components.json           # shadcn config
├── index.html
├── public/
│   └── favicon.svg
└── src/
    ├── main.tsx              # entry - mounts React + Router + Query + Theme
    ├── routeTree.gen.ts      # generated by @tanstack/router-plugin
    ├── styles/
    │   └── globals.css       # Tailwind + shadcn theme tokens (OKLCH)
    ├── lib/
    │   ├── api.ts            # fetch wrapper with cookie + CSRF + typed errors
    │   ├── api-types.ts      # hand-curated types matching the brain's REST shapes
    │   ├── query-client.ts   # TanStack Query setup
    │   ├── format.ts         # date / duration / number formatters
    │   └── utils.ts          # cn() (tailwind-merge)
    ├── components/
    │   ├── ui/               # shadcn primitives
    │   ├── layout/           # sidebar, topbar, project switcher, user menu
    │   └── domain/           # state badges, stat cards, empty states
    ├── hooks/
    │   ├── use-auth.ts
    │   ├── use-stats.ts
    │   ├── use-tasks.ts
    │   └── ...               # one hook per resource
    └── routes/
        ├── __root.tsx
        ├── index.tsx         # smart redirect
        ├── login.tsx
        ├── _authenticated.tsx          # auth gate layout
        └── _authenticated.projects.$slug*.tsx  # all project pages
```

## Theme

The default theme is dark and tuned for an enterprise control plane -
slate canvas, cool primary, OKLCH-based palette so accent additions
stay perceptually uniform. Light mode is also fully supported via the
toggle in the sidebar footer (the local theme provider persists the choice).

## Adding a page

1. Create `src/routes/_authenticated.projects.$slug.<page>.tsx`.
2. Add a corresponding entry to `src/components/layout/app-sidebar.tsx`'s
   `buildNav()` function.
3. Add a hook in `src/hooks/use-<resource>.ts` if the page needs API data.
4. Run `pnpm dev` - `routeTree.gen.ts` regenerates automatically.

## Auth model

- The brain serves session cookies (`__Host-z4j_session` in production,
  `z4j_session` in dev). The dashboard never sees the raw token - the
  cookie is HttpOnly. The browser includes it on every request via
  `credentials: "include"`.
- For state-changing requests the dashboard reads the parallel
  `__Host-z4j_csrf` (or `z4j_csrf`) cookie and echoes it back as the
  `X-CSRF-Token` header. The brain compares it constant-time against
  the session's stored CSRF token.
- All of this is transparent to page code - the api client in
  `lib/api.ts` handles it.

## Type safety

Backend response types live in `src/lib/api-types.ts`, with generated
OpenAPI types in `src/lib/openapi-types.gen.ts`. When the REST surface changes,
refresh the snapshot through `scripts/dump-openapi.py --write`, run
`pnpm openapi:gen`, and update any hand-curated public aliases. CI checks both
the live app against the snapshot and the snapshot against generated types.
