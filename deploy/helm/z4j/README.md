# z4j Helm chart

Deploys the [z4j](https://z4j.com) brain (REST API, dashboard and the agent
WebSocket plane) into a Kubernetes cluster, with the standalone
`z4j-scheduler` companion and a bundled evaluation PostgreSQL as opt-in
components. Everything runs from the one published image, `z4jdev/z4j`;
the scheduler is the same image with its entry point overridden to
`z4j-scheduler serve`.

The chart is published as an OCI artifact:

```sh
helm install z4j oci://ghcr.io/z4jdev/charts/z4j --namespace z4j --create-namespace
```

The chart version equals the z4j release it was built for, so
`--version X` installs chart X running image tag X. Omit `--version` for
the newest release. Kubernetes 1.28 or newer; Helm 3.8 or newer (OCI
registries).

## Design choice: one chart, components folded in

The brain and the scheduler live in one chart as sibling template
directories (`templates/brain/`, `templates/scheduler/`) rather than as a
parent chart with a scheduler subchart. They share one image, one release
version, one `rolloutRevision`, and the scheduler's defaults (brain
endpoints, the mTLS bundle, the leader DSN) are derived from the brain's
own values, which a subchart cannot see. The former standalone use case is
preserved: `brain.enabled=false` with `scheduler.enabled=true` deploys only
the scheduler against a brain that lives elsewhere.

The scheduler's templates keep their own helper namespace
(`z4j-scheduler.*`) and their fail-fast validators, so a misconfigured
release is refused at `helm template` time with a message that names the
value to set.

## Quick start

### Evaluation (defaults)

The defaults mirror the packaged `docker-compose.yml`: one brain replica,
bundled SQLite on a 1 GiB PersistentVolumeClaim, secrets auto-minted on
first boot, no scheduler, reachable through `kubectl port-forward`.

```sh
helm install z4j oci://ghcr.io/z4jdev/charts/z4j --namespace z4j --create-namespace
kubectl --namespace z4j logs deployment/z4j -f        # capture the setup URL
kubectl --namespace z4j port-forward svc/z4j 7700:7700
```

### Production (PostgreSQL, explicit secrets, ingress)

```sh
kubectl --namespace z4j create secret generic z4j-secrets \
  --from-literal=app-secret="$(openssl rand -hex 48)" \
  --from-literal=session-secret="$(openssl rand -hex 48)" \
  --from-literal=audit-chain-secret="$(openssl rand -hex 48)" \
  --from-literal=database-url='postgresql+asyncpg://z4j:PASSWORD@db.internal:5432/z4j?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt'

helm install z4j oci://ghcr.io/z4jdev/charts/z4j --namespace z4j \
  --set brain.publicUrl=https://z4j.example.com \
  --set 'brain.allowedHosts={z4j.example.com}' \
  --set brain.allowHttpPublicUrl=false \
  --set brain.secrets.existingSecret=z4j-secrets \
  --set brain.database.existingSecret=z4j-secrets \
  --set brain.ingress.enabled=true \
  --set 'brain.ingress.hosts[0].host=z4j.example.com' \
  --set 'brain.ingress.hosts[0].paths[0].path=/' \
  --set 'brain.ingress.hosts[0].paths[0].pathType=Prefix'
```

Terminate TLS at the ingress, forward `X-Forwarded-For`, and list the
ingress controller's CIDR in `brain.trustedProxies` so the brain attributes
requests to the real client. WebSocket upgrades on `/ws` need long proxy
timeouts (`nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"` and the
matching `proxy-send-timeout` for nginx-ingress).

## Brain

### Secrets

| Key in `brain.secrets.existingSecret` | Environment variable |
|---|---|
| `app-secret` | `Z4J_SECRET` (master key; agent HMAC secrets derive from it) |
| `session-secret` | `Z4J_SESSION_SECRET` (signs the browser session cookie) |
| `audit-chain-secret` | `Z4J_AUDIT_CHAIN_SECRET` (signs the tamper-evident audit chain) |

The key names are configurable under `brain.secrets.keys`. On PostgreSQL
all three are required and the chart refuses to render without a source.
In SQLite mode the brain mints them on first boot and persists them under
`/data/secret.env`, so they may be omitted. `brain.secrets.inline` exists
for dev and homelab installs; it lands in the release object in plaintext.

### Database

Exactly one of:

- nothing (default): bundled SQLite at `/data/z4j.db` on the persistent
  volume; single replica only;
- `brain.database.existingSecret` with a SQLAlchemy URL under
  `brain.database.existingSecretKey` (default `database-url`), spelled
  `postgresql+asyncpg://...` and carrying `sslmode=require`, `verify-ca`
  or `verify-full` unless `brain.database.requireSsl` is false;
- `postgresql.enabled=true`: the bundled evaluation PostgreSQL below.

Rendering more than one source is refused.

### Persistence

`/data` is `Z4J_HOME`. It holds the SQLite database, generated secrets,
restore-recovery and activation manifests, allowed-host state and the
embedded-scheduler PKI, so the chart claims a PersistentVolumeClaim by
default even on PostgreSQL. The claim is annotated
`helm.sh/resource-policy: keep`: `helm uninstall` leaves it, and removing
it is a deliberate `kubectl delete pvc`.

#### Volume ownership

The brain's secret store opens `/data` only when the directory is owned by
the uid the brain runs as, with no group or world permission bits (mode
0700). A dynamically provisioned claim arrives owned by root, and
`podSecurityContext.fsGroup` changes only its group, so on a fresh volume
the brain exits with `secret-store directory is not owned by the current
uid: /data` and a standalone scheduler crash-loops behind it. The chart
therefore runs a `fix-data-permissions` init container before the brain
(`brain.persistence.fixPermissions.enabled`, on by default): the same image
as root with only `CHOWN` and `FOWNER`, `allowPrivilegeEscalation: false`
and a read-only root filesystem, which gives `/data` to
`brain.podSecurityContext.runAsUser` and `runAsGroup` with mode 0700 and
changes nothing that is already right. It runs on every pod start because
a storage driver that applies `fsGroup` on mount adds the group bits back
each time.

It is the one root container in the release, so the namespace needs the
PodSecurity `baseline` profile or an exemption; `restricted` rejects it.
Where policy forbids root init containers, disable it and prepare the
volume once from a shell that reaches it as root (the node for
hostPath-backed storage, or a one-off pod that mounts the claim):

```sh
chown 10001:10001 /path/to/the/claim && chmod 0700 /path/to/the/claim
```

On a driver that applies `fsGroup` on every mount, also clear it, or the
kubelet re-adds the group bits on the next start and the brain refuses the
directory again:

```sh
helm upgrade z4j oci://ghcr.io/z4jdev/charts/z4j --namespace z4j --reuse-values \
  --set brain.persistence.fixPermissions.enabled=false \
  --set brain.podSecurityContext.fsGroup=null
```

### Rollout strategy and replicas

`brain.strategy.type` defaults to `Recreate`. The brain migrates the
database on boot, and Kubernetes rounds `maxSurge` up, so a rolling update
of even one replica would run the new migration while the old process is
still writing. `brain.replicaCount` above 1 requires PostgreSQL and sticky
session routing for `/ws` on your load balancer; the chart renders no
affinity helper.

### Metrics

`/metrics` requires a bearer token. Point `brain.metrics.authExistingSecret`
at a Secret holding it and, for the Prometheus Operator, enable
`brain.serviceMonitor` with `bearerTokenSecret` naming the same Secret and
key.

## Bundled PostgreSQL

`postgresql.enabled=true` renders a single-instance StatefulSet from the
same digest-pinned image and tuning as the packaged compose stack, a
headless Service and a password Secret (`postgresql.auth.password` inline
or `postgresql.auth.existingSecret`). The brain is wired to it with the
structured `Z4J_DATABASE_*` fields and `Z4J_REQUIRE_DB_SSL=false`, as on
the compose private bridge. It has no replication, no backups and no
operator; use it for evaluation and small installs, and a managed
PostgreSQL or an operator (CloudNativePG, Zalando, Crunchy) for production.

## Scheduler

`scheduler.enabled=true` adds the standalone `z4j-scheduler` Deployment
and turns on the brain's mTLS gRPC listener (port `brain.service.grpcPort`,
default 7701). With `brain.enabled` the scheduler's brain endpoints default
to this release's brain Service; otherwise set `scheduler.brain.grpcUrl`
and `scheduler.brain.restUrl`.

### Scheduler mTLS

The brain needs a server certificate for its listener and the CA that
signs scheduler client certificates; each scheduler needs a client
certificate whose CN is listed in `brain.schedulerGrpc.allowedCNs`. Pick
one source for each side.

Brain side (`brain.schedulerGrpc.tls`):

- `existingSecret`: a Secret with `tls.crt` (server leaf, SANs covering the
  brain Service's cluster DNS name, which is `<fullname>.<namespace>.svc.cluster.local`;
  the fullname is the release name when it contains `z4j`, so the installs on
  this page serve at `z4j.z4j.svc.cluster.local`, and `<release>-z4j` otherwise),
  `tls.key`, and `ca.crt` (the CA for client certificates);
- or `pki.mintJob.enabled=true`, which mints it (below).

Scheduler side (`scheduler.tls`), in order of production-readiness:

1. `scheduler.tls.existingSecret`: a `kubernetes.io/tls` Secret with
   `tls.crt`, `tls.key` and `ca.crt` (the CA that signed the brain's
   server certificate). The chart never sees the material. Mint the leaf
   with `z4j mint-scheduler-cert --name scheduler-1 --ca-cert ca.crt
   --ca-key ca.key --out-dir .` against your own CA, then
   `kubectl create secret generic z4j-scheduler-tls --from-file=tls.crt=scheduler-1.crt --from-file=tls.key=scheduler-1.key --from-file=ca.crt=ca.crt`.
2. `scheduler.tls.certManager.enabled=true`: the chart renders a
   `cert-manager.io/v1` `Certificate` against the Issuer or ClusterIssuer
   you name. `scheduler.tls.certManager.commonName` must be in
   `brain.schedulerGrpc.allowedCNs`.
3. `pki.mintJob.enabled=true`: the Kubernetes counterpart of the compose
   kit's `docker/scheduler-certs.sh`. A pre-install and pre-upgrade hook
   Job, run from the brain image, mints a private CA, the brain's server
   leaf (SANs: the brain Service's cluster DNS names plus
   `pki.mintJob.extraServerDnsNames`) and the scheduler's client leaf
   (`pki.mintJob.schedulerCommonName`), with the script's EC P-256 keys
   and validity defaults (`caValidityDays` 3650, `leafValidityDays` 825),
   and writes both halves as `kubernetes.io/tls` Secrets through the
   Kubernetes API. It is idempotent the same way the script is: an
   existing bundle is left alone unless a half is missing or malformed, a
   leaf does not chain to the CA or match its key, a certificate expires
   within `renewDays`, the names changed, or `pki.mintJob.force` is set.
   Its ServiceAccount can only `get` and `update` those two Secret names
   and `create` Secrets in the release namespace; the RBAC is removed once
   the Job succeeds and the completed Job stays until the next hook run so
   `kubectl logs job/<release>-pki-mint` shows what it did. A renewal
   replaces the Secrets but not the files already loaded by running pods,
   so pass a new `rolloutRevision` on any upgrade near expiry (the log
   says `RENEWED`). The Secrets are not Helm-managed: `helm uninstall`
   leaves them, and a forced rotation is `--set pki.mintJob.force=true`
   together with a new `rolloutRevision` for one upgrade.
4. `scheduler.tls.inline`: PEMs as values. Dev and homelab only; they land
   in the release object in plaintext.

### Leader election and HA

PostgreSQL advisory locks coordinate replicas without pod-local state:

- `scheduler.leader.backend: single`: every process is always leader. Safe
  only with one replica; the chart rejects `replicaCount` above 1.
- `postgres_per_project` (default) or `postgres`: supply
  `scheduler.leader.databaseUrl` or `scheduler.leader.existingSecret`
  (key `scheduler.leader.existingSecretKey`, default `leader-pg-dsn`).
  With the bundled PostgreSQL and an inline `postgresql.auth.password` the
  chart composes the DSN Secret itself.

The leader DSN goes straight to `asyncpg`, so it must use `postgresql://`
or `postgres://`. The brain's `postgresql+asyncpg://` SQLAlchemy spelling
is rejected; use the same database and credentials with the driver
qualifier removed. A brain on SQLite has no advisory locks, so a standalone
scheduler against it must use `single` with one replica.

Two replicas provide failover. Per-project locks let projects land on
different replicas but do not balance them; one faster replica can hold
every project while the other remains a hot standby.

### Metrics auth token (required when scheduler metrics are enabled)

The scheduler refuses to start in production when it binds a non-loopback
address with metrics enabled and no `/metrics` bearer token, and this
chart always binds `0.0.0.0`. A tokenless render would crash-loop, so
`helm template` fails fast unless exactly one of these is set:

1. `scheduler.config.metricsAuthExistingSecret` (recommended): a Secret in
   the release namespace carrying the token under
   `scheduler.config.metricsAuthExistingSecretKey` (default `token`), e.g.
   `kubectl -n z4j create secret generic z4j-scheduler-metrics-token --from-literal=token=$(openssl rand -base64 32)`.
2. `scheduler.config.metricsAuthToken`: inline, dev and homelab only.
3. `scheduler.config.metricsEnabled: false`: `/metrics` is not mounted.

`scheduler.serviceMonitor.enabled` renders a Prometheus Operator
`ServiceMonitor`; point its `bearerTokenSecret` at the same Secret and key.

## Rotating externally managed Secrets

The scheduler loads its client certificate, private key and CA once when
it constructs the gRPC channel. Kubernetes eventually updates files in a
projected Secret volume, but that does not replace the credentials already
in the running process. The chart does not claim automatic rollout for
`scheduler.tls.existingSecret` changes, cert-manager renewals or re-minted
PKI Secrets.

Secret-backed environment variables are also captured when a pod starts.
Rotating `scheduler.leader.existingSecret` or `scheduler.config.metricsAuthExistingSecret` in place
does not update the running process either, and the same holds for
`brain.secrets.existingSecret` and `brain.database.existingSecret`.

After the new Secret data is ready, roll the pods before the old
credentials must stop working; for TLS, complete the rollout before the
old certificate expires. Either restart a Deployment directly:

```sh
kubectl --namespace z4j rollout restart deployment/z4j-scheduler
kubectl --namespace z4j rollout status deployment/z4j-scheduler
```

or keep the restart in Helm's desired state by changing the opaque
revision, which rolls every Deployment in the release:

```sh
helm upgrade z4j oci://ghcr.io/z4jdev/charts/z4j \
  --namespace z4j --reuse-values \
  --set-string rolloutRevision="$(date -u +%Y%m%dT%H%M%SZ)"
```

Use the actual Deployment names if `fullnameOverride` or a different
release name changes them. For cert-manager, run this only after the
`Certificate` is `Ready` and its target Secret contains the renewed bundle.
Changing `rolloutRevision` without first rotating the Secret restarts onto
the old credentials.

## Rolling upgrades

The brain uses `Recreate` (see above). The scheduler uses the default
RollingUpdate strategy; PostgreSQL leader coordination prevents
simultaneous leaders for the same lock, but the chart does not promise
zero-delay firing during a rollout. Both Deployments checksum their
ConfigMaps and chart-rendered inline Secrets, so a values change rolls the
pods. External Secret contents are outside the rendered release: rotate
them first, then restart or bump `rolloutRevision` as above.

Upgrade the release with the same `--version` discipline as install:

```sh
helm upgrade z4j oci://ghcr.io/z4jdev/charts/z4j --namespace z4j --reuse-values
```

## Verifying the chart

Every published chart digest is signed keylessly with cosign by the
publishing workflow and carries a build-provenance attestation:

```sh
helm pull oci://ghcr.io/z4jdev/charts/z4j --destination .
cosign verify ghcr.io/z4jdev/charts/z4j@sha256:<digest from helm pull> \
  --certificate-identity-regexp '^https://github.com/z4jdev/z4j/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Verifying a release

```sh
kubectl --namespace z4j get pods -l app.kubernetes.io/instance=z4j
kubectl --namespace z4j port-forward svc/z4j 7700:7700
curl http://localhost:7700/api/v1/health/ready
```

With the scheduler enabled, `/info` on its Service (port 7800) returns the
scheduler version, instance ID, readiness subsystem state, loaded schedule
count and uptime; per-project leadership is exported through the
authenticated `z4j_scheduler_is_leader` metric.

## Known limitations

- The chart renders no `NetworkPolicy`. If your cluster runs one by
  default, allow ingress to the brain on 7700 (and 7701 from the
  scheduler), egress from the scheduler to the brain and to PostgreSQL,
  and egress from the PKI Job to the Kubernetes API.
- No HorizontalPodAutoscaler. The brain is bound by sticky WebSocket
  routing and the scheduler by per-project locks, not by replica count.
- The bundled PostgreSQL is an evaluation database with no replication or
  backup; `z4j backup` and your own PVC snapshots are the whole story.
- The PKI Job renews only when a hook runs, that is on `helm upgrade`. A
  release that is never upgraded within `leafValidityDays` expires; use
  cert-manager for managed renewal if upgrades are rarer than that.
