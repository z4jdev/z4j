{{/*
Shared names and labels.
*/}}
{{- define "z4j.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name, truncated at 63 chars because
some Kubernetes name fields are limited to this (by the DNS naming spec).
If the release name contains the chart name it is used as the full name.
*/}}
{{- define "z4j.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "z4j.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "z4j.commonLabels" -}}
helm.sh/chart: {{ include "z4j.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: z4j
{{- end }}

{{- define "z4j.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{- define "z4j.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "z4j.imageTag" .) }}
{{- end }}

{{- define "z4j.imagePullSecrets" -}}
{{- with .Values.image.pullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Brain.
*/}}
{{- define "z4j.brain.selectorLabels" -}}
app.kubernetes.io/name: {{ include "z4j.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: brain
{{- end }}

{{- define "z4j.brain.labels" -}}
{{ include "z4j.commonLabels" . }}
{{ include "z4j.brain.selectorLabels" . }}
{{- end }}

{{- define "z4j.brain.serviceAccountName" -}}
{{- if .Values.brain.serviceAccount.create }}
{{- default (include "z4j.fullname" .) .Values.brain.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.brain.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Cluster DNS name of the brain Service. */}}
{{- define "z4j.brain.serviceHost" -}}
{{ include "z4j.fullname" . }}.{{ .Release.Namespace }}.svc.cluster.local
{{- end }}

{{- define "z4j.brain.secretName" -}}
{{- if .Values.brain.secrets.existingSecret -}}
{{ .Values.brain.secrets.existingSecret }}
{{- else -}}
{{ include "z4j.fullname" . }}-secrets
{{- end -}}
{{- end }}

{{/* Server-side mTLS Secret for the brain's scheduler gRPC listener. */}}
{{- define "z4j.brain.schedulerGrpcTlsSecretName" -}}
{{- if .Values.brain.schedulerGrpc.tls.existingSecret -}}
{{ .Values.brain.schedulerGrpc.tls.existingSecret }}
{{- else -}}
{{ include "z4j.fullname" . }}-scheduler-grpc-tls
{{- end -}}
{{- end }}

{{/* "true" when no PostgreSQL source is configured: bundled SQLite under /data. */}}
{{- define "z4j.brain.usesSqlite" -}}
{{- if and (not .Values.postgresql.enabled) (not .Values.brain.database.url) (not .Values.brain.database.existingSecret) -}}true{{- end -}}
{{- end }}

{{- define "z4j.brain.inlineSecretsAny" -}}
{{- if or .Values.brain.secrets.inline.appSecret .Values.brain.secrets.inline.sessionSecret .Values.brain.secrets.inline.auditChainSecret -}}true{{- end -}}
{{- end }}

{{- define "z4j.brain.inlineSecretsAll" -}}
{{- if and .Values.brain.secrets.inline.appSecret .Values.brain.secrets.inline.sessionSecret .Values.brain.secrets.inline.auditChainSecret -}}true{{- end -}}
{{- end }}

{{- define "z4j.brain.hasSecrets" -}}
{{- if or .Values.brain.secrets.existingSecret (include "z4j.brain.inlineSecretsAll" .) -}}true{{- end -}}
{{- end }}

{{/*
Bundled PostgreSQL.
*/}}
{{- define "z4j.postgresql.fullname" -}}
{{ include "z4j.fullname" . }}-postgresql
{{- end }}

{{- define "z4j.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "z4j.name" . }}-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgresql
{{- end }}

{{- define "z4j.postgresql.labels" -}}
{{ include "z4j.commonLabels" . }}
{{ include "z4j.postgresql.selectorLabels" . }}
{{- end }}

{{- define "z4j.postgresql.secretName" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{ .Values.postgresql.auth.existingSecret }}
{{- else -}}
{{ include "z4j.postgresql.fullname" . }}
{{- end -}}
{{- end }}

{{- define "z4j.postgresql.passwordKey" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{ .Values.postgresql.auth.existingSecretKey }}
{{- else -}}
postgres-password
{{- end -}}
{{- end }}

{{- define "z4j.postgresql.host" -}}
{{ include "z4j.postgresql.fullname" . }}.{{ .Release.Namespace }}.svc.cluster.local
{{- end }}

{{- define "z4j.postgresql.image" -}}
{{- if .Values.postgresql.image.digest -}}
{{ .Values.postgresql.image.repository }}:{{ .Values.postgresql.image.tag }}@{{ .Values.postgresql.image.digest }}
{{- else -}}
{{ .Values.postgresql.image.repository }}:{{ .Values.postgresql.image.tag }}
{{- end -}}
{{- end }}

{{/*
PKI minting Job.
*/}}
{{- define "z4j.pki.labels" -}}
{{ include "z4j.commonLabels" . }}
app.kubernetes.io/name: {{ include "z4j.name" . }}-pki-mint
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: pki-mint
{{- end }}

{{/* Labels the Job stamps onto the Secrets it creates (not Helm-managed). */}}
{{- define "z4j.pki.secretLabelsJson" -}}
{{- dict "app.kubernetes.io/name" (include "z4j.name" .) "app.kubernetes.io/instance" .Release.Name "app.kubernetes.io/part-of" "z4j" "app.kubernetes.io/managed-by" "z4j-pki-mint" | toJson -}}
{{- end }}

{{/* Comma-separated DNS SANs for the brain's gRPC server leaf. */}}
{{- define "z4j.pki.serverDnsNames" -}}
{{- $name := include "z4j.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $names := list $name (printf "%s.%s" $name $ns) (printf "%s.%s.svc" $name $ns) (printf "%s.%s.svc.cluster.local" $name $ns) -}}
{{- $names = concat $names .Values.pki.mintJob.extraServerDnsNames -}}
{{- join "," $names -}}
{{- end }}

{{/*
Scheduler.
*/}}
{{- define "z4j-scheduler.name" -}}
{{- printf "%s-scheduler" (include "z4j.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "z4j-scheduler.fullname" -}}
{{- printf "%s-scheduler" (include "z4j.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "z4j-scheduler.selectorLabels" -}}
app.kubernetes.io/name: {{ include "z4j-scheduler.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: scheduler
{{- end }}

{{- define "z4j-scheduler.labels" -}}
{{ include "z4j.commonLabels" . }}
{{ include "z4j-scheduler.selectorLabels" . }}
{{- end }}

{{- define "z4j-scheduler.serviceAccountName" -}}
{{- if .Values.scheduler.serviceAccount.create }}
{{- default (include "z4j-scheduler.fullname" .) .Values.scheduler.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.scheduler.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Brain endpoints: explicit values win, otherwise this release's brain Service. */}}
{{- define "z4j-scheduler.grpcUrl" -}}
{{- if .Values.scheduler.brain.grpcUrl -}}
{{ .Values.scheduler.brain.grpcUrl }}
{{- else if .Values.brain.enabled -}}
{{ include "z4j.brain.serviceHost" . }}:{{ .Values.brain.service.grpcPort }}
{{- end -}}
{{- end }}

{{- define "z4j-scheduler.restUrl" -}}
{{- if .Values.scheduler.brain.restUrl -}}
{{ .Values.scheduler.brain.restUrl }}
{{- else if .Values.brain.enabled -}}
http://{{ include "z4j.brain.serviceHost" . }}:{{ .Values.brain.service.httpPort }}
{{- end -}}
{{- end }}

{{/*
Resolve the scheduler TLS Secret name. The deployment volume, the
cert-manager Certificate and the PKI minting Job all write to or read from
the same name so callers can swap modes without renaming.
*/}}
{{- define "z4j-scheduler.tlsSecretName" -}}
{{- if .Values.scheduler.tls.existingSecret -}}
{{ .Values.scheduler.tls.existingSecret }}
{{- else if or .Values.scheduler.tls.certManager.enabled .Values.pki.mintJob.enabled -}}
{{ include "z4j-scheduler.fullname" . }}-tls
{{- else -}}
{{ include "z4j-scheduler.fullname" . }}-tls-inline
{{- end -}}
{{- end -}}

{{/* "true" when the chart composes the leader DSN from the bundled PostgreSQL. */}}
{{- define "z4j-scheduler.leaderDsnFromBundledPostgres" -}}
{{- if and .Values.postgresql.enabled .Values.postgresql.auth.password (not .Values.scheduler.leader.databaseUrl) (not .Values.scheduler.leader.existingSecret) -}}true{{- end -}}
{{- end }}

{{- define "z4j-scheduler.leaderDsnSecretName" -}}
{{ include "z4j-scheduler.fullname" . }}-leader-dsn
{{- end }}

{{/*
Pre-flight validation. Helm fails fast at template time when the operator
forgot to supply a required value, with a message that points at the exact
key to set.
*/}}
{{- define "z4j-scheduler.validateBrainUrls" -}}
{{- if not (include "z4j-scheduler.grpcUrl" .) -}}
{{- fail "scheduler.brain.grpcUrl is required when brain.enabled is false - set it to the brain SchedulerService endpoint, e.g. z4j-brain.z4j.svc.cluster.local:7701" -}}
{{- end -}}
{{- if not (include "z4j-scheduler.restUrl" .) -}}
{{- fail "scheduler.brain.restUrl is required when brain.enabled is false - set it to the brain REST endpoint, e.g. http://z4j-brain.z4j.svc.cluster.local:7700" -}}
{{- end -}}
{{- end -}}

{{/*
Metrics-token pre-flight. The scheduler refuses to start in production (its
default environment) when it binds a non-loopback address with metrics
enabled and no /metrics bearer token, and this chart always binds 0.0.0.0.
A release rendered with metricsEnabled=true and no token source therefore
crash-loops on boot. Fail at template time instead, with the fix options
spelled out. Setting BOTH token sources is also refused: the deployment
would silently prefer the inline one, and a config where the "real" Secret
is ignored is a footgun.
*/}}
{{- define "z4j-scheduler.validateMetricsToken" -}}
{{- if .Values.scheduler.config.metricsEnabled -}}
{{- if and .Values.scheduler.config.metricsAuthToken .Values.scheduler.config.metricsAuthExistingSecret -}}
{{- fail "scheduler.config.metricsAuthToken and scheduler.config.metricsAuthExistingSecret are both set - pick ONE token source (the existingSecret is recommended; the inline token is dev-only)" -}}
{{- end -}}
{{- if and (not .Values.scheduler.config.metricsAuthToken) (not .Values.scheduler.config.metricsAuthExistingSecret) -}}
{{- fail "scheduler.config.metricsEnabled is true but no /metrics bearer token is configured. The scheduler refuses to start on a non-loopback bind with metrics enabled and no token, so the rendered Deployment would crash-loop. Fix one of: (1) set scheduler.config.metricsAuthExistingSecret to the name of a Secret holding the token (key: scheduler.config.metricsAuthExistingSecretKey, default 'token') - recommended; (2) set scheduler.config.metricsAuthToken to an inline token (dev/homelab only - it lands in the release object in plaintext); (3) set scheduler.config.metricsEnabled to false to not mount /metrics at all" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The brain image is the only published image carrying the scheduler. */}}
{{- define "z4j-scheduler.validateImage" -}}
{{- if not .Values.image.repository -}}
{{- fail "image.repository is required (the published z4jdev/z4j brain image contains the z4j-scheduler entry point)" -}}
{{- end -}}
{{- if and (not .Values.image.tag) (not .Chart.AppVersion) -}}
{{- fail "image.tag is empty and Chart.appVersion is empty; set one explicit scheduler-capable image tag" -}}
{{- end -}}
{{- end -}}

{{/* Exactly one complete source of client mTLS material is required. */}}
{{- define "z4j-scheduler.validateTls" -}}
{{- $tls := .Values.scheduler.tls -}}
{{- $mint := .Values.pki.mintJob.enabled -}}
{{- $inlineAny := or $tls.inline.cert $tls.inline.key $tls.inline.ca -}}
{{- $inlineAll := and $tls.inline.cert $tls.inline.key $tls.inline.ca -}}
{{- if and $tls.existingSecret (or $tls.certManager.enabled $mint $inlineAny) -}}
{{- fail "configure exactly one TLS source: scheduler.tls.existingSecret, scheduler.tls.certManager.enabled, pki.mintJob.enabled, or the complete scheduler.tls.inline cert/key/ca bundle" -}}
{{- end -}}
{{- if and $tls.certManager.enabled (or $mint $inlineAny) -}}
{{- fail "configure exactly one TLS source: cert-manager cannot be combined with pki.mintJob or scheduler.tls.inline" -}}
{{- end -}}
{{- if and $mint $inlineAny -}}
{{- fail "configure exactly one TLS source: pki.mintJob and scheduler.tls.inline cannot both be enabled" -}}
{{- end -}}
{{- if and $inlineAny (not $inlineAll) -}}
{{- fail "scheduler.tls.inline is partial; cert, key, and ca must all be supplied together" -}}
{{- end -}}
{{- if and (not $tls.existingSecret) (not $tls.certManager.enabled) (not $mint) (not $inlineAll) -}}
{{- fail "scheduler mTLS is required; set scheduler.tls.existingSecret, enable scheduler.tls.certManager or pki.mintJob, or supply the complete dev-only scheduler.tls.inline bundle" -}}
{{- end -}}
{{- if and $mint (not .Values.brain.enabled) -}}
{{- fail "pki.mintJob mints material for this release's brain; with brain.enabled=false use scheduler.tls.existingSecret or cert-manager" -}}
{{- end -}}
{{- if $tls.certManager.enabled -}}
{{- if not $tls.certManager.issuerName -}}
{{- fail "scheduler.tls.certManager.issuerName is required when cert-manager mode is enabled" -}}
{{- end -}}
{{- if not $tls.certManager.commonName -}}
{{- fail "scheduler.tls.certManager.commonName is required and must be allowed by the brain" -}}
{{- end -}}
{{- if and .Values.brain.enabled (not (has $tls.certManager.commonName .Values.brain.schedulerGrpc.allowedCNs)) -}}
{{- fail (printf "scheduler.tls.certManager.commonName %q is not listed in brain.schedulerGrpc.allowedCNs" $tls.certManager.commonName) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Prevent duplicate dispatch and missing-DSN crash loops. */}}
{{- define "z4j-scheduler.validateLeader" -}}
{{- $leader := .Values.scheduler.leader -}}
{{- $backend := $leader.backend -}}
{{- if eq $backend "single" -}}
{{- if ne (.Values.scheduler.replicaCount | int) 1 -}}
{{- fail "scheduler.leader.backend=single is always-leader, not election; replicaCount must be exactly 1 or every replica can dispatch the same fire" -}}
{{- end -}}
{{- else if or (eq $backend "postgres") (eq $backend "postgres_per_project") -}}
{{- if and .Values.brain.enabled (include "z4j.brain.usesSqlite" .) -}}
{{- fail "the brain runs on SQLite, which has no advisory locks for the scheduler to coordinate on; use scheduler.leader.backend=single with scheduler.replicaCount=1 or configure PostgreSQL" -}}
{{- end -}}
{{- if and $leader.databaseUrl $leader.existingSecret -}}
{{- fail "scheduler.leader.databaseUrl and scheduler.leader.existingSecret are both set; choose exactly one PostgreSQL DSN source" -}}
{{- end -}}
{{- if and (not $leader.databaseUrl) (not $leader.existingSecret) (not (include "z4j-scheduler.leaderDsnFromBundledPostgres" .)) -}}
{{- fail "the selected PostgreSQL leader backend requires scheduler.leader.databaseUrl or scheduler.leader.existingSecret, even with one replica (the chart composes the DSN itself only from the bundled postgresql with an inline postgresql.auth.password)" -}}
{{- end -}}
{{- else -}}
{{- fail "scheduler.leader.backend must be one of: single, postgres, postgres_per_project" -}}
{{- end -}}
{{- end -}}

{{/* A ServiceMonitor must scrape an endpoint that exists and authenticate. */}}
{{- define "z4j-scheduler.validateServiceMonitor" -}}
{{- if .Values.scheduler.serviceMonitor.enabled -}}
{{- if not .Values.scheduler.config.metricsEnabled -}}
{{- fail "scheduler.serviceMonitor.enabled=true requires scheduler.config.metricsEnabled=true" -}}
{{- end -}}
{{- if not .Values.scheduler.serviceMonitor.bearerTokenSecret.name -}}
{{- fail "scheduler.serviceMonitor.enabled=true requires scheduler.serviceMonitor.bearerTokenSecret.name so Prometheus can authenticate to /metrics" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Brain pre-flight: posture, secrets, database, topology. */}}
{{- define "z4j.validateBrain" -}}
{{- if and .Values.brain.embeddedScheduler .Values.scheduler.enabled -}}
{{- fail "brain.embeddedScheduler and scheduler.enabled are mutually exclusive: the embedded subprocess and the standalone Deployment would both fire every schedule" -}}
{{- end -}}
{{- if not .Values.brain.publicUrl -}}
{{- fail "brain.publicUrl is required (the externally reachable origin of the dashboard)" -}}
{{- end -}}
{{- if not .Values.brain.allowedHosts -}}
{{- fail "brain.allowedHosts is required (the hostnames the brain accepts in the Host header)" -}}
{{- end -}}
{{- if and .Values.brain.secrets.existingSecret (include "z4j.brain.inlineSecretsAny" .) -}}
{{- fail "brain.secrets.existingSecret and brain.secrets.inline are both set; pick one source" -}}
{{- end -}}
{{- if and (include "z4j.brain.inlineSecretsAny" .) (not (include "z4j.brain.inlineSecretsAll" .)) -}}
{{- fail "brain.secrets.inline is partial; appSecret, sessionSecret and auditChainSecret must all be supplied together" -}}
{{- end -}}
{{- if and .Values.brain.database.url .Values.brain.database.existingSecret -}}
{{- fail "brain.database.url and brain.database.existingSecret are both set; choose exactly one" -}}
{{- end -}}
{{- if and .Values.postgresql.enabled (or .Values.brain.database.url .Values.brain.database.existingSecret) -}}
{{- fail "postgresql.enabled renders the bundled database; clear brain.database.url and brain.database.existingSecret or disable it" -}}
{{- end -}}
{{- if (include "z4j.brain.usesSqlite" .) -}}
{{- if and (not .Values.brain.persistence.enabled) (not .Values.brain.persistence.existingClaim) -}}
{{- fail "SQLite mode keeps the database under /data; enable brain.persistence (or set existingClaim) or configure PostgreSQL" -}}
{{- end -}}
{{- if gt (.Values.brain.replicaCount | int) 1 -}}
{{- fail "SQLite is single-writer; brain.replicaCount above 1 requires PostgreSQL" -}}
{{- end -}}
{{- else -}}
{{- if not (include "z4j.brain.hasSecrets" .) -}}
{{- fail "PostgreSQL mode requires explicit application secrets: set brain.secrets.existingSecret (keys app-secret, session-secret, audit-chain-secret) or the complete dev-only brain.secrets.inline" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.brain.serviceMonitor.enabled (not .Values.brain.serviceMonitor.bearerTokenSecret.name) -}}
{{- fail "brain.serviceMonitor.enabled=true requires brain.serviceMonitor.bearerTokenSecret.name so Prometheus can authenticate to /metrics" -}}
{{- end -}}
{{- if and .Values.brain.serviceMonitor.enabled (not .Values.brain.metrics.authExistingSecret) -}}
{{- fail "brain.serviceMonitor.enabled=true requires brain.metrics.authExistingSecret so the brain and Prometheus agree on the /metrics token" -}}
{{- end -}}
{{- if and .Values.scheduler.enabled (not .Values.brain.schedulerGrpc.tls.existingSecret) (not .Values.pki.mintJob.enabled) -}}
{{- fail "scheduler.enabled needs server mTLS material for the brain's gRPC listener: set brain.schedulerGrpc.tls.existingSecret (keys tls.crt, tls.key, ca.crt) or enable pki.mintJob" -}}
{{- end -}}
{{- if and .Values.scheduler.enabled (not .Values.brain.schedulerGrpc.allowedCNs) -}}
{{- fail "brain.schedulerGrpc.allowedCNs must list every scheduler client CN" -}}
{{- end -}}
{{- end -}}

{{- define "z4j.validatePostgresql" -}}
{{- if .Values.postgresql.enabled -}}
{{- if and (not .Values.postgresql.auth.password) (not .Values.postgresql.auth.existingSecret) -}}
{{- fail "postgresql.enabled requires postgresql.auth.password or postgresql.auth.existingSecret" -}}
{{- end -}}
{{- if and .Values.postgresql.auth.password .Values.postgresql.auth.existingSecret -}}
{{- fail "postgresql.auth.password and postgresql.auth.existingSecret are both set; choose one" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "z4j.validatePki" -}}
{{- if .Values.pki.mintJob.enabled -}}
{{- if not .Values.scheduler.enabled -}}
{{- fail "pki.mintJob.enabled has no consumer without scheduler.enabled" -}}
{{- end -}}
{{- if .Values.brain.schedulerGrpc.tls.existingSecret -}}
{{- fail "pki.mintJob mints the brain's gRPC server Secret; clear brain.schedulerGrpc.tls.existingSecret or disable the Job" -}}
{{- end -}}
{{- if not (has .Values.pki.mintJob.schedulerCommonName .Values.brain.schedulerGrpc.allowedCNs) -}}
{{- fail (printf "pki.mintJob.schedulerCommonName %q is not listed in brain.schedulerGrpc.allowedCNs" .Values.pki.mintJob.schedulerCommonName) -}}
{{- end -}}
{{- end -}}
{{- end -}}
