# Production container authority

This directory is a frozen record of the sealed production-image apparatus
as it stood when it was cut, and it is deliberately unfinalized
(`locks/UNFINALIZED`). It is not the contract of the image currently
published; that image is built by the ordinary `Dockerfile` at the package
root from the released sdist. The version named below is the cut this record
describes, not the current release.

This directory is the fail-closed source contract for the complete z4j 1.9.0
production image. It covers the Python environment, Debian runtime packages,
the compiled dashboard, the carrier images and build tooling, and the evidence
needed to qualify and promote one exact multi-architecture OCI index.

The tracked `manifest.json` is deliberately `unfinalized` until
`2026-08-23T04:14:39.107Z`. All artifact-derived pre-tag fields are null and
`locks/UNFINALIZED` is present. A production build, release workflow, or
promotion must fail in that state. Landing this source interface does not
authorize resolving dependencies, creating registry objects, changing Docker
Hub settings, signing a receipt, or publishing a tag.

The tracked manifest carries the stable policy requiring
`z4j.source-tag-authority.v1` plus exact, poison-sealed system-v2 and
dashboard-v1 authority-policy carriers and null authority selections. The
manifest is ordinary reviewed JSON: insignificant whitespace is allowed, but
duplicate keys are rejected. Signed receipts, bundles, and policy carriers
retain their separately declared canonical JSON framing.

The system/dashboard source policies deliberately do not select a GitHub
authority repository, workflow identity, workflow database identity, required
reviewer IDs, or signing workflow identity. They retain only stable protocol
and path data, including GitHub API version `2026-03-10`, the dispatch event,
workflow path/ref, and protected-environment shape. Every unselected field is
readiness poison. Choosing the governed GitHub authority (the **G choice**)
requires reviewed changes to the literal policy bytes and therefore to their
H/N seals in `manifest.json` before the production source freeze; filling only
the manifest selection cannot make either producer ready. The current v1/v2
identifiers describe these provisional source-policy schemas, not an accepted
GitHub deployment.

The realized source-tag receipt, Sigstore bundle, evidence index, workflow
identity, and live tag bindings are necessarily created after the immutable
tag exists and live only in the detached production-finalization authority;
they are never embedded in the Git tree they identify.

## What is sealed

The finalized contract has three independent, digest-pinned data images plus
two audited upstream carriers:

1. CPython 3.14.7 and uv 0.12.5. The manifest binds the official Python index,
   selected amd64/arm64 manifests and configs, CPython source tar, and
   docker-library revision. A z4j-owned wheelhouse carries uv, separate native
   runtime/build locks, all selected wheels, registry provenance, resolver
   transcripts, cadence probes, SBOMs, advisory evidence, and twice-built
   local-wheel expectations.
2. Debian system packages. A z4j-owned bundle carries the exact transitive
   `.deb` closure for `ca-certificates`, `libpq5`, and `tini`, selected from
   post-cutoff `trixie`, `trixie-security`, and `trixie-updates` snapshots.
   Signed Release/InRelease data, audited Debian keys, exact native Packages
   indexes, package metadata and hashes, resolver inputs/transcripts, and a
   strict advisory receipt are sealed. The system authority uses the explicit
   v2 schema chain because each native platform additionally seals a canonical
   real-base installability receipt. That receipt proves every locked package
   installs in the pinned disposable resolver base with network disabled;
   script-free synthetic dpkg metadata remains a separate Trivy scan input.
   A v1/v2 policy, receipt, media type, artifact type, or material mixture is
   rejected.
3. Dashboard assets. A z4j-owned bundle carries a build from the exact tracked
   pnpm lock and source projection. It binds the official Node 24.19.0 carrier,
   pnpm 11.22.0 release evidence, the complete pnpm store, build transcript,
   CycloneDX dependency closure, advisory receipt, and final `dist/` tree.
   The external `dist/` tree must equal the dashboard embedded in the z4j
   source package and is copied explicitly into the runtime image.

The production Dockerfiles also pin Dockerfile frontend 1.20.0, Buildx 0.36.1,
BuildKit 0.32.2, all GitHub Actions by commit, and a source-derived
`SOURCE_DATE_EPOCH`. BuildKit exports with `rewrite-timestamp=true`. All source,
wheel/backend, and Debian maintainer-script execution in production stages uses
`RUN --network=none`; uv's offline flags are an additional enforcement layer,
not the only one.

The `dev-runtime` target in `backend/Dockerfile` remains a development image
and may use live apt. It is expressly outside this production authority and
must never be published as the 1.9.0 runtime.

## Exact bundle layouts

Every payload is a scratch/data-only image with an exact two-descriptor OCI
index: one `linux/amd64` descriptor and one `linux/arm64` descriptor. Unknown
attestation descriptors, extra architectures, symlinks, special files,
unlisted files, and tag-only image references are rejected. Upstream Python and
Node indexes may contain additional descriptors only because their complete raw
index bytes are independently sealed.

The Python wheelhouse root is `/opt/z4j-production`:

```text
bin/cosign
bin/uv
inventory.json
locks/build.txt
locks/runtime.txt
wheels/*.whl
evidence/advisory-receipt.json
evidence/advisory-report.json
evidence/build-requirements.in
evidence/cosign-release.json
evidence/provenance.json
evidence/resolver-transcript.json
evidence/resolver-build.stdout
evidence/resolver-build.stderr
evidence/resolver-runtime.stdout
evidence/resolver-runtime.stderr
evidence/runtime-requirements.in
evidence/sbom.cyclonedx.json
evidence/trivy
evidence/trivy-version.txt
evidence/trivy-database/**
evidence/uv-archive.tar.gz
evidence/uv-release.json
evidence/index/<normalized-project>.json
```

Each lock line is one exact `name==version --hash=sha256:<digest>` pin. The
union of runtime and build-lock package names and hashes must equal the wheel
inventory. URLs, markers, secondary hashes, sdists, editable requirements, and
index fallback are forbidden. Wheel ZIP paths, file types, RECORD rows,
METADATA identity, WHEEL tags, Python ABI and native platform are read back.
The platform-native `bin/cosign` is exact Cosign 3.1.3. Its executable bytes,
mode, version-output bytes, and the retained GitHub release/asset response are
sealed in the manifest and inventory. The verified binary is copied into the
candidate as `/usr/local/bin/cosign`; neither qualification nor rollback
authority verification may install a tool live or select one from `PATH`.
The tracked canonical Sigstore runtime root is sealed under authenticated TUF
root v15 and snapshot v165. Both native Trivy 0.74.0 release archives, their
complete semantic member projections, extracted binaries, and version
transcripts are also source-sealed. This tool-only selection does not select a
Trivy database: its archive, timestamps, metadata and tree remain poison until
the post-cutoff database authority is reviewed. The source-context Git tool
entries likewise remain explicit all-null poison and select no host path.

The system root is `/opt/z4j-production-system`:

```text
inventory.json
locks/packages.json
debs/*.deb
evidence/apt.conf
evidence/sources.list
evidence/resolution-receipt.json
evidence/installability-receipt.json
evidence/advisory-receipt.json
evidence/advisory-report.json
evidence/trivy
evidence/trivy-version.txt
evidence/trivy-database/**
snapshot/debian/{InRelease,Release,archive-keyring.gpg,indexes/main/binary-ARCH/Packages}
snapshot/debian-security/{InRelease,Release,archive-keyring.gpg,indexes/main/binary-ARCH/Packages}
snapshot/debian-updates/{InRelease,Release,archive-keyring.gpg,indexes/main/binary-ARCH/Packages}
```

The verifier checks clear-sign framing, gpgv output against the audited trixie
automatic/stable/security fingerprints, Suite/Codename/Components/Architecture,
Release Date/Valid-Until, exact Packages paths and Release hashes, package
membership, `.deb` control metadata, and canonical apt inputs. A disposable
network-none real-base qualification stage verifies the complete locked `.deb`
closure installs and passes apt's dependency audit; its deterministic canonical
receipt is part of A/B material equality while bounded command streams remain
separate run evidence. The script-free synthetic dpkg status used for Trivy is
derived independently from authenticated control stanzas and executes no
maintainer script.

The system advisory receipt binds `package_lock_sha256`, not the complete
bundle-tree digest. The lock is the stable, pre-scan package subject and Trivy's
retained Debian package inventory must equal it. Binding the complete tree here
would be a cryptographic fixed point because that tree contains the advisory
receipt itself.

The dashboard root is `/opt/z4j-production-dashboard`:

```text
inventory.json
bin/pnpm.cjs
dist/**
store/**
evidence/pnpm-lock.yaml
evidence/pnpm-archive.tgz
evidence/pnpm-registry.json
evidence/pnpm-release.json
evidence/store-inventory.json
evidence/build-receipt.json
evidence/sbom.cyclonedx.json
evidence/advisory-receipt.json
evidence/advisory-report.json
evidence/trivy
evidence/trivy-version.txt
evidence/trivy-database/**
```

The retained `store/` is the exact pnpm v10 content-addressable store. Its
complete file tree is independently hashed, while the store and SBOM component
sets must equal the complete `packages:` section of pnpm lockfile version 9.0,
including each SHA-512 integrity value. The build receipt binds the exact Node
manifest/config, pnpm binary, dashboard source projection, lock/store seals,
environment, offline install/build commands, transcripts, and `dist/` tree.
Qualification copies the store, runs both commands natively with
`--network none`, and requires the replayed `dist/` tree to equal the sealed
bundle. Raw stdout/stderr are retained for review but are not compared across
runs because pnpm and Vite include nondeterministic progress/timing text.
The three top-level release-provenance markers are copied from the sealed
bundle after Vite runs. The verifier independently requires the production
context marker, validates both digest-marker framings, and recomputes
`.build-output.sha256` over the rebuilt output using the canonical release
algorithm before comparing the complete marked tree.

Each native system/dashboard job emits exactly one
`production-MATERIAL-ARCH-native-result.tar` plus canonical
`platform-result.json`. The tar is canonical USTAR: regular files only, exact
0644/0755 modes, uid/gid/mtime zero, UTF-8 byte-sorted traversal-free paths,
and no PAX, GNU-longname, link, device, FIFO, alias, or duplicate member. Its
sidecar seals the literal tar and complete member inventory. Aggregation first
validates both amd64 and arm64 sidecar/carrier pairs without extracting, then
extracts each into an owner-private directory through no-follow dir-fd writes.
It recomputes A/B equality over `payload/` only and separately seals each
build's truthful `run-evidence/`; timing-bearing Trivy and command transcripts
are never smuggled into the deterministic comparison.

## Verification commands

`verify.py` uses only the Python standard library and runs before any bundled
dependency is imported. Representative native checks are:

```bash
python docker/production/system_authority.py manifest \
  --manifest docker/production/manifest.json \
  --policy docker/production/system-authority-policy.json

python docker/production/dashboard_authority.py manifest \
  --manifest docker/production/manifest.json \
  --policy docker/production/dashboard-authority-policy.json

python docker/production/verify.py source \
  --manifest docker/production/manifest.json \
  --repo-root . \
  --require-finalized \
  --release-commit "$RELEASE_SHA" \
  --release-tree "$RELEASE_TREE"

python docker/production/verify.py oci \
  --manifest docker/production/manifest.json \
  --material wheelhouse \
  --platform linux/amd64 \
  --index-json /tmp/wheelhouse.index.json \
  --manifest-json /tmp/wheelhouse.amd64.manifest.json

python docker/production/verify.py wheelhouse \
  --manifest docker/production/manifest.json \
  --platform linux/amd64 \
  --root /opt/z4j-production

python docker/production/verify.py system-bundle \
  --manifest docker/production/manifest.json \
  --platform linux/amd64 \
  --root /opt/z4j-production-system \
  --apt-get /usr/bin/apt-get \
  --gpgv /usr/bin/gpgv \
  --dpkg-deb /usr/bin/dpkg-deb

python docker/production/verify.py dashboard-bundle \
  --manifest docker/production/manifest.json \
  --platform linux/amd64 \
  --root /opt/z4j-production-dashboard \
  --repo-root .

python docker/production/verify.py dashboard-output \
  --manifest docker/production/manifest.json \
  --platform linux/amd64 \
  --directory /tmp/offline-dashboard-replay/dist

python docker/production/verify.py signature-verifier-probe \
  --manifest docker/production/manifest.json \
  --platform linux/amd64 \
  --probe /tmp/signature-verifier.amd64.json
```

The same checks run natively on arm64. The release workflow verifies all five
OCI authorities (Python, Node, wheelhouse, system bundle, and dashboard
bundle) before BuildKit. Each Dockerfile repeats source, payload, uv, local
wheel, installed closure, and cadence checks inside the image build.
Qualification also boots each exact runnable leaf with its real
`ENTRYPOINT ["/usr/bin/tini","--","z4j"]` and `CMD ["serve"]`, an isolated
network namespace, and an ephemeral `/data`. It waits for the declared health
check to pass, then retains the canonical smoke receipt, container inspection,
and logs. The native and finalization receipts seal all three files; promotion
revalidates them before any public tag mutation.

Source projections bind a closed executable-mode policy rather than the
checkout process's read-bit mask. The production and dashboard contracts each
carry their own exact `executables` allowlist; both are empty for 1.9.0 because
every projected Git input is mode `100644`. A projected input must be a
single-link regular file, owner-readable, free of setuid/setgid/sticky bits,
and not group- or world-writable. Execute permission is rejected unless the
logical path is allowlisted, and an allowlisted path must retain owner execute
permission. After those checks, records use canonical mode `0644` for ordinary
files and `0755` for allowlisted executables. Thus an owner-private `0600`
checkout and Hatchling's `0644` sdist header describe the same non-executable
artifact without discarding executable semantics.

## Post-cutoff finalization order

Finalization is a reviewed ceremony, not a resolver command hidden in a Docker
layer. The order matters because the three external bundle digests must be
known before freezing Dockerfile defaults, while the commit containing the
final manifest cannot contain its own Git identity.

1. On or after the cutoff, resolve the reviewed native Python, Debian and pnpm
   closures. Capture registry/snapshot responses, tool binaries and version
   transcripts, vulnerability database bytes/metadata, resolver output, SBOMs,
   advisory reports and source projections. Build each external data image
   without a public release tag and verify it independently on both platforms.
2. Review and sign the external qualification evidence. Replace all three
   poison Dockerfile defaults with their exact digest references before the
   production source freeze. This replacement is part of ordinary reviewed
   source, not an allowlisted post-freeze edit.
3. Run the polyrepo split and create standalone staging commit `U`. `U` must
   contain the reviewed code, pinned Docker defaults and unchanged production
   source projection. The `production_source_freeze.commit/tree` authority is
   the standalone `U` identity, not a monorepo object.
4. Create final standalone commit `R` on top of `U`. `R` may differ only in the
   eight paths named by `allowed_post_freeze_paths`: four Python locks, two
   Debian locks, `manifest.json`, and removal of `locks/UNFINALIZED`. Seal all
   OCI index/manifest/config descriptors, inventories, trees, receipts,
   cadence fingerprints, package/SBOM closures, and `SOURCE_DATE_EPOCH`.
5. Run the focused adversarial tests and the complete release gates from `R`.
   Create and push immutable source tag `v1.9.0`; the tag-triggered
   `release-docker` workflow builds native leaves and an exact two-descriptor
   candidate index. It scans both OS and language packages with exact Trivy
   0.74.0, requires a post-cutoff unexpired database, retains the database
   bytes, reconciles Trivy's Debian and Python package inventories to the
   sealed production locks, signs the candidate, and emits a canonical
   qualification receipt.
   It does not create `:1.9.0` or `:latest`.
6. The qualification artifact contains exactly
   `production-finalization.json`, its Cosign sign-blob bundle,
   `production-finalization.attestation.jsonl`, and the raw candidate index.
   The receipt binds the release Git commit/tree, manifest and source
   projection, exact repository/index/leaves/configs/labels, complete native
   authorities, cadence probes, candidate SBOMs, advisory receipts and scanner
   evidence. It also binds the exact per-platform Cosign 3.1.3 carrier
   authority and probes the binary actually installed at
   `/usr/local/bin/cosign`. That binary signs the literal canonical receipt
   bytes; the OCI attestation is a separately verified discoverability copy.
7. A different operator dispatches `promote-release-docker` with the successful
   tag-triggered qualification run ID. GitHub environment
   `production-release` must require a distinct reviewer and prevent
   self-review. The workflow has no build path: it downloads the exact artifact,
   revalidates the source tag and finalized contract, re-verifies the byte
   signature and OCI attestation under the exact qualification identity, and
   refetches the index, leaves and configs from `docker.io/z4jdev/z4j`.
8. Before the first public mutation, promotion authenticates Docker Hub's
   repository settings and requires the reviewed immutable SemVer rule. It
   rechecks that authority immediately before creating the absent version tag;
   server-side immutability closes the Registry API's absent-to-PUT race. The
   separately authorized settings change is not performed by either workflow.
   Any immutable rule that also matches `latest` is rejected. Promotion is
   retryable when the version tag is absent or already resolves to the exact
   qualified digest; it fails if the existing digest differs. Promotion
   records and byte-signs its result. `latest` is updated only for the highest
   stable source release.

Rollback preparation and reverse gates must execute inside the exact finalized
1.9 candidate image, mount the four-file candidate-authority directory
read-only, and invoke `/usr/local/bin/cosign` by absolute path. Caller-provided
tool paths, host-installed Cosign binaries, environment-only image identities,
and live downloads are not authority. The authenticated finalization receipt
must match the current manifest's `signature_verifier` object and the native
probe before any rollback row is prepared.

Qualification and SBOM artifacts are retained for 90 days. Protected
promotion and archival must complete within that window; expiration requires
a new qualification run against unchanged finalized authority, never an
unverifiable manual reconstruction.

This source contract intentionally does not contain the post-cutoff artifact
finalizer that resolves, downloads, scans, builds and seals the three external
bundle images. That separately reviewed generator/rehearsal tranche and its
native artifacts are mandatory before `manifest.json` can become finalized or
either release workflow can succeed.

A manually dispatched qualification run may diagnose or reproduce a candidate,
but protected promotion intentionally accepts only a successful tag-triggered
qualification whose workflow run `head_sha` is the exact release commit.

Missing, extra, substituted, future-dated, expired, wrong-platform, mutable,
unsigned, self-referential or nonregular inputs are hard failures. A failure is
not permission to loosen the manifest or reuse evidence from a different
subject; resolve the discrepancy and perform a new reviewed ceremony.
