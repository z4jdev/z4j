# z4j 1.8.2 / Python 3.14.7 rollback compatibility image

This directory defines a separate, digest-consumed compatibility image for
rolling a 1.9.0 deployment back to the unchanged 1.8.2 application code. It
does **not** change the 1.8.2 release, replace the normal z4j image, or claim
that 1.8.2 was built from the 1.9.0 source revision.

The image has exactly two content authorities:

1. z4jdev/z4j@sha256:ed2dac... supplies the complete released 1.8.2
   site-packages tree, its RECORD-owned entry points and greenlet header, and
   the architecture-native static tini binary.
2. python:3.14.7-slim-trixie@sha256:ce4076... supplies the operating-system
   root, CPython interpreter, standard library, and all other carrier bytes.

The Dockerfile performs no apt, pip, download, or source build. It deletes the
carrier site-packages directory before copying the released directory as a
unit. It never copies the 1.8.2 image's Python 3.14.6 interpreter or standard
library.

manifest.json is the reviewable lock. It binds the annotated 1.8.2 Git tag,
source commit/tree and source hashes; both source-image platform
manifest/config/layer identities; both Python-carrier platform
manifest/config/layer identities; the exact 73-distribution inventory; the
normalized site tree; copied executables/header/tini; and the cadence payload
expected after the Python patch changes to 3.14.7. During Ceremony A, every
candidate descriptor and receipt slot remains null. Ceremony A emits a
manifest-independent qualification receipt that intentionally contains no
manifest hash, source commit, or source tree. Source finalization copies only
that receipt's exact index/platform/config descriptors and raw receipt SHA-256
plus the complete qualification OCI-artifact/config/layer descriptor seal into
the candidate fields and changes `finalized` to true. Finalization is refused
if that durable qualification seal is absent. The manifest is deliberately not
copied into the image: embedding an image's own digest would
be a recursive identity. Review and rollback ceremonies mount or load this
single external authority.

verify.py is copied into the image and fails closed on:

- platform, CPython, interpreter, and stdlib-carrier identity;
- the real-NUL-framed site tree and the app-content tree;
- exact distribution, console-script, header, and tini inventories;
- behavior-vector, tzdata-tree, dependency, and final cadence fingerprints;
- unresolved dynamic-library dependencies and import of every extension;
- pip check, primary package/CLI imports, CLI startup, and a live health
  endpoint boot probe.

## Local review (never publication)

A reviewer may build one native image into a local-only name and run the same
verifier used by the release workflow:

    docker buildx build \
      --platform linux/amd64 \
      --load \
      --tag z4j-rollback-compat:local-review \
      --file packages/z4j/docker/rollback-1.8.2-py3147/Dockerfile \
      packages/z4j/docker/rollback-1.8.2-py3147

    docker run --rm --platform linux/amd64 \
      --volume "$(pwd)/packages/z4j/docker/rollback-1.8.2-py3147/manifest.json:/rollback-lock/manifest.json:ro" \
      --entrypoint python \
      z4j-rollback-compat:local-review \
      /usr/local/share/z4j-rollback-compat/verify.py \
      --manifest /rollback-lock/manifest.json

That local name is not a release identity and must not be pushed.

## Publication boundary

The dedicated release-rollback-compat.yml workflow is manual-only, runs only
from `main`, and has two separately confirmed ceremonies.

Both publication workflows are authorized exclusively in the standalone public
GitHub repository `z4jdev/z4j`. They authenticate the exact repository name,
numeric repository id `1228454287`, GraphQL node id `R_kgDOSTi5jw`, and public
visibility from the GitHub-created dispatch event before doing release work.
Every prior workflow-run API response is independently required to carry that
same exact name, numeric id, and node id.

Ceremony A (`qualification`) requires `candidate_image.finalized=false` and
all candidate seal slots to be null. Native amd64 and arm64 runners build and
push leaf manifests by digest, run the mounted external lock verifier, fail on
any fixed or unfixed Trivy 0.74 HIGH/CRITICAL finding, and produce Syft 1.50
SBOMs. The ceremony then constructs and publishes an OCI index under its digest
only, registry-rereads the same bytes, signs it, attaches SBOM and provenance
attestations, independently verifies all three proofs, and uploads
`rollback-compat-qualification-receipt.json`. Ceremony A never reads or writes
the target tag. The canonical newline receipt does not hash the manifest, so
sealing its SHA-256 in the manifest creates no manifest/receipt cycle.
The receipt is keyless-signed and, with its Sigstore bundle, authentication
metadata, verification transcript, and every member of its signed
`evidence.files` inventory, is published as deterministic individual layers of
a digest-addressed OCI 1.1 qualification referrer whose subject is the exact
candidate index.

Ceremony B (`finalization`) requires `candidate_image.finalized=true`, every
descriptor slot populated, and the original Ceremony-A run id. It authenticates
that successful manual run, downloads its evidence, requires the raw
qualification-receipt SHA-256 and every index/platform/config/runtime/scanner/
SBOM/provenance binding to equal the finalized manifest, and registry-rereads
the original index, native manifests, and configs by sealed digest. Ceremony B
contains no image build.
It also discovers the qualification referrer by subject and artifact type,
requires the single descriptor sealed in the finalized source, and raw-rereads
and reverifies its manifest, config, every layer, and Sigstore bundle.

Promotion additionally depends on a repository setting that the workflow is
not authorized to create or change. A maintainer must separately preconfigure
Docker Hub repository `z4jdev/z4j` with immutable tags enabled and the sole
specific-tag RE2 rule:

`^1\.8\.2-py3\.14\.7-rollback-1\.9\.0$`

Ceremony B obtains a short-lived Docker Hub API bearer without placing the PAT
in an argument or output, performs an authenticated
`GetRepository` read, and requires the repository identity and
`immutable_tags_settings` to equal that exact enabled singleton rule. Missing
credentials, HTTP failure, malformed or unexpected JSON, a disabled setting,
an extra/different rule, or a different repository stops the workflow. It
canonicalizes this projection as
`docker-hub-immutable-tag-authority.json`, keyless-signs and reverifies its
exact bytes, and retains the Sigstore bundle, transcript, and authentication
metadata.

Before any tag mutation Ceremony B creates the canonical detached
`rollback-compat-finalization-receipt.json`, binding the final Git commit/tree,
finalized manifest hash, qualification receipt/run, candidate descriptors,
registry rereads, proof-verification hashes, and signed immutable-tag authority.
Cosign 3.1.3 keyless-signs the exact receipt bytes into a retained Sigstore
bundle and immediately reverifies that bundle against the exact
workflow-on-main identity and GitHub Actions issuer. The authority, receipt,
both bundles and verification transcripts, and canonical authentication
metadata are uploaded before promotion. The receipt truthfully records the
exact-tag result as pending and authorizes only one create under the verified
immutable rule; a pre-existing target tag is never accepted, including when it
already resolves to the desired digest.
Before that convenience upload and before the target-tag PUT, the same complete
signed finalization evidence is published and raw-read back as its own OCI
referrer, chained to the qualification artifact. A rerun may reuse only the
single byte-exact Q or F artifact; a different or duplicate same-type referrer
is fatal.

Only after that evidence is durable may Ceremony B create the one permitted
public tag:

z4jdev/z4j:1.8.2-py3.14.7-rollback-1.9.0

The publisher first reverifies the retained immutable-authority Sigstore bundle
and requires two target-tag lookups to return 404. Immediately before the
manifest PUT it performs a fresh authenticated Docker Hub settings read,
canonicalizes it independently, and requires raw-byte equality with the signed
capture. The registry PUT does not claim unsupported conditional-create
semantics: race protection comes only from Docker Hub's preconfigured immutable
rule, which prevents a competing tag creation from being overwritten. Only a
201 create is accepted; any existing tag, rule drift, authentication or
transport anomaly, unexpected status, or write rejection stops the workflow.
A final registry HEAD must resolve to the sealed digest. Separate canonical
promotion evidence binds both immutable-policy captures, the promotion-side
bundle reverification, the exact digest, and the sole
`created-under-immutable-rule` transition, and is itself keyless-signed and
reverified. The workflow never reads, creates, or overwrites 1.8.2, 1.8, or
latest.

After the tag is created, the signed promotion receipt includes the exact
Ceremony-B run, repository/workflow/ref, source commit/tree, and qualification
run authority. It and all of its referenced proof files become a promotion OCI
referrer chained to finalization. A final signed release-evidence index referrer
then lists the complete Q -> F -> P descriptor/component graph. If a run crashes
after publishing P but before publishing that index, the protected recovery
workflow may authenticate Q/F/P and publish only the missing index; it may not
create competing recovery evidence or alter Q/F/P.

## Durable evidence authority and retrieval

GitHub Actions artifacts retained for 90 days are convenience mirrors only.
They are not the durable release authority. Each stage uses a dedicated
artifact type under the exact immutable candidate-index subject:

- `application/vnd.z4j.rollback-compat.qualification-evidence.v1`
- `application/vnd.z4j.rollback-compat.finalization-evidence.v1`
- `application/vnd.z4j.rollback-compat.promotion-evidence.v1` or the mutually
  exclusive recovery type
- `application/vnd.z4j.rollback-compat.release-evidence-index.v1`

`durable_evidence.py discover` queries the filtered OCI Referrers API, requires
exactly one matching descriptor, fetches the artifact manifest/config/layers by
digest, verifies all hashes/sizes/titles/media types and predecessor links,
runs Cosign 3.1.3 against the exact receipt and bundle, and writes this portable
stage directory:
Crash replay is absent-or-byte-exact. Before qualification creates a new SBOM,
signature, attestation, provenance, or receipt, it supplies
`--expected-qualification-authority` as canonical JSON binding the current run,
repository/workflow, recipe hashes, candidate index, and both native descriptor
sets. A discovered qualification receipt must have that exact signed projection;
the workflow then reconstructs the prior OCI bytes and skips every signing or
attestation mutation. Finalization likewise requires the unique exact-subject
artifact and qualification predecessor, compares every current stable receipt
field (including source, manifest, rereads, proofs, and authority capture), and
reconstructs only the previously signed nondeterministic Sigstore-linked bytes.
A changed stable field or a different/duplicate same-type referrer is fatal.


```text
record.json
readback/
  referrers.oci.json
  artifact-manifest.oci.json
  config.json
  receipt.json
  bundle.sigstore.json
  authentication.json
  payload/<safe original relative paths...>
```

A complete retained graph has exactly these directories:

```text
qualification/
finalization/
promotion/        # or recovery/, never both
release-index/
```

After taking the digest and size from the finalized manifest and using
owner-private output directories, retrieval begins with qualification and then
passes each verified `record.json` as the next stage's `--predecessor-record`.
Registry access is deliberately unavailable in this source snapshot: the
helper rejects before credentials, process execution, or network I/O until the
reviewed common-E0 runtime-repository authority and PAT-HMAC validator are
integrated.

The eventual protected publisher interface uses only
`Z4J_DOCKERHUB_PUBLISHER_PAT` and
`Z4J_DOCKERHUB_PUBLISHER_PAT_HMAC_KEY_B64`. It must verify the active PAT UUID,
exact `repo:write` metadata scope (read implied, no admin/delete), constant-time
HMAC binding, signed publisher/repository identity, and live immutable-tag
settings before requesting registry scopes `pull,push`. The legacy
`DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` aliases are rejected and are never
sufficient authority. Docker Hub exposes no supported cleanup/retention API,
so the signed settings authority carries `cleanup_api: null`; retention comes
from exact immutable content tags and raw registry readback.

Once that common authority is realized, the protected workflows—not an ad hoc
local invocation—materialize the durable graph into owner-private directories.
Actions artifacts remain convenience mirrors, not durable authority.

The callable, network-free
`verify_local_graph(manifest_path, evidence_root, *, cosign="cosign")` and the
equivalent `verify-local-graph` CLI reverify the four retained portable stage
directories, every raw blob, every Cosign bundle, the candidate seal, all
predecessors, terminal provenance, and the exact release-index document.
`materialize-original` safely reconstructs original regular files without
following links and derives only the deterministic receipt SHA-256 sidecar.
Missing, substituted, duplicate, unsorted, unsafe-path, or cross-linked
evidence fails closed.

The release-index receipt states that its exact bytes must be retained for an
eventual immutable GitHub Release asset. This workflow does not publish that
asset yet. Operators must use the immutable candidate digest proven by the
verified release-evidence index--never the discovery tag--in rollback
configuration.

## Runtime rollback boundary

This image only closes the application/runtime side of rollback compatibility.
It does not authorize a database downgrade. Before schema downgrade, all Brain
and scheduler processes must be stopped and the separately reviewed 1.9.0
rollback-preparation ceremony must transactionally restamp every schedule
through the Boundary-D change-log/revision path to the **actual** cadence
fingerprint of the promoted compatibility-image digest. A complete reverse
rollback gate must then prove both original-1.8 and 1.9-created schedule
cohorts through fire and cursor transitions on unchanged 1.8.2 code.

No rollback is safe merely because this Dockerfile builds or this verifier
passes in isolation.
