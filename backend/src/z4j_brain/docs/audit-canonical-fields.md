# Audit canonical fields, contract

The audit-log row HMAC is computed from a stable JSON
canonicalization of the row's content. Changing what goes into
the canonical form is a wire-protocol change for the verifier:
old rows must continue to verify under the OLD canonical, new
rows under the NEW. This file documents the contract that lets
us evolve the canonical without breaking historical rows.

## Files

- `src/z4j_brain/domain/audit_service.py` -
  - `_CANONICAL_FIELDS`, the tuple of field names that participate
  - `_HMAC_VERSION`, the current canonical version int
  - `AuditEntry`, the dataclass shape (one field per canonical entry)
  - `AuditService._canonicalize`, the per-version payload builder
  - `verify_canonical_fields_emitted`, startup-time round-trip check

## Versioning rule

Every change to `_CANONICAL_FIELDS` or `_canonicalize` is one of:

1. **Adding a field at a new version**
   - Add to `_CANONICAL_FIELDS` tuple.
   - Add a `_check_canonical_field("<name>", "v<N>")` line at module top.
   - Add a `payload[...]` assignment INSIDE the version-gated
     `if version >= N:` block in `_canonicalize`.
   - Bump `_HMAC_VERSION` to N.
   - The fallback chain in `verify_row` MUST pick up version N first
     and fall through to N-1 → ... → 1.

2. **Removing a field**
   - Don't. Once a field is in the canonical, removing it breaks
     verification of every existing row at that version.
   - If you really must, treat it as a brand-new version that
     omits the field, and migrate stored rows.

3. **Renaming a field**
   - Same as remove + add. New version.

## Drift guards

Two guards live in `audit_service.py`:

- **Module-load membership checks** (`_check_canonical_field("id", "v2")`
  etc.), fire `RuntimeError` at import time if a field has
  been deleted from the tuple. Cheap; survives `python -O`.

- **Startup round-trip check** (`verify_canonical_fields_emitted`) -
  called by `create_app` (1.2.2 fifth-pass audit fix CRIT-3). Builds
  a sample `AuditEntry` and asserts every `_CANONICAL_FIELDS` entry
  appears in `_canonicalize`'s JSON output. Catches the inverse
  hole: field in tuple but not emitted by canonicalize.

## Why two checks?

- The module-load check catches the "delete a field" mistake
  early (before any code that imports `audit_service` can run).
- The startup round-trip catches the "field in tuple but not
  emitted" mistake without preventing the brain from booting.
  An operator hitting the round-trip error sees the brain
  REFUSE TO START with a clear message, rather than booting
  and silently signing rows with the wrong canonical.

## Test coverage

- `tests/unit/test_round3_regressions.py::TestR3High1RuntimeDriftGuard`
  exercises the module-load membership check.
- `tests/unit/test_round4_regressions.py::TestR4MedDriftGuardRoundTrip`
  exercises the round-trip check.
- `tests/unit/test_audit_service.py::TestApiKeyAttribution::test_v4_tampered_row_does_not_pass_v3_fallback`
  exercises the version-fallback collision-resistance argument.

## Operator-facing failure modes

If you see `RuntimeError: audit canonical drift: ...`:

- At brain boot: a developer changed `_CANONICAL_FIELDS` or
  `_canonicalize` without following the contract above.
- During `z4j audit verify`: same, module import is
  blocked. Roll back the brain version OR push a fix forward.

The error message names the offending field and points at
this file. The fix is always to either restore the field /
emission, or treat the change as a new HMAC version with a
proper migration of stored rows.
