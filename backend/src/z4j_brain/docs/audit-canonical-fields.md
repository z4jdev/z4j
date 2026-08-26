# Audit canonical fields contract

Audit rows exist in two authenticated formats. They must not be treated as one
versioned function: the legacy format remains readable, while current writes use
the Boundary F format and a dedicated audit-chain key.

## Legacy v1 rows

`domain/audit_service.py` retains the pre-activation canonical form for frozen
historical rows:

- `_CANONICAL_FIELDS` lists the JSON keys in the legacy envelope.
- `_HMAC_VERSION` is `1`.
- `AuditService._canonicalize` builds the v1 JSON payload.
- `AuditService.verify_row` uses that path only for rows which are not active v2
  rows.

`verify_canonical_fields_emitted()` constructs a sample legacy entry and checks
that every name in `_CANONICAL_FIELDS` appears in `_canonicalize`'s output.
`create_app` calls this function during application-factory construction. If it
raises, the factory does not return and a normal Uvicorn `--factory` serve cannot
start.

This is a narrow drift check. It does not run at module import, it does not prove
that field normalization is unchanged, and it cannot detect a field removed from
both the tuple and the payload. One-shot commands such as `z4j audit verify` do
not invoke this startup guard; they perform their own row verification.

## Active v2 rows

`domain/audit_chain.py` is the source of truth for rows written after Boundary F
activation:

- `AUDIT_ROW_HMAC_VERSION` is `2`.
- `canonical_row_payload` builds the closed, backend-neutral payload.
- `canonical_json` rejects unsupported JSON values and produces stable bytes.
- `compute_row_hmac` applies the dedicated audit-chain key and the v2 domain.
- `AuditService._verify_v2_row` selects the key by `hmac_key_id` and refuses
  incomplete or differently-versioned active rows.

The active payload also binds `hmac_key_id` and `chain_generation`. Those fields
are not part of the frozen v1 payload.

## Evolution rule

Never change the bytes produced for an existing version. To change fields,
normalization, or domain separation:

1. Add a new version constant and a new version-specific canonical builder.
2. Keep the v1 and v2 builders available for historical rows.
3. Dispatch verification from the persisted `hmac_version`; do not try new
   canonical forms until one happens to match.
4. Update persistence and migration code so new rows carry the new version and
   every field required by that version.
5. Add fixtures proving old rows still verify and that tampered or cross-version
   rows fail closed.

Removing or renaming a field without a new version invalidates existing HMACs.
Adding a field to an existing payload does the same.

## Current coverage

- `tests/unit/test_audit_chain_boundary_f.py` exercises the active v2 canonical
  payload and Boundary F integrity rules.
- `tests/unit/test_cli_audit_verify.py` exercises legacy v1 timestamp
  canonicalization and the audit verifier command.

When a normal serve reports `RuntimeError: audit canonical drift: ...`, restore
the omitted legacy emission or introduce a new explicit HMAC version. Do not
rewrite historical rows merely to make the startup check pass.
