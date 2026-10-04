# Changelog

## [0.2.0]

First crates.io release.

### Capability provenance (wire 1.2.0)

- Exact capability helpers refuse empty issuance scopes and wildcard capabilities.
- Authority parsing preserves issuer, grant id and revocable metadata. Revocable proofs
  still require the release candidate's revocation source before acceptance.
- Retain signature-first checks, strict JSON, all edge-binding rules, timestamp grammar,
  and the release candidate's existing conformance/differential fixtures.

### Security (actenon-protocol `protocol/13-edge-binding.md`)

- **E1–E4.** The verifier enforces the protected edge's own declarations:
  - the intent's capability must be in `scope_capabilities` (exact match; an
    empty declaration refuses);
  - every edge `parameter_constraints` member must be signed into the proof;
  - the signed target must satisfy a `resource_selectors` entry;
  - only `single_use: true` proofs verify.
  0.1.0 accepted these context fields and ignored them.
- **E5.** `Verifier::with_revocation_checker` consults the revocation source
  for a proof whose signed `extensions.authority` is revocable. Revoked,
  unknown or unreachable authority, or no source at all, refuses with
  `AUTHORITY_REVOKED`. Proofs minted by actenon-permit 2.0 are revocable.
- New refusal codes: `ParameterMismatch`, `AuthorityRevoked`.

### Conformance

- The kernel's shared vectors (`edge_binding_cases.json`,
  `edge_revocation_cases.json`) are vendored byte-identically and pinned to
  kernel `c6564b9` (`fixtures/KERNEL_PIN`), Conformance 1.1.0.

## [0.1.0]

Initial release (git tag only).
