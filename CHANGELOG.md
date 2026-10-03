# Changelog

## [0.2.0]

First crates.io release.

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
  kernel `fce8a5b` (`fixtures/KERNEL_PIN`).

## [0.1.0]

Initial release (git tag only).
