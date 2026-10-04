# Changelog

## Unreleased

Aligned to actenon-protocol package 1.5.0 / wire `PROTOCOL_VERSION` `1.2.0`
([actenon-protocol#21](https://github.com/Actenon/actenon-protocol/pull/21),
pin `d03236403ea160b3b63f0e6019468f380b2dfc6c`). Not published.

### Security

- **Capability codes are canonical.** `SCOPE_CAPABILITY_MISMATCH` and
  `SCOPE_MODE_INVALID` are not rewritten to `PARAMETER_MISMATCH`. A signed
  `single_use` other than `true` is `SCOPE_MODE_INVALID`.
- **No widen-to-wildcard.** `scope_capabilities_for_mint` refuses an empty set
  and any capability containing `*`, `?`, `[`, or `]`. An empty edge
  declaration stays empty and is `SCOPE_CAPABILITY_MISMATCH` after the
  signature verifies. It is not replaced by the attempted action or by `*`.
  Globs are not expanded, including a glob equal to itself.
- **A proof token is not accepted on length or shape.** No configured trust
  root is `ISSUER_UNTRUSTED`. A forged or unverifiable signature is
  `SIGNATURE_INVALID`.
- **Edge binding E1–E5.** The verifier enforces the protected edge's own
  declarations (capability, parameter constraints, resource selectors,
  single-use) and `extensions.authority` revocation via
  `Verifier::with_revocation_checker`.

### Conformance

- Vendored the kernel's `edge_binding_cases.json` and
  `edge_revocation_cases.json` from kernel `b1b175d` (Conformance 1.1.0).
  Existing locked vector hashes are unchanged.
