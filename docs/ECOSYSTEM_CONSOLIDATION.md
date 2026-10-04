# Rust verifier consolidation evidence

This candidate preserves both frozen histories as merge parents:

- Production/release candidate: `c149ab681be437b68f699b4f734a1a18ed7ad0e7`.
- Capability-provenance candidate: `6dfbf391cfb7d8029f76da503ff687905f784d13`.

The production parser, canonicalisation profiles, signature-first verification, exact E1–E5 edge checks and revocation source requirement remain. Wire-1.2 capability helpers and authority metadata are added. A revocable proof without an authoritative checker remains a refusal; parsing `revocable=true` does not authorise execution.

The candidate vendors Kernel core `c6564b90be8bdb7a871c176df5673d5b3a4ab5fc`, the first unified #41+#43 commit. All previous vector records are retained. Six additional counterexamples reject mixed wildcard scopes and incomplete signed authority references. `fixtures/kernel_vector_lock.json` is identical to the pinned Kernel lock; unlocked fixtures are compared separately in CI.

Local all-target tests, clippy, format, documentation and doctest checks pass. CI must also pass against the minimum supported compiler and current stable. No package or tag is published by this consolidation. Existing release evidence remains historical evidence for its original commits; a new coordinated release requires its own exact commit and artifact freeze.
