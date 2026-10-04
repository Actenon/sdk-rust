# Actenon Rust Verifier SDK

Minimal protected-endpoint verifier SDK for Rust, aligned to the Actenon Kernel's public `action_intent` and `pccb` contracts.

This crate is intentionally narrow. It focuses on verifier-side proof checking at the protected execution edge and offline verification of Receipt counter-signatures. It does not issue counter-signatures or contain private-key custody or service code.

Minimum supported Rust version: 1.88.

## Install

Add to `Cargo.toml`:

```toml
[dependencies]
actenon-verifier-sdk = { git = "https://github.com/Actenon/sdk-rust", tag = "v0.1.0" }
```

crates.io publication is prepared (Cargo.toml has all required fields, publish workflow is in place) and will complete once the `CARGO_REGISTRY_TOKEN` secret is added.

## Scope

- `action_intent` v1 and `pccb` v1 Rust data structures, aligned to
  actenon-protocol wire `PROTOCOL_VERSION` `1.2.0` (package 1.5.0,
  [actenon-protocol#21](https://github.com/Actenon/actenon-protocol/pull/21)
  pin `d03236403ea160b3b63f0e6019468f380b2dfc6c`)
- protected-endpoint proof verification, with the checks in the reference
  verifier's order: signature first (no trust root is `ISSUER_UNTRUSTED`; a
  forged signature is `SIGNATURE_INVALID`), then not-before/expiry, audience,
  target, scope, the edge's declared capability, intent, tenant, subject,
  action, and action hash, then the edge's parameter constraints and resource
  selectors, then revocation of `extensions.authority`
- optional verifier-side clock skew tolerance, defaulting to zero
- the `ACTENON-JCS-STRICT-1` canonicalisation profile (and the legacy
  `RFC8785-JCS` label), byte-identical to the Kernel's canonicaliser
- strict JSON decoding: duplicate members and oversized documents are refused
- built-in `Ed25519Verifier` (EdDSA, keys pinned by `kid`, raw keys or JWKs)
  and the deterministic local `HS256` verifier; custom verifiers via the
  exported `SignatureVerifier` trait
- offline Receipt counter-signature verification by historical or active `kid`
- offline, fail-closed issuer-status verification
- signed exact-action approval verification
- transparency-log checkpoint, inclusion and consistency verification

The verifier is stateless. It refuses a proof whose signed `single_use` is
not `true`. It does not record use: record the proof's `pccb_id` / `nonce`
in your replay store, and refuse a second use, before performing the side
effect.

Known limitation (fails closed): integers outside `i64::MIN..=u64::MAX`, and
`-0`, in action parameters are refused, because `serde_json` parses them as
floating point; the reference verifier accepts them.

## Quickstart

```rust,no_run
use actenon_verifier_sdk::{AudienceRef, Ed25519Verifier, VerificationContextInput, Verifier};
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let intent_json = std::fs::read("action_intent.json")?;
    let pccb_json = std::fs::read("pccb.json")?;
    let issuer_jwk = std::fs::read_to_string("public_key.jwk.json")?; // issuer's Ed25519 key

    // Pin the issuer's public key(s) by key ID; clock skew defaults to zero.
    let verifier = Verifier::new(Ed25519Verifier::new().with_jwk(&issuer_jwk)?);
    let context = verifier.build_context(VerificationContextInput {
        request_id: "req-123".to_string(),
        audience: AudienceRef {
            r#type: "service".to_string(),
            id: "actenon-permit-gateway".to_string(),
            uri: None,
        },
        now: OffsetDateTime::now_utc(),
        scope_capabilities: vec!["payment.refund".to_string()],
        parameter_constraints: Default::default(),
        resource_selectors: vec![],
    })?;

    match verifier.verify_json(&intent_json, &pccb_json, context) {
        Ok(verified) => println!(
            "verified: {} on {}",
            verified.intent.action.name, verified.intent.target.resource_id
        ),
        // e.g. ACTION_MISMATCH: The proof action does not exactly match the action intent.
        Err(refusal) => println!("refused: {} {}", refusal.code(), refusal.message()),
    }
    Ok(())
}
```

This quickstart is compiled by `cargo test` (a doctest of this README), and
the same calls run against real Permit-minted proofs in
[`tests/permit_interop_test.rs`](tests/permit_interop_test.rs). For local
proofs signed with the public development key use
`build_local_proof_verifier()` instead.

### Capability provenance

The path is Scan names a power, Permit signs that name into a grant and one
concrete proof capability, this verifier checks the proof, and a receipt
records the decision. This crate is the check. It does not confine a process
or sandbox native code.

- A capability is one exact string. `*`, `?`, `[`, and `]` are grant-scope
  syntax, not capabilities, and they are not expanded. `capability_in_scope`
  refuses a glob even when it is equal to itself.
- `scope_capabilities_for_mint` refuses an empty set. The attempted action and
  `*` are not substitutes.
- `scope_capabilities_for_verification(None, capability)` is exactly that
  capability. An empty declaration stays empty and authorises nothing
  (`SCOPE_CAPABILITY_MISMATCH` after the signature verifies).
- `SCOPE_CAPABILITY_MISMATCH` and `SCOPE_MODE_INVALID` are canonical codes.
  They are not rewritten to `PARAMETER_MISMATCH`. A proof whose signed
  `single_use` is not `true` is `SCOPE_MODE_INVALID`.
- Parsing is not acceptance. A long string, a `v1.` prefix, or well-formed
  JSON is not a proof. With no configured trust root the refusal is
  `ISSUER_UNTRUSTED`. A signature that does not verify is `SIGNATURE_INVALID`.
- When `extensions.authority.revocable` is true, configure
  `Verifier::with_revocation_checker`. Unknown, revoked, or unreadable
  authority is `AUTHORITY_REVOKED`.

`PROTOCOL_VERSION` in this crate is `1.2.0`. Nothing here is published.

## The Actenon ecosystem

<!-- ECOSYSTEM-TABLE:START -->
| Repository | Role | Depends on | Packages |
|---|---|---|---|
| **`actenon-protocol`** | The neutral wire contract — what every artefact looks like on the wire | — | `actenon-protocol` (PyPI) · `@actenon/protocol-types` (npm) |
| **`actenon-kernel`** | The open verifier — defines what a valid proof is | `actenon-protocol` | `actenon-kernel` (PyPI) |
| **`actenon-permit`** | The developer on-ramp and authority broker | `actenon-kernel`, `actenon-protocol` | `actenon-permit` (PyPI) · `@actenon/sdk` (npm) |
| **`actenon-scan`** | The independent static-analysis scanner | — | `actenon-scan` (PyPI) |
| **`sdk-go`** | Go verifier SDK — protected-endpoint proof verification in Go | `actenon-protocol` | [repo](https://github.com/Actenon/sdk-go) |
| **`sdk-rust`** ← you are here | Rust verifier SDK — protected-endpoint proof verification in Rust | `actenon-protocol` | [repo](https://github.com/Actenon/sdk-rust) |

**Optional:** `actenon-cloud` — a managed control plane (private repository, not publicly available). Not required by any component above; every capability in this ecosystem works without it.
<!-- ECOSYSTEM-TABLE:END -->

## Conformance

`cargo test` runs, from [`fixtures/`](fixtures/):

- the Kernel's `verifier_sdk_v1` (16 `cases.json` cases, 6
  fractional-second `timestamp_cases.json` cases, 21 `edge_binding_cases.json`
  cases, and 8 `edge_revocation_cases.json` cases), `canonicalization_strict_v1`,
  `receipt_countersignature_v1`, `transparency_log_v1` and
  `trust_artifacts_v1` vectors, copied byte-for-byte from the Kernel commit
  in `fixtures/KERNEL_PIN`. Every file the Kernel's
  `conformance/vector-lock.json` records for those suites must be vendored
  with that sha256 (checked offline against the verbatim copy
  `fixtures/kernel_vector_lock.json`, and in CI against the lock downloaded at
  the pin). `canonicalization_strict_v1` and the suite READMEs are not in the
  Kernel's lock (`fixtures/KERNEL_UNLOCKED`); CI compares them byte-for-byte
  with the Kernel tree at the pin instead;
- `kernel_interop_v1`: 347 proof and 21 trust-artifact differential cases
  minted and decided by the Python reference verifier (see its README);
- `permit_interop_v1`: real proofs minted through actenon-permit.

See [CONFORMANCE.md](https://github.com/Actenon/actenon-protocol/blob/main/CONFORMANCE.md) for the ecosystem-wide map.

## License

Apache-2.0 — see [LICENSE](LICENSE).
