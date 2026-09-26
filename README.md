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

- `action_intent` v1 and `pccb` v1 Rust data structures
- protected-endpoint proof verification, with the checks in the reference
  verifier's order: signature first, then not-before/expiry, audience,
  target, scope, intent, tenant, subject, action, and action hash
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

The verifier is stateless. It does not enforce single use: record the
proof's `pccb_id` / `nonce` in your replay store, and refuse a second use,
before performing the side effect.

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

## The Actenon ecosystem

<!-- ECOSYSTEM-TABLE:START -->
| Repository | Role | Depends on | Packages |
|---|---|---|---|
| **`actenon-protocol`** | The neutral wire contract — what every artefact looks like on the wire | — | `actenon-protocol` (PyPI) · `@actenon/protocol-types` (npm) |
| **`actenon-kernel`** | The open verifier — defines what a valid proof is | `actenon-protocol` | `actenon-kernel` (PyPI) |
| **`actenon-permit`** | The developer on-ramp and authority broker | `actenon-kernel`, `actenon-protocol` | `actenon-permit` (PyPI) · `@actenon/sdk` (npm) |
| **`actenon-scan`** | The independent static-analysis scanner | — | `actenon-scan` (PyPI) |
| **`sdk-go`** | Go verifier SDK | `actenon-protocol` | `github.com/Actenon/sdk-go` (v1.0.0) |
| **`sdk-rust`** ← you are here | Rust verifier SDK | `actenon-protocol` | `cargo add --git` (crates.io pending) |

**Optional:** [`actenon-cloud`](https://github.com/Actenon/actenon-cloud) — a managed control plane (source-available; see its LICENSE). Not required by any component above; every capability in this ecosystem works without it.
<!-- ECOSYSTEM-TABLE:END -->

## Conformance

`cargo test` runs, from [`fixtures/`](fixtures/):

- the Kernel's `verifier_sdk_v1` (16 cases), `canonicalization_strict_v1`,
  `receipt_countersignature_v1`, `transparency_log_v1` and
  `trust_artifacts_v1` vectors, copied byte-for-byte (they match the
  Kernel's `conformance/vector-lock.json`);
- `kernel_interop_v1`: 347 proof and 21 trust-artifact differential cases
  minted and decided by the Python reference verifier (see its README);
- `permit_interop_v1`: real proofs minted through actenon-permit.

See [CONFORMANCE.md](https://github.com/Actenon/actenon-protocol/blob/main/CONFORMANCE.md) for the ecosystem-wide map.

## License

Apache-2.0 — see [LICENSE](LICENSE).
