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
- protected-endpoint proof verification
- exact audience, tenant, subject, action, target, action-hash, not-before, and expiry checks
- optional verifier-side clock skew tolerance, defaulting to zero
- deterministic local-proof verification using the OSS local `HS256` verifier
- custom signature verification via the exported `SignatureVerifier` trait
- offline Receipt counter-signature verification by historical or active `kid`
- offline, fail-closed issuer-status verification
- signed exact-action approval verification

## Quickstart

```rust
use actenon_verifier_sdk::{verify_pccb, PCCB, ActionIntent};

fn main() {
    match verify_pccb(&intent, &pccb, &opts) {
        Ok(result) => println!("verified: {}", result.action),
        Err(e) => println!("refused: {}", e),
    }
}
```


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

Every Actenon SDK runs against the same 51 conformance vectors in the Kernel. See [CONFORMANCE.md](https://github.com/Actenon/actenon-protocol/blob/main/CONFORMANCE.md) for the canonical map.

## License

Apache-2.0 — see [LICENSE](LICENSE).
