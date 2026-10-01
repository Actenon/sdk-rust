use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::errors::{VerificationError, VerificationErrorCode};
use crate::types::SignatureSpec;

type HmacSha256 = Hmac<Sha256>;

pub const LOCAL_PROOF_KEY_ID: &str = "local-proof-v1";
pub const LOCAL_PROOF_SECRET: &str = "actenon-local-proof-secret-v1";

pub trait SignatureVerifier {
    fn verify(&self, payload: &[u8], signature: &SignatureSpec) -> bool;
}

#[derive(Clone, Debug)]
pub struct HmacSha256Verifier {
    secret: Vec<u8>,
    key_id: String,
    algorithm: String,
}

impl HmacSha256Verifier {
    pub fn new(secret: impl Into<Vec<u8>>, key_id: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            key_id: key_id.into(),
            algorithm: "HS256".to_string(),
        }
    }
}

impl SignatureVerifier for HmacSha256Verifier {
    fn verify(&self, payload: &[u8], signature: &SignatureSpec) -> bool {
        if signature.algorithm != self.algorithm
            || signature.key_id != self.key_id
            || signature.encoding != "base64url"
        {
            return false;
        }

        let provided = match URL_SAFE_NO_PAD.decode(signature.value.as_bytes()) {
            Ok(value) => value,
            Err(_) => return false,
        };

        let mut mac = match HmacSha256::new_from_slice(&self.secret) {
            Ok(value) => value,
            Err(_) => return false,
        };
        mac.update(payload);
        mac.verify_slice(&provided).is_ok()
    }
}

pub fn build_local_proof_verifier() -> HmacSha256Verifier {
    HmacSha256Verifier::new(LOCAL_PROOF_SECRET.as_bytes().to_vec(), LOCAL_PROOF_KEY_ID)
}

/// Verifies EdDSA (Ed25519) PCCB signatures, the algorithm the Kernel and
/// Permit use for production proofs, against public keys pinned by key ID.
/// It verifies the same signing input as the reference: the canonical
/// unsigned PCCB payload.
#[derive(Clone, Debug, Default)]
pub struct Ed25519Verifier {
    keys: BTreeMap<String, VerifyingKey>,
}

fn key_error(message: impl Into<String>) -> VerificationError {
    VerificationError::new(VerificationErrorCode::InvalidContext, message)
}

impl Ed25519Verifier {
    /// An empty verifier; add keys with [`Ed25519Verifier::with_key`] or
    /// [`Ed25519Verifier::with_jwk`]. With no keys every signature is refused.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins a raw 32-byte Ed25519 public key under `key_id`. Historical keys
    /// that must still verify older proofs are pinned alongside the active one.
    pub fn with_key(
        mut self,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<Self, VerificationError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(key_error("Ed25519 key IDs must be non-empty"));
        }
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| key_error("invalid Ed25519 public key"))?;
        if self.keys.insert(key_id, key).is_some() {
            return Err(key_error("duplicate Ed25519 key ID"));
        }
        Ok(self)
    }

    /// Pins a public key published as an OKP/Ed25519 JWK (for example an
    /// issuer's `public_key.jwk.json`), keyed by its `kid`.
    pub fn with_jwk(self, jwk_json: &str) -> Result<Self, VerificationError> {
        let (key_id, public_key) = parse_ed25519_public_jwk(jwk_json)?;
        self.with_key(key_id, public_key)
    }
}

/// Returns the key ID and public key of an OKP/Ed25519 JWK. JWKs carrying
/// private key material (`d`) are refused.
pub fn parse_ed25519_public_jwk(jwk_json: &str) -> Result<(String, [u8; 32]), VerificationError> {
    let jwk: serde_json::Map<String, serde_json::Value> = serde_json::from_str(jwk_json)
        .map_err(|_| key_error("Ed25519 JWK must be a JSON object"))?;
    let text = |name: &str| jwk.get(name).and_then(serde_json::Value::as_str);
    if text("kty") != Some("OKP") || text("crv") != Some("Ed25519") {
        return Err(key_error(
            "Ed25519 JWK must declare kty OKP and crv Ed25519",
        ));
    }
    if jwk.contains_key("alg") && text("alg") != Some("EdDSA") {
        return Err(key_error("Ed25519 JWK alg must be EdDSA"));
    }
    if jwk.contains_key("d") {
        return Err(key_error(
            "Ed25519 JWK must not contain private key material",
        ));
    }
    let key_id = text("kid")
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| key_error("Ed25519 JWK must have a non-empty kid"))?;
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(text("x").unwrap_or_default())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| key_error("Ed25519 JWK x must encode a 32-byte public key"))?;
    Ok((key_id.to_string(), public_key))
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, payload: &[u8], signature: &SignatureSpec) -> bool {
        if signature.algorithm != "EdDSA" || signature.encoding != "base64url" {
            return false;
        }
        let Some(key) = self.keys.get(&signature.key_id) else {
            return false;
        };
        // The base64 engine refuses padding, whitespace and non-canonical
        // trailing bits, so only the canonical encoding verifies.
        let Ok(raw) = URL_SAFE_NO_PAD.decode(signature.value.as_bytes()) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&raw) else {
            return false;
        };
        key.verify_strict(payload, &signature).is_ok()
    }
}
