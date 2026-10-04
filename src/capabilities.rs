//! Exact capabilities and the signed authority extension.
//!
//! Mirrors actenon-protocol 1.5.0 (`PROTOCOL_VERSION` 1.2.0). Scan names a
//! power. Permit signs that name into a grant, then into one concrete proof
//! capability. The Kernel checks that capability against the edge allow-list.
//! A glob is a grant pattern, not a proof capability, and an empty set is not
//! filled in with the attempted action or with `*`.
//!
//! A proof token is not accepted because it is long, prefixed, or JSON. Those
//! are parsing. Acceptance needs a trust root and a signature that verifies.

use serde_json::{Map, Value};

use crate::errors::VerificationErrorCode;
use crate::types::JsonObject;

/// Wire protocol version this SDK aligns to.
///
/// actenon-protocol package 1.5.0, documentation pin
/// `d03236403ea160b3b63f0e6019468f380b2dfc6c`
/// ([actenon-protocol#21](https://github.com/Actenon/actenon-protocol/pull/21)).
/// Artefacts stamped `1.0.0` and `1.1.0` stay valid. `extensions` is optional.
pub const PROTOCOL_VERSION: &str = "1.2.0";

/// Grant-scope metacharacters. A proof names concrete capabilities only.
pub const GLOB_CHARS: &[char] = &['*', '?', '[', ']'];

/// A capability set would widen, or an authority extension is unusable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityError {
    message: String,
}

impl CapabilityError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CapabilityError {}

/// The signed `extensions.authority` object Permit embeds and a revocation
/// checker reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityExtension {
    pub issuer: String,
    pub grant_id: String,
    pub revocable: bool,
}

/// True for one non-empty string that contains no glob character.
pub fn is_concrete_capability(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|ch| GLOB_CHARS.contains(&ch))
}

fn require_concrete(
    capabilities: &[String],
    empty_message: &str,
) -> Result<Vec<String>, CapabilityError> {
    if capabilities.is_empty() {
        return Err(CapabilityError::new(empty_message));
    }
    for capability in capabilities {
        if !is_concrete_capability(capability) {
            return Err(CapabilityError::new(
                "proof capability must name one concrete action; a wildcard is not a capability",
            ));
        }
    }
    Ok(capabilities.to_vec())
}

/// The exact capabilities a proof may carry.
///
/// An empty sequence is refused. It is not replaced by the attempted action
/// or by `*` (that substitution is how an unnamed action became a proof).
pub fn scope_capabilities_for_mint(
    capabilities: &[String],
) -> Result<Vec<String>, CapabilityError> {
    require_concrete(
        capabilities,
        "empty allow-list cannot mint a proof; refusing to widen to the attempted action",
    )
}

/// The set E1 compares the intent's capability against.
///
/// `None` means the caller passed no edge allow-list. The set is then exactly
/// `(intent_capability,)` and is not a second allow-list. An empty sequence
/// stays empty: it authorises nothing, and it is not replaced by the attempted
/// action or by `*`.
pub fn scope_capabilities_for_verification(
    declared: Option<&[String]>,
    intent_capability: &str,
) -> Result<Vec<String>, CapabilityError> {
    if !is_concrete_capability(intent_capability) {
        return Err(CapabilityError::new(
            "intent capability must name one concrete action; a wildcard is not a capability",
        ));
    }
    match declared {
        None => Ok(vec![intent_capability.to_string()]),
        Some([]) => Ok(Vec::new()),
        Some(declared) => require_concrete(declared, "empty edge allow-list authorises nothing"),
    }
}

/// Exact membership. Globs do not match, including a glob equal to itself.
pub fn capability_in_scope(capability: &str, declared: &[String]) -> bool {
    if !is_concrete_capability(capability) {
        return false;
    }
    declared.iter().any(|item| item == capability)
        && declared.iter().all(|item| is_concrete_capability(item))
}

/// The signed `extensions` object Permit embeds on a PCCB.
///
/// `revocable` defaults to `true` when `None`, matching the protocol helper.
pub fn authority_extension(
    issuer: &str,
    grant_id: &str,
    revocable: Option<bool>,
) -> Result<JsonObject, CapabilityError> {
    let revocable = revocable.unwrap_or(true);
    if issuer.is_empty() {
        return Err(CapabilityError::new(
            "authority extension requires an issuer",
        ));
    }
    if grant_id.is_empty() {
        return Err(CapabilityError::new(
            "authority extension requires a grant_id",
        ));
    }
    let mut authority = Map::new();
    authority.insert("issuer".to_string(), Value::String(issuer.to_string()));
    authority.insert("grant_id".to_string(), Value::String(grant_id.to_string()));
    authority.insert("revocable".to_string(), Value::Bool(revocable));
    let mut extensions = Map::new();
    extensions.insert("authority".to_string(), Value::Object(authority));
    Ok(extensions)
}

/// Return `extensions.authority`. Errors when it is missing or unusable.
pub fn parse_authority_extension(
    extensions: Option<&JsonObject>,
) -> Result<AuthorityExtension, CapabilityError> {
    let extensions =
        extensions.ok_or_else(|| CapabilityError::new("proof carries no authority extension"))?;
    let authority = extensions
        .get("authority")
        .and_then(Value::as_object)
        .ok_or_else(|| CapabilityError::new("proof carries no authority extension"))?;
    let issuer = authority
        .get("issuer")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty())
        .ok_or_else(|| CapabilityError::new("authority extension requires an issuer"))?;
    let grant_id = authority
        .get("grant_id")
        .and_then(Value::as_str)
        .filter(|grant_id| !grant_id.is_empty())
        .ok_or_else(|| CapabilityError::new("authority extension requires a grant_id"))?;
    let revocable = match authority.get("revocable") {
        Some(Value::Bool(revocable)) => *revocable,
        _ => {
            return Err(CapabilityError::new(
                "authority extension revocable must be a boolean",
            ))
        }
    };
    Ok(AuthorityExtension {
        issuer: issuer.to_string(),
        grant_id: grant_id.to_string(),
        revocable,
    })
}

/// Refusal code when a token has not been cryptographically accepted.
///
/// Returns `None` only when a trust root is configured and the signature
/// verified. Token length, a `v1.` prefix, and well-formed JSON are not
/// arguments: parsing is not acceptance. A verifier that reported any string
/// of 16 or more characters as valid was non-conformant.
pub fn unauthenticated_refusal(
    trust_root_configured: bool,
    signature_verified: bool,
) -> Option<VerificationErrorCode> {
    if !trust_root_configured {
        return Some(VerificationErrorCode::IssuerUntrusted);
    }
    if !signature_verified {
        return Some(VerificationErrorCode::SignatureInvalid);
    }
    None
}
