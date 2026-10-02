use serde::de::DeserializeOwned;
use serde_json::{json, Deserializer, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::canonical::{canonicalize_bytes, is_accepted_canonicalization, sha256_hex};
use crate::errors::{VerificationError, VerificationErrorCode};
use crate::signers::SignatureVerifier;
use crate::types::{
    ActionIntent, ActionSpec, AudienceRef, JsonObject, PartyRef, ScopeSpec, SignatureSpec,
    TargetRef, TenantRef, VerificationContext, VerificationContextInput, VerifiedProtectedRequest,
    PCCB,
};

pub const DEFAULT_CLOCK_SKEW_TOLERANCE: Duration = Duration::ZERO;

pub fn parse_action_intent_json(raw: &[u8]) -> Result<ActionIntent, VerificationError> {
    let intent: ActionIntent =
        decode_json(raw, VerificationErrorCode::InvalidIntent, "action intent")?;
    normalize_action_intent(intent)
}

pub fn parse_pccb_json(raw: &[u8]) -> Result<PCCB, VerificationError> {
    let pccb: PCCB = decode_json(raw, VerificationErrorCode::InvalidPccb, "pccb")?;
    normalize_pccb(pccb)
}

/// Consults the revocation source for a proof's signed authority
/// (protocol/13-edge-binding.md E5): `Ok(true)` only when the authority is
/// NOT revoked; `Err` when the source could not be consulted.
pub type RevocationChecker =
    Box<dyn Fn(&PCCB, &VerificationContext) -> Result<bool, String> + Send + Sync>;

pub struct Verifier<V: SignatureVerifier> {
    signature_verifier: V,
    clock_skew_tolerance: Duration,
    revocation_checker: Option<RevocationChecker>,
}

impl<V: SignatureVerifier> Verifier<V> {
    pub fn new(signature_verifier: V) -> Self {
        Self {
            signature_verifier,
            clock_skew_tolerance: DEFAULT_CLOCK_SKEW_TOLERANCE,
            revocation_checker: None,
        }
    }

    /// Configures the edge's revocation source. A proof whose signed
    /// authority declares `"revocable": true` is refused without one.
    pub fn with_revocation_checker<F>(mut self, checker: F) -> Self
    where
        F: Fn(&PCCB, &VerificationContext) -> Result<bool, String> + Send + Sync + 'static,
    {
        self.revocation_checker = Some(Box::new(checker));
        self
    }

    pub fn with_clock_skew_tolerance(
        mut self,
        tolerance: Duration,
    ) -> Result<Self, VerificationError> {
        if tolerance.is_negative() {
            return Err(VerificationError::new(
                VerificationErrorCode::InvalidContext,
                "clock skew tolerance must be non-negative.",
            ));
        }
        self.clock_skew_tolerance = tolerance;
        Ok(self)
    }

    pub fn parse_action_intent_json(&self, raw: &[u8]) -> Result<ActionIntent, VerificationError> {
        parse_action_intent_json(raw)
    }

    pub fn parse_pccb_json(&self, raw: &[u8]) -> Result<PCCB, VerificationError> {
        parse_pccb_json(raw)
    }

    pub fn build_context(
        &self,
        input: VerificationContextInput,
    ) -> Result<VerificationContext, VerificationError> {
        normalize_context(input)
    }

    // protocol/13-edge-binding.md E5.
    fn check_revocation(
        &self,
        pccb: &PCCB,
        context: &VerificationContext,
    ) -> Result<(), VerificationError> {
        let unknown = || {
            VerificationError::new(
                VerificationErrorCode::AuthorityRevoked,
                "The proof authority's revocation status could not be established.",
            )
        };
        let mut revocable = false;
        if let Some(authority) = pccb.extensions.get("authority") {
            let authority = authority.as_object().ok_or_else(unknown)?;
            match authority.get("revocable") {
                None => {}
                Some(Value::Bool(flag)) => revocable = *flag,
                Some(_) => return Err(unknown()),
            }
        }
        match &self.revocation_checker {
            None if revocable => Err(unknown()),
            None => Ok(()),
            Some(checker) => match checker(pccb, context) {
                Ok(true) => Ok(()),
                Ok(false) => Err(VerificationError::new(
                    VerificationErrorCode::AuthorityRevoked,
                    "The proof authority has been revoked.",
                )),
                Err(_) => Err(unknown()),
            },
        }
    }

    pub fn verify(
        &self,
        intent: ActionIntent,
        pccb: PCCB,
        context: VerificationContext,
    ) -> Result<VerifiedProtectedRequest, VerificationError> {
        let normalized_intent = normalize_action_intent(intent)?;
        let normalized_pccb = normalize_pccb(pccb)?;
        let normalized_context = normalize_context(VerificationContextInput {
            request_id: context.request_id,
            audience: context.audience,
            now: context.now,
            scope_capabilities: context.scope_capabilities,
            parameter_constraints: context.parameter_constraints,
            resource_selectors: context.resource_selectors,
        })?;

        let not_before = parse_timestamp(
            &normalized_pccb.not_before,
            "pccb.not_before",
            VerificationErrorCode::InvalidPccb,
        )?;
        let expires_at = parse_timestamp(
            &normalized_pccb.expires_at,
            "pccb.expires_at",
            VerificationErrorCode::InvalidPccb,
        )?;

        // ── Signature verification (before any semantic check) ───────────
        // Security principle: verify cryptographic integrity BEFORE interpreting
        // semantic fields, including the validity window. Any mutation to the
        // signed PCCB payload must produce SIGNATURE_INVALID, never a semantic
        // refusal that tells a forger which check it would fail. The order of
        // every check below matches the Python reference verifier
        // (PCCBVerifier.verify steps 4-11).
        let unsigned_payload = canonicalize_bytes(&build_unsigned_pccb_payload(&normalized_pccb))
            .map_err(|_error| {
            VerificationError::new(
                VerificationErrorCode::InvalidPccb,
                "The proof cannot be canonicalized for signature verification.",
            )
        })?;
        if !self
            .signature_verifier
            .verify(&unsigned_payload, &normalized_pccb.signature)
        {
            return Err(VerificationError::new(
                VerificationErrorCode::SignatureInvalid,
                "The proof signature could not be verified.",
            ));
        }

        // ── Semantic checks (after signature is verified) ────────────────
        if normalized_context.now + self.clock_skew_tolerance < not_before {
            return Err(VerificationError::new(
                VerificationErrorCode::ProofNotYetValid,
                "The proof is not yet valid.",
            ));
        }
        if normalized_context.now - self.clock_skew_tolerance > expires_at {
            return Err(VerificationError::new(
                VerificationErrorCode::ProofExpired,
                "The proof has expired.",
            ));
        }
        if normalized_pccb.audience != normalized_context.audience {
            return Err(VerificationError::new(
                VerificationErrorCode::AudienceMismatch,
                "The proof audience does not match this endpoint.",
            ));
        }
        if normalized_pccb.target != normalized_intent.target {
            return Err(VerificationError::new(
                VerificationErrorCode::TargetMismatch,
                "The proof target does not exactly match the action intent.",
            ));
        }
        // Protocol v1 proofs are exact and single-use only (protocol/13 E4).
        if normalized_pccb.scope.mode != "exact" || !normalized_pccb.scope.single_use {
            return Err(VerificationError::new(
                VerificationErrorCode::ScopeModeInvalid,
                "The proof scope mode is not supported.",
            ));
        }
        if !normalized_pccb
            .scope
            .capabilities
            .iter()
            .any(|capability| capability == &normalized_intent.action.capability)
        {
            return Err(VerificationError::new(
                VerificationErrorCode::ScopeCapabilityMismatch,
                "The proof scope does not allow this capability.",
            ));
        }
        // E1: the capability must be one this endpoint declares it performs.
        if !normalized_context
            .scope_capabilities
            .iter()
            .any(|capability| capability == &normalized_intent.action.capability)
        {
            return Err(VerificationError::new(
                VerificationErrorCode::ScopeCapabilityMismatch,
                "The action capability is not one this endpoint performs.",
            ));
        }
        if normalized_pccb.intent_id.as_deref().is_some()
            && normalized_pccb.intent_id.as_deref() != Some(normalized_intent.intent_id.as_str())
        {
            return Err(VerificationError::new(
                VerificationErrorCode::IntentMismatch,
                "The proof does not match the supplied action intent.",
            ));
        }
        if normalized_pccb.tenant != normalized_intent.tenant {
            return Err(VerificationError::new(
                VerificationErrorCode::TenantMismatch,
                "The proof tenant does not match the action intent.",
            ));
        }
        if normalized_pccb.subject != normalized_intent.requester {
            return Err(VerificationError::new(
                VerificationErrorCode::SubjectMismatch,
                "The proof subject does not match the action intent.",
            ));
        }
        if normalized_pccb.action != normalized_intent.action {
            return Err(VerificationError::new(
                VerificationErrorCode::ActionMismatch,
                "The proof action does not exactly match the action intent.",
            ));
        }
        if normalized_pccb.action_hash.algorithm != "sha-256"
            || !is_accepted_canonicalization(&normalized_pccb.action_hash.canonicalization)
        {
            return Err(VerificationError::new(
                VerificationErrorCode::ActionHashAlgorithmInvalid,
                "The proof action hash metadata is invalid.",
            ));
        }

        let expected_hash =
            sha256_hex(&build_action_hash_input(&normalized_intent)).map_err(|_error| {
                VerificationError::new(
                    VerificationErrorCode::InvalidIntent,
                    "The action intent cannot be canonicalized for verification.",
                )
            })?;
        if normalized_pccb.action_hash.value != expected_hash {
            return Err(VerificationError::new(
                VerificationErrorCode::ActionHashMismatch,
                "The proof action hash does not match the action intent.",
            ));
        }
        // E2: every constraint the endpoint relies on was signed into the proof.
        for (key, value) in &normalized_context.parameter_constraints {
            let covered = normalized_pccb
                .scope
                .parameter_constraints
                .get(key)
                .is_some_and(|signed| canonical_value_eq(signed, value));
            if !covered {
                return Err(VerificationError::new(
                    VerificationErrorCode::ParameterMismatch,
                    "The proof parameter constraints do not cover this endpoint's constraints.",
                ));
            }
        }
        // E3: the signed target satisfies at least one declared selector.
        if !normalized_context.resource_selectors.is_empty()
            && !normalized_context
                .resource_selectors
                .iter()
                .any(|selector| target_satisfies(&normalized_pccb.target, selector))
        {
            return Err(VerificationError::new(
                VerificationErrorCode::TargetMismatch,
                "The proof target does not satisfy this endpoint's resource selectors.",
            ));
        }
        self.check_revocation(&normalized_pccb, &normalized_context)?;

        Ok(VerifiedProtectedRequest {
            intent: normalized_intent,
            pccb: normalized_pccb,
            context: normalized_context,
        })
    }

    pub fn verify_json(
        &self,
        intent_raw: &[u8],
        pccb_raw: &[u8],
        context: VerificationContext,
    ) -> Result<VerifiedProtectedRequest, VerificationError> {
        let intent = self.parse_action_intent_json(intent_raw)?;
        let pccb = self.parse_pccb_json(pccb_raw)?;
        self.verify(intent, pccb, context)
    }
}

/// Largest JSON document accepted, as by the reference's JSON ingress.
const MAX_JSON_INPUT_BYTES: usize = 1_048_576;

fn decode_json<T: DeserializeOwned>(
    raw: &[u8],
    code: VerificationErrorCode,
    artifact_name: &str,
) -> Result<T, VerificationError> {
    // The reference's ingress (loads_no_duplicate_keys) refuses oversized
    // documents and duplicate object members. serde_json silently keeps the
    // last duplicate, so check before decoding.
    if raw.len() > MAX_JSON_INPUT_BYTES || reject_duplicate_members(raw).is_err() {
        return Err(VerificationError::new(
            code,
            format!("failed to decode {artifact_name} JSON payload."),
        ));
    }
    let mut deserializer = Deserializer::from_slice(raw);
    let value = T::deserialize(&mut deserializer).map_err(|_error| {
        VerificationError::new(
            code,
            format!("failed to decode {artifact_name} JSON payload."),
        )
    })?;
    deserializer.end().map_err(|_error| {
        VerificationError::new(
            code,
            format!("{artifact_name} JSON payload must contain a single top-level object."),
        )
    })?;
    Ok(value)
}

fn require_non_empty(
    value: &str,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<(), VerificationError> {
    if value.trim().is_empty() {
        return Err(VerificationError::new(
            code,
            format!("{field_name} must be a non-empty string."),
        ));
    }
    Ok(())
}

fn parse_timestamp(
    raw: &str,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<OffsetDateTime, VerificationError> {
    if raw.trim().is_empty() {
        return Err(VerificationError::new(
            code,
            format!("{field_name} must be an RFC3339 timestamp string."),
        ));
    }
    let invalid = || {
        VerificationError::new(
            VerificationErrorCode::InvalidTimestamp,
            format!("{field_name} must be an RFC3339 timestamp string."),
        )
    };
    // The reference (datetime.fromisoformat after replacing "Z") refuses a
    // lowercase "z" designator, which the time crate accepts.
    if raw.contains('z') {
        return Err(invalid());
    }
    let parsed = OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|_error| invalid())?
        .to_offset(UtcOffset::UTC);
    if parsed.year() < 1 {
        return Err(invalid());
    }
    // The reference keeps microsecond precision and drops anything finer.
    parsed
        .replace_nanosecond(parsed.microsecond() * 1_000)
        .map_err(|_error| invalid())
}

/// Renders a UTC timestamp exactly like the reference's canonical form
/// (Python `datetime.isoformat` in UTC with a "Z" suffix): six fractional
/// digits when the microsecond component is non-zero, none otherwise.
/// Signed payloads and action hashes embed this form.
fn format_timestamp(value: OffsetDateTime) -> String {
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    );
    match value.microsecond() {
        0 => format!("{base}Z"),
        micros => format!("{base}.{micros:06}Z"),
    }
}

fn normalize_timestamp(
    raw: &str,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<String, VerificationError> {
    Ok(format_timestamp(parse_timestamp(raw, field_name, code)?))
}

fn normalize_action_intent(intent: ActionIntent) -> Result<ActionIntent, VerificationError> {
    if intent.contract.name != "action_intent" || intent.contract.version != "v1" {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidIntent,
            "contract must declare action_intent v1.",
        ));
    }
    require_non_empty(
        &intent.intent_id,
        "action_intent.intent_id",
        VerificationErrorCode::InvalidIntent,
    )?;
    let tenant = normalize_tenant_ref(
        intent.tenant,
        "action_intent.tenant",
        VerificationErrorCode::InvalidIntent,
    )?;
    let requester = normalize_party_ref(
        intent.requester,
        "action_intent.requester",
        VerificationErrorCode::InvalidIntent,
    )?;
    let action = normalize_action_spec(
        intent.action,
        "action_intent.action",
        VerificationErrorCode::InvalidIntent,
    )?;
    let target = normalize_target_ref(
        intent.target,
        "action_intent.target",
        VerificationErrorCode::InvalidIntent,
    )?;
    reject_empty_optional(
        &intent.idempotency_key,
        "action_intent.idempotency_key",
        VerificationErrorCode::InvalidIntent,
    )?;
    reject_empty_optional(
        &intent.justification,
        "action_intent.justification",
        VerificationErrorCode::InvalidIntent,
    )?;
    // Semantic rules of the reference's Action Intent intake.
    let issued_at = parse_timestamp(
        &intent.issued_at,
        "action_intent.issued_at",
        VerificationErrorCode::InvalidIntent,
    )?;
    let expires_at = parse_timestamp(
        &intent.expires_at,
        "action_intent.expires_at",
        VerificationErrorCode::InvalidIntent,
    )?;
    if expires_at <= issued_at {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidIntent,
            "action_intent.expires_at must be later than issued_at.",
        ));
    }
    if action.parameters.is_empty() {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidIntent,
            "action_intent.action.parameters must contain at least one value.",
        ));
    }

    Ok(ActionIntent {
        contract: crate::types::Contract {
            name: "action_intent".to_string(),
            version: "v1".to_string(),
        },
        intent_id: intent.intent_id,
        idempotency_key: intent.idempotency_key,
        issued_at: format_timestamp(issued_at),
        expires_at: format_timestamp(expires_at),
        tenant,
        requester,
        action,
        target,
        justification: intent.justification,
        context: intent.context,
        evidence_refs: intent.evidence_refs,
        metadata: intent.metadata,
        extensions: intent.extensions,
    })
}

fn normalize_pccb(pccb: PCCB) -> Result<PCCB, VerificationError> {
    if pccb.contract.name != "pccb" || pccb.contract.version != "v1" {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidPccb,
            "contract must declare pccb v1.",
        ));
    }
    require_non_empty(
        &pccb.pccb_id,
        "pccb.pccb_id",
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &pccb.nonce,
        "pccb.nonce",
        VerificationErrorCode::InvalidPccb,
    )?;
    reject_empty_optional(
        &pccb.intent_id,
        "pccb.intent_id",
        VerificationErrorCode::InvalidPccb,
    )?;
    let single_use = pccb.scope.single_use;

    Ok(PCCB {
        contract: crate::types::Contract {
            name: "pccb".to_string(),
            version: "v1".to_string(),
        },
        pccb_id: pccb.pccb_id,
        intent_id: pccb.intent_id,
        issued_at: normalize_timestamp(
            &pccb.issued_at,
            "pccb.issued_at",
            VerificationErrorCode::InvalidPccb,
        )?,
        not_before: normalize_timestamp(
            &pccb.not_before,
            "pccb.not_before",
            VerificationErrorCode::InvalidPccb,
        )?,
        expires_at: normalize_timestamp(
            &pccb.expires_at,
            "pccb.expires_at",
            VerificationErrorCode::InvalidPccb,
        )?,
        issuer: normalize_party_ref(
            pccb.issuer,
            "pccb.issuer",
            VerificationErrorCode::InvalidPccb,
        )?,
        subject: normalize_party_ref(
            pccb.subject,
            "pccb.subject",
            VerificationErrorCode::InvalidPccb,
        )?,
        tenant: normalize_tenant_ref(
            pccb.tenant,
            "pccb.tenant",
            VerificationErrorCode::InvalidPccb,
        )?,
        audience: normalize_audience_ref(
            pccb.audience,
            "pccb.audience",
            VerificationErrorCode::InvalidPccb,
        )?,
        action: normalize_action_spec(
            pccb.action,
            "pccb.action",
            VerificationErrorCode::InvalidPccb,
        )?,
        target: normalize_target_ref(
            pccb.target,
            "pccb.target",
            VerificationErrorCode::InvalidPccb,
        )?,
        scope: normalize_scope_spec(pccb.scope, "pccb.scope")?,
        nonce: pccb.nonce,
        action_hash: normalize_action_hash_spec(pccb.action_hash, "pccb.action_hash")?,
        escrow_reference: normalize_escrow_reference(pccb.escrow_reference, single_use)?,
        signature: normalize_signature_spec(pccb.signature, "pccb.signature")?,
        extensions: pccb.extensions,
    })
}

fn normalize_context(
    input: VerificationContextInput,
) -> Result<VerificationContext, VerificationError> {
    require_non_empty(
        &input.request_id,
        "context.request_id",
        VerificationErrorCode::InvalidContext,
    )?;
    // An empty declaration is refused by edge-binding rule E1 after the
    // signature verifies, with the same code in every SDK.
    let mut capabilities = input.scope_capabilities;
    capabilities.sort();

    Ok(VerificationContext {
        request_id: input.request_id,
        audience: normalize_audience_ref(
            input.audience,
            "context.audience",
            VerificationErrorCode::InvalidContext,
        )?,
        now: input.now.to_offset(UtcOffset::UTC),
        scope_capabilities: capabilities,
        parameter_constraints: input.parameter_constraints,
        resource_selectors: input.resource_selectors,
    })
}

fn normalize_tenant_ref(
    tenant: TenantRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<TenantRef, VerificationError> {
    require_non_empty(&tenant.tenant_id, &format!("{field_name}.tenant_id"), code)?;
    Ok(tenant)
}

fn normalize_party_ref(
    party: PartyRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<PartyRef, VerificationError> {
    require_non_empty(&party.r#type, &format!("{field_name}.type"), code)?;
    require_non_empty(&party.id, &format!("{field_name}.id"), code)?;
    reject_empty_optional(
        &party.display_name,
        &format!("{field_name}.display_name"),
        code,
    )?;
    Ok(party)
}

fn normalize_audience_ref(
    audience: AudienceRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<AudienceRef, VerificationError> {
    require_non_empty(&audience.r#type, &format!("{field_name}.type"), code)?;
    require_non_empty(&audience.id, &format!("{field_name}.id"), code)?;
    reject_empty_optional(&audience.uri, &format!("{field_name}.uri"), code)?;
    Ok(audience)
}

fn normalize_action_spec(
    action: ActionSpec,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<ActionSpec, VerificationError> {
    require_non_empty(&action.name, &format!("{field_name}.name"), code)?;
    require_non_empty(
        &action.capability,
        &format!("{field_name}.capability"),
        code,
    )?;
    Ok(action)
}

fn normalize_target_ref(
    target: TargetRef,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<TargetRef, VerificationError> {
    require_non_empty(
        &target.resource_type,
        &format!("{field_name}.resource_type"),
        code,
    )?;
    require_non_empty(
        &target.resource_id,
        &format!("{field_name}.resource_id"),
        code,
    )?;
    reject_empty_optional(&target.uri, &format!("{field_name}.uri"), code)?;
    Ok(target)
}

fn normalize_scope_spec(
    scope: ScopeSpec,
    field_name: &str,
) -> Result<ScopeSpec, VerificationError> {
    // Whether the mode is supported is a post-signature check
    // (SCOPE_MODE_INVALID), as in the reference.
    require_non_empty(
        &scope.mode,
        &format!("{field_name}.mode"),
        VerificationErrorCode::InvalidPccb,
    )?;
    if scope.capabilities.is_empty() {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidPccb,
            format!("{field_name}.capabilities must contain at least one capability."),
        ));
    }

    // Capabilities are signed in the order presented; never reorder them.
    if scope.capabilities.iter().any(String::is_empty) {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidPccb,
            format!("{field_name}.capabilities must contain non-empty strings."),
        ));
    }

    Ok(ScopeSpec {
        mode: scope.mode,
        capabilities: scope.capabilities,
        single_use: scope.single_use,
        resource_selectors: scope.resource_selectors,
        parameter_constraints: scope.parameter_constraints,
    })
}

fn normalize_action_hash_spec(
    action_hash: crate::types::ActionHashSpec,
    field_name: &str,
) -> Result<crate::types::ActionHashSpec, VerificationError> {
    require_non_empty(
        &action_hash.algorithm,
        &format!("{field_name}.algorithm"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &action_hash.canonicalization,
        &format!("{field_name}.canonicalization"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &action_hash.value,
        &format!("{field_name}.value"),
        VerificationErrorCode::InvalidPccb,
    )?;
    Ok(action_hash)
}

fn normalize_signature_spec(
    signature: SignatureSpec,
    field_name: &str,
) -> Result<SignatureSpec, VerificationError> {
    require_non_empty(
        &signature.algorithm,
        &format!("{field_name}.algorithm"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &signature.key_id,
        &format!("{field_name}.key_id"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &signature.encoding,
        &format!("{field_name}.encoding"),
        VerificationErrorCode::InvalidPccb,
    )?;
    require_non_empty(
        &signature.value,
        &format!("{field_name}.value"),
        VerificationErrorCode::InvalidPccb,
    )?;
    Ok(signature)
}

/// Present-but-empty optional strings are refused: the schemas require
/// minLength >= 1, and sdk-go (which cannot tell "" from absent) refuses
/// them too, so both SDKs bind the same documents.
fn reject_empty_optional(
    value: &Option<String>,
    field_name: &str,
    code: VerificationErrorCode,
) -> Result<(), VerificationError> {
    if value.as_deref() == Some("") {
        return Err(VerificationError::new(
            code,
            format!("{field_name} must not be an empty string."),
        ));
    }
    Ok(())
}

/// Mirrors the reference: escrow_reference is part of the signed payload
/// whenever escrow_id is present, and its single_use is always
/// scope.single_use (the presented escrow_reference.single_use is not
/// signed, so it is never surfaced).
fn normalize_escrow_reference(
    reference: Option<crate::types::EscrowReference>,
    single_use: bool,
) -> Result<Option<crate::types::EscrowReference>, VerificationError> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    if reference.escrow_id.is_empty() {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidPccb,
            "pccb.escrow_reference.escrow_id must be a non-empty string.",
        ));
    }
    Ok(Some(crate::types::EscrowReference {
        escrow_id: reference.escrow_id,
        single_use: Some(single_use),
    }))
}

fn build_action_hash_input(intent: &ActionIntent) -> Value {
    json!({
        "intent_id": intent.intent_id,
        "tenant": intent.tenant,
        "requester": intent.requester,
        "action": intent.action,
        "target": intent.target,
        "issued_at": intent.issued_at,
        "expires_at": intent.expires_at,
    })
}

fn build_unsigned_pccb_payload(pccb: &PCCB) -> Value {
    let mut payload = json!({
        "contract": {"name": "pccb", "version": "v1"},
        "pccb_id": pccb.pccb_id,
        "issued_at": pccb.issued_at,
        "not_before": pccb.not_before,
        "expires_at": pccb.expires_at,
        "issuer": pccb.issuer,
        "subject": pccb.subject,
        "tenant": pccb.tenant,
        "audience": pccb.audience,
        "action": pccb.action,
        "target": pccb.target,
        "scope": pccb.scope,
        "nonce": pccb.nonce,
        "action_hash": pccb.action_hash,
    });

    if let Some(intent_id) = &pccb.intent_id {
        if let Value::Object(ref mut map) = payload {
            map.insert("intent_id".to_string(), Value::String(intent_id.clone()));
        }
    }
    if let Some(reference) = &pccb.escrow_reference {
        if let Value::Object(ref mut map) = payload {
            map.insert(
                "escrow_reference".to_string(),
                json!({
                    "escrow_id": reference.escrow_id,
                    "single_use": pccb.scope.single_use,
                }),
            );
        }
    }
    if !pccb.extensions.is_empty() {
        if let Value::Object(ref mut map) = payload {
            map.insert(
                "extensions".to_string(),
                Value::Object(pccb.extensions.clone()),
            );
        }
    }

    payload
}

/// Walks a JSON document and fails on any object with a repeated member name.
fn reject_duplicate_members(raw: &[u8]) -> Result<(), serde_json::Error> {
    struct NoDuplicates;

    impl<'de> serde::de::DeserializeSeed<'de> for NoDuplicates {
        type Value = ();

        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(self)
        }
    }

    impl<'de> serde::de::Visitor<'de> for NoDuplicates {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a JSON value without duplicate object members")
        }

        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            while seq.next_element_seed(NoDuplicates)?.is_some() {}
            Ok(())
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let mut seen = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key) {
                    return Err(serde::de::Error::custom("duplicate JSON object member"));
                }
                map.next_value_seed(NoDuplicates)?;
            }
            Ok(())
        }
    }

    let mut deserializer = Deserializer::from_slice(raw);
    serde::de::DeserializeSeed::deserialize(NoDuplicates, &mut deserializer)?;
    deserializer.end()
}

fn canonical_value_eq(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    match (canonicalize_bytes(left), canonicalize_bytes(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

// protocol/13-edge-binding.md E3.
fn target_satisfies(target: &TargetRef, selector: &JsonObject) -> bool {
    if selector.is_empty() {
        return false;
    }
    selector.iter().all(|(key, value)| {
        let actual = match key.as_str() {
            "resource_id" => serde_json::Value::String(target.resource_id.clone()),
            "resource_type" => serde_json::Value::String(target.resource_type.clone()),
            other => match target.selectors.get(other) {
                Some(found) => found.clone(),
                None => return false,
            },
        };
        canonical_value_eq(&actual, value)
    })
}
