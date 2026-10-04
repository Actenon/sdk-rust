//! Protocol 1.5.0 / wire 1.2.0 capability provenance.
//!
//! Scan names a power, Permit signs one concrete capability, the Kernel
//! checks it, and a receipt follows. This SDK is the Kernel check: exact
//! capabilities, no widen-to-wildcard, and a forged token is not a proof.

use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    authority_extension, capability_in_scope, is_concrete_capability, parse_action_intent_json,
    parse_authority_extension, parse_pccb_json, scope_capabilities_for_mint,
    scope_capabilities_for_verification, unauthenticated_refusal, AudienceRef, Ed25519Verifier,
    VerificationContextInput, VerificationErrorCode, Verifier, PROTOCOL_VERSION,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/portable-local-proof")
}

fn load_fixture(name: &str) -> Vec<u8> {
    fs::read(fixtures_dir().join(name)).expect("failed to read portable local proof fixture")
}

fn context_with(capabilities: Vec<String>) -> VerificationContextInput {
    VerificationContextInput {
        request_id: "req_capability_provenance".to_string(),
        audience: AudienceRef {
            r#type: "service".to_string(),
            id: "portable-hello-world-endpoint".to_string(),
            uri: None,
        },
        now: OffsetDateTime::parse("2026-01-01T12:00:00Z", &Rfc3339).expect("valid time"),
        scope_capabilities: capabilities,
        parameter_constraints: Default::default(),
        resource_selectors: vec![],
    }
}

#[test]
fn wire_version_is_1_2_0() {
    assert_eq!(PROTOCOL_VERSION, "1.2.0");
}

#[test]
fn capability_codes_are_not_parameter_mismatch() {
    assert_ne!(
        VerificationErrorCode::ScopeCapabilityMismatch.as_str(),
        VerificationErrorCode::ParameterMismatch.as_str()
    );
    assert_ne!(
        VerificationErrorCode::ScopeModeInvalid.as_str(),
        VerificationErrorCode::ParameterMismatch.as_str()
    );
    assert_eq!(
        VerificationErrorCode::ScopeCapabilityMismatch.as_str(),
        "SCOPE_CAPABILITY_MISMATCH"
    );
    assert_eq!(
        VerificationErrorCode::ScopeModeInvalid.as_str(),
        "SCOPE_MODE_INVALID"
    );
}

#[test]
fn mint_refuses_to_widen_an_empty_or_wildcard_set() {
    let empty = scope_capabilities_for_mint(&[]).expect_err("empty mint set");
    assert_eq!(
        empty.message(),
        "empty allow-list cannot mint a proof; refusing to widen to the attempted action"
    );
    assert_ne!(
        scope_capabilities_for_mint(&[]).ok().as_deref(),
        Some(["payment.refund".to_string()].as_slice())
    );
    assert_ne!(
        scope_capabilities_for_mint(&[]).ok().as_deref(),
        Some(["*".to_string()].as_slice())
    );

    let wildcard = scope_capabilities_for_mint(&["payment.*".to_string()])
        .expect_err("wildcard is not a capability");
    assert_eq!(
        wildcard.message(),
        "proof capability must name one concrete action; a wildcard is not a capability"
    );
    for glob in ["*", "?", "payment.refund[id]", "a?b"] {
        assert!(scope_capabilities_for_mint(&[glob.to_string()]).is_err());
        assert!(!is_concrete_capability(glob));
    }

    let minted = scope_capabilities_for_mint(&["payment.refund".to_string()]).expect("concrete");
    assert_eq!(minted, vec!["payment.refund".to_string()]);
}

#[test]
fn verification_set_does_not_replace_an_empty_declaration() {
    let omitted = scope_capabilities_for_verification(None, "payment.refund").expect("omitted");
    assert_eq!(omitted, vec!["payment.refund".to_string()]);

    let empty = scope_capabilities_for_verification(Some(&[]), "payment.refund").expect("empty");
    assert!(empty.is_empty());
    assert_ne!(empty, vec!["payment.refund".to_string()]);
    assert_ne!(empty, vec!["*".to_string()]);

    let wildcard =
        scope_capabilities_for_verification(Some(&["payment.*".to_string()]), "payment.refund")
            .expect_err("declared glob");
    assert_eq!(
        wildcard.message(),
        "proof capability must name one concrete action; a wildcard is not a capability"
    );
    assert!(scope_capabilities_for_verification(None, "payment.*").is_err());
}

#[test]
fn globs_do_not_match_even_themselves() {
    assert!(capability_in_scope(
        "payment.refund",
        &["payment.refund".to_string()]
    ));
    assert!(!capability_in_scope(
        "payment.refund",
        &["payment.*".to_string()]
    ));
    assert!(!capability_in_scope(
        "payment.*",
        &["payment.*".to_string()]
    ));
    assert!(!capability_in_scope(
        "payment.refund",
        &["payment.refund".to_string(), "email.*".to_string()]
    ));
    assert!(capability_in_scope(
        "airlock.unresolved.abc",
        &["airlock.unresolved.abc".to_string()]
    ));
}

#[test]
fn authority_extension_round_trip() {
    let extensions =
        authority_extension("service:actenon-permit", "grant_123", None).expect("extension");
    let parsed = parse_authority_extension(Some(&extensions)).expect("parse");
    assert_eq!(parsed.issuer, "service:actenon-permit");
    assert_eq!(parsed.grant_id, "grant_123");
    assert!(parsed.revocable);
    assert!(authority_extension("", "grant_123", Some(true)).is_err());
    assert!(authority_extension("service:actenon-permit", "", Some(true)).is_err());
    assert!(parse_authority_extension(None).is_err());
}

#[test]
fn unauthenticated_refusal_ignores_token_shape() {
    // Length, a v1. prefix, and well-formed JSON are not arguments.
    assert_eq!(
        unauthenticated_refusal(false, false),
        Some(VerificationErrorCode::IssuerUntrusted)
    );
    assert_eq!(
        unauthenticated_refusal(false, true),
        Some(VerificationErrorCode::IssuerUntrusted)
    );
    assert_eq!(
        unauthenticated_refusal(true, false),
        Some(VerificationErrorCode::SignatureInvalid)
    );
    assert_eq!(unauthenticated_refusal(true, true), None);

    let long_token = format!("v1.{}", "a".repeat(32));
    assert!(long_token.len() >= 16);
    assert!(parse_pccb_json(long_token.as_bytes()).is_err());
    assert!(parse_pccb_json(b"{\"contract\":{}}").is_err());
}

#[test]
fn empty_and_wildcard_edge_declarations_do_not_verify() {
    let verifier = Verifier::new(actenon_verifier_sdk::build_local_proof_verifier());
    let intent = parse_action_intent_json(&load_fixture("action_intent.json")).expect("intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("pccb");

    for declared in [
        Vec::new(),
        vec!["*".to_string()],
        vec!["protected_resource.*".to_string()],
        vec![
            "protected_resource.read".to_string(),
            "protected_resource.*".to_string(),
        ],
    ] {
        let context = verifier
            .build_context(context_with(declared.clone()))
            .expect("empty declaration is a post-signature refusal");
        let error = verifier
            .verify(intent.clone(), pccb.clone(), context)
            .expect_err("wildcard or empty declaration");
        assert_eq!(
            error.code(),
            VerificationErrorCode::ScopeCapabilityMismatch,
            "{declared:?}"
        );
        assert_ne!(error.code(), VerificationErrorCode::ParameterMismatch);
    }
}

#[test]
fn forged_signature_is_refused_before_an_empty_allow_list() {
    let verifier = Verifier::new(actenon_verifier_sdk::build_local_proof_verifier());
    let intent = parse_action_intent_json(&load_fixture("action_intent.json")).expect("intent");
    let mut pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("pccb");
    pccb.signature.value = "a".repeat(43);
    let context = verifier
        .build_context(context_with(Vec::new()))
        .expect("context");
    let error = verifier
        .verify(intent, pccb, context)
        .expect_err("forged signature");
    assert_eq!(error.code(), VerificationErrorCode::SignatureInvalid);
}

#[test]
fn no_trust_root_is_issuer_untrusted() {
    let verifier = Verifier::new(Ed25519Verifier::new());
    let intent = parse_action_intent_json(&load_fixture("action_intent.json")).expect("intent");
    let pccb = parse_pccb_json(&load_fixture("pccb.json")).expect("pccb");
    let context = verifier
        .build_context(context_with(vec!["protected_resource.read".to_string()]))
        .expect("context");
    let error = verifier
        .verify(intent, pccb, context)
        .expect_err("no trust root");
    assert_eq!(error.code(), VerificationErrorCode::IssuerUntrusted);
    assert_ne!(error.code(), VerificationErrorCode::SignatureInvalid);
}
