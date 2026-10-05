//! kernel_interop_v1: differential vectors minted and decided by the Python
//! reference (actenon-kernel). See fixtures/kernel_interop_v1/generate.py.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    build_local_proof_verifier, verify_approval_artifact_for_action, verify_countersignature,
    verify_inclusion, ActionHashSpec, AudienceRef, Ed25519Verifier, SignatureSpec,
    SignatureVerifier, VerificationContextInput, Verifier, LOCAL_PROOF_KEY_ID, LOCAL_PROOF_SECRET,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/kernel_interop_v1")
        .join(name);
    serde_json::from_slice(&fs::read(path).expect("failed to read kernel interop vectors"))
        .expect("failed to decode kernel interop vectors")
}

enum AnyVerifier {
    Local(actenon_verifier_sdk::HmacSha256Verifier),
    Ed25519(Ed25519Verifier),
}

impl SignatureVerifier for AnyVerifier {
    fn verify(&self, payload: &[u8], signature: &SignatureSpec) -> bool {
        match self {
            Self::Local(verifier) => verifier.verify(payload, signature),
            Self::Ed25519(verifier) => verifier.verify(payload, signature),
        }
    }
}

/// The expectation for this SDK: the reference's decision unless the case
/// documents a stricter Rust override. An override may never accept what
/// the reference refuses.
fn expectation(case: &Value) -> (String, String) {
    let reference = &case["expected"];
    // Explicit, versioned correction to historical acceptances. Preserve the
    // old fixture and require refusal under Protocol's32-depth profile.
    let correction: Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/protocol_canonicalisation/legacy-expectation-correction.json"),
        )
        .unwrap(),
    )
    .unwrap();
    if let Some(fixed) = correction["cases"].get(case["id"].as_str().unwrap()) {
        assert_eq!(reference["outcome"], fixed["original_outcome"]);
        assert_eq!(fixed["outcome"], "refused");
        return (
            "refused".to_string(),
            fixed["reason_code"].as_str().unwrap().to_string(),
        );
    }

    let expected = match case.pointer("/sdk_overrides/rust") {
        Some(rust) => {
            assert!(
                !(reference["outcome"] == "refused" && rust["outcome"] == "verified"),
                "an SDK override may never accept what the reference refuses"
            );
            rust
        }
        None => reference,
    };
    (
        expected["outcome"].as_str().unwrap().to_string(),
        expected["reason_code"].as_str().unwrap_or("").to_string(),
    )
}

fn run_case(document: &Value, case: &Value) -> Result<(), String> {
    let invalid_input: BTreeSet<&str> = document["invalid_input_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap())
        .collect();
    let signer = match case["signer"].as_str().unwrap() {
        "hs256" => {
            let hs256 = &document["signers"]["hs256"];
            assert_eq!(hs256["secret"], LOCAL_PROOF_SECRET);
            assert_eq!(hs256["key_id"], LOCAL_PROOF_KEY_ID);
            AnyVerifier::Local(build_local_proof_verifier())
        }
        "ed25519" => {
            let ed25519 = &document["signers"]["ed25519"];
            let public_key: [u8; 32] = URL_SAFE_NO_PAD
                .decode(ed25519["public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            AnyVerifier::Ed25519(
                Ed25519Verifier::new()
                    .with_key(ed25519["key_id"].as_str().unwrap(), public_key)
                    .unwrap(),
            )
        }
        other => panic!("unknown signer {other}"),
    };
    let context = &case["context"];
    let verifier = Verifier::new(signer)
        .with_clock_skew_tolerance(Duration::milliseconds(
            case["clock_skew_tolerance_ms"].as_i64().unwrap(),
        ))
        .unwrap();
    let context = verifier.build_context(VerificationContextInput {
        request_id: context["request_id"].as_str().unwrap().to_string(),
        audience: AudienceRef {
            r#type: context["audience"]["type"].as_str().unwrap().to_string(),
            id: context["audience"]["id"].as_str().unwrap().to_string(),
            uri: context["audience"]["uri"].as_str().map(str::to_string),
        },
        now: OffsetDateTime::parse(context["now"].as_str().unwrap(), &Rfc3339).unwrap(),
        scope_capabilities: context["scope_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect(),
        parameter_constraints: context["parameter_constraints"]
            .as_object()
            .unwrap()
            .clone(),
        resource_selectors: context["resource_selectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_object().unwrap().clone())
            .collect(),
    });
    let result = context.and_then(|context| {
        verifier.verify_json(
            case["intent"].as_str().unwrap().as_bytes(),
            case["pccb"].as_str().unwrap().as_bytes(),
            context,
        )
    });
    let (outcome, reason_code) = expectation(case);
    match (outcome.as_str(), result) {
        ("verified", Ok(_)) => Ok(()),
        ("verified", Err(error)) => Err(format!(
            "reference verifies this proof; SDK refused: {error}"
        )),
        (_, Ok(_)) => Err(format!(
            "reference refuses this proof with {reason_code}; SDK verified it"
        )),
        (_, Err(error)) => {
            let mut code = error.code().as_str();
            if invalid_input.contains(code) {
                code = "INVALID_INPUT";
            }
            if code == reason_code {
                Ok(())
            } else {
                Err(format!("expected refusal {reason_code}, got {error}"))
            }
        }
    }
}

fn run_cases(ids: &[&str]) {
    let document = fixture("cases.json");
    let cases = document["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases {
        let id = case["id"].as_str().unwrap();
        if !ids.is_empty() && !ids.contains(&id) {
            continue;
        }
        ran += 1;
        if let Err(failure) = run_case(&document, case) {
            failures.push(format!("{id}: {failure}"));
        }
    }
    if !ids.is_empty() {
        assert_eq!(ran, ids.len(), "some selected interop cases do not exist");
    }
    assert!(
        failures.is_empty(),
        "{} of {ran} kernel interop cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn artifact_outcome<E: std::fmt::Display>(
    result: Result<(), (String, E)>,
    expected: &Value,
) -> Result<(), String> {
    let outcome = expected["outcome"].as_str().unwrap();
    match (outcome, result) {
        ("verified", Ok(())) => Ok(()),
        ("verified", Err((_, error))) => Err(format!(
            "reference verifies this artifact; SDK refused: {error}"
        )),
        (_, Ok(())) => Err("reference refuses this artifact; SDK verified it".to_string()),
        (_, Err((code, error))) => {
            if code == expected["reason_code"].as_str().unwrap() {
                Ok(())
            } else {
                Err(format!("expected {}, got {error}", expected["reason_code"]))
            }
        }
    }
}

fn artifact_expectation(case: &Value) -> Value {
    match case.pointer("/sdk_overrides/rust") {
        Some(rust) => {
            assert!(!(case["expected"]["outcome"] == "refused" && rust["outcome"] == "verified"));
            rust.clone()
        }
        None => case["expected"].clone(),
    }
}

fn run_artifact_cases(ids: &[&str]) {
    let document = fixture("artifacts.json");
    let mut failures = Vec::new();
    let mut ran = 0;
    let selected = |id: &str| ids.is_empty() || ids.contains(&id);
    for case in document["countersignatures"].as_array().unwrap() {
        let id = format!("countersignature/{}", case["id"].as_str().unwrap());
        if !selected(&id) {
            continue;
        }
        ran += 1;
        let result = verify_countersignature(
            &case["receipt_or_digest"],
            &case["countersignature"],
            &document["countersignature_trusted_keys"],
        )
        .map(|_| ())
        .map_err(|error| (error.code().to_string(), error));
        if let Err(failure) = artifact_outcome(result, &artifact_expectation(case)) {
            failures.push(format!("{id}: {failure}"));
        }
    }
    for case in document["approvals"].as_array().unwrap() {
        let id = format!("approval/{}", case["id"].as_str().unwrap());
        if !selected(&id) {
            continue;
        }
        ran += 1;
        let expected_hash: Option<ActionHashSpec> = match &case["expected_action_hash"] {
            Value::Null => None,
            value => Some(serde_json::from_value(value.clone()).unwrap()),
        };
        let result = verify_approval_artifact_for_action(
            &case["approval"],
            &document["approval_trusted_keys"],
            expected_hash.as_ref(),
        )
        .map(|_| ())
        .map_err(|error| (error.code().to_string(), error));
        if let Err(failure) = artifact_outcome(result, &artifact_expectation(case)) {
            failures.push(format!("{id}: {failure}"));
        }
    }
    for case in document["inclusions"].as_array().unwrap() {
        let id = format!("inclusion/{}", case["id"].as_str().unwrap());
        if !selected(&id) {
            continue;
        }
        ran += 1;
        let result = verify_inclusion(
            &case["digest"],
            &case["inclusion_proof"],
            &case["checkpoint"],
        )
        .map(|_| ())
        .map_err(|error| (error.code().to_string(), error));
        if let Err(failure) = artifact_outcome(result, &artifact_expectation(case)) {
            failures.push(format!("{id}: {failure}"));
        }
    }
    if !ids.is_empty() {
        assert_eq!(ran, ids.len(), "some selected artifact cases do not exist");
    }
    assert!(
        failures.is_empty(),
        "{} of {ran} kernel interop artifact cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn accepts_current_canonicalization_profile() {
    // The Kernel mints action hashes, receipt digests and approvals labelled
    // ACTENON-JCS-STRICT-1 and still accepts the legacy RFC8785-JCS label.
    run_cases(&[
        "hs256/valid",
        "ed25519/valid",
        "hs256/issuer_signed_legacy_label",
        "ed25519/issuer_signed_legacy_label",
        "hs256/issuer_signed_unknown_label",
        "hs256/issuer_signed_hash_alg_sha512",
    ]);
    run_artifact_cases(&[
        "countersignature/receipt_current_profile",
        "countersignature/digest_current_profile",
        "countersignature/digest_legacy_label_vs_current_profile",
        "countersignature/legacy_profile_countersignature",
        "countersignature/unknown_profile_label",
        "approval/current_profile",
        "approval/current_profile_expected_legacy_label",
        "approval/legacy_profile_expected_current_label",
        "approval/different_action",
        "approval/unknown_profile_label",
        "approval/expected_hash_unknown_label",
        "inclusion/legacy_profile",
        "inclusion/current_profile",
        "inclusion/unknown_profile_label",
    ]);
}

#[test]
fn accepts_sub_second_timestamps() {
    // The reference normalizes timestamps to UTC with microsecond precision
    // (datetime.isoformat: six fractional digits whenever the microsecond
    // component is non-zero), so proofs minted from a real clock carry
    // fractional seconds in the signed payload and the action-hash input.
    run_cases(&[
        "hs256/subsecond_micro_123456",
        "hs256/subsecond_micro_123456_before_nbf",
        "hs256/subsecond_micro_500000",
        "hs256/subsecond_micro_500000_before_nbf",
        "hs256/subsecond_micro_000001",
        "hs256/subsecond_micro_000001_before_nbf",
        "ed25519/subsecond_micro_500000",
        "hs256/frac7_pccb_nbf",
        "hs256/frac9_intent_issued",
        "hs256/issuer_signed_pccb_frac_nbf",
        "hs256/issuer_signed_pccb_frac_nbf_presented_short",
        "hs256/pccb_nbf_frac_zero",
        "hs256/pccb_nbf_offset_equiv",
        "hs256/pccb_nbf_leap",
        "hs256/time_nbf_minus_skew_minus1us_skew0",
        "hs256/time_exp_plus_skew_plus1us_skew2000",
    ]);
}

#[test]
fn checks_in_reference_order() {
    // Signature first, then time, audience, target, scope, intent, tenant,
    // subject, action and action hash, so a forged or tampered proof never
    // learns which semantic check it would fail.
    run_cases(&[
        "hs256/expired_and_bad_sig",
        "hs256/not_yet_valid_and_bad_sig",
        "ed25519/expired_and_bad_sig",
        "hs256/pccb_nbf_frac_half",
        "hs256/multi_audience_and_expired",
        "hs256/multi_target_and_tenant",
        "hs256/multi_target_and_capability",
        "hs256/pccb_scope_mode",
        "hs256/issuer_signed_scope_mode_prefix",
    ]);
}

#[test]
fn does_not_reorder_signed_capabilities() {
    // scope.capabilities is signed in the order presented. Sorting it before
    // verification let a reordered proof verify.
    run_cases(&[
        "hs256/issuer_unsorted_caps",
        "hs256/issuer_sorted_caps",
        "hs256/reordered_caps_presented",
        "hs256/dup_caps_presented",
        "ed25519/reordered_caps_presented",
        "ed25519/issuer_unsorted_caps",
    ]);
}

#[test]
fn parses_json_like_the_reference_ingress() {
    // The reference's JSON ingress refuses duplicate members and oversized
    // documents; serde_json keeps the last duplicate, so without these
    // checks the verifier could act on a different document than a
    // first-wins consumer of the same bytes. Present-but-empty optional
    // strings are refused (schemas require minLength >= 1), as in sdk-go.
    run_cases(&[
        "hs256/dup_param_key_same",
        "hs256/dup_param_key_diff_last_signed",
        "hs256/dup_param_key_diff_first_signed",
        "hs256/dup_top_audience_pccb",
        "hs256/dup_top_audience_pccb_signed_last",
        "hs256/intent_tenant_attr_null",
        "hs256/pccb_scope_single_use_str",
        "hs256/pccb_escrow_null",
        "hs256/intent_requester_dn_null",
        "hs256/pccb_intent_id_null",
        "hs256/depth_params_124",
        "hs256/depth_params_125",
        "hs256/depth_params_128",
        "hs256/depth_params_200",
        "hs256/pccb_nbf_lower_z",
        "hs256/pccb_intent_id_empty",
        "hs256/issuer_signed_intent_id_empty",
        "hs256/issuer_signed_escrow_empty",
        "hs256/intent_target_uri_empty",
        "hs256/issuer_signed_dn_empty",
    ]);
}

#[test]
fn enforces_action_intent_semantics_and_escrow_binding() {
    // The reference's intake refuses a non-positive validity window and an
    // action without parameters; escrow_reference is signed whenever
    // escrow_id is present, with single_use taken from scope.single_use.
    run_cases(&[
        "hs256/issuer_signed_window_equal",
        "hs256/issuer_signed_window_inverted",
        "hs256/issuer_signed_empty_params",
        "ed25519/issuer_signed_empty_params",
        "hs256/minted_escrow",
        "hs256/minted_escrow_single_use_tamper",
        "hs256/minted_escrow_removed",
        "hs256/pccb_escrow_space",
        "hs256/pccb_escrow_empty",
    ]);
}

/// Every kernel_interop_v1 case: the SDK must reach the reference's
/// decision (or its documented stricter override) and must never verify a
/// proof the reference refuses.
#[test]
fn kernel_interop_vectors() {
    run_cases(&[]);
}

#[test]
fn kernel_interop_artifact_vectors() {
    run_artifact_cases(&[]);
}
