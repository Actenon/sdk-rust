//! permit_interop_v1: real proofs minted through actenon-permit by the
//! current Kernel (Ed25519 and the local HS256 key, main-branch and
//! published packages, fractional-second timestamps). Expected decisions
//! come from the Python reference (generate_manifest.py).

use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    build_local_proof_verifier, parse_ed25519_public_jwk, parse_pccb_json, Ed25519Verifier,
    SignatureSpec, SignatureVerifier, VerificationContextInput, VerificationError, Verifier,
};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn read(parts: &[&str]) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/permit_interop_v1");
    for part in parts {
        path = path.join(part);
    }
    fs::read_to_string(path).expect("failed to read Permit interop fixture")
}

fn verify<V: SignatureVerifier>(
    signatures: V,
    intent: &str,
    pccb: &str,
) -> Result<(), VerificationError> {
    let parsed = parse_pccb_json(pccb.as_bytes())?;
    let verifier = Verifier::new(signatures);
    let context = verifier.build_context(VerificationContextInput {
        request_id: "req_permit_interop".to_string(),
        audience: parsed.audience.clone(),
        now: OffsetDateTime::parse(&parsed.issued_at, &Rfc3339).unwrap(),
        scope_capabilities: parsed.scope.capabilities.clone(),
        parameter_constraints: Default::default(),
        resource_selectors: vec![],
    })?;
    verifier
        .verify_json(intent.as_bytes(), pccb.as_bytes(), context)
        .map(|_| ())
}

#[test]
fn permit_minted_proofs_match_the_reference() {
    let manifest: Value = serde_json::from_str(&read(&["manifest.json"])).unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let directory = case["directory"].as_str().unwrap();
        let pccb = read(&[directory, "pccb.json"]);
        let intent = read(&[directory, case["intent"].as_str().unwrap()]);
        let result = if pccb.contains("\"EdDSA\"") {
            let signatures = Ed25519Verifier::new()
                .with_jwk(&read(&[directory, "public_key.jwk.json"]))
                .unwrap();
            verify(signatures, &intent, &pccb)
        } else {
            verify(build_local_proof_verifier(), &intent, &pccb)
        };
        let expected = &case["expected"];
        match (expected["outcome"].as_str().unwrap(), result) {
            ("verified", Ok(())) => {}
            ("verified", Err(error)) => {
                panic!("{}: reference verifies; SDK refused: {error}", case["id"])
            }
            (_, Ok(())) => panic!("{}: reference refuses; SDK verified", case["id"]),
            (_, Err(error)) => assert_eq!(
                error.code().as_str(),
                expected["reason_code"].as_str().unwrap(),
                "{}",
                case["id"]
            ),
        }
    }
}

#[test]
fn ed25519_verifier_refuses_wrong_key_kid_and_algorithm() {
    let intent = read(&["main-ed25519", "action_intent.json"]);
    let pccb = read(&["main-ed25519", "pccb.json"]);
    let (kid, key) =
        parse_ed25519_public_jwk(&read(&["main-ed25519", "public_key.jwk.json"])).unwrap();
    let (_, other_key) =
        parse_ed25519_public_jwk(&read(&["published-ed25519", "public_key.jwk.json"])).unwrap();

    verify(
        Ed25519Verifier::new().with_key(kid.clone(), key).unwrap(),
        &intent,
        &pccb,
    )
    .expect("the pinned issuer key verifies");
    for (name, result) in [
        (
            "wrong key",
            verify(
                Ed25519Verifier::new()
                    .with_key(kid.clone(), other_key)
                    .unwrap(),
                &intent,
                &pccb,
            ),
        ),
        (
            "unknown kid",
            verify(
                Ed25519Verifier::new().with_key("another-kid", key).unwrap(),
                &intent,
                &pccb,
            ),
        ),
        (
            "local HS256",
            verify(build_local_proof_verifier(), &intent, &pccb),
        ),
    ] {
        assert_eq!(
            result.expect_err(name).code().as_str(),
            "SIGNATURE_INVALID",
            "{name}"
        );
    }
    // No configured trust root is not a forged signature (wire 1.2.0).
    assert_eq!(
        verify(Ed25519Verifier::new(), &intent, &pccb)
            .expect_err("no keys")
            .code()
            .as_str(),
        "ISSUER_UNTRUSTED"
    );

    let pinned = Ed25519Verifier::new().with_key(kid.clone(), key).unwrap();
    let signature: SignatureSpec = parse_pccb_json(pccb.as_bytes()).unwrap().signature;
    for algorithm in ["HS256", "none", "Ed25519", "eddsa"] {
        let mut changed = signature.clone();
        changed.algorithm = algorithm.to_string();
        assert!(!pinned.verify(b"payload", &changed), "{algorithm}");
    }
    let x = "NffSnVkOkiWgjQAgpOTso5mw3-R7EkluIE4zRW3bN18";
    for jwk in [
        format!(r#"{{"kty":"OKP","crv":"X25519","kid":"k","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","kid":"k","alg":"ES256","x":"{x}"}}"#),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}"#),
        r#"{"kty":"OKP","crv":"Ed25519","kid":"k","x":"NffSnVkOkiWgjQAgpOTso5mw3-R7EkluIE4zRW3bN1"}"#.to_string(),
        format!(r#"{{"kty":"OKP","crv":"Ed25519","kid":"k","x":"{x}","d":"x"}}"#),
    ] {
        assert!(parse_ed25519_public_jwk(&jwk).is_err(), "{jwk}");
    }
    assert!(Ed25519Verifier::new()
        .with_key("k", key)
        .unwrap()
        .with_key("k", key)
        .is_err());
}
