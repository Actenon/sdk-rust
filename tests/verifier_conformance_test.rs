use std::fs;
use std::path::PathBuf;

use actenon_verifier_sdk::{
    build_local_proof_verifier, parse_action_intent_json, parse_pccb_json, AudienceRef,
    VerificationContextInput, Verifier,
};
use serde::Deserialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Deserialize)]
struct Mutation {
    document: String,
    path: Vec<String>,
    value: Value,
}

#[derive(Deserialize)]
struct Expected {
    outcome: String,
    #[serde(default)]
    reason_code: String,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct VectorCase {
    id: String,
    clock_skew_tolerance_ms: i64,
    mutation: Option<Mutation>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Base {
    intent: String,
    pccb: String,
    context: Value,
}

#[derive(Deserialize)]
struct Manifest {
    base: Base,
    cases: Vec<VectorCase>,
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/verifier_sdk_v1")
}

fn load_value(name: &str) -> Value {
    serde_json::from_slice(
        &fs::read(vector_root().join(name)).expect("failed to read shared vector"),
    )
    .expect("failed to decode shared vector")
}

fn set_path(document: &mut Value, path: &[String], value: Value) {
    let mut current = document;
    for segment in &path[..path.len() - 1] {
        current = current
            .as_object_mut()
            .and_then(|object| object.get_mut(segment))
            .expect("shared vector path must resolve to an object");
    }
    current
        .as_object_mut()
        .expect("shared vector path parent must be an object")
        .insert(path[path.len() - 1].clone(), value);
}

fn context_from_value(value: &Value) -> VerificationContextInput {
    let object = value.as_object().expect("context must be an object");
    let audience = object["audience"]
        .as_object()
        .expect("audience must be an object");
    let scope_capabilities = object["scope_capabilities"]
        .as_array()
        .expect("scope capabilities must be an array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("capability must be a string")
                .to_string()
        })
        .collect();
    let resource_selectors = object["resource_selectors"]
        .as_array()
        .expect("resource selectors must be an array")
        .iter()
        .map(|item| {
            item.as_object()
                .expect("resource selector must be an object")
                .clone()
        })
        .collect();
    VerificationContextInput {
        request_id: object["request_id"]
            .as_str()
            .expect("request id must be a string")
            .to_string(),
        audience: AudienceRef {
            r#type: audience["type"]
                .as_str()
                .expect("audience type must be a string")
                .to_string(),
            id: audience["id"]
                .as_str()
                .expect("audience id must be a string")
                .to_string(),
            uri: audience
                .get("uri")
                .and_then(Value::as_str)
                .map(str::to_string),
        },
        now: OffsetDateTime::parse(
            object["now"].as_str().expect("now must be a string"),
            &Rfc3339,
        )
        .expect("now must be RFC3339"),
        scope_capabilities,
        parameter_constraints: object["parameter_constraints"]
            .as_object()
            .expect("parameter constraints must be an object")
            .clone(),
        resource_selectors,
    }
}

#[test]
fn shared_verifier_sdk_conformance_vectors() {
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(vector_root().join("cases.json")).expect("failed to read manifest"),
    )
    .expect("failed to decode manifest");
    let base_intent = load_value(&manifest.base.intent);
    let base_pccb = load_value(&manifest.base.pccb);

    for vector in manifest.cases {
        let mut intent_document = base_intent.clone();
        let mut pccb_document = base_pccb.clone();
        let mut context_document = manifest.base.context.clone();
        if let Some(mutation) = vector.mutation {
            let document = match mutation.document.as_str() {
                "intent" => &mut intent_document,
                "pccb" => &mut pccb_document,
                "context" => &mut context_document,
                other => panic!("unsupported shared vector document: {other}"),
            };
            set_path(document, &mutation.path, mutation.value);
        }

        let verifier = Verifier::new(build_local_proof_verifier())
            .with_clock_skew_tolerance(Duration::milliseconds(vector.clock_skew_tolerance_ms))
            .expect("shared vector skew must be valid");
        let intent = parse_action_intent_json(
            &serde_json::to_vec(&intent_document).expect("intent must encode"),
        )
        .expect("intent must parse");
        let pccb = parse_pccb_json(&serde_json::to_vec(&pccb_document).expect("pccb must encode"))
            .expect("pccb must parse");
        let context = verifier
            .build_context(context_from_value(&context_document))
            .expect("context must parse");
        let result = verifier.verify(intent, pccb, context);

        if vector.expected.outcome == "verified" {
            let verified = result
                .unwrap_or_else(|error| panic!("{} expected verification, got {error}", vector.id));
            assert_eq!(verified.pccb.pccb_id, "pccb_portable_hello_world_001");
            continue;
        }

        let error = result.expect_err("shared refusal vector must fail");
        assert_eq!(
            error.code().as_str(),
            vector.expected.reason_code,
            "{} reason code",
            vector.id,
        );
        assert_eq!(
            error.message(),
            vector.expected.message,
            "{} public message",
            vector.id,
        );
    }
}

#[derive(Deserialize)]
struct TimestampCase {
    id: String,
    intent: String,
    pccb: String,
    context: Value,
    expected: Expected,
}

#[derive(Deserialize)]
struct TimestampManifest {
    clock_skew_tolerance_ms: i64,
    cases: Vec<TimestampCase>,
}

fn read_vector(name: &str) -> Vec<u8> {
    fs::read(vector_root().join(name))
        .unwrap_or_else(|error| panic!("failed to read shared vector {name}: {error}"))
}

fn load_timestamp_manifest() -> TimestampManifest {
    serde_json::from_slice(&read_vector("timestamp_cases.json"))
        .expect("failed to decode timestamp_cases.json")
}

// Kernel timestamp_cases.json: proofs minted with the ACTENON-JCS-STRICT-1
// label and fractional-second timestamps, plus microsecond window boundaries.
// The vendored intent and PCCB bytes are verified as-is (no re-encoding).
#[test]
fn shared_fractional_second_timestamp_vectors() {
    let manifest = load_timestamp_manifest();
    assert!(
        !manifest.cases.is_empty(),
        "timestamp_cases.json has no cases"
    );
    for vector in manifest.cases {
        let id = &vector.id;
        let pccb_raw = read_vector(&vector.pccb);
        let pccb_document: Value = serde_json::from_slice(&pccb_raw).expect("pccb must decode");
        let verifier = Verifier::new(build_local_proof_verifier())
            .with_clock_skew_tolerance(Duration::milliseconds(manifest.clock_skew_tolerance_ms))
            .expect("skew must be valid");
        let intent = parse_action_intent_json(&read_vector(&vector.intent))
            .unwrap_or_else(|error| panic!("{id}: intent must parse: {error}"));
        let pccb = parse_pccb_json(&pccb_raw)
            .unwrap_or_else(|error| panic!("{id}: pccb must parse: {error}"));
        let context = verifier
            .build_context(context_from_value(&vector.context))
            .expect("context must parse");
        let result = verifier.verify(intent, pccb, context);
        if vector.expected.outcome == "verified" {
            let verified =
                result.unwrap_or_else(|error| panic!("{id} expected verification, got {error}"));
            assert_eq!(
                verified.pccb.pccb_id, pccb_document["pccb_id"],
                "{id} pccb id"
            );
            assert_eq!(
                verified.pccb.action_hash.canonicalization, "ACTENON-JCS-STRICT-1",
                "{id} label"
            );
            continue;
        }
        let error = result.expect_err("timestamp refusal vector must fail");
        assert_eq!(
            error.code().as_str(),
            vector.expected.reason_code,
            "{id} reason code"
        );
        assert_eq!(
            error.message(),
            vector.expected.message,
            "{id} public message"
        );
    }
}

// Every JSON file in fixtures/verifier_sdk_v1 must be a manifest with a
// runner above or a document one of those manifests references, so a vector
// cannot be vendored without being executed.
#[test]
fn shared_verifier_vectors_are_all_executed() {
    let manifest: Manifest =
        serde_json::from_slice(&read_vector("cases.json")).expect("failed to decode manifest");
    let mut executed = vec![
        "cases.json".to_string(),
        "timestamp_cases.json".to_string(),
        manifest.base.intent,
        manifest.base.pccb,
    ];
    for vector in load_timestamp_manifest().cases {
        executed.push(vector.intent);
        executed.push(vector.pccb);
    }
    let mut orphans = Vec::new();
    for entry in fs::read_dir(vector_root()).expect("failed to list shared vectors") {
        let name = entry
            .expect("failed to read directory entry")
            .file_name()
            .into_string()
            .expect("vector file names are UTF-8");
        if name.ends_with(".json") && !executed.contains(&name) {
            orphans.push(name);
        }
    }
    assert!(
        orphans.is_empty(),
        "fixtures/verifier_sdk_v1 files vendored but executed by no runner: {orphans:?}"
    );
}
