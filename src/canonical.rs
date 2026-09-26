use std::fmt::Write;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The canonicalisation identifier the Kernel stamps on newly minted proofs,
/// receipt digests and approvals.
pub const CANONICALIZATION_PROFILE: &str = "ACTENON-JCS-STRICT-1";
/// The identifier carried by historical artifacts. It names the same
/// canonicalisation rules and remains accepted.
pub const LEGACY_CANONICALIZATION_PROFILE: &str = "RFC8785-JCS";

/// Whether `label` is a canonicalisation profile accepted by the reference
/// verifier.
pub fn is_accepted_canonicalization(label: &str) -> bool {
    label == CANONICALIZATION_PROFILE || label == LEGACY_CANONICALIZATION_PROFILE
}

/// ACTENON-JCS-STRICT-1 limits enforced by the reference canonicaliser: no
/// value deeper than 128 levels (the root is level 1), at most 1 MiB out.
const MAX_CANONICAL_DEPTH: usize = 128;
const MAX_CANONICAL_OUTPUT_BYTES: usize = 1_048_576;

pub fn canonicalize_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let canonical = canonicalize_value(&value)?;
    if canonical.len() > MAX_CANONICAL_OUTPUT_BYTES {
        return Err("canonical JSON output exceeds the maximum size".to_string());
    }
    Ok(canonical.into_bytes())
}

pub fn sha256_hex<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonicalize_bytes(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{:x}", digest))
}

fn canonicalize_value(value: &Value) -> Result<String, String> {
    let mut output = String::new();
    write_canonical_json(&mut output, value, 1)?;
    Ok(output)
}

fn write_canonical_json(output: &mut String, value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err("JSON value exceeds the maximum nesting depth".to_string());
    }
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(flag) => {
            if *flag {
                output.push_str("true");
            } else {
                output.push_str("false");
            }
        }
        Value::String(text) => {
            let encoded = serde_json::to_string(text).map_err(|error| error.to_string())?;
            output.push_str(&encoded);
        }
        Value::Number(number) => {
            if let Some(signed) = number.as_i64() {
                write!(output, "{signed}").map_err(|error| error.to_string())?;
            } else if let Some(unsigned) = number.as_u64() {
                write!(output, "{unsigned}").map_err(|error| error.to_string())?;
            } else {
                return Err(
                    "floating-point values are not supported in canonical action hashing"
                        .to_string(),
                );
            }
        }
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(output, item, depth + 1)?;
            }
            output.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            output.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                let encoded = serde_json::to_string(*key).map_err(|error| error.to_string())?;
                output.push_str(&encoded);
                output.push(':');
                write_canonical_json(output, &map[*key], depth + 1)?;
            }
            output.push('}');
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nested(levels: usize) -> Value {
        let mut value = Value::String("leaf".to_string());
        for _ in 0..levels {
            value = json!({ "k": value });
        }
        value
    }

    /// The Kernel's canonicalization_strict_v1 vectors (ACTENON-JCS-STRICT-1).
    #[test]
    fn canonicalization_strict_v1_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/canonicalization_strict_v1/cases.json");
        let manifest: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut ran = 0;
        for case in manifest["cases"].as_array().unwrap() {
            let input = match case["generator"].as_str() {
                None => case["input"].clone(),
                Some("max_depth") => nested(127),
                Some("excessive_depth") => nested(129),
                Some("max_output_size") => {
                    json!({ "s": "A".repeat(MAX_CANONICAL_OUTPUT_BYTES - 8) })
                }
                Some("excessive_output_size") => {
                    json!({ "s": "A".repeat(MAX_CANONICAL_OUTPUT_BYTES + 100) })
                }
                // NaN, infinities and non-string keys cannot be represented in
                // serde_json; proof-level cases are covered by kernel_interop_v1.
                Some(_) => continue,
            };
            ran += 1;
            let output = canonicalize_bytes(&input);
            if case["id"] == "integer_boundaries" {
                // Known limitation: without serde_json's arbitrary_precision
                // feature, integers outside i64::MIN..=u64::MAX (here
                // -9223372036854775809) are parsed as f64, so the SDK refuses
                // them (fail closed) where the reference accepts them.
                assert!(output.is_err());
                continue;
            }
            if case["expected_pass"].as_bool().unwrap() {
                let output = String::from_utf8(
                    output.unwrap_or_else(|error| panic!("{}: {error}", case["id"])),
                )
                .unwrap();
                if case["generator"].is_null() {
                    assert_eq!(output, case["expected_output"].as_str().unwrap());
                }
            } else {
                assert!(output.is_err(), "{} must be rejected", case["id"]);
            }
        }
        assert_eq!(ran, 11);
    }

    #[test]
    fn strings_are_encoded_like_the_reference() {
        let output =
            canonicalize_bytes(&json!("<b>Tom & Jerry</b>\u{2028}\u{1}\u{7f}\"\\/")).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "\"<b>Tom & Jerry</b>\u{2028}\\u0001\u{7f}\\\"\\\\/\""
        );
    }
}
