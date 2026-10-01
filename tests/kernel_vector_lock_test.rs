use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

// Fixture suites vendored from actenon-kernel whose files the kernel's hash
// lock (conformance/vector-lock.json) covers: fixtures/ directory and the
// matching directory in the kernel repository.
const LOCKED_KERNEL_SUITES: &[(&str, &str)] = &[
    (
        "receipt_countersignature_v1",
        "conformance/vectors/receipt_countersignature_v1",
    ),
    (
        "transparency_log_v1",
        "conformance/vectors/transparency_log_v1",
    ),
    (
        "trust_artifacts_v1",
        "conformance/vectors/trust_artifacts_v1",
    ),
    (
        "verifier_sdk_v1",
        "actenon/conformance/vectors/verifier_sdk_v1",
    ),
];

// Names a kernel vector-lock.json to check against instead of the vendored
// copy; CI sets it to the lock downloaded from the kernel at
// fixtures/KERNEL_PIN.
const KERNEL_VECTOR_LOCK_ENV: &str = "ACTENON_KERNEL_VECTOR_LOCK";

#[derive(Deserialize)]
struct KernelVectorLock {
    algorithm: String,
    schema_version: u32,
    files: BTreeMap<String, String>,
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn read_fixture(rel: &str) -> Vec<u8> {
    fs::read(fixtures_root().join(rel))
        .unwrap_or_else(|error| panic!("failed to read fixtures/{rel}: {error}"))
}

// fixtures/KERNEL_UNLOCKED: fixtures-relative path -> kernel path.
fn read_kernel_unlocked() -> BTreeMap<String, String> {
    let text =
        String::from_utf8(read_fixture("KERNEL_UNLOCKED")).expect("KERNEL_UNLOCKED is UTF-8");
    let mut unlocked = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 2, "malformed KERNEL_UNLOCKED line: {line:?}");
        unlocked.insert(fields[0].to_string(), fields[1].to_string());
    }
    unlocked
}

fn walk_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display())) {
        let path = entry.expect("failed to read directory entry").path();
        if path.is_dir() {
            walk_files(&path, files);
        } else {
            files.push(path);
        }
    }
}

// Every vendored kernel fixture must be byte-identical to what the kernel's
// hash lock records at fixtures/KERNEL_PIN; every file the lock records for a
// vendored suite must be vendored; and any other file in a vendored kernel
// suite must be listed in KERNEL_UNLOCKED (and must really be unlocked).
#[test]
fn vendored_kernel_vectors_match_kernel_lock() {
    let pin = String::from_utf8(read_fixture("KERNEL_PIN")).expect("KERNEL_PIN is UTF-8");
    let pin = pin.trim();
    assert!(
        pin.len() == 40
            && pin
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "fixtures/KERNEL_PIN must be a full 40-hex commit SHA, got {pin:?}"
    );

    let vendored_lock = read_fixture("kernel_vector_lock.json");
    let lock_raw = match std::env::var_os(KERNEL_VECTOR_LOCK_ENV) {
        Some(path) => {
            let raw = fs::read(&path).unwrap_or_else(|error| {
                panic!("failed to read {KERNEL_VECTOR_LOCK_ENV}={path:?}: {error}")
            });
            assert!(
                raw == vendored_lock,
                "fixtures/kernel_vector_lock.json differs from {path:?} (kernel lock at {pin})"
            );
            raw
        }
        None => vendored_lock,
    };
    let lock: KernelVectorLock =
        serde_json::from_slice(&lock_raw).expect("failed to decode kernel vector lock");
    assert!(
        lock.algorithm == "sha256" && lock.schema_version == 1 && !lock.files.is_empty(),
        "unexpected kernel vector lock: algorithm={:?} schema_version={} files={}",
        lock.algorithm,
        lock.schema_version,
        lock.files.len()
    );

    let mut failures = Vec::new();
    let mut covered = BTreeSet::new();
    for (kernel_path, digest) in &lock.files {
        for (suite, kernel_dir) in LOCKED_KERNEL_SUITES {
            let Some(rest) = kernel_path.strip_prefix(&format!("{kernel_dir}/")) else {
                continue;
            };
            let rel = format!("{suite}/{rest}");
            match fs::read(fixtures_root().join(&rel)) {
                Ok(raw) => {
                    let got = format!("{:x}", Sha256::digest(&raw));
                    if &got != digest {
                        failures.push(format!(
                            "fixtures/{rel} sha256 {got}, kernel lock at {pin} records {digest} for {kernel_path}"
                        ));
                    }
                }
                Err(_) => failures.push(format!(
                    "fixtures/{rel} is missing: the kernel lock at {pin} records {kernel_path}"
                )),
            }
            covered.insert(rel);
        }
    }

    let mut suites: BTreeSet<String> = LOCKED_KERNEL_SUITES
        .iter()
        .map(|(suite, _)| suite.to_string())
        .collect();
    for (rel, kernel_path) in read_kernel_unlocked() {
        if lock.files.contains_key(&kernel_path) {
            failures.push(format!(
                "{kernel_path} is hash-locked by the kernel at {pin}; remove fixtures/{rel} from KERNEL_UNLOCKED"
            ));
        }
        if !fixtures_root().join(&rel).is_file() {
            failures.push(format!(
                "KERNEL_UNLOCKED lists fixtures/{rel}, which is missing"
            ));
        }
        suites.insert(rel.split('/').next().expect("non-empty path").to_string());
        covered.insert(rel);
    }

    for suite in suites {
        let mut files = Vec::new();
        walk_files(&fixtures_root().join(&suite), &mut files);
        for path in files {
            let rel = path
                .strip_prefix(fixtures_root())
                .expect("walked path is under fixtures/")
                .components()
                .map(|component| component.as_os_str().to_str().expect("UTF-8 path"))
                .collect::<Vec<_>>()
                .join("/");
            if !covered.contains(&rel) {
                failures.push(format!(
                    "fixtures/{rel} is neither in the kernel lock at {pin} nor in KERNEL_UNLOCKED"
                ));
            }
        }
    }

    failures.sort();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
