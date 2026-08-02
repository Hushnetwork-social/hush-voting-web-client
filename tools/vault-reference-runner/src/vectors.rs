//! Manifest-first corpus replay across schemas, canonical/AAD bytes, suite primitives,
//! password policy, extensions, lifecycle/migration/generation, sessions, and typed results.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::path::{Component, Path};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

use crate::jcs::{canonicalize, hex_digest};
use crate::report::{Report, VectorRecord};
use crate::strict_json;
use crate::suite::{aes256gcm_encrypt, argon2id, hkdf_vector_sha256};

const MAX_CORPUS_FILE_BYTES: u64 = 1_048_576;
const MAX_MANIFEST_BYTES: u64 = 65_536;
const SUPPORTED_VERSION: &str = "1.0.0";

fn debug_stage(stage: &str) {
    if std::env::var_os("HUSH_VAULT_RUNNER_DEBUG").is_some() {
        eprintln!("vault-reference-runner: debug-stage:{stage}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerError {
    Corpus,
    Internal,
}

impl RunnerError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Corpus => "corpus read/validation failed",
            Self::Internal => "internal validation failure",
        }
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn digest_value(value: &Value) -> Result<String, RunnerError> {
    let canonical = canonicalize(value).map_err(|_| RunnerError::Internal)?;
    Ok(digest_bytes(canonical.as_bytes()))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, RunnerError> {
    let metadata = std::fs::metadata(path).map_err(|_| RunnerError::Corpus)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(RunnerError::Corpus);
    }
    std::fs::read(path).map_err(|_| RunnerError::Corpus)
}

fn read_json(path: &Path, maximum: u64) -> Result<Value, RunnerError> {
    let bytes = read_bounded(path, maximum)?;
    strict_json::parse(&bytes).map_err(|_| RunnerError::Corpus)
}

fn sha256_file(path: &Path) -> Result<String, RunnerError> {
    Ok(digest_bytes(&read_bounded(path, MAX_CORPUS_FILE_BYTES)?))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    contract_version: String,
    corpus_version: String,
    files: Vec<ManifestFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalVector {
    id: String,
    input: Value,
    expected_canonical: String,
    expected_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AadVector {
    id: String,
    input: Value,
    input_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuiteVector {
    id: String,
    kind: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    output_sha256: String,
    #[serde(default)]
    ciphertext_sha256: String,
    #[serde(default)]
    tag_sha256: String,
    #[serde(default)]
    password_utf8: String,
    #[serde(default)]
    salt_hex: String,
    #[serde(default, rename = "memoryKiB")]
    memory_kib: u32,
    #[serde(default)]
    iterations: u32,
    #[serde(default)]
    parallelism: u32,
    #[serde(default)]
    output_bytes: usize,
    #[serde(default)]
    key_hex: String,
    #[serde(default)]
    nonce_hex: String,
    #[serde(default)]
    plaintext_utf8: String,
    #[serde(default)]
    aad_vector_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasswordVector {
    id: String,
    kind: String,
    input: String,
    #[serde(default)]
    alias_terms: Vec<String>,
    expected: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoreVector {
    id: String,
    family: String,
    operation: String,
    input: Value,
    expected_code: String,
    #[serde(default)]
    expected_sha256: Option<String>,
}

fn versioned_vectors<T: for<'de> Deserialize<'de>>(
    path: &Path,
    key: &str,
) -> Result<Vec<T>, RunnerError> {
    let root = read_json(path, MAX_CORPUS_FILE_BYTES)?;
    if root.get("version").and_then(Value::as_str) != Some(SUPPORTED_VERSION) {
        return Err(RunnerError::Corpus);
    }
    serde_json::from_value(root.get(key).cloned().ok_or(RunnerError::Corpus)?)
        .map_err(|_| RunnerError::Corpus)
}

fn record_digest(
    report: &mut Report,
    id: String,
    category: &str,
    expected: String,
    actual: String,
) {
    report.record(VectorRecord {
        id,
        category: category.to_owned(),
        ok: expected == actual,
        expected_digest: Some(expected),
        actual_digest: Some(actual),
        expected_code: None,
        actual_code: None,
    });
}

fn record_code_and_digest(
    report: &mut Report,
    id: String,
    category: &str,
    expected_code: String,
    actual_code: String,
    expected_digest: Option<String>,
    actual_digest: Option<String>,
) {
    let digests_match = expected_digest == actual_digest;
    report.record(VectorRecord {
        id,
        category: category.to_owned(),
        ok: expected_code == actual_code && digests_match,
        expected_digest,
        actual_digest,
        expected_code: Some(expected_code),
        actual_code: Some(actual_code),
    });
}

fn collect_manifest_data_paths(root: &Path) -> Result<Vec<String>, RunnerError> {
    let mut paths = vec!["metadata.json".to_owned()];
    let schemas = root.join("schemas");
    for entry in std::fs::read_dir(schemas).map_err(|_| RunnerError::Corpus)? {
        let entry = entry.map_err(|_| RunnerError::Corpus)?;
        let file_type = entry.file_type().map_err(|_| RunnerError::Corpus)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if file_type.is_file() && name.ends_with(".json") {
            paths.push(format!("schemas/{name}"));
        }
    }
    paths.sort();
    Ok(paths)
}

fn validate_manifest_shape(manifest: &Manifest) -> Result<(), RunnerError> {
    if manifest.contract_version != SUPPORTED_VERSION
        || manifest.corpus_version != SUPPORTED_VERSION
        || manifest.files.is_empty()
        || manifest.files.len() > 128
    {
        return Err(RunnerError::Corpus);
    }
    let paths: Vec<&str> = manifest
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    if paths != sorted || paths.iter().collect::<HashSet<_>>().len() != paths.len() {
        return Err(RunnerError::Corpus);
    }
    for entry in &manifest.files {
        if !is_safe_relative_path(&entry.path)
            || entry.bytes > MAX_CORPUS_FILE_BYTES
            || !is_sha256(&entry.sha256)
        {
            return Err(RunnerError::Corpus);
        }
    }
    Ok(())
}

fn validate_integrity(
    root: &Path,
    manifest: &Manifest,
    report: &mut Report,
    expected_manifest_sha256: Option<&str>,
) -> Result<(), RunnerError> {
    if let Some(expected) = expected_manifest_sha256 {
        if !is_sha256(expected) {
            return Err(RunnerError::Corpus);
        }
        record_digest(
            report,
            "integrity:manifest-pin".to_owned(),
            "integrity",
            expected.to_owned(),
            report.manifest_sha256.clone(),
        );
    }

    let expected_paths: Vec<String> = manifest
        .files
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let actual_paths = collect_manifest_data_paths(root)?;
    record_digest(
        report,
        "integrity:file-set".to_owned(),
        "integrity",
        digest_bytes(expected_paths.join("\n").as_bytes()),
        digest_bytes(actual_paths.join("\n").as_bytes()),
    );

    for entry in &manifest.files {
        let absolute = root.join(&entry.path);
        let actual = if absolute.is_file() {
            sha256_file(&absolute).ok()
        } else {
            None
        };
        let size_matches = std::fs::metadata(&absolute)
            .map(|metadata| metadata.is_file() && metadata.len() == entry.bytes)
            .unwrap_or(false);
        report.record(VectorRecord {
            id: format!("integrity:{}", entry.path),
            category: "integrity".to_owned(),
            ok: actual.as_deref() == Some(entry.sha256.as_str()) && size_matches,
            expected_digest: Some(entry.sha256.clone()),
            actual_digest: actual,
            expected_code: None,
            actual_code: if size_matches {
                None
            } else {
                Some("invalid-size-or-missing".to_owned())
            },
        });
    }
    Ok(())
}

fn validate_schemas(
    root: &Path,
    manifest: &Manifest,
    report: &mut Report,
) -> Result<(), RunnerError> {
    for entry in manifest
        .files
        .iter()
        .filter(|entry| entry.path.starts_with("schemas/"))
    {
        let schema = read_json(&root.join(&entry.path), MAX_MANIFEST_BYTES)?;
        let valid = schema.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema")
            && schema.get("$id").and_then(Value::as_str).is_some()
            && schema.get("title").and_then(Value::as_str).is_some()
            && schema.is_object();
        report.record(VectorRecord {
            id: format!("schema:{}", entry.path),
            category: "schema".to_owned(),
            ok: valid,
            expected_digest: Some(entry.sha256.clone()),
            actual_digest: Some(sha256_file(&root.join(&entry.path))?),
            expected_code: Some("valid-draft-2020-12".to_owned()),
            actual_code: Some(
                if valid {
                    "valid-draft-2020-12"
                } else {
                    "invalid-schema"
                }
                .to_owned(),
            ),
        });
    }
    Ok(())
}

fn build_aad_metadata(input: &Value) -> Result<Value, RunnerError> {
    let object = input.as_object().ok_or(RunnerError::Corpus)?;
    let required = |key: &str| object.get(key).cloned().ok_or(RunnerError::Corpus);
    let kdf = object
        .get("kdfParameters")
        .and_then(Value::as_object)
        .ok_or(RunnerError::Corpus)?;
    let preview = object
        .get("preview")
        .and_then(Value::as_object)
        .ok_or(RunnerError::Corpus)?;
    let kdf_required = |key: &str| kdf.get(key).cloned().ok_or(RunnerError::Corpus);
    let preview_required = |key: &str| preview.get(key).cloned().ok_or(RunnerError::Corpus);

    let mut critical = object
        .get("criticalExtensions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    critical.sort_by(|left, right| left.as_str().cmp(&right.as_str()));

    Ok(json!({
        "envelopeFormatVersion": required("envelopeFormatVersion")?,
        "parameterSuiteVersion": required("parameterSuiteVersion")?,
        "recordSchemaVersion": required("recordSchemaVersion")?,
        "platformWrapperVersion": required("platformWrapperVersion")?,
        "suiteId": required("suiteId")?,
        "kdf": {
            "algorithm": kdf_required("algorithm")?,
            "memoryKiB": kdf_required("memoryKiB")?,
            "iterations": kdf_required("iterations")?,
            "parallelism": kdf_required("parallelism")?,
        },
        "adapterBinding": required("adapterBinding")?,
        "preview": {
            "alias": preview_required("alias")?,
            "signingAddressPrefix": preview_required("signingAddressPrefix")?,
            "signingAddressSuffix": preview_required("signingAddressSuffix")?,
            "lifecycleStatus": preview_required("lifecycleStatus")?,
            "envelopeFormatVersion": preview_required("envelopeFormatVersion")?,
            "parameterSuiteVersion": preview_required("parameterSuiteVersion")?,
            "recordSchemaVersion": preview_required("recordSchemaVersion")?,
        },
        "vaultGeneration": required("vaultGeneration")?,
        "recordGeneration": required("recordGeneration")?,
        "recordPurpose": required("recordPurpose")?,
        "producer": {
            "id": required("producerId")?,
            "version": required("producerVersion")?,
        },
        "signingAddress": required("signingAddress")?,
        "criticalExtensions": critical,
    }))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, RunnerError> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RunnerError::Corpus);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| RunnerError::Corpus)?;
            u8::from_str_radix(text, 16).map_err(|_| RunnerError::Corpus)
        })
        .collect()
}

fn replay_suite(
    root: &Path,
    vectors: Vec<SuiteVector>,
    report: &mut Report,
) -> Result<(), RunnerError> {
    let aad_vectors: Vec<AadVector> =
        versioned_vectors(&root.join("vectors/aad-vectors.json"), "vectors")?;
    for vector in vectors {
        debug_stage(&format!("suite-vector:{}", vector.id));
        let (expected, actual) = match vector.kind.as_str() {
            "hkdf" => (
                vector.output_sha256,
                hkdf_vector_sha256(&vector.label).map_err(|_| RunnerError::Internal)?,
            ),
            "argon2id" => {
                let salt = decode_hex(&vector.salt_hex)?;
                let output = argon2id(
                    vector.password_utf8.as_bytes(),
                    &salt,
                    vector.memory_kib,
                    vector.iterations,
                    vector.parallelism,
                    vector.output_bytes,
                )
                .map_err(|_| RunnerError::Internal)?;
                (vector.output_sha256, digest_bytes(&output))
            }
            "aes-gcm" => {
                let aad_input = aad_vectors
                    .iter()
                    .find(|aad| aad.id == vector.aad_vector_id)
                    .ok_or(RunnerError::Corpus)?;
                let aad = canonicalize(&build_aad_metadata(&aad_input.input)?)
                    .map_err(|_| RunnerError::Internal)?;
                let output = aes256gcm_encrypt(
                    &decode_hex(&vector.key_hex)?,
                    &decode_hex(&vector.nonce_hex)?,
                    vector.plaintext_utf8.as_bytes(),
                    aad.as_bytes(),
                )
                .map_err(|_| RunnerError::Internal)?;
                let (ciphertext, tag) = output.split_at(output.len() - 16);
                let expected = digest_bytes(
                    format!("{}:{}", vector.ciphertext_sha256, vector.tag_sha256).as_bytes(),
                );
                let actual = digest_bytes(
                    format!("{}:{}", digest_bytes(ciphertext), digest_bytes(tag)).as_bytes(),
                );
                (expected, actual)
            }
            _ => return Err(RunnerError::Corpus),
        };
        record_digest(report, vector.id, "algorithm", expected, actual);
    }
    Ok(())
}

fn comparison_representation(input: &str) -> String {
    input.nfkc().collect::<String>().to_lowercase()
}

fn local_strength_score(value: &str) -> u8 {
    let length = value.encode_utf16().count();
    let unique = value.chars().collect::<BTreeSet<_>>().len();
    if length == 0 || length <= 6 {
        0
    } else if length <= 8 && (unique as f64 / length as f64) < 0.5 {
        1
    } else if length <= 10 {
        2
    } else if length <= 14 {
        3
    } else {
        4
    }
}

fn is_identity_derived(value: &str, aliases: &[String]) -> bool {
    aliases.iter().any(|term| {
        let alias = comparison_representation(term);
        if alias.chars().count() < 4 {
            return false;
        }
        if value == alias {
            return true;
        }
        let suffix = value.strip_prefix(&alias).unwrap_or_default();
        let prefix = value.strip_suffix(&alias).unwrap_or_default();
        let numeric = |candidate: &str| {
            !candidate.is_empty()
                && candidate.len() <= 4
                && candidate.bytes().all(|byte| byte.is_ascii_digit())
        };
        numeric(prefix) || numeric(suffix)
    })
}

fn password_policy(input: &str, aliases: &[String]) -> Value {
    const COMMON: &[&str] = &[
        "password",
        "password1",
        "password123",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "abc123",
        "letmein",
        "admin",
        "welcome",
        "monkey",
        "dragon",
        "iloveyou",
        "sunshine",
        "princess",
        "football",
        "baseball",
    ];
    let comparison = comparison_representation(input);
    if COMMON.contains(&comparison.as_str()) {
        return json!({ "ok": false, "code": "COMMON_PASSWORD" });
    }
    if is_identity_derived(&comparison, aliases) {
        return json!({ "ok": false, "code": "IDENTITY_DERIVED" });
    }
    let score = local_strength_score(&comparison);
    json!({ "ok": true, "score": score, "requiresAcknowledgement": score <= 1 })
}

fn password_unicode(input: &str) -> Value {
    let normalized = input.nfc().collect::<String>();
    let graphemes = UnicodeSegmentation::graphemes(normalized.as_str(), true).count();
    let bytes = normalized.len();
    if graphemes < 6 {
        json!({ "ok": false, "code": "TOO_FEW_GRAPHEMES" })
    } else if graphemes > 64 {
        json!({ "ok": false, "code": "TOO_MANY_GRAPHEMES" })
    } else if bytes > 256 {
        json!({ "ok": false, "code": "TOO_MANY_BYTES" })
    } else {
        json!({
            "ok": true,
            "normalizedNfc": normalized,
            "graphemes": graphemes,
            "utf8Bytes": bytes,
        })
    }
}

fn replay_password(vectors: Vec<PasswordVector>, report: &mut Report) -> Result<(), RunnerError> {
    for vector in vectors {
        let actual = match vector.kind.as_str() {
            "unicode" => password_unicode(&vector.input),
            "policy" => password_policy(&vector.input, &vector.alias_terms),
            _ => return Err(RunnerError::Corpus),
        };
        record_digest(
            report,
            vector.id,
            "password",
            digest_value(&vector.expected)?,
            digest_value(&actual)?,
        );
    }
    Ok(())
}

fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn extension_result(input: &Value) -> Result<(String, Option<Value>), RunnerError> {
    let container = input.get("container").ok_or(RunnerError::Corpus)?;
    let known: HashSet<&str> = input
        .get("knownExtensions")
        .and_then(Value::as_array)
        .ok_or(RunnerError::Corpus)?
        .iter()
        .map(|value| value.as_str().ok_or(RunnerError::Corpus))
        .collect::<Result<_, _>>()?;
    let extensions = container
        .get("extensions")
        .and_then(Value::as_object)
        .ok_or(RunnerError::Corpus)?;
    let critical = container
        .get("criticalExtensions")
        .and_then(Value::as_array)
        .ok_or(RunnerError::Corpus)?;
    let critical_names: Vec<&str> = critical
        .iter()
        .map(|value| value.as_str().ok_or(RunnerError::Corpus))
        .collect::<Result<_, _>>()?;
    let unique: HashSet<&str> = critical_names.iter().copied().collect();
    let structurally_valid = extensions.len() <= 16
        && critical_names.len() <= 16
        && unique.len() == critical_names.len()
        && extensions.keys().all(|key| valid_namespace(key))
        && critical_names
            .iter()
            .all(|name| valid_namespace(name) && extensions.contains_key(*name));
    if !structurally_valid {
        return Ok(("INVALID_EXTENSIONS".to_owned(), None));
    }
    if critical_names.iter().any(|name| !known.contains(name)) {
        return Ok(("ExtensionUnsupported".to_owned(), None));
    }
    Ok(("OK".to_owned(), Some(container.clone())))
}

fn lifecycle_state(input: &Value) -> Result<Value, RunnerError> {
    input.get("state").cloned().ok_or(RunnerError::Corpus)
}

fn lifecycle_result(
    operation: &str,
    input: &Value,
) -> Result<(String, Option<Value>), RunnerError> {
    if operation == "passwordChange" {
        let count = input
            .get("rewrappedRecordCount")
            .and_then(Value::as_u64)
            .ok_or(RunnerError::Corpus)?;
        return Ok((
            "OK".to_owned(),
            Some(json!({
                "rewrappedRecordCount": count,
                "payloadsReEncrypted": 0,
                "identityChanged": false,
            })),
        ));
    }
    let state = lifecycle_state(input)?;
    let status = state
        .get("status")
        .and_then(Value::as_str)
        .ok_or(RunnerError::Corpus)?;
    match operation {
        "stagePendingRegistration" => {
            if status != "NoVault" {
                Ok(("INVALID_TRANSITION".to_owned(), Some(state)))
            } else if input.get("verified").and_then(Value::as_bool) != Some(true) {
                Ok(("NOT_VERIFIED".to_owned(), Some(state)))
            } else {
                Ok((
                    "OK".to_owned(),
                    Some(json!({ "status": "PendingRegistration", "pendingSubmission": false })),
                ))
            }
        }
        "beginSubmission" => {
            if status != "PendingRegistration" {
                Ok(("INVALID_TRANSITION".to_owned(), Some(state)))
            } else {
                Ok((
                    "OK".to_owned(),
                    Some(json!({ "status": status, "pendingSubmission": true })),
                ))
            }
        }
        "reconcileToActive" => {
            if status != "PendingRegistration" {
                Ok(("INVALID_TRANSITION".to_owned(), Some(state)))
            } else if input.get("confirmed").and_then(Value::as_bool) != Some(true) {
                Ok(("VERIFICATION_FAILED".to_owned(), Some(state)))
            } else {
                Ok((
                    "OK".to_owned(),
                    Some(json!({ "status": "Active", "pendingSubmission": false })),
                ))
            }
        }
        "completeRemoval" => Ok((
            "OK".to_owned(),
            Some(json!({ "status": "NoVault", "pendingSubmission": false })),
        )),
        _ => Err(RunnerError::Corpus),
    }
}

fn migration_result(input: &Value) -> Result<(String, Option<Value>), RunnerError> {
    let version = input.get("version").ok_or(RunnerError::Corpus)?;
    let supported = version.get("envelopeFormatVersion").and_then(Value::as_u64) == Some(1)
        && version.get("parameterSuiteVersion").and_then(Value::as_u64) == Some(1)
        && version.get("recordSchemaVersion").and_then(Value::as_u64) == Some(1)
        && version
            .get("platformWrapperVersion")
            .and_then(Value::as_u64)
            == Some(0);
    if supported {
        Ok((
            "OK".to_owned(),
            Some(json!({ "readable": true, "target": version })),
        ))
    } else {
        Ok(("UnsupportedVaultVersion".to_owned(), None))
    }
}

fn generation_summary(
    active: Option<u64>,
    rollback: Option<u64>,
    generation: u64,
    verified: bool,
) -> Value {
    json!({
        "activeSlotGeneration": active,
        "rollbackSlotGeneration": rollback,
        "activeGeneration": generation,
        "newSlotVerified": verified,
    })
}

fn generation_result(input: &Value) -> Result<(String, Option<Value>), RunnerError> {
    let state = input.get("state").ok_or(RunnerError::Corpus)?;
    let active = state.get("activeSlotGeneration").and_then(Value::as_u64);
    let rollback = state.get("rollbackSlotGeneration").and_then(Value::as_u64);
    let generation = state
        .get("activeGeneration")
        .and_then(Value::as_u64)
        .ok_or(RunnerError::Corpus)?;
    let verified = state
        .get("newSlotVerified")
        .and_then(Value::as_bool)
        .ok_or(RunnerError::Corpus)?;
    let expected = input
        .get("expectedGeneration")
        .and_then(Value::as_u64)
        .ok_or(RunnerError::Corpus)?;
    let new_generation = input
        .get("newGeneration")
        .and_then(Value::as_u64)
        .ok_or(RunnerError::Corpus)?;
    let current = generation_summary(active, rollback, generation, verified);
    if active.is_some() && (generation != expected || new_generation <= generation) {
        return Ok(("GENERATION_CONFLICT".to_owned(), Some(current)));
    }
    for (field, code) in [
        ("writeOk", "WRITE_FAILED"),
        ("verifyOk", "VERIFY_FAILED"),
        ("switchOk", "SWITCH_FAILED"),
    ] {
        if input.get(field).and_then(Value::as_bool) != Some(true) {
            return Ok((code.to_owned(), Some(current)));
        }
    }
    let output = if let Some(previous) = active {
        generation_summary(Some(new_generation), Some(previous), new_generation, false)
    } else {
        generation_summary(Some(new_generation), None, new_generation, true)
    };
    Ok(("OK".to_owned(), Some(output)))
}

fn session_result(operation: &str, input: &Value) -> Result<(String, Option<Value>), RunnerError> {
    let state = input.get("state").cloned().ok_or(RunnerError::Corpus)?;
    let epoch = state
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or(RunnerError::Corpus)?;
    let phase = state
        .get("phase")
        .and_then(Value::as_str)
        .ok_or(RunnerError::Corpus)?;
    let fresh = state.get("fresh").cloned().unwrap_or_else(|| json!({}));
    match operation {
        "localUnlock" => {
            if phase != "Locked" {
                Ok(("INVALID_PHASE_TRANSITION".to_owned(), None))
            } else {
                Ok((
                    "OK".to_owned(),
                    Some(json!({ "epoch": epoch, "phase": "VerificationOnly", "fresh": fresh })),
                ))
            }
        }
        "exactOnlineVerification" => {
            if phase != "VerificationOnly" && phase != "Authenticated" {
                Ok(("INVALID_PHASE_TRANSITION".to_owned(), None))
            } else {
                Ok((
                    "OK".to_owned(),
                    Some(json!({ "epoch": epoch, "phase": "Authenticated", "fresh": fresh })),
                ))
            }
        }
        "invalidate" => Ok((
            "OK".to_owned(),
            Some(json!({ "epoch": epoch + 1, "phase": "Locked", "fresh": {} })),
        )),
        "freshPassword" => {
            let channel = input
                .get("channelId")
                .and_then(Value::as_str)
                .ok_or(RunnerError::Corpus)?;
            let purpose = input
                .get("purpose")
                .and_then(Value::as_str)
                .ok_or(RunnerError::Corpus)?;
            let now = input
                .get("nowMs")
                .and_then(Value::as_u64)
                .ok_or(RunnerError::Corpus)?;
            if !["mnemonic-reveal", "password-change", "local-user-removal"].contains(&purpose) {
                return Ok(("OperationForbidden".to_owned(), None));
            }
            let mut fresh_object = fresh.as_object().cloned().ok_or(RunnerError::Corpus)?;
            fresh_object.insert(
                channel.to_owned(),
                json!({ "purpose": purpose, "expiresAtMs": now + 60_000, "consumed": false }),
            );
            Ok((
                "OK".to_owned(),
                Some(
                    json!({ "epoch": epoch, "phase": "FreshPasswordVerified", "fresh": fresh_object }),
                ),
            ))
        }
        "consumeFreshPassword" => {
            let channel = input
                .get("channelId")
                .and_then(Value::as_str)
                .ok_or(RunnerError::Corpus)?;
            let purpose = input
                .get("purpose")
                .and_then(Value::as_str)
                .ok_or(RunnerError::Corpus)?;
            let now = input
                .get("nowMs")
                .and_then(Value::as_u64)
                .ok_or(RunnerError::Corpus)?;
            let mut fresh_object = fresh.as_object().cloned().ok_or(RunnerError::Corpus)?;
            let capability = fresh_object.get(channel).cloned();
            let Some(mut capability) = capability else {
                return Ok(("OperationForbidden".to_owned(), None));
            };
            let valid = capability.get("consumed").and_then(Value::as_bool) == Some(false)
                && capability
                    .get("expiresAtMs")
                    .and_then(Value::as_u64)
                    .is_some_and(|expiry| now <= expiry)
                && capability.get("purpose").and_then(Value::as_str) == Some(purpose);
            if !valid {
                return Ok(("OperationForbidden".to_owned(), None));
            }
            capability["consumed"] = Value::Bool(true);
            fresh_object.insert(channel.to_owned(), capability);
            Ok((
                "OK".to_owned(),
                Some(json!({ "epoch": epoch, "phase": "Authenticated", "fresh": fresh_object })),
            ))
        }
        _ => Err(RunnerError::Corpus),
    }
}

fn typed_result_meta(code: &str) -> Option<Value> {
    let (retryable, actions): (bool, &[&str]) = match code {
        "NoVault" => (false, &["reprovision"]),
        "UnsupportedVaultVersion" => (false, &[]),
        "MalformedEnvelope" => (true, &["reprovision"]),
        "WrongPasswordOrDamagedData" => (true, &["retry", "reprovision"]),
        "Throttled" => (true, &["retry"]),
        "KdfResourceLimit" => (true, &["verifyOnline"]),
        "PlatformProtectionUnavailable" => (true, &["unlockPlatformProtection", "retry"]),
        "PlatformProtectionInvalidated" => (false, &["reprovision"]),
        "IdentityBindingMismatch" => (false, &["reprovision"]),
        "MigrationFailedRollbackAvailable" => (true, &["retry"]),
        "GenerationConflict" => (true, &["retry"]),
        "StorageUnavailable" => (true, &["retry"]),
        "StorageQuotaExceeded" | "PersistenceDenied" => (true, &["requestPersistence"]),
        "StaleSession" => (true, &["retry"]),
        "OperationForbidden" => (false, &[]),
        "CleanupFailed" => (true, &["retry", "resumeRemoval"]),
        "ExtensionUnsupported" => (false, &[]),
        _ => return None,
    };
    Some(json!({ "code": code, "retryable": retryable, "allowedActions": actions }))
}

fn core_result(vector: &CoreVector) -> Result<(String, Option<Value>), RunnerError> {
    match vector.family.as_str() {
        "extension" => extension_result(&vector.input),
        "lifecycle" => lifecycle_result(&vector.operation, &vector.input),
        "migration" => migration_result(&vector.input),
        "generation" => generation_result(&vector.input),
        "session" => session_result(&vector.operation, &vector.input),
        "typed-result" => {
            let code = vector
                .input
                .get("code")
                .and_then(Value::as_str)
                .ok_or(RunnerError::Corpus)?;
            Ok(("OK".to_owned(), typed_result_meta(code)))
        }
        _ => Err(RunnerError::Corpus),
    }
}

fn replay_core(vectors: Vec<CoreVector>, report: &mut Report) -> Result<(), RunnerError> {
    for vector in vectors {
        let (actual_code, actual_value) = core_result(&vector)?;
        let actual_digest = actual_value.as_ref().map(digest_value).transpose()?;
        let category = match vector.family.as_str() {
            "generation" | "lifecycle" => "lifecycle",
            other => other,
        };
        record_code_and_digest(
            report,
            vector.id,
            category,
            vector.expected_code,
            actual_code,
            vector.expected_sha256,
            actual_digest,
        );
    }
    Ok(())
}

pub fn run_corpus_validation(
    corpus: &str,
    expected_manifest_sha256: Option<&str>,
) -> Result<Report, RunnerError> {
    let root = Path::new(corpus);
    let manifest_path = root.join("manifest.json");
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest_sha256 = digest_bytes(&manifest_bytes);
    let manifest_value = strict_json::parse(&manifest_bytes).map_err(|_| RunnerError::Corpus)?;
    let manifest: Manifest =
        serde_json::from_value(manifest_value).map_err(|_| RunnerError::Corpus)?;
    validate_manifest_shape(&manifest)?;
    debug_stage("manifest");

    let mut report = Report::new(manifest_sha256);
    validate_integrity(root, &manifest, &mut report, expected_manifest_sha256)?;
    debug_stage("integrity");
    report.finish();
    if !report.passed {
        return Ok(report);
    }

    validate_schemas(root, &manifest, &mut report)?;
    debug_stage("schemas");
    report.finish();
    if !report.passed {
        return Ok(report);
    }

    let canonical_vectors: Vec<CanonicalVector> =
        versioned_vectors(&root.join("vectors/canonical-byte-vectors.json"), "vectors")?;
    for vector in canonical_vectors {
        let actual = canonicalize(&vector.input).map_err(|_| RunnerError::Internal)?;
        let actual_digest = digest_bytes(actual.as_bytes());
        let expected_digest = digest_bytes(vector.expected_canonical.as_bytes());
        let digest_matches = actual_digest == vector.expected_sha256;
        report.record(VectorRecord {
            id: vector.id,
            category: "canonical".to_owned(),
            ok: actual == vector.expected_canonical && digest_matches,
            expected_digest: Some(expected_digest),
            actual_digest: Some(actual_digest),
            expected_code: None,
            actual_code: None,
        });
    }

    debug_stage("canonical");

    let aad_vectors: Vec<AadVector> =
        versioned_vectors(&root.join("vectors/aad-vectors.json"), "vectors")?;
    for vector in aad_vectors {
        let actual = digest_value(&build_aad_metadata(&vector.input)?)?;
        record_digest(
            &mut report,
            vector.id,
            "canonical",
            vector.input_sha256,
            actual,
        );
    }
    debug_stage("aad");

    let suite_vectors: Vec<SuiteVector> =
        versioned_vectors(&root.join("vectors/suite-vectors.json"), "vectors")?;
    debug_stage("suite-parsed");
    replay_suite(root, suite_vectors, &mut report)?;
    debug_stage("suite");

    let password_vectors: Vec<PasswordVector> =
        versioned_vectors(&root.join("vectors/password-vectors.json"), "vectors")?;
    replay_password(password_vectors, &mut report)?;
    debug_stage("password");

    let core_vectors: Vec<CoreVector> =
        versioned_vectors(&root.join("vectors/core-vectors.json"), "vectors")?;
    replay_core(core_vectors, &mut report)?;
    debug_stage("core");

    report.finish();
    Ok(report)
}
