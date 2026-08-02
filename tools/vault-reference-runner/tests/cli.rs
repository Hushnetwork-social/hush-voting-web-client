use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempCorpus {
    root: PathBuf,
}

impl TempCorpus {
    fn new() -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("hush-vault-runner-{}-{unique}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root).expect("remove stale temporary corpus");
        }
        copy_tree(&canonical_corpus(), &root);
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for TempCorpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn canonical_corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vault/v1")
        .canonicalize()
        .expect("canonical corpus")
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).expect("create temporary corpus");
    for entry in std::fs::read_dir(source).expect("read corpus") {
        let entry = entry.expect("corpus entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy corpus file");
        }
    }
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vault-reference-runner"))
        .args(arguments)
        .output()
        .expect("execute runner")
}

fn run_with_environment(arguments: &[&str], name: &str, value: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vault-reference-runner"))
        .args(arguments)
        .env(name, value)
        .output()
        .expect("execute runner")
}

#[test]
fn valid_corpus_report_is_sorted_complete_and_redacted() {
    let corpus = canonical_corpus();
    let report = std::env::temp_dir().join(format!("vault-report-{}.json", std::process::id()));
    let output = run(&[
        "--corpus",
        corpus.to_str().expect("corpus path"),
        "--check",
        "--report",
        report.to_str().expect("report path"),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = std::fs::read_to_string(&report).expect("report");
    let value: Value = serde_json::from_str(&text).expect("report JSON");
    assert_eq!(value["total"], 84);
    assert_eq!(value["passed"], true);
    let records = value["records"].as_array().expect("records");
    let keys: Vec<String> = records
        .iter()
        .map(|record| {
            format!(
                "{}:{}",
                record["category"].as_str().unwrap(),
                record["id"].as_str().unwrap()
            )
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    let categories: BTreeSet<&str> = records
        .iter()
        .map(|record| record["category"].as_str().unwrap())
        .collect();
    for category in [
        "integrity",
        "schema",
        "canonical",
        "algorithm",
        "password",
        "extension",
        "lifecycle",
        "migration",
        "session",
        "typed-result",
    ] {
        assert!(categories.contains(category), "missing category {category}");
    }
    for prohibited in [
        "correct horse battery staple",
        "password-bytes",
        "ordinary record payload",
        "public-test-channel",
        "Alice",
    ] {
        assert!(
            !text.contains(prohibited),
            "report leaked public vector value"
        );
    }
    let _ = std::fs::remove_file(report);
}

#[test]
fn manifest_mismatch_stops_before_vector_replay() {
    let corpus = TempCorpus::new();
    std::fs::OpenOptions::new()
        .append(true)
        .open(corpus.path("schemas/envelope.schema.json"))
        .expect("schema")
        .write_all(b"\n")
        .expect("tamper schema");
    let report = corpus.path("mismatch-report.json");
    let output = run(&[
        "--corpus",
        corpus.root.to_str().unwrap(),
        "--check",
        "--report",
        report.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value: Value =
        serde_json::from_slice(&std::fs::read(report).expect("report")).expect("JSON");
    assert!(value["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|record| record["category"] == "integrity"));
}

#[test]
fn wrong_manifest_pin_is_a_mismatch_and_missing_path_is_invalid() {
    let corpus = canonical_corpus();
    let output = run(&[
        "--corpus",
        corpus.to_str().unwrap(),
        "--check",
        "--expected-manifest-sha256",
        &"0".repeat(64),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let missing = run(&["--corpus", "/definitely/missing/vault-corpus", "--check"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&missing.stderr).contains("/definitely/missing"));
}

#[test]
fn duplicate_json_and_oversized_vectors_are_invalid_corpus() {
    let duplicate = TempCorpus::new();
    let path = duplicate.path("vectors/core-vectors.json");
    let original = std::fs::read_to_string(&path).expect("core vectors");
    let changed = original.replacen(
        "\"version\": \"1.0.0\",",
        "\"version\": \"1.0.0\", \"version\": \"1.0.0\",",
        1,
    );
    std::fs::write(&path, changed).expect("duplicate vector key");
    let output = run(&["--corpus", duplicate.root.to_str().unwrap(), "--check"]);
    assert_eq!(output.status.code(), Some(2));

    let oversized = TempCorpus::new();
    std::fs::write(
        oversized.path("vectors/core-vectors.json"),
        format!(
            "{{\"version\":\"1.0.0\",\"vectors\":[],\"padding\":\"{}\"}}",
            "x".repeat(1_048_576)
        ),
    )
    .expect("oversized vector");
    let output = run(&["--corpus", oversized.root.to_str().unwrap(), "--check"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn internal_report_failure_and_debug_panic_are_contained() {
    let corpus = canonical_corpus();
    let output = run(&[
        "--corpus",
        corpus.to_str().unwrap(),
        "--check",
        "--report",
        "/definitely/missing/report.json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("report-write-failed"));

    let panic = run_with_environment(
        &["--corpus", corpus.to_str().unwrap(), "--check"],
        "HUSH_VAULT_RUNNER_TEST_PANIC",
        "1",
    );
    assert_eq!(panic.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&panic.stderr);
    assert!(stderr.contains("panic-contained"));
    assert!(!stderr.contains("contained non-production test panic"));
}
