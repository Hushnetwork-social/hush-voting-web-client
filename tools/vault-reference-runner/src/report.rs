//! Deterministic secret-safe conformance reports.
//!
//! Serialized reports conform to `conformance/vault/v1/schemas/report.schema.json`.
//! Records contain stable identifiers, codes, and SHA-256 digests only.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorRecord {
    pub id: String,
    pub category: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u8,
    pub generator: String,
    pub corpus_version: String,
    pub manifest_sha256: String,
    pub passed: bool,
    pub total: u32,
    pub records: Vec<VectorRecord>,
    /// Internal summary field. The report schema derives this from failed records and
    /// intentionally does not serialize an additional property.
    #[serde(skip)]
    pub mismatches: u32,
}

impl Report {
    pub fn new(manifest_sha256: String) -> Self {
        Self {
            schema_version: 1,
            generator: "hush-vault-rust-reference".to_owned(),
            corpus_version: "1.0.0".to_owned(),
            manifest_sha256,
            passed: true,
            total: 0,
            records: Vec::new(),
            mismatches: 0,
        }
    }

    pub fn record(&mut self, record: VectorRecord) {
        self.records.push(record);
    }

    /// Sort records and recalculate all summaries so output is independent of filesystem
    /// and input insertion order.
    pub fn finish(&mut self) {
        self.records
            .sort_by(|left, right| (&left.category, &left.id).cmp(&(&right.category, &right.id)));
        self.total = self.records.len() as u32;
        self.mismatches = self.records.iter().filter(|record| !record.ok).count() as u32;
        self.passed = self.total > 0 && self.mismatches == 0;
    }
}

pub fn render_summary(report: &Report) -> String {
    format!(
        "VAULT RUST CONFORMANCE {} (generator={}, corpus={}, manifest={}, total={}, mismatches={})",
        if report.passed { "PASS" } else { "FAIL" },
        report.generator,
        report.corpus_version,
        &report.manifest_sha256[..16.min(report.manifest_sha256.len())],
        report.total,
        report.mismatches
    )
}

pub fn write_report(path: &str, report: &Report) -> Result<(), Box<dyn std::error::Error>> {
    let mut json = serde_json::to_string_pretty(report)?;
    json.push('\n');
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_shape_is_camel_case_and_schema_closed() {
        let mut report = Report::new("0".repeat(64));
        report.record(VectorRecord {
            id: "C-001".to_owned(),
            category: "canonical".to_owned(),
            ok: true,
            expected_digest: Some("1".repeat(64)),
            actual_digest: Some("1".repeat(64)),
            expected_code: None,
            actual_code: None,
        });
        report.finish();
        let value = serde_json::to_value(report).expect("serialize report");
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["manifestSha256"], "0".repeat(64));
        assert!(value.get("schema_version").is_none());
        assert!(value.get("mismatches").is_none());
        assert!(value["records"][0].get("expectedDigest").is_some());
    }
}
