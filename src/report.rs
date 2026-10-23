//! Finding data model, severities, and machine-readable report types.
//!
//! All public types are serialized with serde so a `Report` can be emitted as
//! structured JSON. Exit-code semantics are encoded as constants so that both
//! the CLI and integration tests agree on behavior.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Exit-code contract used by the `check` subcommand.
pub const EXIT_OK: i32 = 0; // no findings at the configured severity
pub const EXIT_FINDINGS: i32 = 1; // one or more findings at/above threshold
pub const EXIT_ERROR: i32 = 2; // bad input / IO error / internal failure

/// Impact potential if the finding is real. Ordered Critical -> Info.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Rank so that more severe = greater (Critical is greatest, Info least).
    fn rank(self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// How much static evidence supports the finding.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Whether the finding is backed by deterministic static evidence (`Static`) or
/// is a `ManualReview` recommendation where evidence is insufficient for a
/// definitive incompatibility claim.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Static,
    ManualReview,
}

/// A single analysis result for one rule at one location.
#[derive(Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub kind: Kind,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    pub explanation: String,
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitations: Option<String>,
}

impl Finding {
    /// Create a finding with required fields; callers chain `.location`/`.explanation`/`.sources`.
    pub fn new(
        rule_id: &str,
        title: &str,
        severity: Severity,
        confidence: Confidence,
        kind: Kind,
        file: &str,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            severity,
            confidence,
            kind,
            file: file.to_string(),
            line: None,
            column: None,
            snippet: None,
            explanation: String::new(),
            sources: Vec::new(),
            recommendation: None,
            limitations: None,
        }
    }

    pub fn location(mut self, line: usize, column: Option<usize>, snippet: Option<&str>) -> Self {
        self.line = Some(line);
        self.column = column;
        self.snippet = snippet
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        self
    }

    pub fn explanation(mut self, s: &str) -> Self {
        self.explanation = s.trim().to_string();
        self
    }

    pub fn sources(mut self, s: &[&str]) -> Self {
        self.sources = s.iter().map(|x| x.to_string()).collect();
        self
    }

    pub fn recommendation(mut self, s: &str) -> Self {
        self.recommendation = Some(s.trim().to_string());
        self
    }

    pub fn limitations(mut self, s: &str) -> Self {
        self.limitations = Some(s.trim().to_string());
        self
    }
}

/// Metadata describing a rule that is always included in the report header,
/// independent of whether any file triggered it.
#[derive(Serialize)]
pub struct RuleDef {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub status: String,
    pub protocol: String,
    pub cap: String,
    pub limitations: Option<String>,
}

/// Aggregate counts for a completed scan.
#[derive(Serialize)]
pub struct Summary {
    pub files_scanned: usize,
    pub files_with_findings: usize,
    pub findings: usize,
    #[serde(serialize_with = "severity_counts")]
    pub by_severity: BTreeMap<Severity, usize>,
    pub by_rule: BTreeMap<String, usize>,
}

fn severity_counts<S>(m: &BTreeMap<Severity, usize>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let plain: BTreeMap<&str, usize> = m.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    plain.serialize(s)
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Static => "static",
            Kind::ManualReview => "manual_review",
        }
    }
}

/// Top-level machine-readable report. `schema_version` is the single source of
/// truth for the JSON shape; consumers should gate on it.
#[derive(Serialize)]
pub struct Report {
    pub schema_version: String,
    pub tool: ToolMeta,
    pub target: TargetMeta,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub rules: Vec<RuleDef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<String>,
}

#[derive(Serialize)]
pub struct ToolMeta {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct TargetMeta {
    pub path: String,
    pub protocol_version: u32,
    pub protocol_name: &'static str,
    pub scanned_at_epoch: u64,
}

impl Report {
    pub fn new(path: String, rules: Vec<RuleDef>) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            tool: ToolMeta {
                name: "stellar-upgrade-radar",
                version: env!("CARGO_PKG_VERSION"),
            },
            target: TargetMeta {
                path,
                protocol_version: 30,
                protocol_name: "Bell",
                scanned_at_epoch: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
            summary: Summary {
                files_scanned: 0,
                files_with_findings: 0,
                findings: 0,
                by_severity: BTreeMap::new(),
                by_rule: BTreeMap::new(),
            },
            findings: Vec::new(),
            rules,
            notices: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
    }

    #[test]
    fn finding_builder_defaults() {
        let f = Finding::new(
            "SUR-X",
            "t",
            Severity::Medium,
            Confidence::Low,
            Kind::ManualReview,
            "p.rs",
        )
        .explanation("why")
        .sources(&["https://example.org"]);
        assert_eq!(f.explanation, "why");
        assert_eq!(f.sources.len(), 1);
        assert!(f.line.is_none());
        assert!(f.recommendation.is_none());
    }

    #[test]
    fn report_schema_is_1_0() {
        let r = Report::new(".".to_string(), Vec::new());
        assert_eq!(r.schema_version, "1.0");
        assert_eq!(r.target.protocol_version, 30);
        assert_eq!(r.target.protocol_name, "Bell");
    }
}
