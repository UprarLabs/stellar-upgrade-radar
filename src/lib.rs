//! stellar-upgrade-radar — evidence-driven static analysis for Stellar
//! protocol upgrade compatibility and application readiness.
//!
//! Public API:
//! - [`analyze`] runs the full rule set over a directory and returns a
//!   [`Report`].
//! - [`report`], [`rules`], [`scan`], [`sources`] are exposed for tests.

pub mod report;
pub mod rules;
pub mod sarif;
pub mod scan;
pub mod sources;

use std::path::Path;

use report::{Report, RuleDef, Severity};

/// Severity floor returned as findings. Findings below this severity are
/// omitted from the report (they still count toward nothing).
pub fn analyze(root: &Path, min_severity: Severity) -> Report {
    let mut report = Report::new(root.to_string_lossy().to_string(), rules_meta());
    let rules = rules::registry();

    let files = scan::collect_files(root);
    let mut files_with_findings = 0;
    let mut by_rule: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for path in &files {
        let Some(ctx) = scan::context_for(root, path) else {
            continue;
        };
        report.summary.files_scanned += 1;

        let mut file_had = false;
        for rule in &rules {
            for finding in rule.scan(&ctx) {
                if finding.severity < min_severity {
                    continue;
                }
                let id = finding.rule_id.clone();
                report.findings.push(finding);
                *by_rule.entry(id).or_insert(0) += 1;
                file_had = true;
            }
        }
        if file_had {
            files_with_findings += 1;
        }
    }

    for f in &report.findings {
        *report.summary.by_severity.entry(f.severity).or_insert(0) += 1;
    }
    report.summary.files_with_findings = files_with_findings;
    report.summary.findings = report.findings.len();
    report.summary.by_rule = by_rule
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();

    // Honest framing about the tool's present capability.
    report.notices.push(
        "Protocol 30 (Bell) mainnet activation is scheduled for 2026-11-23; this scan is \
         static and cannot detect runtime-only incompatibilities."
            .to_string(),
    );
    report.notices.push(
        "No finding replaces an integration test against a Protocol 30 node or SDK.".to_string(),
    );

    report
}

/// Build the rule catalogue header from the registered rule list.
fn rules_meta() -> Vec<RuleDef> {
    rules::registry()
        .iter()
        .map(|r| RuleDef {
            id: r.id().to_string(),
            title: r.title().to_string(),
            description: r.description().to_string(),
            severity: r.severity(),
            status: r.status().to_string(),
            protocol: r.protocol().to_string(),
            cap: r.cap().to_string(),
            limitations: r.limitations().map(|s| s.to_string()),
        })
        .collect()
}

/// Human-readable severity parse for the CLI.
pub fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        _ => Err(format!("unknown severity: {s}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn analyze_ends_with_notice_and_meta() {
        let dir = std::env::temp_dir().join("sur_analyze_smoke");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[dependencies]\nstellar-xdr = \"28.0.1\"\n",
        )
        .unwrap();
        let report = analyze(&dir, Severity::Info);
        assert!(!report.rules.is_empty());
        assert!(report.notices.iter().any(|n| n.contains("static")));
        let found = report.findings.iter().any(|f| f.rule_id == "SUR-1002");
        assert!(found);
    }
}
