//! SUR-1002 — SDK / XDR dependency readiness under Protocol 30.
//!
//! Evidence-based rule: `stellar-xdr` crate 30.0.0 and `soroban-sdk` 30.x carry
//! the CAP-84/CAP-88 XDR (verified against crates.io). For Rust crates we compare
//! the numeric major against verified release lines. For every other ecosystem we
//! emit a manual-review note only, because we do NOT claim a specific minimum
//! version without verified evidence.

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::Rule;
use crate::scan::FileCtx;

pub struct DependencyRule;

impl Rule for DependencyRule {
    fn id(&self) -> &'static str {
        "SUR-1002"
    }
    fn title(&self) -> &'static str {
        "Stellar SDK/XDR dependency predates Protocol 30"
    }
    fn description(&self) -> &'static str {
        "Flags Stellar SDK/XDR dependencies that lack Protocol 30 (CAP-84/CAP-88) definitions."
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn kind(&self) -> Kind {
        Kind::Static
    }
    fn protocol(&self) -> &'static str {
        "30"
    }
    fn cap(&self) -> &'static str {
        "CAP-84, CAP-88"
    }
    fn limitations(&self) -> Option<&'static str> {
        Some("Rust version truth is verified against crates.io. Other ecosystems report presence only with a manual-review recommendation; presence alone is not a definitive incompatibility.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        let name = std::path::Path::new(&ctx.rel_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if name == "Cargo.toml" {
            return self.scan_cargo(ctx);
        }
        if name == "package.json" {
            return self.scan_package_json(ctx);
        }
        if name == "requirements.txt" || name == "pyproject.toml" || name == "go.mod" {
            return self.scan_other_ecosystem(ctx);
        }
        Vec::new()
    }
}

impl DependencyRule {
    fn scan_cargo(&self, ctx: &FileCtx) -> Vec<Finding> {
        let mut out = Vec::new();
        let checks: [(&str, u32, Severity, Confidence, &str); 2] = [
            (
                "stellar-xdr",
                30,
                Severity::High,
                Confidence::High,
                "The stellar-xdr crate 30.0.0 is the Protocol 30 release carrying CAP-84 and CAP-88 XDR.",
            ),
            (
                "soroban-sdk",
                30,
                Severity::Medium,
                Confidence::Medium,
                "The Protocol 30 Soroban SDK line is 30.0.0-rc.1; the prior stable line is 29.x.",
            ),
        ];
        for (token, min_major, sev, conf, note) in checks {
            let Some((line_no, req)) = find_req(ctx, token) else {
                continue;
            };
            match crate::rules::cargo_major_version(&req) {
                Some(major) if major < min_major => {
                    out.push(
                        Finding::new(self.id(), self.title(), sev, conf, Kind::Static, &ctx.rel_path)
                            .location(line_no, None, Some(&ctx.lines[line_no - 1]))
                            .explanation(&format!(
                                "{} {} is older than Protocol 30. {} It cannot decode the CAP-84 W-address variant or the CAP-88 millisecond StellarValue arms.",
                                token,
                                req.trim_matches('"'),
                                note
                            ))
                            .sources(&[
                                "https://crates.io/crates/stellar-xdr/30.0.0",
                                "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md",
                            ])
                            .recommendation(&format!("Upgrade to {token} >= {min_major}.0."))
                            .limitations(note),
                    );
                }
                None => {
                    out.push(
                        Finding::new(self.id(), self.title(), sev, conf, Kind::ManualReview, &ctx.rel_path)
                            .location(line_no, None, None)
                            .explanation(&format!(
                                "{token} is referenced without a numeric version (likely a git or path dependency). Verify the resolved commit carries Protocol 30 (CAP-84/CAP-88) XDR."
                            ))
                            .sources(&[
                                "https://crates.io/crates/stellar-xdr/30.0.0",
                                "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
                            ])
                            .recommendation("Pin to the Protocol 30 release and rerun this scan.")
                            .limitations("Manual review: version not statically determinable."),
                    );
                }
                _ => {}
            }
        }
        out
    }

    fn scan_package_json(&self, ctx: &FileCtx) -> Vec<Finding> {
        let mut out = Vec::new();
        if ctx.content.contains("@stellar/stellar-sdk") {
            out.push(manual(
                self,
                &ctx.rel_path,
                "package.json declares @stellar/stellar-sdk. The Protocol 30 JS SDK release ships updated XDR for CAP-84/88; confirm the resolved version is the Protocol 30 release.",
            ));
        }
        out
    }

    fn scan_other_ecosystem(&self, ctx: &FileCtx) -> Vec<Finding> {
        let mut out = Vec::new();
        if ctx.content.contains("stellar-sdk")
            || ctx.content.contains("stellar-base")
            || ctx.content.contains("stellar/go")
        {
            out.push(manual(
                self,
                &ctx.rel_path,
                "Declares a Stellar SDK dependency; confirm it ships Protocol 30 definitions before production use.",
            ));
        }
        out
    }
}

fn manual(rule: &dyn Rule, file: &str, expl: &str) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        Severity::Medium,
        Confidence::Low,
        Kind::ManualReview,
        file,
    )
    .explanation(expl)
    .sources(&["https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide"])
    .recommendation("Upgrade to the latest Protocol 30 SDK and rerun this scan.")
}

/// Find the requirement string for a dependency token in Cargo.toml content.
/// Returns (1-based line number, requirement-as-written). Handles bare string
/// versions and inline tables; returns the raw rhs for git/path/workspace deps
/// so callers downgrade to a manual-review finding.
fn find_req(ctx: &FileCtx, token: &str) -> Option<(usize, String)> {
    for (i, line) in ctx.lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.to_lowercase().starts_with(token) {
            continue;
        }
        let after = trimmed[token.len()..].trim_start();
        let Some(rhs) = after.strip_prefix('=') else {
            continue;
        };
        let rhs = rhs.trim();
        if rhs.starts_with('{') {
            if let Some(v) = extract_version_field(rhs) {
                return Some((i + 1, v));
            }
            if rhs.contains("git") || rhs.contains("path") || rhs.contains("workspace") {
                return Some((i + 1, rhs.to_string()));
            }
            return None;
        }
        if rhs.starts_with('"') {
            return Some((i + 1, extract_quoted(rhs)));
        }
    }
    None
}

fn extract_quoted(rhs: &str) -> String {
    let body = rhs.trim_start_matches('"');
    match body.find('"') {
        Some(end) => body[..end].to_string(),
        None => body.to_string(),
    }
}

/// Minimal `version = "..."` extractor for a Cargo inline table.
fn extract_version_field(table: &str) -> Option<String> {
    let idx = table.find("version")?;
    let rest = table[idx + "version".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    if rest.starts_with('"') {
        Some(extract_quoted(rest))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_quoted_reads_inner() {
        assert_eq!(extract_quoted("\"30.0.0\""), "30.0.0");
    }

    #[test]
    fn find_req_bare_string() {
        let ctx = FileCtx::from_source("Cargo.toml", "[dependencies]\nstellar-xdr = \"28.0.1\"\n");
        let (ln, req) = find_req(&ctx, "stellar-xdr").unwrap();
        assert_eq!(ln, 2);
        assert_eq!(req, "28.0.1");
    }

    #[test]
    fn find_req_inline_table() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar-xdr = { version = \"30.0.0\", features = [\"parse\"] }\n",
        );
        let (ln, req) = find_req(&ctx, "stellar-xdr").unwrap();
        assert_eq!(ln, 2);
        assert_eq!(req, "30.0.0");
    }

    #[test]
    fn find_req_git_dep_has_no_major() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar-xdr = { git = \"https://github.com/stellar/stellar-xdr\" }\n",
        );
        let (_ln, req) = find_req(&ctx, "stellar-xdr").unwrap();
        assert!(crate::rules::cargo_major_version(&req).is_none());
    }

    #[test]
    fn flags_old_xdr_as_high() {
        let ctx = FileCtx::from_source("Cargo.toml", "[dependencies]\nstellar-xdr = \"28.0.1\"\n");
        let f = DependencyRule.scan(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "SUR-1002");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].kind, Kind::Static);
    }

    #[test]
    fn passes_current_xdr() {
        let ctx = FileCtx::from_source("Cargo.toml", "[dependencies]\nstellar-xdr = \"30.0.0\"\n");
        assert!(DependencyRule.scan(&ctx).is_empty());
    }

    #[test]
    fn passes_soroban_v30_rc() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nsoroban-sdk = \"30.0.0-rc.1\"\n",
        );
        assert!(DependencyRule.scan(&ctx).is_empty());
    }

    #[test]
    fn flags_old_soroban_sdk() {
        let ctx = FileCtx::from_source("Cargo.toml", "[dependencies]\nsoroban-sdk = \"29.0.1\"\n");
        let f = DependencyRule.scan(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }
}
