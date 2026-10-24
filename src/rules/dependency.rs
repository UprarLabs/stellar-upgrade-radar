//! SUR-1002 — SDK / XDR dependency readiness under Protocol 30.
//!
//! Evidence policy (from the Bell upgrade guide + CAP-84/88):
//! - `stellar-xdr` < 30 cannot decode Protocol 30 ledgers (CAP-88 adds new
//!   StellarValue union arms; XDR decoding fails on unknown arms). A **resolved**
//!   older version is a genuine decoder risk -> High/Static.
//! - `soroban-sdk` < 30 is NOT a contract-compatibility break: existing Soroban
//!   contracts keep working unchanged. A rebuild is required only to adopt
//!   CAP-87 (ML-DSA) or to accept muxed contract addresses (CAP-84). Reported as
//!   a manual-review note, not a defect.
//! - The **resolved** version (from the nearest `Cargo.lock`) is authoritative:
//!   a manifest that declares `stellar-xdr = "30.0.0"` but whose lockfile still
//!   resolves `28.0.1` is flagged (stale lockfile), and a version range is
//!   resolved by the lockfile instead of being left ambiguous.
//! - If no lockfile is available, ranges and git/path/workspace deps are manual
//!   review (uncertainty is reported, not guessed).
//! - Other ecosystems: presence only, manual review (no verified minimum).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::{cargo_major_version, Rule};
use crate::scan::FileCtx;

pub struct DependencyRule;

const MIN_PROTOCOL: u32 = 30;

impl Rule for DependencyRule {
    fn id(&self) -> &'static str {
        "SUR-1002"
    }
    fn title(&self) -> &'static str {
        "Stellar SDK/XDR dependency predates Protocol 30"
    }
    fn description(&self) -> &'static str {
        "Flags Stellar SDK/XDR dependencies whose resolved (lockfile) or declared version lacks Protocol 30 (CAP-84/CAP-88) definitions. Covers Rust (stellar-xdr/soroban-sdk) plus JS/TS, Python, Go and Elixir SDKs; only stellar-xdr is pinned as a definite break, other cases are Medium/manual-review."
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
        Some("Rust crate truth is verified against crates.io and the nearest Cargo.lock. Workspaces share one lockfile (field syntax `dep.workspace = true` is recognized). When a lockfile lists multiple versions of a crate, the first is used (order-dependent); confirm the actually-resolved version by manual review. Non-Rust ecosystems (JS/TS, Python, Go, Elixir) are checked from the manifest plus a lockfile (package-lock/yarn/pnpm, poetry/uv/Pipfile, mix.lock); a manifest range is never treated as the resolved version. JS and Go use verified Protocol 30 release thresholds (v16.4.0/v17.3.0 and v0.8.0); Python and Elixir have no verified Protocol 30 release, so they are manual-review. Go honours `replace` directives and treats pseudo-versions and `github.com/stellar/go` as manual-review; Python matches dependency names in context (project names are not flagged); JS resolves monorepo root lockfiles (bounded search) and reports manual-review on ambiguous lockfiles; Elixir git/path deps are unknown. Prerelease versions (e.g. `17.3.0-rc.1`, `v0.8.0-rc.1`) are never auto-Ready — they are reported as manual-review/unknown because prerelease readiness is not provable from the version. Findings report the SDK version, not application runtime or on-chain compatibility.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        let name = Path::new(&ctx.rel_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if name == "Cargo.toml" {
            return self.scan_cargo(ctx);
        }
        // JS/TS, Python, Go, Elixir SDK readiness (manifest + lockfile aware).
        crate::rules::dependency_sdk::scan(ctx)
    }
}

/// How the manifest declares a dependency.
enum ManifestReq {
    /// A concrete pin whose major is below Protocol 30.
    PinBelow(u32),
    /// A concrete pin at or above Protocol 30.
    PinAtOrAbove,
    /// A range / compound requirement (cannot be resolved from the manifest).
    Range,
    /// git / path / workspace / no numeric version.
    Unresolvable,
}

impl DependencyRule {
    fn scan_cargo(&self, ctx: &FileCtx) -> Vec<Finding> {
        let mut out = Vec::new();
        let lock_path = ctx.abs_path.as_deref().and_then(nearest_lockfile);
        let lock_versions = lock_path
            .as_deref()
            .and_then(resolved_versions)
            .unwrap_or_default();

        for token in ["stellar-xdr", "soroban-sdk"] {
            let Some((line_no, req)) = find_req(ctx, token) else {
                continue;
            };
            let raw_line = ctx.lines[line_no - 1].clone();
            let class = classify_manifest(&req);
            let is_xdr = token == "stellar-xdr";
            let resolved: Option<(String, u32)> = lock_versions
                .get(token)
                .and_then(|v| cargo_major_version(v).map(|m| (v.clone(), m)));

            // Case 1: the manifest itself pins an old concrete version. The pin is
            // a static defect regardless of what the lockfile says.
            if let ManifestReq::PinBelow(major) = class {
                out.push(if is_xdr {
                    pin_high(self, token, major, &ctx.rel_path, line_no, &raw_line)
                } else {
                    pin_soroban_note(self, token, &raw_line, &ctx.rel_path, line_no)
                });
                continue;
            }

            match resolved {
                // Case 2: the lockfile resolves an old version. Authoritative.
                Some((ver, major)) if major < MIN_PROTOCOL => {
                    out.push(if is_xdr {
                        lock_high(self, token, &ver, &ctx.rel_path, line_no, &raw_line)
                    } else {
                        lock_soroban_note(self, token, &ver, &ctx.rel_path, line_no, &raw_line)
                    });
                }
                // Case 3: the lockfile resolves a compliant version. Suppress the
                // ambiguous manifest note; the project is ready.
                Some(_) => {}
                // Case 4: no lockfile to consult. Fall back to the manifest only.
                None => match class {
                    ManifestReq::PinAtOrAbove => {}
                    ManifestReq::Range => out.push(range_note(
                        self,
                        token,
                        &req,
                        &ctx.rel_path,
                        line_no,
                        &raw_line,
                    )),
                    ManifestReq::Unresolvable => out.push(unresolvable_note(
                        self,
                        token,
                        &ctx.rel_path,
                        line_no,
                        &raw_line,
                    )),
                    ManifestReq::PinBelow(_) => {}
                },
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Manifest classification
// ---------------------------------------------------------------------------

fn classify_manifest(req: &str) -> ManifestReq {
    if req.starts_with('{') {
        // Inline table: a version field pins it; git/path/workspace does not.
        return match extract_version_field(req) {
            Some(v) => classify_pin(&v),
            None => ManifestReq::Unresolvable,
        };
    }
    let bare = req.trim().trim_matches('"');
    if is_range(bare) {
        return ManifestReq::Range;
    }
    match cargo_major_version(req) {
        Some(m) if m < MIN_PROTOCOL => ManifestReq::PinBelow(m),
        Some(_) => ManifestReq::PinAtOrAbove,
        None => ManifestReq::Unresolvable,
    }
}

fn classify_pin(v: &str) -> ManifestReq {
    match cargo_major_version(v) {
        Some(m) if m < MIN_PROTOCOL => ManifestReq::PinBelow(m),
        Some(_) => ManifestReq::PinAtOrAbove,
        None => ManifestReq::Unresolvable,
    }
}

/// A requirement is a *range* if it uses operators or an interval. Such
/// requirements cannot be resolved to a definite major from the manifest.
fn is_range(req: &str) -> bool {
    let r = req.trim().trim_matches('"');
    r.contains('>') || r.contains('<') || r.contains(',') || r.contains(' ')
}

// ---------------------------------------------------------------------------
// Lockfile resolution
// ---------------------------------------------------------------------------

/// Walk up from the manifest's directory to the nearest `Cargo.lock`. Bounded so
/// it cannot wander into unrelated projects; a workspace shares one lockfile.
fn nearest_lockfile(manifest: &Path) -> Option<PathBuf> {
    let mut dir = manifest.parent()?;
    for _ in 0..32 {
        let cand = dir.join("Cargo.lock");
        if cand.is_file() {
            return Some(cand);
        }
        dir = dir.parent()?;
    }
    None
}

/// Parse a Cargo.lock into `crate name -> version` for the packages it resolves.
/// Handles lockfile v3 and v4 (`[[package]]` blocks). The first locked version
/// of a crate wins.
fn resolved_versions(path: &Path) -> Option<HashMap<String, String>> {
    let content = std::fs::read_to_string(path).ok()?;
    Some(parse_lockfile(&content))
}

fn parse_lockfile(content: &str) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let mut cur_name: Option<String> = None;
    let mut cur_ver: Option<String> = None;
    for line in content.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            if let (Some(n), Some(v)) = (cur_name.take(), cur_ver.take()) {
                out.entry(n).or_insert(v);
            }
            continue;
        }
        if let Some((k, v)) = kv(t) {
            match k.as_str() {
                "name" => cur_name = Some(v),
                "version" => cur_ver = Some(v),
                _ => {}
            }
        }
    }
    if let (Some(n), Some(v)) = (cur_name, cur_ver) {
        out.entry(n).or_insert(v);
    }
    out
}

/// Parse `key = "value"` into (key, value); returns None otherwise.
fn kv(line: &str) -> Option<(String, String)> {
    let eq = line.find('=')?;
    let key = line[..eq].trim().to_string();
    let rest = line[eq + 1..].trim();
    let v = extract_quoted(rest);
    if key.is_empty() || v.is_empty() {
        None
    } else {
        Some((key, v))
    }
}

// ---------------------------------------------------------------------------
// Emit helpers
// ---------------------------------------------------------------------------

fn pin_high(
    rule: &dyn Rule,
    token: &str,
    major: u32,
    file: &str,
    line: usize,
    raw: &str,
) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        Severity::High,
        Confidence::High,
        Kind::Static,
        file,
    )
    .location(line, None, Some(raw))
    .explanation(&format!(
        "{token} is pinned to major {major}, older than Protocol 30. It lacks the CAP-84 SC_ADDRESS_TYPE_MUXED_CONTRACT variant and the CAP-88 STELLAR_VALUE_*_MS arms, so ledger decoding fails on unknown union arms."
    ))
    .sources(&[
        "https://crates.io/crates/stellar-xdr/30.0.0",
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md",
    ])
    .recommendation("Upgrade to stellar-xdr 30.0.0+ before decoding Protocol 30 ledgers.")
    .limitations("Only applies if this crate decodes ledger data; confirm usage.")
}

fn pin_soroban_note(rule: &dyn Rule, token: &str, raw: &str, file: &str, line: usize) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        Severity::Low,
        Confidence::Low,
        Kind::ManualReview,
        file,
    )
    .location(line, None, Some(raw))
    .explanation(&format!(
        "{token} is pinned to a version predating the Protocol 30 SDK line. Existing Soroban contracts keep working unchanged after the upgrade; rebuild is required only to adopt CAP-87 (ML-DSA) host functions or to accept muxed contract addresses (CAP-84) as destinations."
    ))
    .sources(&[
        "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide",
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
    ])
    .recommendation("Rebuild against soroban-sdk 30.x if you need CAP-87 or muxed contract destinations; otherwise no action is required.")
    .limitations("Manual review: not a contract-compatibility break.")
}

fn lock_high(
    rule: &dyn Rule,
    token: &str,
    version: &str,
    file: &str,
    line: usize,
    raw: &str,
) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        Severity::High,
        Confidence::High,
        Kind::Static,
        file,
    )
    .location(line, None, Some(raw))
    .explanation(&format!(
        "Cargo.lock resolves {token} to {version}, older than Protocol 30. This is the version actually built and run, so ledger decoding uses the CAP-84/CAP-88-incomplete XDR regardless of the manifest requirement."
    ))
    .sources(&[
        "https://crates.io/crates/stellar-xdr/30.0.0",
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md",
    ])
    .recommendation("Run `cargo update stellar-xdr` so the lockfile resolves 30.0.0+, then rebuild.")
    .limitations("Based on the nearest Cargo.lock found for this manifest; a workspace may share one lockfile.")
}

fn lock_soroban_note(
    rule: &dyn Rule,
    token: &str,
    version: &str,
    file: &str,
    line: usize,
    raw: &str,
) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        Severity::Low,
        Confidence::Low,
        Kind::ManualReview,
        file,
    )
    .location(line, None, Some(raw))
    .explanation(&format!(
        "Cargo.lock resolves {token} to {version}, older than the Protocol 30 SDK line. Existing Soroban contracts keep working; rebuild is needed only for CAP-87 (ML-DSA) or to accept muxed contract addresses (CAP-84)."
    ))
    .sources(&[
        "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide",
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
    ])
    .recommendation("Rebuild against soroban-sdk 30.x if you need CAP-87 or muxed contract destinations.")
    .limitations("Manual review: not a contract-compatibility break.")
}

fn range_note(
    rule: &dyn Rule,
    token: &str,
    req: &str,
    file: &str,
    line: usize,
    raw: &str,
) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        Severity::Low,
        Confidence::Low,
        Kind::ManualReview,
        file,
    )
    .location(line, None, Some(raw))
    .explanation(&format!(
        "`{token} = {req}` is a version range or compound requirement and no Cargo.lock was found to resolve it. The resolved version may be Protocol 30-compatible or not; verify it before assuming incompatibility."
    ))
    .sources(&["https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide"])
    .recommendation("Run `cargo generate-lockfile` (or update) and rerun this scan; the lockfile resolves the range.")
}

fn unresolvable_note(rule: &dyn Rule, token: &str, file: &str, line: usize, raw: &str) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        Severity::Low,
        Confidence::Low,
        Kind::ManualReview,
        file,
    )
    .location(line, None, Some(raw))
    .explanation(&format!(
        "{token} is referenced without a numeric version (git, path, or workspace dependency) and no Cargo.lock was found. The resolved version cannot be determined statically; verify it carries Protocol 30 (CAP-84/CAP-88) XDR."
    ))
    .sources(&[
        "https://crates.io/crates/stellar-xdr/30.0.0",
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
    ])
    .recommendation("Pin to the Protocol 30 release or confirm the resolved commit.")
}

/// Find the requirement for a dependency in Cargo.toml. Matches a bare key
/// (`stellar-xdr = "..."`) and a renamed dependency
/// (`stellar_xdr = { package = "stellar-xdr", version = "..." }`). Returns
/// (1-based line, requirement-as-written). Renamed deps with no version field
/// return the raw rhs so callers downgrade to manual review.
fn find_req(ctx: &FileCtx, token: &str) -> Option<(usize, String)> {
    for (i, line) in ctx.lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains('=') {
            continue;
        }
        let eq = trimmed.find('=').unwrap();
        // Dependency names cannot contain '.', but Cargo's field syntax can:
        // `stellar-xdr.workspace = true` keeps the dependency name before the '.'.
        let dep = trimmed[..eq]
            .trim()
            .split('.')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_lowercase();
        let rhs = trimmed[eq + 1..].trim();

        // Resolve the real crate name: `package = "..."` overrides the key.
        let real_crate = extract_package(rhs).unwrap_or_else(|| dep.clone());
        if !real_crate.eq_ignore_ascii_case(token) {
            continue;
        }

        if rhs.starts_with('{') {
            if let Some(v) = extract_version_field(rhs) {
                return Some((i + 1, v));
            }
            return Some((i + 1, rhs.to_string()));
        }
        if rhs.starts_with('"') {
            return Some((i + 1, extract_quoted(rhs)));
        }
        return Some((i + 1, rhs.to_string()));
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

/// Extract `package = "..."` from a Cargo inline table.
fn extract_package(table: &str) -> Option<String> {
    let idx = table.find("package")?;
    let rest = table[idx + "package".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    if rest.starts_with('"') {
        Some(extract_quoted(rest))
    } else {
        None
    }
}

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
    fn extract_package_reads_value() {
        assert_eq!(
            extract_package("{ package = \"stellar-xdr\", version = \"28.0.1\" }").as_deref(),
            Some("stellar-xdr")
        );
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
    fn find_req_renamed_dependency() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar_xdr = { package = \"stellar-xdr\", version = \"28.0.1\" }\n",
        );
        let (ln, req) = find_req(&ctx, "stellar-xdr").unwrap();
        assert_eq!(req, "28.0.1");
        assert_eq!(ln, 2);
    }

    #[test]
    fn does_not_match_prefix_only_crate_name() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar-xdr-extra = \"1.0\"\n",
        );
        assert!(find_req(&ctx, "stellar-xdr").is_none());
    }

    #[test]
    fn find_req_git_dep_has_no_major() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar-xdr = { git = \"https://github.com/stellar/stellar-xdr\" }\n",
        );
        let (_ln, req) = find_req(&ctx, "stellar-xdr").unwrap();
        assert!(cargo_major_version(&req).is_none());
    }

    #[test]
    fn parse_lockfile_reads_versions() {
        let lock = "version = 4\n\n[[package]]\nname = \"stellar-xdr\"\nversion = \"28.0.1\"\nsource = \"registry+https://example\"\nchecksum = \"abc\"\n\n[[package]]\nname = \"other\"\nversion = \"1.2.3\"\n";
        let map = parse_lockfile(lock);
        assert_eq!(map.get("stellar-xdr").map(String::as_str), Some("28.0.1"));
        assert_eq!(map.get("other").map(String::as_str), Some("1.2.3"));
    }

    #[test]
    fn parse_lockfile_ignores_dependency_entries() {
        let lock = "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"stellar-xdr 28.0.1\",\n \"serde 1.0.0\",\n]\n";
        let map = parse_lockfile(lock);
        assert_eq!(map.get("app").map(String::as_str), Some("0.1.0"));
        assert!(!map.contains_key("stellar-xdr"));
    }

    #[test]
    fn parse_lockfile_first_version_of_a_crate_wins() {
        // A lockfile may list multiple versions of a crate; we honor the first
        // one encountered (documented behavior; the actually-resolved version for
        // a given package requires dependency-edge analysis).
        let lock = "[[package]]\nname = \"stellar-xdr\"\nversion = \"30.0.0\"\nsource = \"registry+https://example\"\n\n[[package]]\nname = \"stellar-xdr\"\nversion = \"28.0.1\"\nsource = \"registry+https://example\"\n";
        let map = parse_lockfile(lock);
        assert_eq!(map.get("stellar-xdr").map(String::as_str), Some("30.0.0"));
    }

    #[test]
    fn find_req_workspace_field_syntax() {
        // `stellar-xdr.workspace = true` (field syntax, not the table form).
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar-xdr.workspace = true\n",
        );
        let (_ln, req) = find_req(&ctx, "stellar-xdr").unwrap();
        assert_eq!(req, "true");
        assert!(cargo_major_version(&req).is_none());
    }

    #[test]
    fn flags_old_xdr_pin_as_high() {
        let ctx = FileCtx::from_source("Cargo.toml", "[dependencies]\nstellar-xdr = \"28.0.1\"\n");
        let f = DependencyRule.scan(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "SUR-1002");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].kind, Kind::Static);
    }

    #[test]
    fn renamed_old_xdr_is_flagged() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar_xdr = { package = \"stellar-xdr\", version = \"28.0.1\" }\n",
        );
        let f = DependencyRule.scan(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn version_range_without_lockfile_is_manual_review_not_defect() {
        let ctx = FileCtx::from_source(
            "Cargo.toml",
            "[dependencies]\nstellar-xdr = \">=28, <31\"\n",
        );
        let f = DependencyRule.scan(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert_eq!(f[0].severity, Severity::Low);
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
    fn old_soroban_sdk_is_manual_review_not_defect() {
        let ctx = FileCtx::from_source("Cargo.toml", "[dependencies]\nsoroban-sdk = \"29.0.1\"\n");
        let f = DependencyRule.scan(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn classify_manifest_distinguishes_pins_and_ranges() {
        assert!(matches!(
            classify_manifest("28.0.1"),
            ManifestReq::PinBelow(28)
        ));
        assert!(matches!(
            classify_manifest("30.0.0"),
            ManifestReq::PinAtOrAbove
        ));
        assert!(matches!(
            classify_manifest("^30"),
            ManifestReq::PinAtOrAbove
        ));
        assert!(matches!(classify_manifest(">=28, <31"), ManifestReq::Range));
        assert!(matches!(
            classify_manifest("{ git = \"https://x\" }"),
            ManifestReq::Unresolvable
        ));
        assert!(matches!(
            classify_manifest("{ package = \"stellar-xdr\", version = \"28.0.1\" }"),
            ManifestReq::PinBelow(28)
        ));
    }
}
