//! Integration tests: run the analyzer over the fixture corpus and exercise the
//! real CLI binary (exit codes and JSON output). Every assertion is checked
//! against actual output, not assumptions.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use stellar_upgrade_radar::analyze;
use stellar_upgrade_radar::report::{Finding, Kind, Severity};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn findings() -> Vec<Finding> {
    analyze(&fixtures_root(), Severity::Info).findings
}

fn files_for(rule_id: &str) -> Vec<String> {
    findings()
        .into_iter()
        .filter(|f| f.rule_id == rule_id)
        .map(|f| f.file)
        .collect()
}

fn findings_for(rule_id: &str) -> Vec<Finding> {
    findings()
        .into_iter()
        .filter(|f| f.rule_id == rule_id)
        .collect()
}

fn rule_counts() -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in findings() {
        *m.entry(f.rule_id).or_insert(0) += 1;
    }
    m
}

#[test]
fn sur_1001_flags_unsafe_and_spares_safe_w_address_fixture() {
    let files = files_for("SUR-1001");
    assert!(
        files.iter().any(|f| f.ends_with("w_address_unsafe.rs")),
        "expected SUR-1001 on w_address_unsafe.rs, got {files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with("w_address_packed.rs")),
        "packed string allowlist must be detected, got {files:?}"
    );
    for expected in [
        "w_address_string_url.rs",
        "w_address_escaped_quote.rs",
        "w_address_real_comment.rs",
    ] {
        assert!(
            files.iter().any(|f| f.ends_with(expected)),
            "genuine allowlist {expected} must be detected, got {files:?}"
        );
    }
    for safe in [
        "w_address_safe.rs",
        "w_address_palette.rs",
        "w_address_library.rs",
    ] {
        assert!(
            !files.iter().any(|f| f.ends_with(safe)),
            "SUR-1001 must not fire on {safe}, got {files:?}"
        );
    }
}

#[test]
fn sur_1002_flags_old_deps_and_spares_current_deps() {
    let files = files_for("SUR-1002");
    for expected in [
        "dep_old/Cargo.toml",
        "dep_renamed/Cargo.toml",
        "dep_strkey/Cargo.toml",
        "dep_git/Cargo.toml",
        "dep_range/Cargo.toml",
    ] {
        assert!(
            files.iter().any(|f| f.contains(expected)),
            "missing {expected}: {files:?}"
        );
    }
    for clean in ["dep_new/Cargo.toml", "dep_prefix/Cargo.toml"] {
        assert!(
            !files.iter().any(|f| f.contains(clean)),
            "SUR-1002 must not fire on {clean}, got {files:?}"
        );
    }
}

#[test]
fn sur_1002_defect_is_high_static_only_for_stellar_xdr() {
    let f = findings_for("SUR-1002");
    let dep_old = f
        .iter()
        .find(|x| x.file.contains("dep_old"))
        .expect("dep_old finding");
    assert_eq!(dep_old.severity, Severity::High);
    assert_eq!(dep_old.kind, Kind::Static);

    // soroban-sdk < 30 is NOT a contract-compatibility break.
    let dep_strkey = f
        .iter()
        .find(|x| x.file.contains("dep_strkey"))
        .expect("dep_strkey finding");
    assert_eq!(dep_strkey.severity, Severity::Low);
    assert_eq!(dep_strkey.kind, Kind::ManualReview);

    // A version range cannot be resolved statically.
    let dep_range = f
        .iter()
        .find(|x| x.file.contains("dep_range"))
        .expect("dep_range finding");
    assert_eq!(dep_range.severity, Severity::Low);
    assert_eq!(dep_range.kind, Kind::ManualReview);
}

#[test]
fn sur_1002_stale_lockfile_is_high() {
    // Manifest declares 30.0.0 but Cargo.lock resolves 28.0.1: stale lockfile.
    let f = findings_for("SUR-1002");
    let m = f
        .iter()
        .find(|x| x.file.contains("dep_lock_mismatch"))
        .expect("stale lockfile must be flagged");
    assert_eq!(m.severity, Severity::High);
    assert_eq!(m.kind, Kind::Static);
    assert!(
        m.explanation.contains("28.0.1"),
        "explanation must cite the resolved version"
    );
}

#[test]
fn sur_1002_compliant_lockfile_suppresses_range_note() {
    // A range whose lockfile resolves 30.0.0 is compliant: no finding.
    let files = files_for("SUR-1002");
    assert!(
        !files.iter().any(|f| f.contains("dep_lock_clean")),
        "lockfile resolved to 30 must suppress the range note: {files:?}"
    );
}

#[test]
fn sur_1002_workspace_field_syntax_resolves_via_lockfile() {
    // `stellar-xdr.workspace = true` must be recognized and resolved from the
    // nearest Cargo.lock; a stale lockfile is flagged.
    let files = files_for("SUR-1002");
    assert!(
        files.iter().any(|f| f.contains("dep_workspace_field")),
        "workspace field-syntax dependency must be detected: {files:?}"
    );
    let f = findings_for("SUR-1002");
    let m = f
        .iter()
        .find(|x| x.file.contains("dep_workspace_field"))
        .expect("workspace dep with stale lockfile must be flagged");
    assert_eq!(m.severity, Severity::High);
    assert_eq!(m.kind, Kind::Static);
}
#[test]
fn sur_1002_lockfile_mismatch_is_high() {
    // Manifest declares 30.0.0 but Cargo.lock still resolves 28.0.1: the stale
    // lockfile is a definite defect.
    let f = findings_for("SUR-1002");
    let m = f
        .iter()
        .find(|x| x.file.contains("dep_lock_mismatch"))
        .expect("stale lockfile must be flagged");
    assert_eq!(m.severity, Severity::High);
    assert_eq!(m.kind, Kind::Static);
}

#[test]
fn sur_1002_lockfile_compliant_suppresses_range_note() {
    // A range that resolves to 30.0.0 in the lockfile must not produce a manual
    // review note (the project is compliant).
    let files = files_for("SUR-1002");
    assert!(
        !files.iter().any(|f| f.contains("dep_lock_clean")),
        "lockfile resolved to 30 must suppress the range note: {files:?}"
    );
}

#[test]
fn sur_1002_non_rust_ecosystems() {
    let f = findings_for("SUR-1002");
    let find = |needle: &str| f.iter().find(|x| x.file.contains(needle));

    // JS: old exact pin -> Medium/Static; ready -> none.
    let js_old = find("js_old/package.json").expect("js_old finding");
    assert_eq!(js_old.severity, Severity::Medium);
    assert_eq!(js_old.kind, Kind::Static);
    assert!(js_old.explanation.contains("16.3.1"));
    assert!(
        find("js_new/package.json").is_none(),
        "ready JS SDK must not be flagged"
    );

    // JS: range resolved by the lockfile (^16.0.0 -> 16.3.1) -> Medium/Static.
    let js_lock = find("js_lock_old/package.json").expect("js_lock_old finding");
    assert_eq!(js_lock.severity, Severity::Medium);
    assert!(js_lock.explanation.contains("16.3.1"));

    // JS: a description mentioning an old version must not trigger a finding.
    assert!(
        find("js_comment/package.json").is_none(),
        "non-dependency mention must not be flagged"
    );

    // Python: no released Protocol 30 SDK -> Low/ManualReview.
    for path in ["py_req/requirements.txt", "py_pyproject/pyproject.toml"] {
        let py = find(path).unwrap_or_else(|| panic!("missing {path}"));
        assert_eq!(py.kind, Kind::ManualReview, "{path}");
        assert_eq!(py.severity, Severity::Low, "{path}");
    }

    // Go: v0.7.3 -> Medium/Static; v0.8.0 -> none.
    let go = find("go_old/go.mod").expect("go_old finding");
    assert_eq!(go.severity, Severity::Medium);
    assert_eq!(go.kind, Kind::Static);
    assert!(go.explanation.contains("v0.7.3"));
    assert!(
        find("go_new/go.mod").is_none(),
        "ready Go SDK must not be flagged"
    );

    // Elixir: no verified Protocol 30 release -> Low/ManualReview.
    let ex = find("elixir_mix/mix.exs").expect("elixir finding");
    assert_eq!(ex.kind, Kind::ManualReview);
    assert_eq!(ex.severity, Severity::Low);
}

#[test]
fn sur_1002_fix_regressions() {
    let f = findings_for("SUR-1002");
    let find = |needle: &str| f.iter().find(|x| x.file.contains(needle));

    // Python: a project/package name is not a dependency.
    assert!(
        find("py_name/pyproject.toml").is_none(),
        "a project name must not be flagged"
    );
    let pyv = find("py_name_valid/pyproject.toml").expect("valid py dep");
    assert_eq!(pyv.kind, Kind::ManualReview);

    // Go: replace-with-version is Ready; replace-path / pseudo / alt are manual.
    assert!(
        find("go_replace/go.mod").is_none(),
        "replace to v0.9.0 must be Ready"
    );
    let gpath = find("go_replace_path/go.mod").expect("replace path");
    assert_eq!(gpath.kind, Kind::ManualReview);
    let gpseudo = find("go_pseudo/go.mod").expect("pseudo-version");
    assert_eq!(gpseudo.kind, Kind::ManualReview);
    let galt = find("go_alt/go.mod").expect("alt module");
    assert_eq!(galt.kind, Kind::ManualReview);
    let gblock = find("go_require_block/go.mod").expect("require block");
    assert_eq!(gblock.severity, Severity::Medium);

    // JS nested object extracts the real version.
    assert!(
        find("js_nested/package.json").is_none(),
        "nested 17.3.0 must be Ready"
    );
    let jn = find("js_nested_old/package.json").expect("nested old");
    assert_eq!(jn.severity, Severity::Medium);
    assert!(jn.explanation.contains("16.3.1"));

    // JS monorepo: the root lockfile resolves the sub-package.
    let jm = find("js_mono_root/pkg/package.json").expect("monorepo");
    assert_eq!(jm.severity, Severity::Medium);
    assert!(jm.explanation.contains("16.3.1"));

    // JS ambiguous lockfile -> manual review, not a confident verdict.
    let ja = find("js_ambig/package.json").expect("ambiguous lockfile");
    assert_eq!(ja.kind, Kind::ManualReview);

    // Elixir git dep must not show a URL as the version.
    let ex = find("elixir_git/mix.exs").expect("elixir git dep");
    assert_eq!(ex.kind, Kind::ManualReview);
    assert!(
        !ex.explanation.contains("kommitters/stellar_sdk"),
        "must not show a URL as the version"
    );
}

#[test]
fn sur_1002_prerelease_is_unknown() {
    let f = findings_for("SUR-1002");
    let find = |needle: &str| f.iter().find(|x| x.file.contains(needle));

    // At the threshold, below it, and lockfile-resolved: Unknown/ManualReview.
    for path in [
        "js_prerelease/package.json",
        "js_prerelease_below/package.json",
        "js_prerelease_lock/package.json",
    ] {
        let x = find(path).unwrap_or_else(|| panic!("missing {path}"));
        assert_eq!(x.kind, Kind::ManualReview, "{path}");
        assert_eq!(x.severity, Severity::Low, "{path}");
    }
    let g = find("go_prerelease/go.mod").expect("go prerelease");
    assert_eq!(g.kind, Kind::ManualReview);
    assert_eq!(g.severity, Severity::Low);

    // Stable thresholds unchanged.
    assert!(
        find("js_new/package.json").is_none(),
        "stable 17.3.0 must stay Ready"
    );
    assert!(
        find("go_new/go.mod").is_none(),
        "stable v0.8.0 must stay Ready"
    );
}

#[test]
fn sur_1001_sur_1003_adversarial_regressions() {
    let f1 = findings_for("SUR-1001");
    let f3 = findings_for("SUR-1003");
    let f1_has = |needle: &str| f1.iter().any(|x| x.file.ends_with(needle));
    let f3_has = |needle: &str| f3.iter().any(|x| x.file.ends_with(needle));

    // SUR-1001: four reproduced false positives must stay unflagged.
    for safe in [
        "w_address_string_context.rs",
        "w_address_prefix_identifier.rs",
        "w_address_hex_palette.rs",
        "w_address_short_string.rs",
    ] {
        assert!(!f1_has(safe), "must not flag {safe}: {f1:?}");
    }
    // SUR-1001: multi-line allowlist false negative fixed.
    assert!(
        f1_has("w_address_multiline.rs"),
        "multi-line allowlist must be flagged: {f1:?}"
    );

    // SUR-1003: arm-name-in-string false positive fixed.
    assert!(
        !f3_has("xdr_arm_string.rs"),
        "a string-literal arm value must not be flagged: {f3:?}"
    );
    // SUR-1003: trailing-comment and helper-name false negatives fixed.
    let comment = f3
        .iter()
        .find(|x| x.file.ends_with("xdr_arm_comment.rs"))
        .expect("trailing comment must still flag the legacy arm");
    assert_eq!(comment.kind, Kind::Static);
    let helper = f3
        .iter()
        .find(|x| x.file.ends_with("xdr_closetime_helper.rs"))
        .expect("a closetime_ms helper must still flag the legacy arm");
    assert_eq!(helper.kind, Kind::Static);
}

#[test]
fn sur_1003_flags_old_xdr_and_spares_ms_aware_fixture() {
    let files = files_for("SUR-1003");
    assert!(
        files.iter().any(|f| f.ends_with("xdr_old.rs")),
        "got {files:?}"
    );
    assert!(
        !files.iter().any(|f| f.ends_with("xdr_new.rs")),
        "SUR-1003 must not fire on xdr_new.rs, got {files:?}"
    );
}

#[test]
fn sur_1003_does_not_double_report_a_line() {
    let f: Vec<Finding> = findings_for("SUR-1003")
        .into_iter()
        .filter(|x| x.file.ends_with("xdr_old.rs"))
        .collect();
    assert_eq!(
        f.iter().filter(|x| x.line == Some(3)).count(),
        1,
        "line 3 must not be reported twice: {f:?}"
    );
    assert_eq!(
        f.iter().filter(|x| x.line == Some(4)).count(),
        1,
        "line 4 must not be reported twice: {f:?}"
    );
    assert!(f.iter().all(|x| x.kind == Kind::Static));
}

#[test]
fn sur_1003_detects_the_legacy_block_in_a_mixed_file() {
    // A file with an updated decoder alongside a legacy one must still flag the
    // legacy block (and only that block).
    let files = files_for("SUR-1003");
    assert!(
        files.iter().any(|f| f.ends_with("xdr_mixed.rs")),
        "legacy block in a mixed file must be flagged: {files:?}"
    );
    let f: Vec<Finding> = findings_for("SUR-1003")
        .into_iter()
        .filter(|x| x.file.ends_with("xdr_mixed.rs"))
        .collect();
    assert_eq!(f.len(), 1, "only the legacy arm should be flagged: {f:?}");
    assert_eq!(f[0].kind, Kind::Static);
}

#[test]
fn sur_1003_fully_updated_block_is_not_flagged() {
    // A match block that handles both pre-MS and _MS arms is compliant.
    let files = files_for("SUR-1003");
    assert!(
        !files.iter().any(|f| f.ends_with("xdr_updated.rs")),
        "fully updated block must not be flagged: {files:?}"
    );
}

#[test]
fn sur_1004_flags_timestamp_assumption_and_spares_ms_aware_fixture() {
    let files = files_for("SUR-1004");
    assert!(
        files.iter().any(|f| f.ends_with("timestamp_unsafe.rs")),
        "got {files:?}"
    );
    for safe in ["timestamp_safe.rs", "timing_broad.rs"] {
        assert!(
            !files.iter().any(|f| f.ends_with(safe)),
            "SUR-1004 must not fire on {safe}, got {files:?}"
        );
    }
}

#[test]
fn clean_fixture_produces_no_findings() {
    let report = analyze(&fixtures_root().join("clean"), Severity::Info);
    assert_eq!(
        report.summary.findings, 0,
        "clean dir should be finding-free"
    );
}

#[test]
fn report_carries_stable_rule_ids_and_evidence() {
    let report = analyze(&fixtures_root(), Severity::Info);
    let ids: Vec<&str> = report.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["SUR-1001", "SUR-1002", "SUR-1003", "SUR-1004"]);
    assert_eq!(report.schema_version, "1.0");
    for f in &report.findings {
        assert!(!f.sources.is_empty(), "{} lacks sources", f.rule_id);
        assert!(f.line.is_some(), "{} lacks a line number", f.rule_id);
    }
    assert!(rule_counts().contains_key("SUR-1001"));
    assert!(findings_for("SUR-1001")
        .iter()
        .all(|k| k.kind == Kind::Static));
    assert!(findings_for("SUR-1004")
        .iter()
        .all(|k| k.kind == Kind::ManualReview));
}

#[test]
fn json_report_is_valid_and_well_formed() {
    let report = analyze(&fixtures_root(), Severity::Info);
    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["tool"]["name"], "stellar-upgrade-radar");
    assert_eq!(v["target"]["protocol_version"], 30);
    assert_eq!(v["target"]["protocol_name"], "Bell");
    assert!(v["findings"].is_array());
    assert!(v["summary"]["findings"].as_u64().unwrap() > 0);
    let sev = &v["summary"]["by_severity"];
    for key in sev.as_object().unwrap().keys() {
        assert!(
            ["critical", "high", "medium", "low", "info"].contains(&key.as_str()),
            "unexpected severity key: {key}"
        );
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_stellar-upgrade-radar")
}

#[test]
fn cli_version_prints_semver() {
    let out = Command::new(bin()).arg("--version").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("stellar-upgrade-radar 0.1.0"), "got: {s}");
}

#[test]
fn cli_help_succeeds() {
    let out = Command::new(bin()).arg("--help").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("check"), "help must document the check command");
}

#[test]
fn cli_json_scan_exits_1_and_emits_parseable_json() {
    let out = Command::new(bin())
        .args([
            "check",
            fixtures_root().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1), "findings present => exit 1");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(v["schema_version"], "1.0");
    assert!(!v["findings"].as_array().unwrap().is_empty());
}

#[test]
fn cli_exits_0_on_clean_directory() {
    let out = Command::new(bin())
        .args(["check", fixtures_root().join("clean").to_str().unwrap()])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0), "no findings => exit 0");
}

#[test]
fn cli_exits_2_on_missing_path() {
    let out = Command::new(bin())
        .args(["check", "/definitely/not/a/real/path"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "bad path => exit 2");
}

#[test]
fn cli_min_severity_filters_findings() {
    let out = Command::new(bin())
        .args([
            "check",
            fixtures_root().to_str().unwrap(),
            "--format",
            "json",
            "--min-severity",
            "high",
        ])
        .output()
        .expect("run");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
    let ids: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !ids.iter().any(|id| id == "SUR-1004"),
        "Low should be filtered: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id == "SUR-1001"),
        "High should remain: {ids:?}"
    );
}

#[test]
fn empty_and_whitespace_files_produce_no_findings() {
    // Robustness: a zero-byte file and a whitespace-only file must scan without
    // panicking and produce no findings.
    let report = analyze(&fixtures_root().join("empty"), Severity::Info);
    assert_eq!(
        report.summary.findings, 0,
        "empty/whitespace files must not produce findings"
    );
    assert!(
        report.summary.files_scanned >= 2,
        "the empty fixtures must still be scanned"
    );
}

#[test]
fn non_source_file_yields_only_manual_review_candidates() {
    // A prose file that mentions timing/address words must not produce a
    // confident static verdict; at most a Low/ManualReview candidate. This
    // pins the rule that ambiguous input is a manual-review candidate, never an
    // over-confident static finding.
    let report = analyze(&fixtures_root().join("unrelated"), Severity::Info);
    assert!(
        !report.findings.is_empty(),
        "the prose mentions a timing assumption, so a candidate is expected"
    );
    for f in &report.findings {
        assert_eq!(
            f.severity,
            Severity::Low,
            "no confident verdict on prose: {f:?}"
        );
        assert_eq!(
            f.kind,
            Kind::ManualReview,
            "prose must be a manual-review candidate: {f:?}"
        );
    }
}

#[test]
fn scan_is_deterministic_in_order_and_content() {
    let a = analyze(&fixtures_root(), Severity::Info);
    let b = analyze(&fixtures_root(), Severity::Info);
    // Findings and summary are deterministic across runs; only the report's
    // `scanned_at_epoch` timestamp differs.
    let key = |f: &Finding| {
        (
            f.rule_id.clone(),
            f.file.clone(),
            f.line,
            f.column,
            f.kind,
            f.severity,
        )
    };
    let ka: Vec<_> = a.findings.iter().map(key).collect();
    let kb: Vec<_> = b.findings.iter().map(key).collect();
    assert_eq!(
        ka, kb,
        "finding order and content must be stable across runs"
    );
    assert_eq!(a.summary.findings, b.summary.findings);
    assert_eq!(a.summary.by_rule, b.summary.by_rule);
    assert_eq!(a.summary.files_with_findings, b.summary.files_with_findings);
    // Emitted in a stable (file, rule) order.
    let mut sorted = ka.clone();
    sorted.sort_by_key(|x| (x.1.clone(), x.0.clone()));
    assert_eq!(
        ka, sorted,
        "findings must be emitted in a stable (file, rule) order"
    );
}

#[test]
fn json_summary_counts_are_consistent() {
    let report = analyze(&fixtures_root(), Severity::Info);
    let json = serde_json::to_string(&report).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let by_rule = v["summary"]["by_rule"]
        .as_object()
        .expect("by_rule present");
    let total: u64 = by_rule.values().map(|x| x.as_u64().unwrap()).sum();
    assert_eq!(
        total,
        v["summary"]["findings"].as_u64().unwrap(),
        "by_rule must sum to findings"
    );
    assert!(
        v["summary"]["files_with_findings"].as_u64().unwrap() > 0,
        "files_with_findings must be reported"
    );
    assert!(
        v["target"]["scanned_at_epoch"].is_u64(),
        "scan metadata must be present"
    );
    assert!(
        v["notices"].as_array().is_some_and(|a| !a.is_empty()),
        "notices must be present and non-empty"
    );
    let ids: Vec<&str> = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["SUR-1001", "SUR-1002", "SUR-1003", "SUR-1004"]);
}

#[test]
fn cli_min_severity_info_shows_all_findings() {
    // The `info` floor must not filter anything, so Low findings appear.
    let out = Command::new(bin())
        .args([
            "check",
            fixtures_root().to_str().unwrap(),
            "--format",
            "json",
            "--min-severity",
            "info",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1), "findings present => exit 1");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
    let ids: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.iter().any(|id| id == "SUR-1004"),
        "Low findings must be included at the info floor: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id == "SUR-1001"),
        "High findings must be included at the info floor: {ids:?}"
    );
}

#[test]
fn cli_invalid_min_severity_exits_2() {
    let out = Command::new(bin())
        .args([
            "check",
            fixtures_root().to_str().unwrap(),
            "--min-severity",
            "bogus",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "invalid severity => exit 2");
}

fn run_cli(args: &[&str]) -> serde_json::Value {
    let out = Command::new(bin()).args(args).output().expect("run");
    assert!(
        matches!(out.status.code(), Some(0) | Some(1)),
        "expected exit 0/1, got {:?} for {args:?}",
        out.status.code()
    );
    serde_json::from_slice(&out.stdout).expect("JSON")
}

#[test]
fn cli_sarif_output_is_well_formed() {
    let v = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
    let run = &v["runs"][0];
    assert_eq!(run["columnKind"], "unicodeCodePoints");
    let driver = &run["tool"]["driver"];
    assert_eq!(driver["name"], "stellar-upgrade-radar");
    assert_eq!(driver["version"], "0.1.0");
    assert_eq!(
        driver["informationUri"],
        "https://github.com/UprarLabs/stellar-upgrade-radar"
    );
    let rule_ids: Vec<&str> = driver["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        rule_ids,
        vec!["SUR-1001", "SUR-1002", "SUR-1003", "SUR-1004"]
    );
    let results = run["results"].as_array().unwrap();
    assert!(!results.is_empty());
    for r in results {
        let rid = r["ruleId"].as_str().unwrap();
        assert!(
            rule_ids.contains(&rid),
            "ruleId must reference driver.rules: {r}"
        );
        let idx = r["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rule_ids[idx], rid, "ruleIndex must match ruleId");
        assert!(
            r["message"]["text"].as_str().is_some_and(|s| !s.is_empty()),
            "message.text must be present"
        );
        let level = r["level"].as_str().unwrap();
        assert!(
            ["error", "warning", "note", "none"].contains(&level),
            "invalid SARIF level: {level}"
        );
    }
    assert!(
        run["properties"]["notices"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "notices must be present"
    );
}

#[test]
fn cli_sarif_preserves_manual_review_kind() {
    let v = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    let results = v["runs"][0]["results"].as_array().unwrap();
    let mr: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r["properties"]["kind"] == "manual_review")
        .collect();
    assert!(
        !mr.is_empty(),
        "manual_review results must be preserved, not dropped"
    );
    for r in &mr {
        assert_eq!(r["properties"]["severity"], "low");
        assert_eq!(r["properties"]["confidence"], "low");
        assert_ne!(
            r["level"], "error",
            "a manual-review candidate must not be reported as an error"
        );
    }
}

#[test]
fn cli_json_format_is_unchanged() {
    // Regression: --format json must keep the previous contract.
    let v = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["tool"]["name"], "stellar-upgrade-radar");
    assert_eq!(v["target"]["protocol_version"], 30);
    assert_eq!(v["target"]["protocol_name"], "Bell");
    assert!(v["findings"].is_array());
    assert!(v["summary"]["by_rule"].is_object());
    assert!(v["summary"]["files_with_findings"].is_number());
    assert!(v["notices"].as_array().is_some_and(|a| !a.is_empty()));
}

#[test]
fn cli_sarif_is_deterministic() {
    let a = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    let b = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    assert_eq!(a, b, "SARIF output must be deterministic across runs");
}

#[test]
fn cli_sarif_partial_fingerprints_are_stable() {
    let a = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    let b = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    let ids = |v: &serde_json::Value| -> Vec<String> {
        v["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                r["partialFingerprints"]["stellarUpgradeRadarStableId"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    };
    let fa = ids(&a);
    assert_eq!(fa, ids(&b), "fingerprints must be stable");
    assert!(!fa.is_empty());
    assert!(
        fa.iter()
            .all(|s| s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())),
        "fingerprints must be 16-hex stable ids"
    );
}

#[test]
fn cli_sarif_locations_match_snippet_columns() {
    let v = run_cli(&[
        "check",
        fixtures_root().to_str().unwrap(),
        "--format",
        "sarif",
    ]);
    for r in v["runs"][0]["results"].as_array().unwrap() {
        let region = &r["locations"][0]["physicalLocation"]["region"];
        let start_line = region["startLine"].as_u64().unwrap();
        assert!(start_line >= 1);
        let snippet = region["snippet"]["text"].as_str().unwrap_or("");
        if let Some(sc) = region["startColumn"].as_u64() {
            let idx = snippet.find(['\'', '"']).unwrap_or(0);
            assert_eq!(
                sc,
                (idx + 1) as u64,
                "startColumn must match the snippet: {snippet:?}"
            );
        }
    }
}
