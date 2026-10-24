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
