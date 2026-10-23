//! Integration tests: run the analyzer over the fixture corpus and exercise the
//! real CLI binary (exit codes and JSON output). Every assertion is checked
//! against actual output, not assumptions.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use stellar_upgrade_radar::analyze;
use stellar_upgrade_radar::report::Severity;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn findings() -> Vec<stellar_upgrade_radar::report::Finding> {
    analyze(&fixtures_root(), Severity::Info).findings
}

fn files_for(rule_id: &str) -> Vec<String> {
    findings()
        .into_iter()
        .filter(|f| f.rule_id == rule_id)
        .map(|f| f.file)
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
        !files.iter().any(|f| f.ends_with("w_address_safe.rs")),
        "SUR-1001 must not fire on w_address_safe.rs, got {files:?}"
    );
}

#[test]
fn sur_1002_flags_old_deps_and_spares_current_deps() {
    let files = files_for("SUR-1002");
    assert!(
        files.iter().any(|f| f.contains("dep_old/Cargo.toml")),
        "got {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("dep_strkey/Cargo.toml")),
        "got {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("dep_git/Cargo.toml")),
        "got {files:?}"
    );
    assert!(
        !files.iter().any(|f| f.contains("dep_new/Cargo.toml")),
        "SUR-1002 must not fire on dep_new/Cargo.toml, got {files:?}"
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
fn sur_1004_flags_timestamp_assumption_and_spares_ms_aware_fixture() {
    let files = files_for("SUR-1004");
    assert!(
        files.iter().any(|f| f.ends_with("timestamp_unsafe.rs")),
        "got {files:?}"
    );
    assert!(
        !files.iter().any(|f| f.ends_with("timestamp_safe.rs")),
        "SUR-1004 must not fire on timestamp_safe.rs, got {files:?}"
    );
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
    // Every finding must carry at least one authoritative source and a location.
    for f in &report.findings {
        assert!(!f.sources.is_empty(), "{} lacks sources", f.rule_id);
        assert!(f.line.is_some(), "{} lacks a line number", f.rule_id);
    }
    let counts = rule_counts();
    assert!(counts.contains_key("SUR-1001"));
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
    // Severity keys must be lowercase labels, not enum debug names.
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
    // SUR-1004 is Low; asking for High must drop it.
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
        "Low finding should be filtered: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id == "SUR-1001"),
        "High finding should remain: {ids:?}"
    );
}
