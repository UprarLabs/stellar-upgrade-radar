//! Minimal SARIF 2.1.0 emitter (no new dependency — built on `serde_json`).
//!
//! Design decisions (documented):
//! - **`level`** is a coarse SARIF level derived from `severity`:
//!   Critical/High -> `"error"`, Medium -> `"warning"`, Low -> `"note"`,
//!   Info -> `"none"`. `Info` -> `"none"` is a **policy decision**, not an
//!   automatic default: the scanner treats Info as "informational, not a
//!   problem", and SARIF `"none"` means the result does not indicate a problem.
//!   The original `severity`, `confidence` and `kind` are preserved in
//!   `result.properties`, so the coarser SARIF level loses no information.
//! - **`columnKind` is `"unicodeCodePoints"`.** The internal `Finding.column` is
//!   a 1-based **byte** offset; it is converted to a 1-based Unicode code-point
//!   column for the reported snippet line (exact for ASCII and tabs; a byte
//!   offset landing inside a multibyte UTF-8 character is mapped to that
//!   character's start). Declaring `unicodeCodePoints` without converting would
//!   be wrong, so the conversion is performed.
//! - **Notices** are emitted under `runs[0].properties.notices` (documented)
//!   rather than as notification descriptors, to avoid referencing a
//!   `reportingDescriptor` that is not defined in the run.
//! - **`partialFingerprints`** uses a stable, **non-cryptographic** FNV-1a 64
//!   hash of `(rule_id, file, line, snippet)` under the key
//!   `stellarUpgradeRadarStableId`. It is a matching id for baselines/dedup, not
//!   a cryptographic hash.
//! - The existing JSON output (`--format json`) is untouched.

use serde_json::{json, Value};

use crate::report::{Finding, Report, RuleDef, Severity};

/// Repository URL advertised as the tool's `informationUri`.
pub const REPO_URL: &str = "https://github.com/UprarLabs/stellar-upgrade-radar";

pub fn to_sarif(report: &Report) -> Value {
    let rules: Vec<Value> = report.rules.iter().map(rule_descriptor).collect();
    let results: Vec<Value> = report.findings.iter().map(|f| result(report, f)).collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool.name,
                    "version": report.tool.version,
                    "informationUri": REPO_URL,
                    "rules": rules,
                }
            },
            "columnKind": "unicodeCodePoints",
            "results": results,
            "properties": {
                "notices": report.notices,
                "target": {
                    "path": report.target.path,
                    "protocolVersion": report.target.protocol_version,
                    "protocolName": report.target.protocol_name,
                },
            },
        }]
    })
}

fn rule_descriptor(r: &RuleDef) -> Value {
    json!({
        "id": r.id,
        "name": r.title,
        "shortDescription": { "text": r.title },
        "fullDescription": { "text": r.description },
        "help": { "text": r.limitations.as_deref().unwrap_or("") },
        "defaultConfiguration": { "level": severity_to_level(r.severity) },
        "properties": {
            "protocol": r.protocol,
            "cap": r.cap,
            "status": r.status,
        },
    })
}

fn result(report: &Report, f: &Finding) -> Value {
    let rule_index = report
        .rules
        .iter()
        .position(|r| r.id == f.rule_id)
        .unwrap_or(0);
    let mut v = json!({
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "message": { "text": f.explanation },
        "level": severity_to_level(f.severity),
        "properties": {
            "severity": f.severity.as_str(),
            "confidence": f.confidence.as_str(),
            "kind": f.kind.as_str(),
        },
        "partialFingerprints": { "stellarUpgradeRadarStableId": stable_id(f) },
    });
    if let Some(loc) = location(f) {
        v["locations"] = json!([loc]);
    }
    v
}

/// Percent-encode a path for use as a SARIF `artifactLocation.uri` (RFC 3986).
/// Unreserved characters (`A-Z a-z 0-9 - . _ ~`) and `/` are kept; everything
/// else — spaces, `[`, `]`, `#`, `?`, and non-ASCII bytes — is encoded. This is
/// URI encoding, which is distinct from JSON string escaping (handled by the
/// serializer) and from path resolution.
fn encode_uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/');
        if keep {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

fn location(f: &Finding) -> Option<Value> {
    let line = f.line?;
    let snippet = f.snippet.as_deref().unwrap_or("");
    let col = byte_col_to_codepoint_col(snippet, f.column);
    let mut region = json!({ "startLine": line });
    if let Some(c) = col {
        region["startColumn"] = json!(c);
    }
    if !snippet.is_empty() {
        region["snippet"] = json!({ "text": snippet });
    }
    Some(json!({
        "physicalLocation": {
            "artifactLocation": { "uri": encode_uri(&f.file) },
            "region": region,
        }
    }))
}

/// SARIF level for a severity. `Info -> "none"` is a documented policy decision
/// (see module docs).
pub fn severity_to_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

/// Convert a 1-based byte offset into a 1-based Unicode code-point column.
pub fn byte_col_to_codepoint_col(line: &str, byte_col: Option<usize>) -> Option<usize> {
    let bc = byte_col?;
    if bc == 0 {
        return Some(1);
    }
    let n = floor_char_boundary(line, (bc - 1).min(line.len()));
    Some(line[..n].chars().count() + 1)
}

fn floor_char_boundary(s: &str, mut n: usize) -> usize {
    if n >= s.len() {
        return s.len();
    }
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    n
}

/// Stable, non-cryptographic identity for a finding (FNV-1a 64).
pub fn stable_id(f: &Finding) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let line = f.line.map(|l| l.to_string()).unwrap_or_default();
    let snippet = f.snippet.as_deref().unwrap_or("");
    for part in [f.rule_id.as_str(), f.file.as_str(), line.as_str(), snippet] {
        for b in part.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h ^= 0xff; // field separator
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Confidence, Finding, Kind};

    #[test]
    fn severity_mapping_covers_all_levels() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
        assert_eq!(severity_to_level(Severity::High), "error");
        assert_eq!(severity_to_level(Severity::Medium), "warning");
        assert_eq!(severity_to_level(Severity::Low), "note");
        assert_eq!(severity_to_level(Severity::Info), "none");
    }

    #[test]
    fn byte_column_matches_codepoint_for_ascii_and_tab() {
        assert_eq!(byte_col_to_codepoint_col("abc", Some(1)), Some(1));
        assert_eq!(byte_col_to_codepoint_col("abc", Some(3)), Some(3));
        assert_eq!(byte_col_to_codepoint_col("\t\t['G'", Some(3)), Some(3));
    }

    #[test]
    fn byte_column_converts_multibyte_utf8() {
        // bytes: a(1) é(2,3) X(4). Byte col 2 -> 'é' (code point 2); col 4 -> 'X' (code point 3).
        assert_eq!(byte_col_to_codepoint_col("aéX", Some(2)), Some(2));
        assert_eq!(byte_col_to_codepoint_col("aéX", Some(4)), Some(3));
        // A byte offset landing inside the multibyte char maps to its start.
        assert_eq!(byte_col_to_codepoint_col("aéX", Some(3)), Some(2));
    }

    #[test]
    fn stable_id_is_stable_and_distinct() {
        let f = Finding::new(
            "SUR-1001",
            "t",
            Severity::High,
            Confidence::High,
            Kind::Static,
            "a.rs",
        )
        .location(3, Some(6), Some("['G']"));
        let g = Finding::new(
            "SUR-1001",
            "t",
            Severity::High,
            Confidence::High,
            Kind::Static,
            "a.rs",
        )
        .location(3, Some(6), Some("['G']"));
        let h = Finding::new(
            "SUR-1002",
            "t",
            Severity::High,
            Confidence::High,
            Kind::Static,
            "a.rs",
        )
        .location(3, Some(6), Some("['G']"));
        assert_eq!(stable_id(&f), stable_id(&g), "same input -> same id");
        assert_ne!(
            stable_id(&f),
            stable_id(&h),
            "different rule -> different id"
        );
    }

    #[test]
    fn sarif_structure_has_required_fields() {
        let report = crate::report::Report::new(".".to_string(), Vec::new());
        let v = to_sarif(&report);
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
        let run = &v["runs"][0];
        assert_eq!(run["columnKind"], "unicodeCodePoints");
        assert_eq!(run["tool"]["driver"]["name"], "stellar-upgrade-radar");
        assert_eq!(run["tool"]["driver"]["informationUri"], REPO_URL);
    }

    #[test]
    fn encode_uri_percent_encodes_special_characters() {
        // Unreserved characters and `/` are preserved.
        assert_eq!(encode_uri("src/lib.rs"), "src/lib.rs");
        assert_eq!(encode_uri("a-b_c.d~e"), "a-b_c.d~e");
        // Spaces, brackets and other reserved characters are percent-encoded.
        assert_eq!(encode_uri("src with spaces.rs"), "src%20with%20spaces.rs");
        assert_eq!(encode_uri("src[special].rs"), "src%5Bspecial%5D.rs");
        assert_eq!(encode_uri("a#b?c"), "a%23b%3Fc");
        // Non-ASCII is encoded per byte (UTF-8), not per character.
        assert_eq!(encode_uri("émoji.rs"), "%C3%A9moji.rs");
    }
}
