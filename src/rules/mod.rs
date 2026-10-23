//! Rule framework: trait, registry, and shared helpers for locating evidence.

use crate::report::{Finding, Kind, Severity};
use crate::scan::FileCtx;

/// A single upgrade-readiness check. Implementations are `Sync` so the scan
/// loop can (eventually) run rules across files in parallel.
pub trait Rule: Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn kind(&self) -> Kind;
    fn protocol(&self) -> &'static str;
    fn cap(&self) -> &'static str;
    fn limitations(&self) -> Option<&'static str> {
        None
    }
    fn status(&self) -> &'static str {
        "implemented"
    }
    fn scan(&self, ctx: &FileCtx) -> Vec<Finding>;
}

pub mod dependency;
pub mod timestamp;
pub mod w_address;
pub mod xdr_header;

/// Build the canonical registry. Order is stable so report headers are stable.
pub fn registry() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(w_address::WAddressRule),
        Box::new(dependency::DependencyRule),
        Box::new(xdr_header::XdrHeaderRule),
        Box::new(timestamp::TimestampRule),
    ]
}

/// All known version-byte / first-char strkey prefixes (excluding W), drawn from
/// SEP-23. Used by the W-address rule's literals scan.
pub const STRKEY_NON_W_CHARS: &[char] = &['G', 'M', 'S', 'T', 'X', 'P', 'C', 'L', 'B'];
/// The muxed contract strkey prefix (W) and its version byte, SEP-23 / CAP-84.
pub const W_STRKEY_CHAR: char = 'W';
pub const W_VERSION_BYTE: u32 = 0xb0; // 22 << 3
/// Known non-W version bytes (base values only; algorithm spec low bits = 0).
pub const STRKEY_NON_W_BYTES: &[u32] = &[0x30, 0x60, 0x90, 0x98, 0xb8, 0x78, 0x10, 0x58, 0x08];

/// Locate every occurrence of `needle` as a substring, returning 1-based
/// (line, column) where column is the byte offset within the line.
pub fn locate(content: &str, needle: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let mut start = 0;
        while let Some(pos) = line[start..].find(needle) {
            let col = start + pos + 1; // 1-based column
            out.push((i + 1, col));
            start += pos + needle.len();
        }
    }
    out
}

/// Trim context to a bounded snippet window around `col` (1-based) so evidence
/// in the report stays readable.
pub fn snippet_at(line: &str, col: usize) -> String {
    let col0 = col.saturating_sub(1);
    let start = col0.saturating_sub(6);
    let end = (col0 + 40).min(line.len());
    let seg = &line[start..end];
    if start > 0 {
        format!("... {}", seg.trim())
    } else {
        format!("{} ...", seg.trim())
    }
}

/// Parse the first integer-major from a Cargo.toml requirement spec such as
/// `"^28"`, `"0.28.0"`, `">= 30.0.0"`, or `30`. Returns `None` for git/path deps
/// (no numeric version) so callers can downgrade to a manual-review finding.
pub fn cargo_major_version(req: &str) -> Option<u32> {
    let cleaned = req.trim_start_matches(|c: char| !c.is_ascii_digit());
    let num: String = cleaned
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let first = num.split('.').next()?;
    first.parse::<u32>().ok()
}

/// Detect a substring literal token delimited by single or double quotes on a
/// line, returning each quoted token's text. Used to scan strkey allowlists
/// that appear as `['G', 'M', ...]` or `"GMCB..."`.
pub fn quoted_tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, quote) in line.char_indices().filter(|(_, c)| *c == '\'' || *c == '"') {
        if let Some(end) = line[i + 1..].find(quote) {
            let body = &line[i + 1..i + 1 + end];
            if !body.is_empty() && body.len() <= 16 {
                out.push(body.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_finds_all_occurrences() {
        let hits = locate("aXb\nXb\n", "Xb");
        assert_eq!(hits, vec![(1, 2), (2, 1)]);
    }

    #[test]
    fn cargo_major_strips_caret_and_rc() {
        assert_eq!(cargo_major_version("^28.0.1"), Some(28));
        assert_eq!(cargo_major_version("30.0.0-rc.1"), Some(30));
        assert_eq!(cargo_major_version(">= 29.0.0"), Some(29));
        assert_eq!(cargo_major_version("0.28.0"), Some(0));
        assert_eq!(cargo_major_version("git = \"https://...\""), None);
    }

    #[test]
    fn quoted_tokens_single_and_double() {
        let toks = quoted_tokens("let a = ['G','M','W']\n");
        assert!(toks.contains(&"G".to_string()));
        assert!(toks.contains(&"M".to_string()));
        assert!(toks.contains(&"W".to_string()));
    }
}
