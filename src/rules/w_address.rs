//! SUR-1001 — muxed contract address (W-address) handling under CAP-84/SEP-23.
//!
//! A W address uses `STRKEY_MUXED_CONTRACT` (version byte `0xb0`, first char `W`).
//! An application that validates addresses by enumerating only the pre-CAP-84
//! strkey prefixes will reject W addresses. We flag **literal prefix/version-byte
//! allowlists** that omit the W variant — but only inside a file that actually
//! talks about addresses/strkeys, so unrelated character sets are not flagged.
//!
//! Deliberately NOT flagged: address validation delegated to a maintained strkey
//! library, which handles W internally without the application hard-coding `'W'`.

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::Rule;
use crate::rules::{STRKEY_NON_W_BYTES, STRKEY_NON_W_CHARS, W_STRKEY_CHAR, W_VERSION_BYTE};
use crate::scan::FileCtx;

pub struct WAddressRule;

impl Rule for WAddressRule {
    fn id(&self) -> &'static str {
        "SUR-1001"
    }
    fn title(&self) -> &'static str {
        "Strkey allowlist omits W-address (CAP-84/SEP-23) variant"
    }
    fn description(&self) -> &'static str {
        "Flags literal strkey prefix/version-byte allowlists (in address-related code) that enumerate known non-W variants but exclude the W (muxed contract) variant."
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
        "CAP-84"
    }
    fn limitations(&self) -> Option<&'static str> {
        Some("Only flags explicit literal allowlists in files that reference addresses/strkeys. Validation delegated to a strkey library is not flagged (correctly, but also not verified). Dynamically built allowlists are out of scope. Raw strings (`r\"...\"`, `r#\"...\"#`) and byte strings are approximated as ordinary strings; a raw string with an embedded `#`/quote pattern is not parsed precisely.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        // Context gate: a bare character set is not an address check.
        if !is_address_context(&ctx.content) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for (i, line) in ctx.lines.iter().enumerate() {
            let ln = i + 1;

            // Strategy 1: quoted prefix tokens — ['G','M','C'] or the packed
            // string form "GMCBXT" (decomposed into its characters).
            let found = quoted_prefix_chars(line);
            let non_w: Vec<char> = found
                .iter()
                .filter(|c| STRKEY_NON_W_CHARS.contains(c))
                .copied()
                .collect();
            if non_w.len() >= 3 && !found.contains(&W_STRKEY_CHAR) {
                findings.push(emit(
                    self,
                    &ctx.rel_path,
                    ln,
                    char_allowlist_column(line),
                    line,
                    "This allowlist enumerates known strkey prefixes but omits the W (muxed contract address) variant. After Protocol 30, addresses beginning with W are valid destinations for Stellar Asset Contract transfers and will be rejected here.",
                    "Add the W variant to the allowlist, or replace hand-rolled validation with a maintained strkey library that understands CAP-84.",
                ));
            }

            // Strategy 2: version-byte arrays, e.g. [0x30, 0x60, 0x90].
            if line.contains("0x") || line.contains("0X") {
                let bytes = hex_bytes(line);
                let non_w_b = bytes
                    .iter()
                    .filter(|b| STRKEY_NON_W_BYTES.contains(b))
                    .count();
                if non_w_b >= 2 && !bytes.contains(&W_VERSION_BYTE) {
                    findings.push(emit(
                        self,
                        &ctx.rel_path,
                        ln,
                        line.find("0x").or_else(|| line.find("0X")).map(|p| p + 1),
                        line,
                        "This version-byte allowlist enumerates known non-W strkey version bytes but omits 0xb0 (STRKEY_MUXED_CONTRACT), so W addresses are rejected.",
                        "Add version byte 0xb0 to the supported set.",
                    ));
                }
            }
        }
        findings
    }
}

/// The file must mention addresses/strkeys in code (not in a comment) for a
/// character set to be treated as an address allowlist. Comments are stripped
/// first so an unrelated comment cannot trigger a false positive; conversely a
/// `// address allowlist` comment on the same line as an allowlist can produce
/// a false negative (documented limitation).
fn is_address_context(content: &str) -> bool {
    let code = strip_comments(content).to_lowercase();
    code.contains("strkey")
        || code.contains("prefix")
        || code.contains("address")
        || code.contains("muxed")
}

/// Remove `/* */` block comments and `//` line comments **without** treating
/// comment markers inside string/char literals as comments. The scanner tracks
/// `"..."` / `'...'` literals and backslash escapes, so `//` inside
/// `"https://..."` or `/*` inside a string is preserved. Documented limitation:
/// a `//` or `/*` inside a string is preserved but not interpreted as code, and
/// a raw/byte literal is approximated as a normal string.
fn strip_comments(s: &str) -> String {
    #[derive(PartialEq)]
    enum State {
        Normal,
        Str,
        Char,
        Block,
        Line,
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut state = State::Normal;
    let mut i = 0;
    let n = b.len();
    while i < n {
        let c = b[i];
        match state {
            State::Normal => {
                if i + 1 < n && c == b'/' && b[i + 1] == b'/' {
                    state = State::Line;
                    i += 2;
                    continue;
                }
                if i + 1 < n && c == b'/' && b[i + 1] == b'*' {
                    state = State::Block;
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    state = State::Str;
                } else if c == b'\'' {
                    state = State::Char;
                }
                out.push(c as char);
                i += 1;
            }
            State::Str | State::Char => {
                let quote = if state == State::Str { b'"' } else { b'\'' };
                if c == b'\\' {
                    out.push(c as char);
                    if i + 1 < n {
                        out.push(b[i + 1] as char);
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if c == quote {
                    state = State::Normal;
                }
                out.push(c as char);
                i += 1;
            }
            State::Block => {
                if i + 1 < n && c == b'*' && b[i + 1] == b'/' {
                    state = State::Normal;
                    i += 2;
                    continue;
                }
                i += 1;
            }
            State::Line => {
                if c == b'\n' {
                    state = State::Normal;
                    out.push(c as char);
                }
                i += 1;
            }
        }
    }
    out
}

/// Characters appearing as quoted prefix tokens: single-char tokens (`'G'`) and
/// packed string tokens whose contents are entirely strkey-alphabet characters
/// (`"GMCBXT"`). A token mixing in other characters is ignored.
fn quoted_prefix_chars(line: &str) -> Vec<char> {
    let mut out = Vec::new();
    for (i, quote) in line.char_indices().filter(|(_, c)| *c == '\'' || *c == '"') {
        let Some(end) = line[i + 1..].find(quote) else {
            continue;
        };
        let body = &line[i + 1..i + 1 + end];
        if body.is_empty() || body.len() > 16 {
            continue;
        }
        let all_strkey = body
            .chars()
            .all(|c| STRKEY_NON_W_CHARS.contains(&c) || c == W_STRKEY_CHAR);
        if all_strkey {
            out.extend(body.chars());
        }
    }
    out
}

/// 1-based column of the opening quote of the first quoted prefix token.
fn char_allowlist_column(line: &str) -> Option<usize> {
    for (i, quote) in line.char_indices().filter(|(_, c)| *c == '\'' || *c == '"') {
        let Some(end) = line[i + 1..].find(quote) else {
            continue;
        };
        let body = &line[i + 1..i + 1 + end];
        if body
            .chars()
            .any(|c| STRKEY_NON_W_CHARS.contains(&c) || c == W_STRKEY_CHAR)
        {
            return Some(i + 1);
        }
    }
    None
}

fn hex_bytes(line: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for tok in line.split(|c: char| !(c.is_ascii_hexdigit() || c == 'x' || c == 'X')) {
        let stripped = tok.trim_start_matches("0x").trim_start_matches("0X");
        if stripped.len() == 2 {
            if let Ok(v) = u32::from_str_radix(stripped, 16) {
                out.push(v);
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn emit(
    rule: &dyn Rule,
    file: &str,
    line: usize,
    column: Option<usize>,
    raw: &str,
    expl: &str,
    rec: &str,
) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        rule.severity(),
        Confidence::High,
        rule.kind(),
        file,
    )
    .location(line, column, Some(raw))
    .explanation(expl)
    .sources(&[
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
        "https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md",
    ])
    .recommendation(rec)
    .limitations(
        "Only literal allowlists in address-related files; confirm custom decoders manually.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Confidence, Kind, Severity};
    use crate::scan::FileCtx;

    fn ctx(file: &str, src: &str) -> FileCtx {
        FileCtx::from_source(file, src)
    }

    #[test]
    fn flags_char_allowlist_missing_w() {
        let src =
            "fn valid_strkey_prefix(c: char) -> bool { ['G','M','C','B','X','T'].contains(&c) }";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "SUR-1001");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!(f[0].kind, Kind::Static);
        assert_eq!(f[0].line, Some(1));
        assert_eq!(f[0].column, Some(src.find('\'').unwrap() + 1));
    }

    #[test]
    fn flags_packed_string_allowlist_missing_w() {
        let src = "const STRKEY_PREFIXES: &str = \"GMCBXT\";";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1, "packed string form must be detected");
    }

    #[test]
    fn does_not_flag_allowlist_with_w() {
        let src = "fn valid_strkey_prefix(c: char) -> bool { ['G','M','W','C'].contains(&c) }";
        assert!(WAddressRule.scan(&ctx("x.rs", src)).is_empty());
    }

    #[test]
    fn does_not_flag_unrelated_char_set_without_address_context() {
        // Regression: a colour/palette array must not be read as an address allowlist.
        let src = "fn palette() -> [char; 3] { ['G','M','C'] }";
        assert!(WAddressRule.scan(&ctx("x.rs", src)).is_empty());
    }

    #[test]
    fn comment_mentioning_address_does_not_create_context() {
        // Regression: the word "address" in a comment must not trigger a finding.
        let src = "// no address context here\nfn palette() -> [char; 3] { ['G','M','C'] }";
        assert!(WAddressRule.scan(&ctx("x.rs", src)).is_empty());
    }

    #[test]
    fn strip_comments_preserves_url_inside_string() {
        let src = r#"let u = "https://example.org"; // address-context"#;
        let stripped = strip_comments(src);
        assert!(
            stripped.contains("https://example.org"),
            "URL inside a string must survive stripping"
        );
        assert!(
            !stripped.contains("address-context"),
            "trailing line comment must be stripped"
        );
    }

    #[test]
    fn strip_comments_handles_escaped_quote() {
        let src = r#"let s = "a\"b//c"; // trailing"#;
        let stripped = strip_comments(src);
        assert!(
            stripped.contains(r#""a\"b//c""#),
            "escaped quote must not end the string: {stripped}"
        );
        assert!(!stripped.contains("trailing"), "trailing comment stripped");
    }

    #[test]
    fn url_string_does_not_truncate_a_genuine_allowlist() {
        // Regression: a `//` inside a URL string on the same line as a genuine
        // allowlist must not truncate the allowlist (a naive stripper would miss
        // the finding).
        let src = concat!(
            "fn valid_strkey_prefix(c: char) -> bool { ",
            "let _ = \"https://x.org\"; ",
            "['G','M','C','B','X','T'].contains(&c) }"
        );
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(
            f.len(),
            1,
            "allowlist on a URL-string line must be flagged: {f:?}"
        );
    }

    #[test]
    fn does_not_flag_library_based_validation() {
        let src =
            "fn valid_address(s: &str) -> bool { stellar_strkey::Strkey::from_string(s).is_ok() }";
        assert!(WAddressRule.scan(&ctx("x.rs", src)).is_empty());
    }

    #[test]
    fn flags_byte_array_missing_w() {
        let src = "const STRKEY_ALLOWED: [u8; 3] = [0x30, 0x60, 0x90];";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn does_not_flag_byte_array_with_w() {
        let src = "const STRKEY_ALLOWED: [u8; 4] = [0x30, 0x60, 0x90, 0xb0];";
        assert!(WAddressRule.scan(&ctx("x.rs", src)).is_empty());
    }

    #[test]
    fn ignores_lines_with_few_chars() {
        assert!(WAddressRule.scan(&ctx("x.rs", "let x = 'X';")).is_empty());
    }
}
