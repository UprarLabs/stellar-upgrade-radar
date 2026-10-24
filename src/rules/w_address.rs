//! SUR-1001 — muxed contract address (W-address) handling under CAP-84/SEP-23.
//!
//! A W address uses `STRKEY_MUXED_CONTRACT` (version byte `0xb0`, first char `W`).
//! An application that validates addresses by enumerating only the pre-CAP-84
//! strkey prefixes will reject W addresses. We flag **literal prefix/version-byte
//! allowlists** that omit the W variant.
//!
//! Precision rules (from adversarial audit):
//! - Context is computed from **code only**: string-literal contents and comments
//!   are ignored, so a doc string like `"the address format"` or a comment does
//!   not create address context. Context requires a strkey/muxed/Soroban-address
//!   type term, or an allowlist-named declaration — a bare `address`/`prefix`
//!   substring in an unrelated identifier is not enough.
//! - A char/string allowlist must be a real enumeration (an array literal, or a
//!   `const`/`static`/`let` binding whose name is allowlist-ish). An arbitrary
//!   short string such as `"GMC"` is not treated as an allowlist.
//! - Version-byte arrays additionally require a strkey/muxed term in the same
//!   declaration, so unrelated byte arrays are not flagged.
//! - Allowlist arrays may span multiple lines.

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
        "Flags literal strkey prefix/version-byte allowlists (in strkey/address code) that enumerate known non-W variants but exclude the W (muxed contract) variant."
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
        Some("Context is derived from code only (string/comment contents ignored) and requires strkey/muxed/Soroban-address evidence, an allowlist-named binding, or a strkey-char array used in a validation predicate (`.contains`/`.iter`/`.any`/`.position`); a bare `address`/`prefix` substring in an unrelated identifier is not context. Char/string allowlists must be an array literal or an allowlist-named binding — an arbitrary short string is not an allowlist. Version-byte arrays require a strkey/muxed term in the same declaration. Validation delegated to a strkey library is not flagged (correctly, but also not verified). Dynamically built allowlists and a strkey-char array with no validation use or allowlist name are out of scope.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        if !context_ok(ctx) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for (ln, unit) in array_units(&ctx.lines) {
            // The snippet and column must refer to the same (trimmed) text so the
            // reported location is accurate.
            let first = ctx
                .lines
                .get(ln - 1)
                .map(|s| s.trim())
                .unwrap_or("")
                .to_string();

            // Strategy 1: char/string allowlist enumeration.
            if let Some(found) = char_allowlist_chars(&unit) {
                let non_w = found
                    .iter()
                    .filter(|c| STRKEY_NON_W_CHARS.contains(c))
                    .count();
                if non_w >= 3 && !found.contains(&W_STRKEY_CHAR) {
                    findings.push(emit(
                        self,
                        &ctx.rel_path,
                        ln,
                        char_allowlist_column(&first),
                        &first,
                        "This allowlist enumerates known strkey prefixes but omits the W (muxed contract address) variant. After Protocol 30, addresses beginning with W are valid destinations for Stellar Asset Contract transfers and will be rejected here.",
                        "Add the W variant to the allowlist, or replace hand-rolled validation with a maintained strkey library that understands CAP-84.",
                    ));
                }
            }

            // Strategy 2: version-byte allowlist (requires a strkey/muxed term).
            let lower = unit.to_lowercase();
            if (lower.contains("strkey") || lower.contains("muxed"))
                && (unit.contains("0x") || unit.contains("0X"))
            {
                let bytes = hex_bytes(&unit);
                let non_w_b = bytes
                    .iter()
                    .filter(|b| STRKEY_NON_W_BYTES.contains(b))
                    .count();
                if non_w_b >= 2 && !bytes.contains(&W_VERSION_BYTE) {
                    let col = first.find("0x").or_else(|| first.find("0X")).map(|p| p + 1);
                    findings.push(emit(
                        self,
                        &ctx.rel_path,
                        ln,
                        col,
                        &first,
                        "This version-byte allowlist enumerates known non-W strkey version bytes but omits 0xb0 (STRKEY_MUXED_CONTRACT), so W addresses are rejected.",
                        "Add version byte 0xb0 to the supported set.",
                    ));
                }
            }
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Strong address/strkey evidence in code (string/comment contents removed).
fn has_strong_context(code: &str) -> bool {
    [
        "strkey",
        "muxed",
        "scaddress",
        "muxedcontract",
        "muxedaddress",
    ]
    .iter()
    .any(|k| code.contains(k))
}

/// A file is in scope when it shows strong strkey/address evidence, or it declares
/// an allowlist-named binding that actually holds strkey characters.
fn context_ok(ctx: &FileCtx) -> bool {
    let code = blank_strings(&strip_comments(&ctx.content)).to_lowercase();
    has_strong_context(&code) || has_allowlist_use(ctx)
}

/// The file uses a strkey allowlist: either an allowlist-named binding holding
/// strkey characters, or a strkey-char array used in a validation predicate.
fn has_allowlist_use(ctx: &FileCtx) -> bool {
    for (_, unit) in array_units(&ctx.lines) {
        if let Some(name) = declaration_name(&unit) {
            if is_allowlist_name(&name) && !quoted_prefix_chars(&unit).is_empty() {
                return true;
            }
        }
        let strkey_chars = quoted_prefix_chars(&unit)
            .iter()
            .filter(|c| STRKEY_NON_W_CHARS.contains(c))
            .count();
        if strkey_chars >= 1
            && [".contains(", ".iter(", ".any(", ".position("]
                .iter()
                .any(|k| unit.contains(k))
        {
            return true;
        }
    }
    false
}

fn is_allowlist_name(name: &str) -> bool {
    let n = name.to_lowercase();
    ["strkey", "prefix", "allow", "muxed", "valid"]
        .iter()
        .any(|k| n.contains(k))
}

/// The binding name of a `const`/`static`/`let` declaration, if the unit is one.
fn declaration_name(unit: &str) -> Option<String> {
    let t = unit.trim_start();
    let t = t.strip_prefix("pub ").unwrap_or(t);
    for kw in ["const ", "static ", "let "] {
        if let Some(rest) = t.strip_prefix(kw) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Array units (multi-line aware)
// ---------------------------------------------------------------------------

/// Split the file into units, joining array literals that span multiple lines so
/// an allowlist written one character per line is analysed as one unit.
fn array_units(lines: &[String]) -> Vec<(usize, String)> {
    let mut units = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        let opens = line.matches('[').count();
        let closes = line.matches(']').count();
        let has_quote = line.contains('\'') || line.contains('"');
        if opens > closes && has_quote {
            let start = i;
            let mut acc = line.clone();
            let mut depth = opens as i32 - closes as i32;
            let mut j = i;
            while depth > 0 && j + 1 < lines.len() {
                j += 1;
                acc.push(' ');
                acc.push_str(&lines[j]);
                depth +=
                    lines[j].matches('[').count() as i32 - lines[j].matches(']').count() as i32;
            }
            units.push((start + 1, acc));
            i = j + 1;
            continue;
        }
        units.push((i + 1, line.clone()));
        i += 1;
    }
    units
}

/// Characters of a strkey prefix/string allowlist, or `None` when the unit is not
/// an allowlist enumeration.
fn char_allowlist_chars(unit: &str) -> Option<Vec<char>> {
    if unit.contains('[') && unit.contains(']') {
        let chars = quoted_prefix_chars(unit);
        return if chars.is_empty() { None } else { Some(chars) };
    }
    // Packed string form (`const STRKEY_PREFIXES: &str = "GMCBXT"`).
    let name = declaration_name(unit)?;
    if !is_allowlist_name(&name) {
        return None;
    }
    let chars = quoted_prefix_chars(unit);
    if chars.is_empty() {
        None
    } else {
        Some(chars)
    }
}

/// Remove `/* */` block comments and `//` line comments **without** treating
/// comment markers inside string/char literals as comments.
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

/// Replace the contents of string/char literals with spaces (quotes kept), so
/// words inside strings do not create address context.
fn blank_strings(s: &str) -> String {
    #[derive(PartialEq)]
    enum State {
        Normal,
        Str,
        Char,
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut state = State::Normal;
    let mut i = 0;
    let n = b.len();
    while i < n {
        let c = b[i];
        match state {
            State::Normal => {
                if c == b'"' {
                    state = State::Str;
                    out.push(c);
                } else if c == b'\'' {
                    state = State::Char;
                    out.push(c);
                } else {
                    out.push(c);
                }
                i += 1;
            }
            State::Str | State::Char => {
                let quote = if state == State::Str { b'"' } else { b'\'' };
                if c == b'\\' {
                    out.push(b' ');
                    if i + 1 < n {
                        out.push(b' ');
                        i += 2;
                    } else {
                        i += 1;
                    }
                } else if c == quote {
                    out.push(c);
                    state = State::Normal;
                    i += 1;
                } else {
                    out.push(b' ');
                    i += 1;
                }
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    .recommendation(rec)
    .sources(&[
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
        "https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md",
    ])
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
        let src = "fn palette() -> [char; 3] { ['G','M','C'] }";
        assert!(WAddressRule.scan(&ctx("x.rs", src)).is_empty());
    }

    #[test]
    fn comment_mentioning_address_does_not_create_context() {
        let src = "// no address context here\nfn palette() -> [char; 3] { ['G','M','C'] }";
        assert!(WAddressRule.scan(&ctx("x.rs", src)).is_empty());
    }

    #[test]
    fn strip_comments_preserves_url_inside_string() {
        let src = r#"let u = "https://example.org"; // address-context"#;
        let stripped = strip_comments(src);
        assert!(stripped.contains("https://example.org"));
        assert!(!stripped.contains("address-context"));
    }

    #[test]
    fn strip_comments_handles_escaped_quote() {
        let src = r#"let s = "a\"b//c"; // trailing"#;
        let stripped = strip_comments(src);
        assert!(stripped.contains(r#""a\"b//c""#));
        assert!(!stripped.contains("trailing"));
    }

    #[test]
    fn url_string_does_not_truncate_a_genuine_allowlist() {
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

    // ---- adversarial-audit regressions ----

    #[test]
    fn does_not_flag_address_word_inside_a_string() {
        let src =
            "let doc = \"this describes the address format\";\nfn palette() -> [char; 3] { ['G', 'M', 'C'] }\n";
        assert!(
            WAddressRule.scan(&ctx("x.rs", src)).is_empty(),
            "a string must not create address context"
        );
    }

    #[test]
    fn does_not_flag_unrelated_prefix_identifier() {
        let src = "fn set_prefix_label() { let colors = ['G', 'M', 'C']; }\n";
        assert!(
            WAddressRule.scan(&ctx("x.rs", src)).is_empty(),
            "an unrelated identifier must not create context"
        );
    }

    #[test]
    fn does_not_flag_unrelated_hex_bytes() {
        let src = "fn address_palette() -> [u8; 3] { [0x90, 0xb8, 0x78] }\n";
        assert!(
            WAddressRule.scan(&ctx("x.rs", src)).is_empty(),
            "unrelated byte arrays must not be flagged"
        );
    }

    #[test]
    fn does_not_flag_short_strkey_string() {
        let src = "fn valid_strkey_prefix() { let s = \"GMC\"; }\n";
        assert!(
            WAddressRule.scan(&ctx("x.rs", src)).is_empty(),
            "an arbitrary short string is not an allowlist"
        );
    }

    #[test]
    fn flags_multiline_char_allowlist() {
        let src = "fn valid_strkey_prefix(c: char) -> bool {\n    ['G',\n     'M',\n     'C',\n     'B',\n     'X',\n     'T'].contains(&c)\n}\n";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1, "multi-line allowlist must be detected: {f:?}");
        assert_eq!(f[0].line, Some(2));
    }

    #[test]
    fn flags_allowlist_named_prefixes_without_strkey() {
        let src = "const PREFIXES: &[char] = &['G', 'M', 'C', 'B'];\n";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(
            f.len(),
            1,
            "allowlist-named declaration must be detected: {f:?}"
        );
    }
}
