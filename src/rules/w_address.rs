//! SUR-1001 — muxed contract address (W-address) handling under CAP-84/SEP-23.
//!
//! A W address uses `STRKEY_MUXED_CONTRACT` (version byte `0xb0`, first char `W`).
//! Any application that validates, displays, stores or routes Stellar addresses
//! by enumerating only the pre-CAP-84 strkey prefixes will reject W addresses.
//! We flag explicit literal allowlists that enumerate 3+ known prefixes but
//! omit W, plus version-byte arrays listing 2+ known bytes but omitting `0xb0`.

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::Rule;
use crate::rules::{
    quoted_tokens, STRKEY_NON_W_BYTES, STRKEY_NON_W_CHARS, W_STRKEY_CHAR, W_VERSION_BYTE,
};
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
        "Flags literal strkey prefix/version-byte allowlists that enumerate known non-W variants but exclude the W (muxed contract) variant."
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
        Some("Only detects explicit literal allowlists. Opaque or dynamically-built validators are out of scope and should be confirmed manually.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (i, line) in ctx.lines.iter().enumerate() {
            let ln = i + 1;

            // Strategy 1: quoted strkey prefix tokens, e.g ['G','M','C'] or "GMCB".
            let toks = quoted_tokens(line);
            let mut found = Vec::new();
            for t in &toks {
                if t.len() == 1 {
                    if let Some(ch) = t.chars().next() {
                        found.push(ch);
                    }
                }
            }
            let non_w: Vec<char> = found
                .iter()
                .filter(|c| STRKEY_NON_W_CHARS.contains(c))
                .copied()
                .collect();
            if non_w.len() >= 3 && !found.contains(&W_STRKEY_CHAR) {
                findings.push(emit(
                    self, &ctx.rel_path, ln, line,
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
                let has_w = bytes.contains(&W_VERSION_BYTE);
                if non_w_b >= 2 && !has_w {
                    findings.push(emit(
                        self, &ctx.rel_path, ln, line,
                        "This version-byte allowlist enumerates known non-W strkey version bytes but omits 0xb0 (STRKEY_MUXED_CONTRACT), so W addresses are rejected.",
                        "Add version byte 0xb0 to the supported set.",
                    ));
                }
            }
        }
        findings
    }
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

fn emit(rule: &dyn Rule, file: &str, line: usize, raw: &str, expl: &str, rec: &str) -> Finding {
    Finding::new(
        rule.id(),
        rule.title(),
        rule.severity(),
        Confidence::High,
        rule.kind(),
        file,
    )
    .location(line, Some(1), Some(raw))
    .explanation(expl)
    .sources(&[
        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
        "https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md",
    ])
    .recommendation(rec)
    .limitations("ponytail: only literal allowlists; verify custom decoders manually.")
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
        let src = "fn valid(c: char) -> bool { ['G','M','C','B','X','T'].contains(&c) }";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "SUR-1001");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!(f[0].kind, Kind::Static);
        assert_eq!(f[0].line, Some(1));
    }

    #[test]
    fn does_not_flag_allowlist_with_w() {
        let src = "fn valid(c: char) -> bool { ['G','M','W','C'].contains(&c) }";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert!(f.is_empty());
    }

    #[test]
    fn flags_byte_array_missing_w() {
        let src = "const ALLOWED: [u8; 3] = [0x30, 0x60, 0x90];";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn does_not_flag_byte_array_with_w() {
        let src = "const ALLOWED: [u8; 4] = [0x30, 0x60, 0x90, 0xb0];";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert!(f.is_empty());
    }

    #[test]
    fn ignores_lines_with_few_chars() {
        let src = "let x = 'X';";
        let f = WAddressRule.scan(&ctx("x.rs", src));
        assert!(f.is_empty());
    }
}
