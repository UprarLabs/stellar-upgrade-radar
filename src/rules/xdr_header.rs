//! SUR-1003 — XDR / ledger-header decoding under CAP-88.
//!
//! CAP-88 adds `STELLAR_VALUE_SIGNED_MS` and `STELLAR_VALUE_EMPTY_TX_SET_MS`
//! arms to `StellarValue.ext`, plus a `closeTimeMs` (TimePointMs) field. XDR
//! decoding fails on unknown union arms, so any consumer that decodes
//! `StellarValue` / `LedgerHeader` / `LedgerCloseMeta` must handle the new arms.
//!
//! We scan **per match/switch block** (brace-depth tracked) rather than per file
//! or per line, so that:
//! - a block that already enumerates the `_MS` arms is treated as updated;
//! - a legacy block in the same file as an updated block is still flagged;
//! - a fully updated block (both pre-MS and `_MS` arms) is not flagged;
//! - a single arm line is reported once (mutually-exclusive branches).

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::Rule;
use crate::scan::FileCtx;

pub struct XdrHeaderRule;

impl Rule for XdrHeaderRule {
    fn id(&self) -> &'static str {
        "SUR-1003"
    }
    fn title(&self) -> &'static str {
        "StellarValue / ledger-header decoding omits CAP-88 millisecond arms"
    }
    fn description(&self) -> &'static str {
        "Flags match/switch blocks that enumerate StellarValueType arms without the new STELLAR_VALUE_*_MS arms added by CAP-88."
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
        "CAP-88"
    }
    fn limitations(&self) -> Option<&'static str> {
        Some("Detects named-arm and numeric-discriminant enumeration only, within match/switch blocks whose opening brace is on the keyword line. Arms must place the arm name and `=>` on the same line (multiline arms are missed), and a numeric `case` arm sharing the `match`/`switch` keyword line is missed (named arms with `=>` on that line are detected). Brace counting does not strip string/char literals, so braces inside literals can mis-track nesting. Generated bindings, macro-driven or opaque library decoders, and arms whose `_MS` handling lives in a called helper are out of scope; confirm those by manual review.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        let lower = ctx.content.to_lowercase();
        if !references_ledger_value(&lower) {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut depth: i32 = 0;
        let mut blocks: Vec<Block> = Vec::new();

        for (i, line) in ctx.lines.iter().enumerate() {
            let ln = i + 1;
            let local = line.to_lowercase();
            let opens = line.matches('{').count() as i32;
            let closes = line.matches('}').count() as i32;

            if (local.contains("match ") || local.contains("switch")) && opens > 0 {
                blocks.push(Block {
                    start_depth: depth,
                    arms: Vec::new(),
                });
            }

            if let Some(block) = blocks.last_mut() {
                if is_arm_line(line) {
                    let ms = mentions_ms_arm(&local);
                    block.arms.push(Arm {
                        line_no: ln,
                        text: line.clone(),
                        is_ms: ms,
                        is_named_pre: !ms && line_mentions_named_arm(line),
                        is_numeric: !ms
                            && !line_mentions_named_arm(line)
                            && looks_like_numeric_discriminant_match(line),
                    });
                }
            }

            depth += opens - closes;

            while let Some(block) = blocks.last() {
                if depth > block.start_depth {
                    break;
                }
                let block = blocks.pop().unwrap();
                // A block that already handles an _MS arm is considered updated.
                if block.arms.iter().any(|a| a.is_ms) {
                    continue;
                }
                for arm in &block.arms {
                    if arm.is_named_pre {
                        out.push(
                            Finding::new(self.id(), self.title(), self.severity(), Confidence::Medium, Kind::Static, &ctx.rel_path)
                                .location(arm.line_no, None, Some(&arm.text))
                                .explanation("This match block enumerates StellarValue type arms without the CAP-88 millisecond variants (STELLAR_VALUE_SIGNED_MS / EMPTY_TX_SET_MS). XDR decoding fails on unknown union arms, so Protocol 30 ledgers may fail to decode here.")
                                .sources(&["https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md", "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide"])
                                .recommendation("Update to the Protocol 30 XDR and handle the _MS arms as equivalents of the whole-second arms.")
                                .limitations("Detects named-arm enumeration within a brace-delimited block; see rule limitations."),
                        );
                    } else if arm.is_numeric {
                        out.push(
                            Finding::new(self.id(), self.title(), self.severity(), Confidence::Low, Kind::ManualReview, &ctx.rel_path)
                                .location(arm.line_no, None, Some(&arm.text))
                                .explanation("Numeric discriminant match near ledger-value decoding. Confirm arms 3 (STELLAR_VALUE_SIGNED_MS) and 4 (STELLAR_VALUE_EMPTY_TX_SET_MS) are handled, or decoding will fail on Protocol 30 ledgers.")
                                .sources(&["https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md"])
                                .recommendation("Add explicit handling for discriminants 3 and 4, or switch to named arms.")
                                .limitations("Manual review: arm identity is not statically resolvable."),
                        );
                    }
                }
            }
        }

        // Any block still open at EOF (malformed/truncated) is reported for its
        // legacy pre-MS arms so analysis is honest about incomplete input.
        for block in &blocks {
            if block.arms.iter().any(|a| a.is_ms) {
                continue;
            }
            for arm in &block.arms {
                if arm.is_named_pre {
                    out.push(
                        Finding::new(self.id(), self.title(), self.severity(), Confidence::Medium, Kind::Static, &ctx.rel_path)
                            .location(arm.line_no, None, Some(&arm.text))
                            .explanation("This match block enumerates StellarValue type arms without the CAP-88 millisecond variants (STELLAR_VALUE_SIGNED_MS / EMPTY_TX_SET_MS).")
                            .sources(&["https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md"])
                            .recommendation("Update to the Protocol 30 XDR and handle the _MS arms.")
                            .limitations("Block appears unterminated in this source slice; confirmed by manual review."),
                    );
                }
            }
        }
        out
    }
}

struct Block {
    start_depth: i32,
    arms: Vec<Arm>,
}

struct Arm {
    line_no: usize,
    text: String,
    is_ms: bool,
    is_named_pre: bool,
    is_numeric: bool,
}

fn is_arm_line(line: &str) -> bool {
    line.contains("=>") || line.trim_start().starts_with("case ")
}

fn references_ledger_value(lower: &str) -> bool {
    lower.contains("stellarvalue")
        || lower.contains("ledgerheader")
        || lower.contains("ledgerclosemeta")
}

fn mentions_ms_arm(lower: &str) -> bool {
    lower.contains("stellar_value_signed_ms")
        || lower.contains("stellar_value_empty_tx_set_ms")
        || lower.contains("stellarvaluesignedms")
        || lower.contains("stellarvalueemptytxsetms")
        || lower.contains("closetime_ms")
        || lower.contains("timepointms")
}

fn line_mentions_named_arm(line: &str) -> bool {
    let l = line.to_lowercase();
    l.contains("stellar_value")
        || l.contains("stellarvaluetype")
        || l.contains("stellarvaluesigned")
        || l.contains("stellarvalueemptytxset")
}

fn looks_like_numeric_discriminant_match(line: &str) -> bool {
    let t = line.trim();
    (t.starts_with("case ") || t.contains("=>"))
        && t.contains(':')
        && !line_mentions_named_arm(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FileCtx;

    fn ctx(file: &str, src: &str) -> FileCtx {
        FileCtx::from_source(file, src)
    }

    #[test]
    fn flags_named_arms_without_ms() {
        let src = "fn f(t: StellarValueType) {\n    match t {\n        StellarValueType::StellarValueSigned => a(),\n        StellarValueType::StellarValueEmptyTxSet => b(),\n    }\n}\n";
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        // One finding per arm line, and only one kind each: no double report.
        assert_eq!(f.len(), 2, "expected one finding per arm line, got {f:?}");
        assert!(f.iter().all(|x| x.kind == Kind::Static));
        assert_eq!(f.iter().filter(|x| x.line == Some(3)).count(), 1);
        assert_eq!(f.iter().filter(|x| x.line == Some(4)).count(), 1);
    }

    #[test]
    fn passes_when_ms_arms_present() {
        let src = "fn f(t: StellarValueType) {\n    match t {\n        STELLAR_VALUE_SIGNED => a(),\n        STELLAR_VALUE_SIGNED_MS => a(),\n    }\n}\n";
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        assert!(
            f.is_empty(),
            "fully updated block must not be flagged: {f:?}"
        );
    }

    #[test]
    fn flags_only_the_legacy_block_in_a_mixed_file() {
        // One block handles the _MS arm; a second block does not. Only the
        // legacy block's pre-MS arm must be flagged.
        let src = "fn modern(v: &StellarValueType) {\n    match v {\n        StellarValueType::StellarValueSignedMs => a(),\n    }\n}\n\nfn legacy(v: &StellarValueType) {\n    match v {\n        StellarValueType::StellarValueSigned => b(),\n    }\n}\n";
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1, "only the legacy arm should be flagged: {f:?}");
        assert_eq!(f[0].line, Some(9));
        assert_eq!(f[0].kind, Kind::Static);
    }

    #[test]
    fn ignores_unrelated_files() {
        let src = "fn add(a: i32, b: i32) -> i32 { a + b }";
        let ctx = ctx("x.rs", src);
        assert!(XdrHeaderRule.scan(&ctx).is_empty());
    }

    #[test]
    fn numeric_discriminant_is_manual_review() {
        let src = "fn f(v: StellarValue) {\n    match v.ext {\n        case 1: signed(),\n        case 2: empty(),\n    }\n}\n";
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        assert!(f.iter().any(|x| x.kind == Kind::ManualReview));
        assert!(!f.iter().any(|x| x.kind == Kind::Static));
    }

    #[test]
    fn multiline_arm_is_not_flagged_documented_limitation() {
        // Documented gap: the arm name and `=>` must be on the same line.
        let src = "fn f(v: &StellarValueType) {\n    match v {\n        StellarValueType::StellarValueSigned\n            => emit(),\n    }\n}\n";
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        assert!(
            f.is_empty(),
            "multiline arms are a documented false negative: {f:?}"
        );
    }

    #[test]
    fn named_arm_on_a_single_line_match_is_flagged() {
        // A single-line match whose named arm sits on the keyword line is
        // detected (the arm carries `=>`).
        let src = "fn f(v: &StellarValueType) {\n    match v { StellarValueType::StellarValueSigned => a(), }\n}\n";
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        assert_eq!(f.len(), 1, "named single-line arm must be flagged: {f:?}");
        assert_eq!(f[0].kind, Kind::Static);
    }

    #[test]
    fn numeric_single_line_match_is_not_flagged_documented_limitation() {
        // Documented gap: a numeric `case` arm sharing the `switch`/`match`
        // keyword line is not detected.
        let src = "fn f(x: i32) {\n    switch (x) { case 1: a(), }\n}\n";
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        assert!(
            f.is_empty(),
            "numeric single-line case arms are a documented false negative: {f:?}"
        );
    }

    #[test]
    fn brace_in_string_literal_does_not_false_positive_on_updated_block() {
        // Documented gap: brace counting does not ignore braces inside string
        // literals. This pins that such a block is still treated as updated
        // (no misleading finding) when it contains the _MS arm.
        let src = concat!(
            "fn f(v: &StellarValueType) {\n",
            "    match v {\n",
            "        StellarValueType::StellarValueSignedMs => { let s = \"}\"; a() },\n",
            "    }\n",
            "}\n"
        );
        let f = XdrHeaderRule.scan(&ctx("x.rs", src));
        assert!(
            f.is_empty(),
            "updated block with a string-literal brace must not be flagged: {f:?}"
        );
    }
}
