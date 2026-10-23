//! SUR-1003 — XDR / ledger-header decoding under CAP-88.
//!
//! CAP-88 adds `STELLAR_VALUE_SIGNED_MS` and `STELLAR_VALUE_EMPTY_TX_SET_MS`
//! arms to `StellarValue.ext`, plus a `closeTimeMs` (TimePointMs) field. XDR
//! decoding fails on unknown union arms, so any consumer that decodes
//! `StellarValue`/`LedgerHeader`/`LedgerCloseMeta` must handle the new arms. We
//! flag code that enumerates the pre-Protocol-30 arms without the `_MS` arms,
//! and we emit a `ManualReview` note for numeric-discriminant matches where arm
//! identity cannot be resolved statically.

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
        "Flags code that enumerates StellarValueType arms without the new STELLAR_VALUE_*_MS arms added by CAP-88."
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
        Some("Detects named-arm and numeric-discriminant enumeration only. Generated bindings, macro-driven decoders, or opaque library decoders are out of scope; confirm those by manual review.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        let lower = ctx.content.to_lowercase();
        if !references_ledger_value(&lower) {
            return Vec::new();
        }
        let mentions_pre_ms = mentions_pre_ms_arm(&lower);
        let mentions_ms = mentions_ms_arm(&lower);

        let mut out = Vec::new();
        for (i, line) in ctx.lines.iter().enumerate() {
            let ln = i + 1;
            // Named/arm-style enumeration missing the _MS arms.
            if mentions_pre_ms
                && !mentions_ms
                && line_has_arm(line)
                && line_mentions_named_arm(line)
            {
                out.push(
                    Finding::new(self.id(), self.title(), self.severity(), Confidence::Medium, Kind::Static, &ctx.rel_path)
                        .location(ln, None, Some(line))
                        .explanation("This code enumerates StellarValue type arms without the CAP-88 millisecond variants (STELLAR_VALUE_SIGNED_MS / EMPTY_TX_SET_MS). XDR decoding fails on unknown union arms, so Protocol 30 ledgers may fail to decode here.")
                        .sources(&["https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md", "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide"])
                        .recommendation("Update to the Protocol 30 XDR and handle the _MS arms as equivalents of the whole-second arms.")
                        .limitations("Only fires when pre-MS arms are named on an arm line; see rule limitations."),
                );
            }
            // Numeric-discriminant match where identity cannot be resolved statically.
            if mentions_pre_ms && !mentions_ms && looks_like_numeric_discriminant_match(line) {
                out.push(
                    Finding::new(self.id(), self.title(), self.severity(), Confidence::Low, Kind::ManualReview, &ctx.rel_path)
                        .location(ln, None, Some(line))
                        .explanation("Numeric discriminant match near ledger-value decoding. Confirm arms 3 (STELLAR_VALUE_SIGNED_MS) and 4 (STELLAR_VALUE_EMPTY_TX_SET_MS) are handled, or decoding will fail on Protocol 30 ledgers.")
                        .sources(&["https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md"])
                        .recommendation("Add explicit handling for discriminants 3 and 4, or switch to named arms.")
                        .limitations("Manual review: arm identity is not statically resolvable."),
                );
            }
        }
        out
    }
}

fn references_ledger_value(lower: &str) -> bool {
    lower.contains("stellarvalue")
        || lower.contains("ledgerheader")
        || lower.contains("ledgerclosemeta")
}

fn mentions_pre_ms_arm(lower: &str) -> bool {
    lower.contains("stellar_value_signed")
        || lower.contains("stellar_value_empty_tx_set")
        || lower.contains("stellarvaluetype")
        || lower.contains("stellarvalue")
        || lower.contains("stellarvaluesigned")
        || lower.contains("stellarvalueemptytxset")
}

fn mentions_ms_arm(lower: &str) -> bool {
    lower.contains("stellar_value_signed_ms")
        || lower.contains("stellar_value_empty_tx_set_ms")
        || lower.contains("stellarvaluesignedms")
        || lower.contains("stellarvalueemptytxsetms")
        || lower.contains("closetime_ms")
        || lower.contains("timepointms")
        || lower.contains("closetime_ms")
        || lower.contains("closes_ms")
}

fn line_has_arm(line: &str) -> bool {
    line.contains("=>") || line.contains("case ") || line.contains("switch")
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
    (t.starts_with("case ") || t.contains(" => "))
        && t.contains(':')
        && !t.contains("stellar_value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_named_arms_without_ms() {
        let src = "fn f(t: StellarValueType) {\n    match t {\n        StellarValueType::StellarValueSigned => a(),\n        StellarValueType::StellarValueEmptyTxSet => b(),\n    }\n}\n";
        let ctx = FileCtx::from_source("x.rs", src);
        let f = XdrHeaderRule.scan(&ctx);
        assert!(!f.is_empty());
        assert_eq!(f[0].rule_id, "SUR-1003");
        assert_eq!(f[0].kind, Kind::Static);
    }

    #[test]
    fn passes_when_ms_arms_present() {
        let src = "fn f(t: StellarValueType) {\n    match t {\n        STELLAR_VALUE_SIGNED => a(),\n        STELLAR_VALUE_SIGNED_MS => a(),\n    }\n}\n";
        let ctx = FileCtx::from_source("x.rs", src);
        assert!(XdrHeaderRule.scan(&ctx).is_empty());
    }

    #[test]
    fn ignores_unrelated_files() {
        let src = "fn add(a: i32, b: i32) -> i32 { a + b }";
        let ctx = FileCtx::from_source("x.rs", src);
        assert!(XdrHeaderRule.scan(&ctx).is_empty());
    }

    #[test]
    fn numeric_discriminant_is_manual_review() {
        let src = "fn f(v: StellarValue) {\n    match v.ext {\n        case 1: signed(),\n        case 2: empty(),\n    }\n}\n";
        let ctx = FileCtx::from_source("x.rs", src);
        let f = XdrHeaderRule.scan(&ctx);
        assert!(f.iter().any(|x| x.kind == Kind::ManualReview));
    }
}
