//! SUR-1004 — whole-second timestamp assumptions weakened by CAP-88.
//!
//! CAP-88 makes consecutive ledgers able to close within the same whole second,
//! so "one ledger later" no longer implies "at least one second later".
//! Static detection of a *semantic* assumption is inherently unreliable, so this
//! rule emits `ManualReview` findings (Low severity / Low confidence) that point
//! at concrete lines for a human to confirm, rather than asserting breakage.

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::Rule;
use crate::scan::FileCtx;

pub struct TimestampRule;

impl Rule for TimestampRule {
    fn id(&self) -> &'static str {
        "SUR-1004"
    }
    fn title(&self) -> &'static str {
        "Whole-second ledger timing assumption may be weakened by CAP-88"
    }
    fn description(&self) -> &'static str {
        "Flags close-time / ledger-timestamp code or comments that assume consecutive ledgers differ by at least one second."
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn kind(&self) -> Kind {
        Kind::ManualReview
    }
    fn protocol(&self) -> &'static str {
        "30"
    }
    fn cap(&self) -> &'static str {
        "CAP-88"
    }
    fn limitations(&self) -> Option<&'static str> {
        Some("Heuristic. Flags candidate lines for human review only; a match is not evidence of a defect, and the absence of a match is not evidence of correctness.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        let mut out = Vec::new();
        for (i, line) in ctx.lines.iter().enumerate() {
            let lower = line.to_lowercase();
            let time_ref = lower.contains("closetime")
                || lower.contains("close_time")
                || lower.contains("ledger_timestamp")
                || lower.contains("ledger_close_time")
                || lower.contains("minseqage");
            let second_assumption = lower.contains("one ledger later")
                || lower.contains("at least one second")
                || lower.contains("seconds later")
                || lower.contains("1 second")
                || lower.contains("one second")
                || lower.contains("per ledger");
            if time_ref && second_assumption {
                out.push(
                    Finding::new(self.id(), self.title(), self.severity(), Confidence::Low, Kind::ManualReview, &ctx.rel_path)
                        .location(i + 1, None, Some(line))
                        .explanation("This line ties ledger progress to a whole-second timing assumption. Under CAP-88 consecutive ledgers can close within the same whole second, so 'one ledger later' no longer implies 'at least one second later'.")
                        .sources(&[
                            "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md",
                            "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide",
                        ])
                        .recommendation("Confirm the logic does not rely on a one-second-per-ledger increment. Where millisecond precision matters, read closeTimeMs; protocol time features keep whole-second semantics.")
                        .limitations("Manual review required; this rule flags candidates, not confirmed defects."),
                );
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_ledger_second_assumption() {
        let src =
            "// closeTime: one ledger later implies at least one second\nlet cur_close_time = prev_close_time + 1; // one ledger later, assume >= 1s";
        let ctx = FileCtx::from_source("x.rs", src);
        let f = TimestampRule.scan(&ctx);
        assert!(!f.is_empty());
        assert_eq!(f[0].rule_id, "SUR-1004");
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn ignores_ms_aware_code() {
        let src = "let ms = value.close_time_ms; // millisecond resolution";
        let ctx = FileCtx::from_source("x.rs", src);
        assert!(TimestampRule.scan(&ctx).is_empty());
    }

    #[test]
    fn ignores_unrelated_timing_code() {
        let src = "let timeout = Duration::from_secs(30);";
        let ctx = FileCtx::from_source("x.rs", src);
        assert!(TimestampRule.scan(&ctx).is_empty());
    }
}
