//! SUR-1005 — Soroban contract parameters that reject muxed contract (W) addresses.
//!
//! CAP-84 makes a muxed contract address a valid destination for a Stellar Asset
//! Contract `transfer`/`mint`. The Bell upgrade guide states the contract-side
//! consequence explicitly:
//!
//! > If your contract accepts addresses from users ... decide whether it should
//! > accept the muxed variant: a function declared with a plain `Address` rejects
//! > a W address, and one declared with `MuxedAddress` accepts both.
//!
//! So a `#[contractimpl]` function that takes an `Address` parameter can never
//! receive a W address. Whether that is a defect depends on the contract's
//! intent, which static analysis cannot know — this rule therefore emits a
//! `ManualReview` candidate, not a breakage claim.
//!
//! Deliberately narrow: only public contract entry points (inside a
//! `#[contractimpl]` block) with a parameter typed `Address` are reported.
//! Internal helper functions, `MuxedAddress` parameters, and non-contract code
//! are out of scope.

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::Rule;
use crate::scan::FileCtx;

pub struct ContractAddressRule;

impl Rule for ContractAddressRule {
    fn id(&self) -> &'static str {
        "SUR-1005"
    }
    fn title(&self) -> &'static str {
        "Contract entry point takes a plain Address and rejects muxed contract (W) addresses"
    }
    fn description(&self) -> &'static str {
        "Flags public functions inside a #[contractimpl] block whose parameter is typed `Address`. Per CAP-84, a plain `Address` parameter rejects a muxed contract (W) address; `MuxedAddress` accepts both."
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
        "CAP-84"
    }
    fn limitations(&self) -> Option<&'static str> {
        Some("Manual review only: whether a contract *should* accept a muxed contract address is a design decision this rule cannot make. Detects parameter type `Address` on functions inside a `#[contractimpl]` block whose closing brace is at the same or lower indent; macro-expanded signatures, type aliases, and generic address wrappers are out of scope. A finding does not mean the contract is broken — it means the entry point cannot receive a W address.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        if !ctx.content.contains("contractimpl") {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut in_impl = false;
        let mut impl_depth: i32 = 0;

        for (i, line) in ctx.lines.iter().enumerate() {
            let lower = line.to_lowercase();

            if !in_impl {
                if lower.contains("#[contractimpl]") {
                    in_impl = true;
                    impl_depth = 0;
                }
                continue;
            }

            impl_depth += line.matches('{').count() as i32;
            impl_depth -= line.matches('}').count() as i32;

            if let Some(param) = address_param(line) {
                out.push(
                    Finding::new(
                        self.id(),
                        self.title(),
                        self.severity(),
                        Confidence::Low,
                        Kind::ManualReview,
                        &ctx.rel_path,
                    )
                    .location(i + 1, None, Some(line))
                    .explanation(&format!(
                        "`{param}` is typed `Address`. Per CAP-84 a plain `Address` parameter rejects a muxed contract (W) address, while `MuxedAddress` accepts both muxed and non-muxed. Confirm whether this entry point should accept W addresses."
                    ))
                    .sources(&[
                        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
                        "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide",
                    ])
                    .recommendation(
                        "If the entry point should accept muxed contract addresses, change the parameter type to `MuxedAddress`; otherwise document the restriction.",
                    )
                    .limitations(
                        "Manual review: accepting a muxed contract address is a design decision, not a defect.",
                    ),
                );
            }

            if impl_depth < 0 || (impl_depth == 0 && line.contains('}')) {
                in_impl = false;
            }
        }
        out
    }
}

/// The parameter name when a function signature line declares an `Address`
/// parameter (`to: Address`, `to: Address,`, `to: Address)` ...). Returns `None`
/// for `MuxedAddress`, `Vec<Address>`, and other non-plain forms.
fn address_param(line: &str) -> Option<String> {
    let idx = line.find(": Address")?;
    // Reject `MuxedAddress` (the match above already requires a space before
    // `Address`), `Vec<Address>`, `Option<Address>`, and similar wrappers: those
    // contain a preceding identifier character.
    let name: String = line[..idx]
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(file: &str, src: &str) -> FileCtx {
        FileCtx::from_source(file, src)
    }

    #[test]
    fn flags_address_param_in_contractimpl() {
        let src = "#[contractimpl]\nimpl Token {\n    pub fn transfer(env: Env, to: Address, amount: i128) {}\n}\n";
        let f = ContractAddressRule.scan(&ctx("lib.rs", src));
        assert_eq!(f.len(), 1, "expected one finding, got {f:?}");
        assert_eq!(f[0].rule_id, "SUR-1005");
        assert_eq!(f[0].severity, Severity::Low);
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert_eq!(f[0].line, Some(3));
        assert!(f[0].explanation.contains("`to`"));
    }

    #[test]
    fn does_not_flag_muxed_address() {
        let src = "#[contractimpl]\nimpl Token {\n    pub fn transfer(env: Env, to: MuxedAddress, amount: i128) {}\n}\n";
        assert!(
            ContractAddressRule.scan(&ctx("lib.rs", src)).is_empty(),
            "MuxedAddress accepts both forms and must not be flagged"
        );
    }

    #[test]
    fn does_not_flag_code_outside_contractimpl() {
        let src = "fn helper(to: Address) {}\n";
        assert!(
            ContractAddressRule.scan(&ctx("lib.rs", src)).is_empty(),
            "a non-entry-point helper is out of scope"
        );
    }

    #[test]
    fn does_not_flag_wrapped_address_types() {
        let src =
            "#[contractimpl]\nimpl Token {\n    pub fn batch(env: Env, tos: Vec<Address>) {}\n}\n";
        assert!(
            ContractAddressRule.scan(&ctx("lib.rs", src)).is_empty(),
            "Vec<Address> is not a plain Address parameter"
        );
    }

    #[test]
    fn ignores_files_without_contractimpl() {
        let src = "fn f(to: Address) {}";
        assert!(ContractAddressRule.scan(&ctx("lib.rs", src)).is_empty());
    }
}
