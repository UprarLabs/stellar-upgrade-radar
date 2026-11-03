//! SUR-1006 — muxed contract (W) addresses used as Soroban storage keys.
//!
//! CAP-84 § *`SC_ADDRESS_TYPE_MUXED_CONTRACT` is prohibited in storage keys*:
//!
//! > a muxed contract address is meant to support off-chain multiplexing and
//! > would by definition be a mistake to use in a contract data storage key.
//! > **The Soroban host will produce an error** if
//! > `SC_ADDRESS_TYPE_MUXED_CONTRACT` is present in a contract data key `SCVal`
//! > (either directly, or anywhere in the nested containers). This restriction
//! > is applied to all kinds of contract data storage, including instance
//! > storage.
//!
//! The host therefore errors at runtime, so storing through a `MuxedAddress`
//! key is a defect, not a preference.
//!
//! Detection is deliberately local: only a storage call on the same line whose
//! key argument is a parameter explicitly typed `MuxedAddress` is reported as
//! `static`. A parameter typed `Address` may or may not carry a W address at
//! runtime — static analysis cannot know — so it is a `manual_review`
//! candidate, never a defect claim. Values explicitly converted to a non-muxed
//! `Address` before the call are not reported.
//!
//! Out of scope: data-flow across functions or files, nested tuples,
//! `Vec<MuxedAddress>` keys, and dynamically chosen storage types.

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::rules::Rule;
use crate::scan::FileCtx;

pub struct MuxedStorageKeyRule;

impl Rule for MuxedStorageKeyRule {
    fn id(&self) -> &'static str {
        "SUR-1006"
    }
    fn title(&self) -> &'static str {
        "Muxed contract (W) address used as a Soroban storage key"
    }
    fn description(&self) -> &'static str {
        "Flags a Soroban storage call whose key is a `MuxedAddress` parameter. CAP-84 makes the host error when SC_ADDRESS_TYPE_MUXED_CONTRACT appears in a contract data key."
    }
    fn severity(&self) -> Severity {
        Severity::Medium
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
        Some("Same-line detection only: the key argument must be named directly in the storage call. A `MuxedAddress` reached through a helper, a cross-function/data-flow path, a nested tuple, a `Vec<MuxedAddress>`, or a dynamically chosen storage type is not detected. A plain `Address` key is reported only as manual review because static analysis cannot prove the runtime value carries a muxed id. Conversions to a non-muxed address before the call are not flagged.")
    }

    fn scan(&self, ctx: &FileCtx) -> Vec<Finding> {
        if !ctx.content.contains("env.storage()") && !ctx.content.contains(".storage()") {
            return Vec::new();
        }
        let muxed: Vec<String> = typed_params(&ctx.content, "MuxedAddress");
        let plain: Vec<String> = typed_params(&ctx.content, "Address");
        if muxed.is_empty() && plain.is_empty() {
            return Vec::new();
        }

        let mut out = Vec::new();
        for (i, line) in ctx.lines.iter().enumerate() {
            let Some(call) = storage_call(line) else {
                continue;
            };
            let op = call.op;
            let Some(key) = call.key else { continue };

            if muxed.contains(&key) {
                out.push(
                    Finding::new(
                        self.id(),
                        self.title(),
                        Severity::Medium,
                        Confidence::High,
                        Kind::Static,
                        &ctx.rel_path,
                    )
                    .location(i + 1, None, Some(line))
                    .explanation(&format!(
                        "`{key}` is a `MuxedAddress` used as the key of `{op}`. CAP-84 prohibits a muxed contract address in a contract data key: the Soroban host produces an error if SC_ADDRESS_TYPE_MUXED_CONTRACT appears in a key SCVal, including nested containers and instance storage."
                    ))
                    .sources(&[
                        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
                    ])
                    .recommendation(
                        "Store the underlying non-muxed contract address instead (decompose the muxed address into its base address and id, and use the base address as the key).",
                    )
                    .limitations(
                        "Static evidence: the parameter type is explicitly `MuxedAddress`.",
                    ),
                );
            } else if plain.contains(&key) && !converted_to_plain(&ctx.content, &key) {
                out.push(
                    Finding::new(
                        self.id(),
                        self.title(),
                        Severity::Low,
                        Confidence::Low,
                        Kind::ManualReview,
                        &ctx.rel_path,
                    )
                    .location(i + 1, None, Some(line))
                    .explanation(&format!(
                        "`{key}` is typed `Address` and used as the key of `{op}`. If a muxed contract (W) address can reach this key, the Soroban host errors per CAP-84. Static analysis cannot tell whether the runtime value carries a muxed id, so confirm manually."
                    ))
                    .sources(&[
                        "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
                    ])
                    .recommendation(
                        "Confirm the key can never hold a muxed contract address; otherwise store the base (non-muxed) contract address.",
                    )
                    .limitations(
                        "Manual review: a plain `Address` key may or may not carry a muxed id at runtime.",
                    ),
                );
            }
        }
        out
    }
}

/// A recognised storage call on one line.
struct StorageCall {
    op: String,
    key: Option<String>,
}

/// Matches `env.storage().persistent().set(&key, &v)` and the `temporary` /
/// `instance` variants, plus `has`/`remove`/`get`, returning the operation label
/// and the first argument (the key) when it is a plain identifier reference.
fn storage_call(line: &str) -> Option<StorageCall> {
    let s = line.replace(' ', "");
    let storage = "storage()";
    let si = s.find(storage)?;
    let rest = &s[si..];

    let storage_type = if rest.contains(".persistent()") {
        "persistent"
    } else if rest.contains(".temporary()") {
        "temporary"
    } else if rest.contains(".instance()") {
        "instance"
    } else {
        return None;
    };

    let op = ["set", "has", "remove", "get"]
        .iter()
        .find(|o| rest.contains(&format!(".{o}(")))?;

    // The key is the first argument of the operation, referenced as `&name`
    // (or `name`), and must be a bare identifier so we do not guess about
    // expressions, tuples, or vectors.
    let after = &rest[rest.find(&format!(".{op}("))? + op.len() + 2..];
    let first = after.split(',').next()?.trim_start_matches('&').trim();
    let key: String = first
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if key.is_empty() || key.len() != first.len() {
        // Expression / literal / tuple / vector: out of scope.
        return Some(StorageCall {
            op: format!("{storage_type}().{op}"),
            key: None,
        });
    }
    Some(StorageCall {
        op: format!("{storage_type}().{op}"),
        key: Some(key),
    })
}

/// Parameter names declared with the given type, e.g. `who: MuxedAddress`.
fn typed_params(content: &str, ty: &str) -> Vec<String> {
    let needle = format!(": {ty}");
    let mut out = Vec::new();
    for line in content.lines() {
        let mut rest = line;
        while let Some(pos) = rest.find(&needle) {
            let name: String = rest[..pos]
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if !name.is_empty() {
                out.push(name);
            }
            rest = &rest[pos + needle.len()..];
        }
    }
    out
}

/// True when the file demonstrates an explicit conversion of `name` to a
/// non-muxed address before storage (e.g. `.to_address()`, `.address()`,
/// `.base_address()`), in which case the key is no longer a muxed address.
fn converted_to_plain(content: &str, name: &str) -> bool {
    [
        format!("{name}.to_address()"),
        format!("{name}.address()"),
        format!("{name}.base_address()"),
        format!("{name}.underlying()"),
    ]
    .iter()
    .any(|pat| content.replace(' ', "").contains(&pat.replace(' ', "")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(file: &str, src: &str) -> FileCtx {
        FileCtx::from_source(file, src)
    }

    #[test]
    fn flags_muxed_address_as_persistent_key() {
        let src = "pub fn set(env: Env, who: MuxedAddress) {\n    env.storage().persistent().set(&who, &1u32);\n}\n";
        let f = MuxedStorageKeyRule.scan(&ctx("lib.rs", src));
        assert_eq!(f.len(), 1, "expected one finding, got {f:?}");
        assert_eq!(f[0].rule_id, "SUR-1006");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].kind, Kind::Static);
        assert_eq!(f[0].line, Some(2));
        assert!(f[0].explanation.contains("MuxedAddress"));
    }

    #[test]
    fn flags_temporary_and_instance_storage() {
        for ty in ["temporary", "instance"] {
            let src = format!(
                "pub fn set(env: Env, who: MuxedAddress) {{\n    env.storage().{ty}().set(&who, &1u32);\n}}\n"
            );
            let f = MuxedStorageKeyRule.scan(&ctx("lib.rs", &src));
            assert_eq!(f.len(), 1, "{ty} storage must be detected: {f:?}");
        }
    }

    #[test]
    fn plain_address_key_is_manual_review_not_static() {
        let src = "pub fn set(env: Env, who: Address) {\n    env.storage().persistent().set(&who, &1u32);\n}\n";
        let f = MuxedStorageKeyRule.scan(&ctx("lib.rs", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert_eq!(f[0].severity, Severity::Low);
        assert!(
            !f[0].explanation.contains("host produces an error if"),
            "must not assert a defect for a plain Address"
        );
    }

    #[test]
    fn converted_muxed_address_is_not_flagged() {
        let src = "pub fn set(env: Env, who: MuxedAddress) {\n    let base = who.to_address();\n    env.storage().persistent().set(&base, &1u32);\n}\n";
        let f = MuxedStorageKeyRule.scan(&ctx("lib.rs", src));
        assert!(
            f.iter().all(|x| x.kind != Kind::Static),
            "a converted address must not be a static defect: {f:?}"
        );
    }

    #[test]
    fn non_address_keys_are_ignored() {
        for src in [
            "pub fn set(env: Env, id: u32, sym: Symbol) {\n    env.storage().persistent().set(&id, &1u32);\n}\n",
            "pub fn set(env: Env, sym: Symbol) {\n    env.storage().instance().set(&sym, &1u32);\n}\n",
        ] {
            assert!(
                MuxedStorageKeyRule.scan(&ctx("lib.rs", src)).is_empty(),
                "non-address key must not be flagged: {src}"
            );
        }
    }

    #[test]
    fn no_storage_usage_is_ignored() {
        let src = "pub fn f(who: MuxedAddress) {}\n";
        assert!(MuxedStorageKeyRule.scan(&ctx("lib.rs", src)).is_empty());
    }

    #[test]
    fn no_duplicate_finding_for_one_key() {
        let src = "pub fn set(env: Env, who: MuxedAddress) {\n    env.storage().persistent().set(&who, &1u32);\n    env.storage().persistent().extend_ttl(&who, 1, 2);\n}\n";
        let f = MuxedStorageKeyRule.scan(&ctx("lib.rs", src));
        assert_eq!(
            f.len(),
            1,
            "one storage usage must yield one finding: {f:?}"
        );
    }
}
