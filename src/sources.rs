//! Registry of authoritative protocol sources and the exact claims each one
//! supports. Rules attach the most relevant `sources` entries to a finding so
//! that every result is traceable to a primary reference. Entries are
//! intentionally minimal: one id, one URL, one claim sentence.

pub static SOURCES: &[Source] = &[
    Source {
        id: "stellar-protocol-30-guide",
        url: "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide",
        claim: "Bell, Protocol 30 upgrade guide. Testnet vote 2026-11-03, mainnet vote 2026-11-23. The SDK upgrade is required for CAP-84 (W addresses) and CAP-88 (millisecond close times).",
    },
    Source {
        id: "cap-84",
        url: "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md",
        claim: "CAP-0084 adds the SC_ADDRESS_TYPE_MUXED_CONTRACT variant to SCAddress and a W strkey (version byte 0xb0, base value 22 << 3) defined in SEP-23.",
    },
    Source {
        id: "cap-88",
        url: "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md",
        claim: "CAP-0088 adds STELLAR_VALUE_SIGNED_MS and STELLAR_VALUE_EMPTY_TX_SET_MS arms with a closeTimeMs (TimePointMs) field; decoders of StellarValue/LedgerHeader/LedgerCloseMeta must be updated or they fail on unknown union arms.",
    },
    Source {
        id: "sep-23",
        url: "https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md",
        claim: "SEP-23 assigns STRKEY_MUXED_CONTRACT = 22 << 3, version byte 0xb0, first char W. Updated 2026-09-18.",
    },
    Source {
        id: "stellar-xdr-v30",
        url: "https://crates.io/crates/stellar-xdr/30.0.0",
        claim: "stellar-xdr crate 30.0.0 is the Protocol 30 release carrying CAP-84 and CAP-88 XDR definitions.",
    },
    Source {
        id: "soroban-sdk-v30",
        url: "https://crates.io/crates/soroban-sdk/30.0.0-rc.1",
        claim: "soroban-sdk 30.0.0-rc.1 is the Protocol 30 Soroban SDK line (preceding stable line is 29.x).",
    },
    Source {
        id: "cap-87",
        url: "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md",
        claim: "CAP-0087 adds ML-DSA host functions verify_sig_ml_dsa_44/65/87; no backward incompatibilities; network-level signatures remain Ed25519.",
    },
    Source {
        id: "js-sdk-protocol-30",
        url: "https://github.com/stellar/js-stellar-sdk/releases/tag/v17.3.0",
        claim: "js-stellar-sdk v17.3.0 is titled 'Protocol 30': it adds CAP-84 muxed contract (W…) addresses and regenerates XDR with CAP-84/87/88 (StellarValueType adds stellarValueSignedMs / stellarValueEmptyTxSetMs). The v16.4.0 LTS release is also 'Protocol 30' (regenerated from stellar-xdr v30.0); v17.0.0 is 'Protocol 28'.",
    },
    Source {
        id: "go-sdk-protocol-30",
        url: "https://github.com/stellar/go-stellar-sdk/releases/tag/v0.8.0",
        claim: "go-stellar-sdk v0.8.0 'Adds Support for Protocol 30 (CAP-0084, CAP-0087, CAP-0088)'; module path github.com/stellar/go-stellar-sdk.",
    },
    Source {
        id: "py-sdk-protocol-30-pending",
        url: "https://github.com/StellarCN/py-stellar-base/blob/main/CHANGELOG.md",
        claim: "py-stellar-base lists CAP-84 (Protocol 30) muxed contract address support under 'Pending' — no released Python SDK version carries Protocol 30 as of 2026-10 (latest tag 16.1.1).",
    },
    Source {
        id: "elixir-sdk",
        url: "https://github.com/kommitters/stellar_sdk/releases",
        claim: "kommitters/stellar_sdk latest release v0.23.0 (2026-06-03) has no Protocol 30 / CAP-84 / CAP-88 release note; readiness is unknown.",
    },
];

pub struct Source {
    pub id: &'static str,
    pub url: &'static str,
    pub claim: &'static str,
}

impl Source {
    pub fn by_id(id: &str) -> Option<&'static Source> {
        SOURCES.iter().find(|s| s.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_source_has_required_fields() {
        for s in SOURCES {
            assert!(!s.id.is_empty());
            assert!(s.url.starts_with("https://"));
            assert!(!s.claim.is_empty());
        }
    }

    #[test]
    fn cap_84_w_byte_is_documented() {
        let cap84 = Source::by_id("cap-84").unwrap();
        assert!(cap84.claim.contains("0xb0"));
    }

    #[test]
    fn non_rust_sdk_sources_are_registered() {
        for id in [
            "js-sdk-protocol-30",
            "go-sdk-protocol-30",
            "py-sdk-protocol-30-pending",
            "elixir-sdk",
        ] {
            assert!(Source::by_id(id).is_some(), "missing source {id}");
        }
    }
}
