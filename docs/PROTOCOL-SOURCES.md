# Protocol source registry

This is the single source of truth that rules cite. Each entry states the
**exact claim** the tool relies on, so a finding is always traceable to a
primary reference. Claims are re-verified before each release; `sources.rs` is
generated from this registry.

## Protocol 30 — Bell

| Source | URL | Key claims used by the tool |
|--------|-----|------------------------------|
| Bell Protocol 30 Upgrade Guide | https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide | Testnet vote 2026-11-03, mainnet vote 2026-11-23. SDK upgrade required for CAP-84 and CAP-88. CAP-88 adds new `StellarValue` arms; decoders must update or fail. CAP-84 adds W strkey for address fields, transfer `to`, and ledger meta. |
| Introducing Bell, Protocol 30 | https://stellar.org/blog/developers/introducing-bell-protocol-30-on-stellar | CAP-84 = muxed contract addresses (W prefix). CAP-88 = millisecond ledger close times. CAP-87 = ML-DSA host functions (Ed25519 unchanged at transaction level). |
| Protocol upgrades overview | https://stellar.org/protocol-upgrades | Protocol upgrade history and mechanism. |

## Core CAPs

| CAP | URL | Status | Key claims |
|-----|-----|--------|------------|
| CAP-84 Muxed Contract Addresses | https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md | Implemented | Adds `SC_ADDRESS_TYPE_MUXED_CONTRACT` (contract id + u64). New strkey prefix W (version byte 0xb0 per SEP-23). SAC `transfer` accepts a muxed contract address as `to`; events carry `to_muxed_id`. Prohibited in contract storage keys; a plain `Address` argument rejects a W address. Additive; no backward incompatibility. |
| CAP-87 ML-DSA host functions | https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md | Implemented | Adds `verify_sig_ml_dsa_44/65/87` host functions. No backward incompatibilities. Network-level signatures remain Ed25519. |
| CAP-88 Millisecond close times | https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md | Implemented | Adds `STELLAR_VALUE_SIGNED_MS` and `STELLAR_VALUE_EMPTY_TX_SET_MS` arms + `closeTimeMs` (TimePointMs). Old whole-second arms no longer produced. `closeTime == closeTimeMs / 1000`. Time bounds, `minSeqAge`, predicates, Soroban `ledger_timestamp` keep whole-second semantics. Consecutive ledgers may close in the same whole second. |
| CAP-67 Muxed accounts (predecessor) | https://github.com/stellar/stellar-protocol/blob/master/core/cap-0067.md | Active | Origin of `to_muxed_id` event convention and storage-key prohibition reused by CAP-84. |

## SEPs

| SEP | URL | Key claims |
|-----|-----|------------|
| SEP-23 Strkeys | https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md | `STRKEY_MUXED_CONTRACT = 22 << 3`, version byte `0xb0`, first char `W`. Updated 2026-09-18. |

## SDK / XDR releases (verified against official registries/release notes, 2026-10)

| Ecosystem | Package / module | Protocol 30 line | Evidence |
|-----------|------------------|------------------|----------|
| Rust | `stellar-xdr` (crates.io) | 30.0.0 | crates.io; carries CAP-84 + CAP-88 XDR |
| Rust | `soroban-sdk` (crates.io) | 30.0.0-rc.1 | crates.io |
| JS/TS | `@stellar/stellar-sdk` (npm) | **v17.3.0** and **v16.4.0** (LTS) | release notes titled "Protocol 30"; v17.0.0 is "Protocol 28" |
| Go | `github.com/stellar/go-stellar-sdk` | **v0.8.0** | release notes "Adds Support for Protocol 30 (CAP-0084/87/88)" |
| Python | `stellar-sdk` (PyPI, StellarCN/py-stellar-base) | none released | CAP-84 support is under CHANGELOG "Pending" (latest tag 16.1.1) |
| Elixir | `stellar_sdk` (hex, kommitters) | none released | latest v0.23.0 (2026-06-03) has no Protocol 30 note |

Sources consulted for SDK readiness:
- https://github.com/stellar/rs-soroban-sdk/releases
- https://github.com/stellar/js-stellar-sdk/releases (Protocol 30 = v17.3.0; LTS v16.4.0; migration guides: https://stellar.github.io/js-stellar-sdk/migration/00-migration)
- https://github.com/stellar/go-stellar-sdk/releases
- https://github.com/StellarCN/py-stellar-base/blob/main/CHANGELOG.md
- https://github.com/kommitters/stellar_sdk/releases
- https://github.com/stellar/stellar-xdr/releases

## Implementation references

- stellar-core PR implementing CAP-88: https://github.com/stellar/stellar-core/pull/5423
- stellar-xdr PR: https://github.com/stellar/stellar-xdr/pull/316

## Evidence policy

- A rule ships only if the claim above is supported by a listed source.
- `SUR-1002` pins `stellar-xdr` (Rust) as a definite break. For non-Rust
  ecosystems it derives readiness only where a **verified** Protocol 30 release
  exists (JS: v16.4.0/v17.3.0; Go: v0.8.0). Python and Elixir have no verified
  Protocol 30 release, so their findings are `manual_review`/unknown — the tool
  never guesses a minimum version.
- A manifest version range is never treated as the resolved version; a sibling
  lockfile is preferred, and a range that only *might* satisfy the threshold is
  reported as unknown rather than asserted.
- This registry is re-checked before each release; stale claims are removed.
