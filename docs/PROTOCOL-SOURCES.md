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

## SDK / XDR releases (verified against crates.io, 2026-10)

| Crate | Protocol 30 line | Prior line |
|-------|------------------|------------|
| `stellar-xdr` | 30.0.0 (new `StellarValue` arms, `SC_ADDRESS_TYPE_MUXED_CONTRACT`) | 28.0.1 |
| `soroban-sdk` | 30.0.0-rc.1 | 29.0.1 |

Sources consulted for SDK readiness:
- https://github.com/stellar/rs-soroban-sdk/releases
- https://github.com/stellar/js-stellar-sdk/releases (Protocol 30 line ships v17.x; migration guides: https://stellar.github.io/js-stellar-sdk/migration/00-migration)
- https://github.com/stellar/stellar-xdr/releases

## Implementation references

- stellar-core PR implementing CAP-88: https://github.com/stellar/stellar-core/pull/5423
- stellar-xdr PR: https://github.com/stellar/stellar-xdr/pull/316

## Evidence policy

- A rule ships only if the claim above is supported by a listed source.
- `SUR-1002` compares Rust crate majors against the verified crates.io lines
  above; other ecosystems emit `manual_review` because no per-SDK verified
  minimum is hardcoded.
- This registry is re-checked before each release; stale claims are removed.
