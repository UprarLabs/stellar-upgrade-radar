# Changelog

All notable changes to stellar-upgrade-radar are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Maintainer-readiness pack: issue templates (bug report, feature request),
  pull request template, CODEOWNERS, and this changelog.

## [0.1.0] — 2026-11-26

First public release: evidence-driven static analysis for Stellar protocol
upgrade compatibility and application readiness. Protocol 30 (Bell) activated
on mainnet on 2026-11-23.

### Added

- Six rules (SUR-1001 – SUR-1006) covering Protocol 30:
  - CAP-84 muxed contract addresses (`W` strkey variant): allowlists,
    entry points that reject muxed addresses, muxed addresses used as
    storage keys
  - CAP-88 millisecond ledger close times: XDR `StellarValue` decoder arm
    coverage
  - SDK dependency checks (SUR-1002) across Rust, JavaScript/TypeScript,
    Python, Go and Elixir manifests and lockfiles, with verified
    Protocol 30 release thresholds
- Three report formats: human-readable text, stable-schema JSON
  (`schema_version` 1.0), and SARIF 2.1.0 for code-scanning integrations
- CI-gate friendly: documented exit codes (0 clean, 1 findings at/above
  threshold, 2 input/internal error) and `--min-severity` filtering
- Every finding carries a stable rule ID, severity, confidence,
  authoritative source URLs, and explicit limitations
- Documentation: `docs/RULES.md`, `docs/PROTOCOL-SOURCES.md`,
  `docs/SARIF.md`, `docs/MAINTAINER-READINESS.md`,
  `docs/contributor-issues.md`, `CONTRIBUTING.md`, `SECURITY.md`

### Fixed

- Reduced false positives in upgrade readiness rules
- Improved rule precision and lockfile analysis
- Improved SARIF interoperability coverage

## [0.1.0] history — pre-release development

- 2026-10-23 — Initial Protocol 30 upgrade-readiness analyzer (MVP)
- 2026-10-23 — Full Apache-2.0 license text; canonical SPDX license texts
- 2026-10-24 — SUR-1002: JS/TS, Python, Go and Elixir SDK readiness checks
- 2026-10-24 — SARIF 2.1.0 output format
- 2026-11-03 — SUR-1005: flag contract entry points that reject muxed
  contract addresses; SUR-1006: flag muxed contract addresses used as
  storage keys
- 2026-11-26 — README updated for Protocol 30 mainnet activation; v0.1.0
  tagged and released

[Unreleased]: https://github.com/UprarLabs/stellar-upgrade-radar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/UprarLabs/stellar-upgrade-radar/releases/tag/v0.1.0
