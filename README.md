stellar-upgrade-radar

Evidence-driven static analysis for Stellar protocol upgrade compatibility and
application readiness.

# Overview

`stellar-upgrade-radar` scans a Stellar application or indexer for evidence of
readiness (or risk) around network protocol upgrades. The initial focus is
Bell, **Protocol 30**, which is scheduled for a mainnet activation vote on
2026-11-23 (testnet vote 2026-11-03). Protocol 30 bundles three CAPs:

- **CAP-84** — muxed contract addresses, surfaced as a new strkey prefix `W`.
  Every application that validates, displays, stores, or routes addresses must
  accept the new variant.
- **CAP-87** — ML-DSA host functions for Soroban smart contracts (post-quantum
  signature verification). Opt-in; no transaction-level incompatibility.
- **CAP-88** — millisecond-resolution ledger close times, adding
  `STELLAR_VALUE_SIGNED_MS` / `STELLAR_VALUE_EMPTY_TX_SET_MS` arms to
  `StellarValue` and a `closeTimeMs` field. Consumers that decode ledger data
  must update their XDR or decoding fails on unknown union arms.

This tool performs **static analysis only**. It finds structural evidence of
incomplete preparation; it does **not** replace integration testing against a
Protocol 30 node or SDK.

# Install

```bash
cargo install --git https://github.com/UprarLabs/stellar-upgrade-radar
```

For a local build from source:

```bash
git clone https://github.com/UprarLabs/stellar-upgrade-radar
cd stellar-upgrade-radar
cargo build --release
./target/release/stellar-upgrade-radar --help
```

# Usage

```bash
# Text report (default)
stellar-upgrade-radar check /path/to/project

# Structured JSON report
stellar-upgrade-radar check /path/to/project --format json

# Report only Medium and above
stellar-upgrade-radar check /path/to/project --min-severity medium
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Scan completed with no findings at/above the severity threshold. |
| 1    | One or more findings at/above the severity threshold. |
| 2    | Bad input, IO error, or internal failure (e.g. path does not exist). |

This makes the tool usable as a CI gate: a non-zero exit fails the build.

# Output

`--format json` emits a stable-schema report. The shape is versioned by
`schema_version` (currently `"1.0"`):

```jsonc
{
  "schema_version": "1.0",
  "tool": { "name": "stellar-upgrade-radar", "version": "0.1.0" },
  "target": { "path": ".", "protocol_version": 30, "protocol_name": "Bell", "scanned_at_epoch": 1728000000 },
  "summary": {
    "files_scanned": 3,
    "files_with_findings": 1,
    "findings": 2,
    "by_severity": { "high": 1, "medium": 1 },
    "by_rule": { "SUR-1001": 1, "SUR-1002": 1 }
  },
  "findings": [
    {
      "rule_id": "SUR-1001",
      "title": "Strkey allowlist omits W-address (CAP-84/SEP-23) variant",
      "severity": "high",
      "confidence": "high",
      "kind": "static",
      "file": "src/validate.rs",
      "line": 12,
      "snippet": "... ['G','M','C','B','X','T'] ...",
      "explanation": "...",
      "sources": ["https://github.com/stellar/stellar-protocol/blob/master/core/cap-0084.md"],
      "recommendation": "...",
      "limitations": "..."
    }
  ],
  "rules": [
    { "id": "SUR-1001", "title": "...", "description": "...", "severity": "high",
      "status": "implemented", "protocol": "30", "cap": "CAP-84", "limitations": "..." }
  ],
  "notices": [ "..." ]
}
```

Every finding carries `sources` (authoritative URLs), a `severity`, a
`confidence`, and a `kind` of either `static` (deterministic evidence) or
`manual_review` (candidate for human confirmation). `SUR-*` IDs are stable
across releases; a finding never changes from one rule into another.

# Rules

| ID       | CAP     | Severity | Confidence | Status        |
|----------|---------|----------|------------|---------------|
| SUR-1001 | CAP-84  | High     | High       | Implemented   |
| SUR-1002 | CAP-84/88 | High/Medium | High/Medium/Low | Implemented |
| SUR-1003 | CAP-88  | High     | Medium/Low | Implemented   |
| SUR-1004 | CAP-88  | Low      | Low        | Manual-review |

`SUR-1002` covers Rust (`Cargo.toml` + `Cargo.lock`) plus the JS/TS
(`package.json` + `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`), Python
(`pyproject.toml`/`requirements.txt` + `poetry.lock`/`uv.lock`/`Pipfile.lock`),
Go (`go.mod`) and Elixir (`mix.exs` + `mix.lock`) SDKs. See
[`docs/PROTOCOL-SOURCES.md`](docs/PROTOCOL-SOURCES.md) for the verified
Protocol 30 release thresholds per ecosystem.

See [`docs/RULES.md`](docs/RULES.md) for the rule architecture and how to add a
new rule, and [`docs/PROTOCOL-SOURCES.md`](docs/PROTOCOL-SOURCES.md) for the
authoritative source registry.

# Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

# Current limitations

- **Static only.** No runtime, network, or deployed-ledger checks.
- **Rule-specific scope.** Each rule flags what its static heuristics can see;
  a clean scan does not prove readiness. See per-rule `limitations` and
  [`docs/RULES.md`](docs/RULES.md).
- **No false-positive elimination beyond fixtures.** Treat `static` findings as
  evidence requiring confirmation; treat `manual_review` findings as a prompt
  for a human to confirm.
- **`SUR-1002` covers Rust and four non-Rust SDK ecosystems.** For Rust it
  resolves the nearest `Cargo.lock` (a stale lockfile — manifest says 30,
  lockfile resolves 28 — is a High finding). For JS/TS, Python, Go and Elixir it
  reads the manifest plus a sibling lockfile; a manifest **range is never
  treated as the resolved version**. JS (`@stellar/stellar-sdk` >= v17.3.0 or
  the v16.4.x LTS line) and Go (`github.com/stellar/go-stellar-sdk` >= v0.8.0)
  use **verified** Protocol 30 release thresholds; Python (`stellar-sdk`) and
  Elixir (`stellar_sdk`) have no verified Protocol 30 release, so they are
  reported as `manual_review`/unknown. Findings report the SDK version, not
  application runtime or on-chain compatibility. Python matches a dependency
  name in dependency context (a project name is not flagged); Go honours
  `replace` directives and treats pseudo-versions and the `github.com/stellar/go`
  monorepo as manual-review; JS reads nested dependency objects, resolves a
  monorepo's root lockfile (bounded search) and reports manual-review on
  ambiguous lockfiles; Elixir git/path deps never show a URL as a version.
- **`SUR-1003` is block-aware, not exhaustive.** It does **not** imply
  comprehensive decoder coverage: a file mixing an updated decoder with a
  legacy one is caught (only the legacy block is flagged), and a block that
  enumerates the `_MS` arms is not flagged. **Multiline arms** (arm name and
  `=>` on different lines) are not detected, and a **numeric `case` arm sharing
  the `match`/`switch` keyword line** is not detected (a *named* arm with `=>`
  on that line is detected). Brace counting does not ignore braces inside
  string/char literals, so braces inside literals can mis-track nesting. Arms
  whose `_MS` handling lives in a called helper are out of scope.
- **Protocol 30 has not yet activated on mainnet** at the time of writing.
  Findings describe structural risk relative to the announced upgrade.

# License

Dual-licensed under MIT or Apache-2.0, at your option. See
[`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).
