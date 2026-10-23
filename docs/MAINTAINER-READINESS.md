# Maintainer readiness

This document explains the project's goals, non-goals, and the state of its
readiness to accept external contributors.

## Goals

- Give Stellar application developers a **single, evidence-driven** report of
  structural readiness for network protocol upgrades, starting with Bell
  (Protocol 30).
- Keep every finding **traceable**: a stable rule id, a severity, a confidence,
  a source URL, and an explicit limitation.
- Be useful as a **CI gate** (documented exit codes) without over-claiming.
- Build a **contributor-friendly rule architecture** so the ecosystem can add
  checks for future protocol upgrades.

## Non-goals

- Not a Stellar node, wallet, indexer, or ledger-data service.
- Not a runtime or dynamic analyzer; it does not execute user code or connect to
  the network during a scan.
- Not a smart-contract security scanner. Soroban **security** analysis
  (reentrancy, access control, etc.) is out of scope; existing tools cover it.
- Not a compatibility *guarantee*. A clean scan is not proof of readiness.

## How findings are verified

See [`docs/RULES.md`](RULES.md) for the full process. In short:

- `static` findings fire only on deterministic structural evidence.
- `manual_review` findings flag candidates for human confirmation and are Low
  severity.
- Every finding carries authoritative sources; a regression test asserts that no
  finding is emitted without at least one source and a line number.

## Running tests locally

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

## Known limitations and false-positive considerations

- Rules match **patterns**, not semantics. A rule can fire on code that is
  correct for reasons the scanner cannot see (e.g. an allowlist built elsewhere).
  Treat `static` findings as evidence to confirm, and `manual_review` findings as
  a prompt.
- `SUR-1002` compares Rust crate majors only where crates.io versioning maps to
  the protocol version. Other ecosystems are manual-review by design.
- The CAP-88 `MS_CLOSE_TIME` feature-flag nuance is **not** yet detected; see
  issue candidate #5.
- Binary files, generated bindings, and macro-driven decoders are not analyzed.

## Contribution path

- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — workflow and policy.
- [`docs/RULES.md`](RULES.md) — rule architecture and how to add a rule.
- [`docs/contributor-issues.md`](contributor-issues.md) — eight scoped
  contributor tasks with independent acceptance criteria. **Drafts; not yet
  published.** Point estimates there are internal estimates, not approved Drips
  Wave points.

## Drips Wave readiness (self-assessment)

**What is already in place**
- A public, MIT/Apache-2.0 dual-licensed repository with a working MVP.
- A passing local test suite (unit + integration + real CLI exit-code tests).
- CI defined (fmt, clippy `-D warnings`, tests, CLI smoke test).
- Contributor documentation: `CONTRIBUTING.md`, `docs/RULES.md`,
  `docs/PROTOCOL-SOURCES.md`, and eight scoped issue candidates with acceptance
  criteria.

**What still needs to happen before an application**
- Publish the issue candidates (only after interfaces stabilize).
- Demonstrate the issue → PR → review → merge lifecycle with at least one
  external contributor.
- Accumulate a consistent commit cadence and, ideally, a second maintainer.
- Confirm CI is green on the remote (local results are not CI results).

**Candidate tasks and acceptance-criteria status**

| # | Task | Acceptance criteria written | Implemented |
|---|------|------------------------------|-------------|
| 1 | Protocol source registry | Yes | No |
| 2 | JSON report schema | Yes | No |
| 3 | SDK dependency detection | Yes | No |
| 4 | W-address rule + fixtures | Yes | No |
| 5 | XDR / CAP-88 analysis | Yes | No |
| 6 | GitHub Action integration | Yes | No |
| 7 | Baseline / suppression | Yes | No |
| 8 | Docs + regression corpus | Yes | No |

All eight are drafts. Point estimates are internal engineering estimates, not
approved Drips Wave points.
