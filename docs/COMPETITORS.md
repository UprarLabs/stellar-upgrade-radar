# Competitor & overlap audit

Scope: open-source or officially-supported tooling that addresses Stellar
**protocol-upgrade compatibility / upgrade-readiness** for application
developers. This is a focused scan, not exhaustive, performed to support a
honest differentiation claim.

## Tools found

| Tool | URL | Primary purpose | Upgrade-readiness coverage |
|------|-----|------------------|----------------------------|
| stellar-xdr (crate/repo) | https://github.com/stellar/stellar-xdr | XDR type definitions and codegen for Stellar | Provides the updated schema; does **not** scan consumer code to verify it handles the new arms. |
| js-stellar-sdk migration guides | https://stellar.github.io/js-stellar-sdk/migration/00-migration | SDK API migration (v16→v17 XDR/Uint8Array changes) | SDK-bound; covers API renames, not project-wide readiness. |
| stellar-galexie | https://github.com/stellar/stellar-galexie | Indexer that ingests ledger data | Consumes ledger data (must update XDR); is not a static analyzer for third-party consumers. |
| Soroban static security scanners (SARIF topic) | https://github.com/topics/sarif?l=rust | Static security analysis of Soroban contracts | Security, not protocol-upgrade compatibility. |
| Sanctifier | https://github.com/HyperSafeD/Sanctifier | Soroban security + formal verification | Security, not upgrade readiness. |
| Stellar Security Portal | https://github.com/inferara/soroban-security-portal | Audit findings & educational security resources | Security findings, not upgrade-readiness scanning. |

A web search ([1] "Stellar protocol upgrade readiness scanner", [2] "Stellar
XDR decoder compatibility tool", [3] "Soroban static analysis linter") returned
no dedicated protocol-upgrade-readiness scanner for the Stellar ecosystem as of
2026-10. The closest matches are SDK-specific migration guides and Soroban
**security** scanners; neither covers the cross-cutting structural checks this
project targets (CAP-84 address handling + CAP-88 XDR arm handling + SDK/XDR
version readiness in one report).

## Differentiation (evidence-supported, not exclusive)

1. **Cross-CAP scope.** Existing tools are scoped to a single concern
   (security, or one SDK's API migration). `stellar-upgrade-radar` covers
   CAP-84 (address handling) and CAP-88 (XDR decoding) together, so a consumer
   cannot satisfy one and miss the other.
2. **Dependency-version grounding.** `SUR-1002` compares the `stellar-xdr` and
   `soroban-sdk` crate majors against the **verified** crates.io Protocol 30
   release lines (stellar-xdr 30.0.0; soroban-sdk 30.0.0-rc.1), rather than
   guessing a minimum.
3. **Source-bounded findings.** Every finding carries an authoritative source URL
   and an explicit confidence/uncertainty level; `manual_review` findings are
   Low-severity candidates rather than asserted defects.

## Uncertainties / scope limits

- "No dedicated tool exists" is bounded to this search; undiscovered tools may
  exist.
- stellar-xdr 30.0.0: a docs.rs/crates.io features scan of the released crate
  shows **no** `MS_CLOSE_TIME` consumer feature — the `#ifdef MS_CLOSE_TIME`
  directives in stellar-protocol's `.x` files are a source-branch development
  concern (next/curr branch workflow, discussion #1896), not a published toggle.
  Therefore the released Protocol 30 crate decodes the CAP-88 millisecond arms by
  default, and `SUR-1002`'s version check (`stellar-xdr >= 30`) is not a false
  negative. Detecting "compiles a non-default XDR feature" remains a planned
  extension (see `docs/MAINTAINER-READINESS.md`, task #5).
