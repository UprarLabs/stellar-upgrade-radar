# Contributor issue candidates (DRAFTS — NOT PUBLISHED)

These are eight proposed contributor issues for the `stellar-upgrade-radar`
project. They are **local drafts** and must not be published until the MVP and
its interfaces are stable. **Point estimates below are internal engineering
estimates only — they are not approved Drips Wave points** and must not be
presented as such.

Each issue lists independent acceptance criteria so a contributor can take it
as a self-contained task.

---

## ISSUE 1 — Formalize the protocol source registry

**Title:** Turn `docs/PROTOCOL-SOURCES.md` into a versioned, testable source registry

**Body:**
Move the source registry from a hand-written markdown file into a machine-readable
data file (e.g. `data/sources.yaml` or a Rust `static` table) that is loaded by
`src/sources.rs` and verified at test time. Each entry must include: `id`, `url`,
`claim`, and the CAP/SEP/protocol version it applies to.

Acceptance criteria:
- `src/sources.rs` loads entries from the data file (or an equivalent
  generated source) and returns the same public `SOURCES` list.
- A test asserts every entry's URL is reachable (HTTP 2xx/3xx) and that its
  `claim` string is non-empty.
- `docs/PROTOCOL-SOURCES.md` is regenerated or kept in sync.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  and `cargo test --all-targets` pass.

Internal estimate: Small (1-2 days).

---

## ISSUE 2 — Stabilize the JSON report schema and add a schema document

**Title:** Version the JSON report and publish a JSON Schema

**Body:**
The CLI emits JSON with `schema_version`. Make that contract explicit by adding a
committed JSON Schema (`docs/report.schema.json`) and a test that validates a
freshly emitted report against it. Document breaking-change rules for the schema
in `docs/`.

Acceptance criteria:
- A JSON Schema file describes the report, including every field currently
  emitted by `src/report.rs`.
- A test generates a report (JSON) and validates it against the schema.
- `README.md` links to the schema and documents `schema_version` semantics.
- CI passes.

Internal estimate: Small-Medium.

---

## ISSUE 3 — Extend SDK dependency detection with verified minimums  — ✅ IMPLEMENTED

**Title:** Ground SUR-1002 for JS/Python/Go/Elixir SDKs with verified Protocol 30 minimums

**Status:** implemented in `src/rules/dependency_sdk.rs` (uncommitted working tree).

**Body:**
`SUR-1002` compares Rust crate majors (`stellar-xdr`, `soroban-sdk`) against
verified crates.io lines, and now also covers the JS (`@stellar/stellar-sdk`),
Python (`stellar-sdk`), Go (`github.com/stellar/go-stellar-sdk`) and Elixir
(`stellar_sdk`) SDKs from their release pages. Each ecosystem ships a
manifest+lockfile check with fixtures.

Acceptance criteria — all met:
- `docs/PROTOCOL-SOURCES.md` records each ecosystem's verified Protocol 30
  release line with a citation URL (JS v17.3.0 / v16.4.0 LTS; Go v0.8.0;
  Python and Elixir: none released).
- `SUR-1002` flags pre-Protocol-30 versions for JS and Go (Medium/Static), with
  negative fixtures proving current versions pass; Python and Elixir are
  manual-review because no verified Protocol 30 release exists.
- Sources are attached to each finding.
- Tests pass (99 total).

Internal estimate: Medium (2-4 days). — closed.

---

## ISSUE 4 — Widen the W-address rule and add negative fixtures

**Title:** Extend SUR-1001 to strkey-decoding call sites and prove M-address handling is not conflated

**Body:**
`SUR-1001` detects literal allowlists that omit `W`. Extend detection to call
sites of strkey decoding helpers (e.g. functions named `decode_strkey`,
`strkey::decode`, `Address::from_str`) and ensure a muxed **account** (`M`) path
that does not handle `W` is not silently treated as correct. Add fixtures that
must **not** trigger.

Acceptance criteria:
- New positive fixtures that trigger the rule.
- New negative fixtures (including M-only handling and already-W-aware code)
  that produce no finding.
- Assertions added to `tests/integration.rs`.
- Limitation text in `docs/RULES.md` updated to match the new coverage.

Internal estimate: Small (1-3 days).

---

## ISSUE 5 — XDR / CAP-88 analysis: feature-flag and arm coverage

**Title:** Detect stellar-xdr feature-flag use and verify decoder arm coverage

**Body:**
`stellar-xdr` gates the CAP-88 arms behind the `MS_CLOSE_TIME` feature flag.
Extend `SUR-1003` to (a) flag projects that enable `stellar-xdr` without the
millisecond feature, and (b) verify that decoder sites handle the two new arms.
Use fixtures and keep the false-positive rate auditable.

Acceptance criteria:
- A fixture where stellar-xdr is used without the ms feature produces a finding.
- A fixture where all four arms are handled produces no finding.
- Numeric-discriminant matches remain `manual_review`, Low severity.
- Tests pass; `docs/RULES.md` limitations updated.

Internal estimate: Medium-Large (3-6 days).

---

## ISSUE 6 — GitHub Action integration

**Title:** Publish a reusable GitHub Action for upgrade-readiness checks

**Body:**
Add a composite/reusable GitHub Action (`.github/actions/upgrade-radar/action.yml`)
that runs the CLI on a repository and fails when findings meet a configurable
severity threshold. Include an example workflow and documentation.

Acceptance criteria:
- Action YAML runs the CLI via a prebuilt or cached binary and honors
  `min-severity` and `path` inputs.
- Exit-code semantics are preserved (1 on findings).
- Example workflow in `README.md`.
- Action is lintable (actionlint) or documented as such.

Internal estimate: Small (1-2 days).

---

## ISSUE 7 — Baseline and suppression support

**Title:** Add `.upgrade-radar.toml` suppression and baseline mode

**Body:**
Allow projects to acknowledge known findings without editing code, so the tool
can serve as a CI gate over time. Implement a config file that can suppress by
rule id and/or file path, plus a baseline mode that records current findings and
fails only on new ones.

Acceptance criteria:
- Config parsing with validation and helpful errors.
- Suppression and baseline behavior with regression tests.
- Documentation in `docs/` and `CONTRIBUTING.md`.
- Tests pass; clippy clean.

Internal estimate: Medium (2-4 days).

---

## ISSUE 8 — Documentation and regression corpus

**Title:** Build a structured regression corpus and a rule-author guide

**Body:**
Turn the ad-hoc fixtures into a documented corpus with per-fixture expected
outcomes, and write a concise rule-author guide covering how to add a rule,
write fixtures, and bound confidence. This is the onboarding path for new
contributors.

Acceptance criteria:
- A corpus manifest mapping each fixture file to its expected rule results.
- A CI check that diffs actual vs. expected fixture results.
- `docs/RULES.md` gains an explicit "authoring a new rule" checklist.
- All tests pass.

Internal estimate: Medium (2-4 days).
