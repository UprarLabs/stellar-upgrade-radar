# Rule architecture

A **rule** is a unit of upgrade-readiness analysis. Each rule:

- Has a stable ID (`SUR-1001`, `SUR-1002`, ...). The `SUR-` prefix denotes
  *Stellar Upgrade Radar*. IDs never change meaning across releases; a finding
  is always attributable to the rule that produced it.
- Declares a `severity` (Critical > High > Medium > Low > Info) and a
  `confidence` (Low / Medium / High) **at definition time**.
- Declares a `kind`: `static` (deterministic evidence) or `manual_review`
  (a candidate for human confirmation where static evidence is insufficient).
- Cites one or more `sources` — authoritative URLs (CAP, SEP, SDK release,
  upgrade guide). Every finding carries the sources the rule used for that
  specific detection.
- States its `limitations`. These are honest about what the rule cannot see.

## The `Rule` trait

```rust
pub trait Rule: Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn kind(&self) -> Kind;
    fn protocol(&self) -> &'static str;
    fn cap(&self) -> &'static str;
    fn limitations(&self) -> Option<&'static str> { None }
    fn status(&self) -> &'static str { "implemented" }
    fn scan(&self, ctx: &FileCtx) -> Vec<Finding>;
}
```

`scan` receives a `FileCtx` (file-relative path, raw content, and pre-split
lines) and returns zero or more `Finding`s. Rules decide applicability by file
type and content; the orchestrator in `src/lib.rs::analyze` walks the tree,
skipping binary files and VCS/build directories.

## How a finding is verified

1. **Source binding.** The rule attaches the authoritative source(s) the
   detection is derived from. A finding without a source is a bug — a regression
   test asserts every finding has `>= 1` source.
2. **Static, not speculative.** We do not claim a compatibility break from a
   single token match. `static` findings only fire when the structural evidence
   is deterministic (e.g. an allowlist that omits the W strkey prefix; a
   `stellar-xdr` version whose crates.io release predates the Protocol 30 XDR).
3. **Manual review when evidence is insufficient.** `manual_review` findings
   flag a candidate line for a human and explicitly state that the match is
   heuristic. They are Low severity by convention.
4. **Fixtures.** Each rule ships positive and negative fixtures under
   `tests/fixtures/`, asserted from `tests/integration.rs`. A change to a rule
   must keep the fixtures green.

## How to add a rule

1. Create `src/rules/<slug>.rs` implementing `Rule`.
2. Register it in `rules::registry()` in `src/rules/mod.rs`.
3. Add it to the `RuleDef` list in the README's rules table.
4. Add `tests/fixtures/<slug>_{safe,unsafe}.*` fixtures and assertions in
   `tests/integration.rs`.
5. Document its source(s) in `docs/PROTOCOL-SOURCES.md`.

## Adding a finding without over-claiming

The project's hard policy: **no unsupported incompatibility claims.** Before a
`static` finding can ship, the maintainer must be able to point at a primary
source that supports the claim. If the only signal is a suspicious pattern
without a proven mechanism, the finding must be `manual_review`, Low severity.

## Confidence levels

- **High** — deterministic: e.g. a literal allowlist missing a required variant.
- **Medium** — structural but possibly indirect: e.g. a named-arm enum match
  without the new arms.
- **Low** — heuristic candidate for human review.

## Known limitations

- The scanner is not a symbolic executor. It cannot prove the absence of a risk.
- It does not inspect compiled artifacts or Wasm; only source files.
- SDK-version comparison is verified only where crates.io versioning maps to the
  protocol version (`stellar-xdr`, `soroban-sdk`). Other ecosystems report
  presence with a manual-review recommendation.
