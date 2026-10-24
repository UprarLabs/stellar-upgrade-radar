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
- `SUR-1002` resolves the nearest `Cargo.lock` and treats the resolved version
  as authoritative: a manifest pin below 30 is a High defect, and a stale
  lockfile (manifest declares 30 but the lockfile resolves an older version) is
  also a High defect. Renamed dependencies (`package = "..."`) and workspace
  field syntax (`dep.workspace = true`) resolve to the real crate name. If no
  lockfile is found, ranges and git/path/workspace dependencies are low-severity
  manual-review candidates (uncertainty reported, not guessed). When a lockfile
  lists multiple versions of a crate, the first is used (order-dependent); the
  actually-resolved version requires manual confirmation. `soroban-sdk < 30` is
  a manual-review candidate, not a contract break, because existing contracts
  remain compatible after the upgrade.
- `SUR-1002` also covers non-Rust SDK ecosystems via `rules::dependency_sdk`:
  JS/TS (`package.json` + `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`),
  Python (`pyproject.toml`/`requirements.txt` + `poetry.lock`/`uv.lock`/
  `Pipfile.lock`), Go (`go.mod`) and Elixir (`mix.exs` + `mix.lock`). A manifest
  range is never treated as the resolved version; JS (v17.3.0 / v16.4.x LTS)
  and Go (v0.8.0) use verified Protocol 30 release thresholds, while Python and
  Elixir have no verified release and are reported as `manual_review`/unknown.
  Lockfile parsers are heuristic (line/JSON/TOML/YAML scans), so an unusual
  lockfile layout can miss a resolution; a manifest exact pin is still reported.
- Non-Rust specifics: Python matches a dependency **name in dependency context**
  only (a project/package name such as `my-stellar-sdk-app` is not flagged);
  Go honours `replace` directives (a replace with a Ready version is not
  reported, a path replace is unknown) and treats pseudo-versions as unknown;
  `github.com/stellar/go` (the Go monorepo) is detected as `manual_review`
  because no verified Protocol 30 release threshold exists for it. JS reads a
  nested dependency object's `version`, searches for a lockfile up to the
  project root (monorepo support, bounded by `.git`/depth) and reports
  `manual_review` when a lockfile lists multiple resolutions for the SDK.
  Elixir git/path dependencies are reported as unknown (a URL or path is never
  shown as the version).
- Prerelease versions (`17.3.0-rc.1`, `v0.8.0-rc.1`) are **never auto-Ready**:
  their readiness is not provable from the version, so they are reported as
  `manual_review`/unknown even when the numeric part meets the stable threshold.
  Stable thresholds are unchanged.
- `SUR-1003` is **block-aware** (brace-depth tracked): a file that mixes an
  updated decoder with a legacy one is caught (only the legacy block is flagged),
  and a block that already enumerates the `_MS` arms is not flagged. Arm
  identity is read from the arm **pattern** (left of `=>`, or a `case` label),
  so a stellar-value name inside a string literal or a trailing comment cannot
  change the verdict, and a non-StellarValue match is not flagged. Arms must
  place the arm name and `=>` on the same line (multiline arms are missed), and
  a numeric `case` arm sharing the `match`/`switch` keyword line is missed
  (named arms with `=>` on that line are detected). Brace counting does not
  strip string/char literals, so braces inside literals can mis-track nesting.
  Arms whose `_MS` handling lives in a called helper remain out of scope
  (manual review).
- `SUR-1001` strips comments with a string-aware scanner and blanks string/char
  literal contents, so `//`, `/*` and address/strkey words inside strings or
  comments do not create context. Context requires strkey/muxed/Soroban-address
  evidence, an allowlist-named binding, or a strkey-char array used in a
  validation predicate (`.contains`/`.iter`/`.any`/`.position`); a bare
  `address`/`prefix` substring in an unrelated identifier is not context. Char
  allowlists must be an array literal or an allowlist-named binding (an
  arbitrary short string such as `"GMC"` is not an allowlist), version-byte
  arrays require a strkey/muxed term in the same declaration, and allowlists may
  span multiple lines. String/packed allowlists and char arrays of < 3 strkey
  chars are not flagged; validation delegated to a strkey library is not
  flagged (correctly, but also not verified).

