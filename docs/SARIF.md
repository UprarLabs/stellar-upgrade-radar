# SARIF 2.1.0 emitter — design note

`--format sarif` emits a minimal SARIF 2.1.0 run built with the existing
`serde_json` (no new dependency). `--format json` is unchanged
(`schema_version: 1.0`, same shape and semantics), and the default format is
still `text`.

## Severity → level mapping

SARIF has four levels (`error`, `warning`, `note`, `none`); the scanner has five
severities, so the mapping is a **documented policy decision**, not automatic:

| Severity | SARIF `level` | Rationale |
|----------|---------------|-----------|
| Critical | `error` | definite break |
| High     | `error` | definite break (e.g. `stellar-xdr` below the Protocol 30 line) |
| Medium   | `warning` | evidence-backed risk, not proven |
| Low      | `note` | candidate for review |
| Info     | `none` | **policy decision**: the scanner treats Info as "informational, not a problem", and SARIF `none` means the result does not indicate a problem |

The original `severity`, `confidence` and `kind` are preserved verbatim in
`result.properties`, so the coarser SARIF `level` loses no information and
`manual_review` findings are never silently promoted to an error.

## Column / location

- `runs[0].columnKind` = `unicodeCodePoints`.
- The internal `Finding.column` is a **1-based byte offset** within the
  (trimmed) snippet line. It is converted to a **1-based Unicode code-point
  column** before emission (`byte_col_to_codepoint_col`), so the column matches
  the snippet exactly. This is a conversion, not a relabelling.
- Exact for ASCII and tabs; a byte offset that lands inside a multibyte UTF-8
  character is mapped to that character's start (see `src/sarif.rs`).
- `artifactLocation.uri` is the reported file path (`Finding.file`), consistent
  across JSON and SARIF.
- Results without a line (currently none) omit `locations`.

## Stability

- `partialFingerprints["stellarUpgradeRadarStableId"]` is a stable,
  **non-cryptographic** FNV-1a 64 hash of `(rule_id, file, line, snippet)`. It
  is a matching id for baselines/dedup — it is **not** a cryptographic hash.
- SARIF output is deterministic across runs (unlike the JSON report, which
  carries `scanned_at_epoch`).

## Notices

`Report.notices` are emitted under `runs[0].properties.notices` (documented)
rather than as notification descriptors, to avoid referencing a
`reportingDescriptor` that is not defined in the run.

## Conformance limitation

Conformance is **not** validated with an external SARIF validator (adding one
would be a new dependency). What is proven is limited to the structure and
invariants asserted in `src/sarif.rs` and `tests/integration.rs`:

- `version == "2.1.0"`, `$schema` present, one `runs[]` entry.
- `tool.driver` has `name`, `version`, `informationUri`, and a `rules[]` list
  whose ids are exactly the scanner's stable rule ids.
- every `result.ruleId` references `driver.rules` and `ruleIndex` matches.
- `message.text` present; `level ∈ {error, warning, note, none}`.
- `manual_review` results are preserved with `properties.kind`.
- locations carry `startLine`, and `startColumn` matches the snippet.
- deterministic output and stable fingerprints.

A full schema-conformance check against the SARIF 2.1.0 meta-schema remains
**not verified**.

## Tests

- Unit: severity mapping (all five), byte→code-point column conversion (ASCII,
  tab, multibyte), fingerprint stability, top-level structure.
- Integration (real CLI): SARIF well-formedness, `manual_review` preservation,
  JSON regression, determinism, fingerprint stability, and location/column
  consistency against the fixture corpus.
