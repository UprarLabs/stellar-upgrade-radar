---
name: Bug report
about: Report a wrong result, a crash, or a CLI behaviour that does not match the documented contract
title: ""
labels: ["bug"]
assignees: []
---

## Scope

<!-- What is affected: a rule (SUR-XXXX), an output format (text / JSON / SARIF), the CLI, or CI. One area per issue. -->

## Context

<!-- What you were scanning (language, manifest, single file or directory), the command you ran, and the tool version (`stellar-upgrade-radar --version` or the commit hash). -->

## Problem

<!-- What the tool did, versus what the documented behaviour says it should do. Include the exact command and its output. -->

```console
$ stellar-upgrade-radar check <path> --format json
```

## Steps to reproduce

1.
2.
3.

## Expected behaviour

<!-- The finding, exit code, or output you expected, and where it is documented (README, docs/RULES.md, docs/SARIF.md). -->

## Acceptance criteria

<!-- Checkable conditions that close this issue, e.g. "the command above reports the same findings as scanning the parent directory". -->

- [ ]
- [ ]

## Verification

<!-- How the fix should be verified: regression test, fixture, or manual command. A fix for a rule must add or update a fixture under `tests/fixtures/` and assert it from `tests/integration.rs`. -->
