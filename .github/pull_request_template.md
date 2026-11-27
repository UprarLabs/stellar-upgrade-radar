## Summary

<!-- What this PR changes, in one or two sentences. Link the issue it closes, e.g. "Closes #4". -->

## Checklist

- [ ] Tests added or updated for the changed behaviour (fixtures under `tests/fixtures/`, asserted from `tests/integration.rs`)
- [ ] Rule IDs are stable — no existing rule ID was renamed, removed, or re-scoped without a note in the PR description
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --all-targets` passes
- [ ] Docs updated (`docs/RULES.md` if a rule's detection or limitations changed, README if the CLI contract changed)
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] One rule or one behaviour change per PR — the diff stays focused

## Verification

<!-- Commands run and their results, e.g. `cargo test --all-targets` output, or the exact scan command and its findings. -->
