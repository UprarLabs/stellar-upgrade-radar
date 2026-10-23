# Contributing to stellar-upgrade-radar

Thanks for your interest. This project exists to make Stellar protocol upgrades
safer and more observable for application developers.

## Development

```bash
git clone https://github.com/UprarLabs/stellar-upgrade-radar
cd stellar-upgrade-radar
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

`cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test --all-targets`
must all pass before a pull request is merged. CI enforces the same.

## How rules are designed

Every rule is **evidence-bounded**: it cites an authoritative source (CAP, SEP,
SDK release, or upgrade guide) and states an honest confidence level. A rule
may only assert an incompatibility when static evidence deterministically
supports it. Where static evidence is insufficient, the rule emits a
`manual_review` finding instead of claiming a defect. This is a hard policy,
not a default.

See [`docs/RULES.md`](docs/RULES.md) for the rule-authoring process and
[`docs/PROTOCOL-SOURCES.md`](docs/PROTOCOL-SOURCES.md) for the source registry.

## Adding a fixture

Each rule ships positive and negative fixtures under `tests/fixtures/`. Add a
fixture for any new behavior, and assert it from `tests/integration.rs`. A PR
that changes a rule must update the expected fixture results.

## Pull requests

- Keep diffs focused; one rule or one behavior change per PR.
- Update `docs/RULES.md` when a rule's detection or limitations change.
- Do not commit generated output under `target/`.
- Sign your commits (the repo does not enforce DCO yet, but it is good practice).
