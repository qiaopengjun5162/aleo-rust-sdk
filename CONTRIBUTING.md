# Contributing

## Development Setup

1. Ensure Rust toolchain is installed (rustup)
2. Install pre-commit: `brew install pre-commit && pre-commit install`
3. Install cargo-deny: `cargo install cargo-deny`
4. Install typos: `cargo install typos-cli`
5. Install git-cliff: `cargo install git-cliff`

## Code Style

- Run `make format` before committing
- Run `make clippy` and fix all warnings
- Run `make test` to ensure tests pass

## Commit Messages

Use conventional commits: feat, fix, docs, refactor, test, chore
