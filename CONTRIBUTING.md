# Contributing to aleo-rust-sdk

Thank you for considering contributing to `aleo-rust-sdk`! By participating in this project, you help improve the Aleo blockchain development experience for Rust developers worldwide.

## How to Contribute

### 1. Reporting Bugs

If you find a bug, please:

- Check the [issues](https://github.com/qiaopengjun5162/aleo-rust-sdk/issues) to see if it has already been reported.
- If not, create a new issue with:
  - A clear description of the problem.
  - Steps to reproduce the bug.
  - Any relevant logs or error output.

### 2. Suggesting Features

Have an idea for a new feature or improvement?

- Search existing issues to see if your idea is already suggested.
- If not, open a new issue with a clear description, why it's valuable, and any additional context.

### 3. Submitting Code Changes

1. Fork the repository to your GitHub account.
2. Create a new branch: `feature/your-feature` or `fix/bug-description`.
3. Make your changes in this branch.
4. Ensure all tests pass and the code passes every check CI runs (see [Quality Gates](#quality-gates)):

   ```bash
   cargo fmt --all -- --check
   taplo fmt --check
   typos
   cargo clippy --all-targets --all-features --tests --benches -- -D warnings
   cargo deny check
   cargo test --all-features
   ```

   Or run them all at once with [`just`](https://github.com/casey/just): `just ci-full`.

5. Commit with clear, concise messages following [Conventional Commits](https://www.conventionalcommits.org/):

   ```
   feat: add support for record decryption
   fix: resolve panic on empty program response
   docs: update README with transfer example
   test: add integration tests for network module
   ```

6. Push to your fork and create a Pull Request to the `main` branch.

### 4. Code Style

- Follow the [Rust style guide](https://doc.rust-lang.org/book/ch01-01-installation.html).
- Run `cargo fmt` before committing.
- Keep imports grouped: standard library → external crates → local modules.
- Aim for meaningful test coverage on new code.

## Development Setup

Requires **Rust 1.88+** (edition 2024 + `time` 0.3.47 security fix). `rust-toolchain.toml`
pins `stable`, so `rustup` picks the right toolchain automatically.

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/aleo-rust-sdk.git
cd aleo-rust-sdk

# Build
cargo build --all-features

# Run tests
cargo test --all-features

# Run lints
cargo clippy --all-targets --all-features --tests --benches -- -D warnings
```

## Quality Gates

CI (`.github/workflows/ci.yml`) enforces all of the following. A PR cannot merge
until `build-rust (ubuntu-latest)` is green.

| Check | Command | Config |
|-------|---------|--------|
| Rust formatting | `cargo fmt --all -- --check` | `rustfmt.toml` |
| TOML formatting | `taplo fmt --check` | `taplo.toml` (excludes `target/**`) |
| Spelling | `typos` | `_typos.toml` |
| Compile | `cargo check --all-features` | — |
| Lints | `cargo clippy … -- -D warnings` | — |
| Dependency audit | `cargo deny check` | `deny.toml` |
| Tests | `cargo nextest run --all-features` | — |

Notes:

- **Never** silence a failing check with `|| echo "skipping"` — that swallows both
  the error output and the exit code, turning the gate into a no-op.
- Tests under `tests/real_prove.rs` are `#[ignore]` (Varuna proving takes 15–60s each).
  Run them with `cargo test --all-features -- --ignored`.
- Do not add an `update` (Restrict updates) rule to the `main` ruleset: it blocks
  every pull-request merge, including for admins.

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see [LICENSE](LICENSE)).
