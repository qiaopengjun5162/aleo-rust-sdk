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
4. Ensure all tests pass and the code is properly linted:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features --tests --benches -- -D warnings
   cargo test --all-features
   ```

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

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see [LICENSE](LICENSE)).
