# aleo-rust-sdk — Rust SDK for Aleo blockchain
# see https://github.com/casey/just

set positional-arguments := true

# ── Build ────────────────────────────────────────────

# Build the project (all features)
build:
    cargo build --all-features

# Release build
build-release:
    cargo build --release --all-features

# Clean build artifacts
clean:
    cargo clean

# ── Test ────────────────────────────────────────────

# Run all tests (nextest preferred, fallback to cargo test)
test:
    cargo nextest run --all-features || cargo test --all-features

# Run benchmarks
bench:
    cargo bench --all-features

# ── Lint / Check ────────────────────────────────────

# Quick code check
check:
    cargo check --all-features

# Lint with Clippy
# `--all-targets` matters: without it the `#[cfg(test)]` modules are not
# compiled and a broken test is only discovered by `just test`.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Format code check (CI)
format:
    cargo fmt --all -- --check

# Fix code formatting
format-fix:
    cargo fmt --all

# Spell check with typos
typos:
    typos

# ── Docs ────────────────────────────────────────────

# Generate documentation
docs:
    cargo doc --no-deps --all-features

# Open docs in browser
docs-open:
    cargo doc --no-deps --all-features --open

# ── Quality ─────────────────────────────────────────

# Generate coverage report (requires cargo-llvm-cov)
coverage:
    cargo llvm-cov --all-features --lcov --output-path lcov.info
    @echo "Coverage report: lcov.info"

# Security audit (requires cargo-deny)
audit:
    cargo deny check

# Update dependencies
update:
    cargo update

# Generate changelog (requires git-cliff)
changelog:
    git cliff -o CHANGELOG.md

# ── Run all ─────────────────────────────────────────

# Run all checks: format + check + clippy + test
#
# Not the CI gate — see `gate` below. This recipe predates most of the workflow
# and can be green while CI is red.
all: format check clippy test

# Full local suite: everything in `all`, plus audit + docs
ci-full: format check clippy test audit docs

# ── CI gate ─────────────────────────────────────────

# Reproduce the CI gate locally, in the workflow's own order.
#
# `ci-full` above predates most of the gate: it never runs taplo, typos, rustdoc
# with `-D warnings`, doc-tests or the coverage floor, so "local green, CI red"
# is possible. This mirrors `.github/workflows/ci.yml` step for step — if you
# change one, change the other.
#
# `cargo nextest` does NOT run doc-tests, hence the separate step: without it the
# rustdoc examples in src/ are never compiled.
gate:
    cargo fmt --all -- --check
    taplo fmt --check
    typos
    cargo clippy --all-targets --all-features --tests --benches -- -D warnings
    cargo deny check
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
    cargo nextest run --all-features
    cargo test --doc --all-features

# `gate` plus the instrumented coverage run — the slowest step in CI (>10 min),
# which is why it is separate. The floor matches the workflow; raise it when a
# round of test work lifts the baseline, never lower it.
gate-cov:
    @just gate
    cargo llvm-cov --all-features --lcov --output-path lcov.info --fail-under-lines 87

# ── Publish ─────────────────────────────────────────

# Publish to crates.io (dry-run first)
publish-dry-run:
    cargo publish --dry-run

# Publish to crates.io
publish:
    cargo publish
