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
clippy:
    cargo clippy --all-features -- -D warnings

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
all: format check clippy test

# Full CI suite: format + check + clippy + test + audit + docs
ci-full: format check clippy test audit docs

# ── Publish ─────────────────────────────────────────

# Publish to crates.io (dry-run first)
publish-dry-run:
    cargo publish --dry-run

# Publish to crates.io
publish:
    cargo publish
