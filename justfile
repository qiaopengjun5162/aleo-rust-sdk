# aleo-rust-sdk — Rust SDK for Aleo blockchain
# see https://github.com/casey/just

set positional-arguments := true

# Build the project (all features)
build:
    cargo build --all-features

# Release build
build-release:
    cargo build --release --all-features

# Clean build artifacts
clean:
    cargo clean

# Run all tests (nextest preferred, fallback to cargo test)
test:
    cargo nextest run --all-features || cargo test --all-features

# Run benchmarks
bench:
    cargo bench --all-features

# Quick code check
check:
    cargo check --all-features

# Lint with Clippy
clippy:
    cargo clippy --all-features -- -D warnings

# Format code check
format:
    cargo fmt --all -- --check

# Fix code formatting
format-fix:
    cargo fmt --all

# Generate coverage report (requires cargo-llvm-cov)
coverage:
    cargo llvm-cov --all-features --lcov --output-path lcov.info
    @echo "Coverage report: lcov.info"

# Update dependencies
update:
    cargo update

# Generate changelog (requires git-cliff)
changelog:
    git cliff -o CHANGELOG.md

# Run all checks: format + check + clippy + test
all: format check clippy test
