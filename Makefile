# ==============================================================================
# Project: aleo-rust-sdk
# Description: Rust SDK for Aleo blockchain — accounts, programs, execution, network
# Author: Paxon Qiao
# ==============================================================================

CARGO := cargo
SHELL := /bin/bash
MAIN_BRANCH := main

.PHONY: all build clean test bench check clippy format release update help

all: build

## build: 编译项目 (Build the project)
build:
	@$(CARGO) build --all-features

## build-release: 以 release 模式编译 (Build in release mode)
build-release:
	@$(CARGO) build --release --all-features

## clean: 清理构建产物 (Clean build artifacts)
clean:
	@$(CARGO) clean

## test: 运行所有测试 (Run all tests)
test:
	@$(CARGO) nextest run --all-features 2>/dev/null || $(CARGO) test --all-features

## bench: 运行 benchmark (Run benchmarks)
bench:
	@$(CARGO) bench --all-features

## check: 快速检查代码 (Quickly check code for errors)
check:
	@$(CARGO) check --all-features

## clippy: 使用 Clippy 进行代码 lint (Lint code with Clippy)
clippy:
	@$(CARGO) clippy --all-features -- -D warnings

## format: 格式化代码 (Format the code)
format:
	@$(CARGO) fmt --all -- --check

## coverage: 生成测试覆盖率报告 (Generate coverage report)
coverage:
	@cargo llvm-cov --all-features --lcov --output-path lcov.info
	@echo "Coverage report: lcov.info"

## release: 创建新 release 版本 (Create a new release)
release: test
	@echo "🧪 Tests passed. Proceeding with release..."
	@cargo release --execute 2>/dev/null || echo "cargo-release not installed, skipping"
	@git cliff -o CHANGELOG.md 2>/dev/null || echo "git-cliff not installed, skipping"
	@git add CHANGELOG.md
	@git commit --amend --no-edit || echo "No changes to commit"
	@git push --follow-tags origin $(MAIN_BRANCH)
	@echo "✅ Release process complete."

## update: 更新依赖 (Update dependencies)
update:
	@$(CARGO) update

## help: 显示此帮助信息 (Show this help message)
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
.DEFAULT_GOAL := help
