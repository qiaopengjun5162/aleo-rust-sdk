CARGO := cargo
SHELL := /bin/bash
MAIN_BRANCH := main

.PHONY: all build clean test check clippy format
all: build

build:
	$(CARGO) build --all-features

build-release:
	$(CARGO) build --release --all-features

clean:
	$(CARGO) clean

test:
	$(CARGO) nextest run --all-features

check:
	$(CARGO) check --all-features

clippy:
	$(CARGO) clippy --all-features -- -D warnings

format:
	$(CARGO) fmt --all -- --check

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
.DEFAULT_GOAL := help
