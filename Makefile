# Common development tasks. Run `make help` for the list.

BIN := rustradar

.PHONY: help build release test lint fmt fmt-check doc check install clean docker

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Debug build
	cargo build

release: ## Optimized build (target/release/rustradar)
	cargo build --release

test: ## Run all tests (offline)
	cargo test

lint: ## Clippy with warnings as errors
	cargo clippy --all-targets -- -D warnings

fmt: ## Format the code
	cargo fmt

fmt-check: ## Check formatting
	cargo fmt -- --check

doc: ## Build API docs (target/doc/rustradar/index.html)
	cargo doc --no-deps

check: fmt-check lint test ## Everything CI runs

install: ## Install the binary into ~/.cargo/bin
	cargo install --path . --force

clean: ## Remove build artifacts
	cargo clean

docker: ## Build the container image
	docker build -t $(BIN):local .
