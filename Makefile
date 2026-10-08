SHELL := /bin/bash
.DEFAULT_GOAL := help

CARGO ?= cargo
SUDO ?= sudo -E
RUST_LOG ?= info,hids_server=debug
BIND_ADDR ?= 127.0.0.1:8000

AGENT_BIN := target/release/hids
SERVER_MANIFEST := hids-server/Cargo.toml
SERVER_BIN_DEBUG := hids-server/target/debug/hids-server
SERVER_BIN_RELEASE := hids-server/target/release/hids-server

ARCH ?= x86_64
MUSL_TARGET ?= $(ARCH)-unknown-linux-musl
MUSL_CC ?= $(ARCH)-linux-musl-gcc

.PHONY: help
help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"; printf "HIDS make targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: fmt fmt-agent fmt-server
fmt: fmt-agent fmt-server ## Format Rust code in both workspaces.
fmt-agent:
	$(CARGO) fmt --all
fmt-server:
	$(CARGO) fmt --manifest-path $(SERVER_MANIFEST) --all

.PHONY: fmt-check fmt-check-agent fmt-check-server
fmt-check: fmt-check-agent fmt-check-server ## Check Rust formatting in both workspaces.
fmt-check-agent:
	$(CARGO) fmt --all -- --check
fmt-check-server:
	$(CARGO) fmt --manifest-path $(SERVER_MANIFEST) --all -- --check

.PHONY: check check-agent check-server
check: check-agent check-server ## Type-check the default agent crates and hids-server.
check-agent:
	$(CARGO) check
check-server:
	$(CARGO) check --manifest-path $(SERVER_MANIFEST)

.PHONY: test test-agent test-server test-no-run
test: test-agent test-server ## Run unit tests in both workspaces.
test-agent:
	$(CARGO) test
test-server:
	$(CARGO) test --manifest-path $(SERVER_MANIFEST)
test-no-run: ## Compile tests without running them.
	$(CARGO) test --no-run
	$(CARGO) test --manifest-path $(SERVER_MANIFEST) --no-run

.PHONY: clippy clippy-agent clippy-server
clippy: clippy-agent clippy-server ## Run clippy with warnings denied.
clippy-agent:
	$(CARGO) clippy --all-targets -- -D warnings
clippy-server:
	$(CARGO) clippy --manifest-path $(SERVER_MANIFEST) --all-targets -- -D warnings

.PHONY: build build-agent build-server
build: build-agent build-server ## Build debug binaries.
build-agent:
	$(CARGO) build
build-server:
	$(CARGO) build --manifest-path $(SERVER_MANIFEST)

.PHONY: release release-agent release-server
release: release-agent release-server ## Build release binaries.
release-agent:
	$(CARGO) build -p hids --release
release-server:
	$(CARGO) build --manifest-path $(SERVER_MANIFEST) --release

.PHONY: build-ebpf
build-ebpf: ## Rebuild the eBPF object from source; requires nightly rust-src and bpf-linker.
	AYA_BUILD_EBPF=1 $(CARGO) build -p hids --release

.PHONY: cross-musl
cross-musl: ## Cross-compile the agent for Linux musl, e.g. ARCH=aarch64.
	CC=$(MUSL_CC) $(CARGO) build --package hids --release \
		--target=$(MUSL_TARGET) \
		--config=target.$(MUSL_TARGET).linker=\"$(MUSL_CC)\"

.PHONY: run-agent run-server run-server-release
run-agent: release-agent ## Build and run the agent as root.
	$(SUDO) ./$(AGENT_BIN)
run-server: build-server ## Build and run hids-server without Cargo runner indirection.
	RUST_LOG="$(RUST_LOG)" BIND_ADDR="$(BIND_ADDR)" ./$(SERVER_BIN_DEBUG)
run-server-release: release-server ## Build and run release hids-server.
	RUST_LOG="$(RUST_LOG)" BIND_ADDR="$(BIND_ADDR)" ./$(SERVER_BIN_RELEASE)

.PHONY: es-template replay-spool
es-template: ## Apply Elasticsearch ILM policy and index template.
	cd hids-server && ./scripts/apply-es-template.sh
replay-spool: ## Replay failed server bulk spool files into Elasticsearch.
	cd hids-server && ./scripts/replay-spool.sh

.PHONY: ci
ci: check test-no-run ## Fast local CI that avoids explicit eBPF source rebuilds.

.PHONY: doctor
doctor: ## Print important tool versions and optional runtime helpers.
	@$(CARGO) --version
	@rustc --version
	@command -v bpf-linker >/dev/null && bpf-linker --version || echo "bpf-linker: missing (needed for make build-ebpf)"
	@command -v bpftool >/dev/null && bpftool version || echo "bpftool: missing (optional, useful for eBPF diagnostics)"

.PHONY: clean clean-agent clean-server clean-runtime
clean: clean-agent clean-server ## Clean Cargo build artifacts in both workspaces.
clean-agent:
	$(CARGO) clean
clean-server:
	$(CARGO) clean --manifest-path $(SERVER_MANIFEST)
clean-runtime: ## Remove local generated spool/cache outputs.
	rm -rf spool spool-server graphify-out hids-server/spool-server
