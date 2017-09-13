.DEFAULT_GOAL := help

DOCKER_RUST := advancedtelematic/rust:x86-1.20.0

DOCKER_RUN := \
	@docker run --rm \
		--env RUST_LOG=$(RUST_LOG) \
		--env RUST_BACKTRACE=$(RUST_BACKTRACE) \
		--volume ~/.cargo/git:/root/.cargo/git \
		--volume ~/.cargo/registry:/root/.cargo/registry \
		--volume $(CURDIR):/src \
		--workdir /src \
		$(DOCKER_RUST)

.PHONY: help
help: ## Print this message
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

.PHONY: clean
clean: ## Remove temp/useless files
	@find . -name '*.rs.bk' -type f -delete

.PHONY: dev-docs
dev-docs: ## Generate the documentation for all modules (dev friendly)
	@cargo rustdoc --all-features --open -- --no-defaults --passes "collapse-docs" --passes "unindent-comments"

.PHONY: check
check: ## Runs `cargo check` in the dockerized environment
	$(DOCKER_RUN) cargo check

.PHONY: test
test: ## Runs `cargo test` in the dockerized environment
	$(DOCKER_RUN) cargo test


.PHONY: build
build: ## Runs `cargo build` in the docerized environment
	$(DOCKER_RUN) cargo build
