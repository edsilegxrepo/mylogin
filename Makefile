BIN_DIR := bin
GO ?= go
VERSION ?= $(shell cat version.txt 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
GO_OPTS ?= -trimpath -buildmode=pie

.PHONY: all build test test-integration coverage vet fmt clean help

all: test build

build: ## Compile all CLI binaries into bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GO_OPTS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/mylogin ./cmd/mylogin
	$(GO) build $(GO_OPTS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/mylogin-dsn ./cmd/mylogin-dsn
	$(GO) build $(GO_OPTS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/mylogin-key ./cmd/mylogin-key

test: ## Run unit tests with data race detector
	$(GO) test -race ./...

test-integration: ## Run live unmocked MySQL integration tests
	$(GO) test -v -tags=integration ./...

coverage: ## Calculate unit test coverage without polluting repo
	@COV=$$(mktemp) && \
	trap 'rm -f -- "$$COV"' EXIT && \
	$(GO) test -coverprofile="$$COV" ./... && \
	$(GO) tool cover -func="$$COV"

vet: ## Run static analysis (go vet, govulncheck, gosec)
	$(GO) vet ./...
	govulncheck ./...
	gosec ./...

fmt: ## Format Go source code with gofumpt
	gofumpt -l -w .

clean: ## Remove compiled binaries and temporary test artifacts
	@if [ -z "$(BIN_DIR)" ] || [ "$(BIN_DIR)" = "/" ] || [ "$(BIN_DIR)" = "." ] || [ "$(BIN_DIR)" = ".." ]; then \
		echo "Refusing to remove unsafe BIN_DIR: '$(BIN_DIR)'" >&2; exit 1; \
	fi
	rm -rf -- "$(BIN_DIR)"
	rm -f -- *.out coverage.txt

help: ## Display available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'
