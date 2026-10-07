BIN_DIR := bin
GO ?= go

.PHONY: all build test test-integration coverage vet fmt clean help

all: test build

build: ## Compile all CLI binaries into bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/mylogin ./cmd/mylogin
	$(GO) build -o $(BIN_DIR)/mylogin-dsn ./cmd/mylogin-dsn
	$(GO) build -o $(BIN_DIR)/mylogin-key ./cmd/mylogin-key

test: ## Run unit tests with data race detector
	$(GO) test -race ./...

test-integration: ## Run live unmocked MySQL integration tests
	$(GO) test -v -tags=integration ./...

coverage: ## Calculate unit test coverage without polluting repo
	@COV=$$(mktemp) && \
	$(GO) test -coverprofile="$$COV" ./... && \
	$(GO) tool cover -func="$$COV" && \
	rm -f "$$COV"

vet: ## Run go vet analysis
	$(GO) vet ./...

fmt: ## Format Go source code
	gofmt -s -w .

clean: ## Remove compiled binaries and temporary test artifacts
	rm -rf $(BIN_DIR) *.out coverage.txt

help: ## Display available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'
