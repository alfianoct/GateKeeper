.PHONY: build test cover lint vet fmt check clean docker run vuln help

BINARY  := gatekeeper
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.1b)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the binary
	go build $(LDFLAGS) -o $(BINARY) ./cmd/gatekeeper

test: ## Run tests
	go test -count=1 ./internal/...

race: ## Run tests with race detector (requires CGO / gcc)
	go test -race -count=1 ./internal/...

cover: ## Run tests with coverage summary
	go test -cover -count=1 ./internal/...

lint: vet fmt ## Run all lint checks

vet: ## Run go vet
	go vet ./...

fmt: ## Check formatting
	@test -z "$$(gofmt -l cmd internal web)" || (echo "gofmt found unformatted files:" && gofmt -l cmd internal web && exit 1)

check: lint test ## Lint + test (CI shortcut)

clean: ## Remove build artifacts
	rm -f $(BINARY) $(BINARY).exe coverage.out

docker: ## Build Docker image
	docker build -t gatekeeper:$(VERSION) .

run: build ## Build and run
	./$(BINARY)

vuln: ## Run govulncheck
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
