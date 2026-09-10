.PHONY: build test test-coverage lint fmt run demo clean deps help

GO := $(shell which go 2>/dev/null || echo "/home/mauropm/go/go/bin/go")

build:
	CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" $(GO) build -o quetzalog ./cmd/siem/

test:
	CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" $(GO) test -p 1 -timeout 20m ./...

test-coverage:
	CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" $(GO) test -p 1 -timeout 20m -cover ./...

lint:
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, skipping"

fmt:
	gofmt -s -w .

run: build
	./quetzalog serve

demo: build
	./quetzalog demo

clean:
	rm -rf bin/ data/ quetzalog

deps:
	$(GO) mod tidy

help:
	@echo "Available targets:"
	@echo "  build            Build the binary with FTS5 support"
	@echo "  test             Run tests"
	@echo "  test-coverage    Run tests with coverage"
	@echo "  lint             Run go vet and golangci-lint"
	@echo "  fmt              Format code with gofmt"
	@echo "  run              Build and run the server"
	@echo "  demo             Build and run with demo data"
	@echo "  clean            Remove bin/ and data/"
	@echo "  deps             Run go mod tidy"
	@echo "  help             Show this help message"
