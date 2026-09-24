BINARY_NAME=sshm
VERSION ?= 1.0.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS = -ldflags "-X github.com/kulangaraalwinjoy/sshm/internal/cli.Version=$(VERSION) -X github.com/kulangaraalwinjoy/sshm/internal/cli.Commit=$(COMMIT) -X github.com/kulangaraalwinjoy/sshm/internal/cli.BuildDate=$(DATE)"

.PHONY: all build test race lint clean cross-compile

all: lint test build

build:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/sshm

test:
	go test -v ./...

race:
	go test -v -race ./...

lint:
	go vet ./...

clean:
	rm -rf bin dist coverage.out coverage.html

cross-compile:
	@mkdir -p dist
	@echo "Building for Windows (amd64, arm64)..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/sshm
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-arm64.exe ./cmd/sshm
	@echo "Building for Linux (amd64, arm64)..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/sshm
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/sshm
	@echo "Building for macOS (amd64, arm64)..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/sshm
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/sshm
	@echo "Cross-compilation complete! Binaries located in dist/"
