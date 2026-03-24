.PHONY: build test lint clean install tools

BINARY := beacon
BUILD_DIR := ./dist
MAIN := ./cmd/beacon

build:
	go build -o $(BUILD_DIR)/$(BINARY) $(MAIN)

install:
	go install $(MAIN)

test:
	go test ./... -race -timeout 60s

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)

tools:
	./scripts/install-tools.sh

# Quick smoke test — dry run against example.com
smoke:
	$(BUILD_DIR)/$(BINARY) scan --domain example.com

.DEFAULT_GOAL := build
