GO ?= go
VERSION_FILE ?= VERSION
DIST_DIR ?= dist

.PHONY: test test-race fuzz vet build release sdk

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

fuzz:
	$(GO) test -fuzz=FuzzExecute -fuzztime=$${FUZZ_TIME:-15s} ./runtime/

vet:
	$(GO) vet ./...

build:
	$(GO) build ./...

release:
	./scripts/build-release.sh

sdk:
	@echo "SDK validation runs in CI; use the language-specific package instructions under sdk/"
