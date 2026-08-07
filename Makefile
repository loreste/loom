GO ?= go
VERSION_FILE ?= VERSION
DIST_DIR ?= dist

.PHONY: test test-race fuzz vet build release checksums sdk

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
	sh ./scripts/generate-checksums.sh "$${DIST_DIR:-dist}"

checksums:
	sh ./scripts/generate-checksums.sh "$${DIST_DIR:-dist}"

sdk:
	@echo "SDK validation runs in CI; use the language-specific package instructions under sdk/"
