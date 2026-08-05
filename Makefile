# Loom build helpers
#
#   make build          # native binary → bin/loom
#   make release        # all platforms → dist/
#   make test
#   make clean

# Product version: VERSION file is canonical (e.g. 0.1.0). Override with VERSION=…
VERSION ?= $(shell tr -d '[:space:]' < VERSION 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build release test vet clean docker install

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/loom ./cmd/loom

release:
	@chmod +x scripts/build-release.sh
	VERSION=$(VERSION) ./scripts/build-release.sh

# Install native or dist binary into PREFIX (default $HOME/.local)
PREFIX ?= $(HOME)/.local
install: build
	install -d $(PREFIX)/bin
	install -m 0755 bin/loom $(PREFIX)/bin/loom
	@echo "installed $(PREFIX)/bin/loom"

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t loom:$(VERSION) -t loom:local .

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -rf bin/ dist/
