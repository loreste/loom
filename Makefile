# Loom build helpers
#
#   make build          # native binary → bin/loom
#   make release        # all platforms → dist/
#   make test
#   make clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build release test vet clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/loom ./cmd/loom

release:
	@chmod +x scripts/build-release.sh
	VERSION=$(VERSION) ./scripts/build-release.sh

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -rf bin/ dist/
