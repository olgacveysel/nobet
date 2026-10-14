VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet snapshot clean

# Two binaries: the nobet CLI and the optional nobet-web dashboard.
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o nobet ./cmd/nobet
	go build -trimpath -ldflags "$(LDFLAGS)" -o nobet-web ./cmd/nobet-web

test:
	go test ./...

vet:
	go vet ./...

# Local dry run of a release (needs goreleaser and a git repository).
snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf nobet nobet-web dist
