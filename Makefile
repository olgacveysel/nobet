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

# Local dry run of a release: binaries, archives and deb/rpm/apk packages in
# dist/ (needs goreleaser and a git repository). Signatures and SBOMs come
# with real releases.
snapshot:
	goreleaser release --snapshot --clean --skip=sign,sbom

clean:
	rm -rf nobet nobet-web dist
