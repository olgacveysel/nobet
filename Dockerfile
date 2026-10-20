# syntax=docker/dockerfile:1
#
# Two images from one build (see compose.yaml):
#   scanner  runs `nobet scan` on a schedule; the only one that gets the SSH key
#   web      the read-only nobet-web dashboard, on a distroless base with no shell
# Both run as the unprivileged user 65532 and keep scans in /var/lib/nobet.

# The build stage runs on the builder's own platform and cross-compiles, so
# multi-arch images (release workflow) need no emulation. The final stages
# have no RUN steps for the same reason.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/nobet ./cmd/nobet \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/nobet-web ./cmd/nobet-web \
 && mkdir -p /out/data/scans

FROM alpine:3.22 AS scanner
COPY --from=build /out/nobet /usr/local/bin/nobet
COPY --chmod=755 contrib/docker/nobet-scan-loop /usr/local/bin/nobet-scan-loop
COPY --from=build --chown=65532:65532 /out/data /var/lib/nobet
ENV NOBET_DATA_DIR=/var/lib/nobet HOME=/var/lib/nobet
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/nobet-scan-loop"]

FROM gcr.io/distroless/static-debian12:nonroot AS web
COPY --from=build /out/nobet-web /usr/local/bin/nobet-web
COPY --from=build --chown=65532:65532 /out/data /var/lib/nobet
ENV NOBET_DATA_DIR=/var/lib/nobet
USER 65532:65532
EXPOSE 8080
# Inside the container it has to listen on all interfaces; compose.yaml
# publishes the port on the host's localhost only.
ENTRYPOINT ["/usr/local/bin/nobet-web", "-listen", ":8080"]
