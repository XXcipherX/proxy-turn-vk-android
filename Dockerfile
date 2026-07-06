# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.4

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY server.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
  go build -mod=mod -trimpath -ldflags="-s -w" -o /out/wdtt-server ./server.go

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables procps \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/wdtt-server /usr/local/bin/wdtt-server

VOLUME ["/etc/wdtt"]
EXPOSE 56000/udp 56001/udp

ENTRYPOINT ["/usr/local/bin/wdtt-server"]
