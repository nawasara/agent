FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum* ./
COPY . .

RUN go mod tidy

# VERSION is stamped into the binary so `nawasara-agent version` and heartbeats
# report the release tag. TARGETARCH is set by buildx for multi-arch builds.
ARG VERSION=dev
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X github.com/nawasara/agent/internal/reporter.Version=${VERSION}" \
    -o /out/nawasara-agent \
    ./cmd/agent

# ───────────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S nawasara && \
    adduser -S -G nawasara nawasara && \
    mkdir -p /etc/nawasara-agent /var/lib/nawasara-agent && \
    chown -R nawasara:nawasara /etc/nawasara-agent /var/lib/nawasara-agent

COPY --from=builder /out/nawasara-agent /usr/local/bin/nawasara-agent

# Persisted identity + buffer DB live here — declare as volumes so compose can
# mount named volumes over them without losing ownership.
VOLUME ["/etc/nawasara-agent", "/var/lib/nawasara-agent"]

ENTRYPOINT ["/usr/local/bin/nawasara-agent"]
CMD ["run"]
