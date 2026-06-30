FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum* ./
COPY . .

RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/nawasara-agent \
    ./cmd/agent

# ───────────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S nawasara && \
    adduser -S -G nawasara nawasara

COPY --from=builder /out/nawasara-agent /usr/local/bin/nawasara-agent

ENTRYPOINT ["/usr/local/bin/nawasara-agent"]
CMD ["run"]
