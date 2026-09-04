# Build stage
FROM golang:1.23-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1"
ARG CGO_LDFLAGS="-lm"
RUN go build -o /siem ./cmd/siem/

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /siem /siem
RUN mkdir -p /data /logs
VOLUME ["/data"]
EXPOSE 8080 8088 5514 4317 4318
CMD ["/siem", "serve", "--config", "/app/config.yaml"]
