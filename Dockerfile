FROM golang:1.24-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/judsenb/gatekeeper"
LABEL org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /gatekeeper ./cmd/gatekeeper

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 gatekeeper
WORKDIR /app
COPY --from=builder /gatekeeper .
COPY configs/gatekeeper.yaml configs/gatekeeper.yaml
RUN mkdir -p recordings configs/tls && chown -R gatekeeper:gatekeeper /app
USER gatekeeper
EXPOSE 8443 8080
VOLUME ["/app/recordings", "/app/configs"]
ENTRYPOINT ["./gatekeeper"]
CMD ["-config", "configs/gatekeeper.yaml"]
