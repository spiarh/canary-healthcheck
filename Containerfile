FROM docker.io/library/golang:1.21 AS builder

WORKDIR /build
COPY main.go main.go
COPY go.mod go.mod
RUN CGO_ENABLED=0 GOOS=linux go build -o canary-healthcheck

FROM cgr.dev/chainguard/static:latest

WORKDIR /
COPY --from=builder /build/canary-healthcheck /canary-healthcheck

EXPOSE 8080/tcp
EXPOSE 8443/tcp

ENTRYPOINT ["/canary-healthcheck"]
