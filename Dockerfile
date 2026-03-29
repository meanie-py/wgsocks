FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /wgsocks ./cmd/wgsocks

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /wgsocks /usr/local/bin/wgsocks

EXPOSE 1080

ENTRYPOINT ["/usr/local/bin/wgsocks"]
