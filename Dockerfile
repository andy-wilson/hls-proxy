FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies if needed
RUN if [ -f go.sum ]; then go mod download; else go mod tidy; fi

# Copy source code
COPY *.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o hls-proxy .

# Create a minimal runtime image
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/hls-proxy .

# Create a directory for config files
RUN mkdir -p /app/config
RUN mkdir -p /app/certs

# Copy the sample config
COPY config.json /app/config/

# Mount points for certificates
VOLUME ["/app/certs"]

EXPOSE 8080
EXPOSE 8443

# Set the entrypoint
ENTRYPOINT ["/app/hls-proxy"]

# Default command runs with the sample config
CMD ["-config", "/app/config/config.json"]
