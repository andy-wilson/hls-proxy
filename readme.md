# HLS Proxy

A MITM proxy tool, initially built for using with Apple's mediastreamvalidator while doing some playback debugging and I needed to add auth headers to all requests, which aren't supported in mediastreamvalidator. But I've since found it useful for other things too. Hopefully this will be useful for someone else too. 

## Overview

HLS Proxy provides a reasonably flexible solution for manipulating HTTP traffic that require authentication or other custom headers. It serves as a reverse proxy that adds necessary headers to requests, performs URL rewrites, and even some basic content body rewrites. Specifically built for use in debugging HTTP Live Streams.

## Features

- **Authentication Headers**: Add custom headers to all requests, such as CDN authentication tokens
- **URL Rewriting**: Transform request paths using regular expressions
- **Content Transformation**: Modify response content like HLS manifests using regex patterns
- **TLS Support**: Secure connections for both proxy server and target origin
- **Logging**: Detailed request and response logging for debugging
- **Flexible Configuration**: Configure via JSON config file or command-line arguments

## Installation

```bash
# Clone the repository
git clone https://github.com/andy-wilson/hls-proxy
cd hls-proxy-tool

# Build the binary
go build -o hls-proxy
```

## Basic Usage

```bash
# Run with a config file
./hls-proxy -config config.json

# Run with command-line arguments
./hls-proxy -target https://live-stream.example.com -listen :8080 -header "X-CDN-Auth:test"
```

## Using with mediastreamvalidator

1. Start the proxy:
   ```bash
   ./hls-proxy -config config.json
   ```

2. Use mediastreamvalidator with the proxy:
   ```bash
   mediastreamvalidator http://localhost:8080/path/to/master.m3u8
   ```

## Configuration Options

The proxy can be configured via a JSON configuration file or command-line arguments.

### Config File Format

```json
{
  "listen_address": ":8080",
  "target_host": "https://example.com",
  "headers": {
    "X-CDN-Auth": "test",
    "User-Agent": "HLSProxy/1.0"
  },
  "rewrite_rules": [
    {
      "pattern": "^/local/(.*\\.m3u8)$",
      "replacement": "/streams/$1"
    }
  ],
  "content_rewrites": [
    {
      "pattern": "https://cdn\\.example\\.com/([^\"\\s]+)",
      "replacement": "http://localhost:8080/local/$1",
      "content_types": ["application/vnd.apple.mpegurl"],
      "global": true
    }
  ],
  "log_requests": true,
  "log_responses": true,
  "timeout": 60,
  "tls": {
    "enabled": false,
    "cert_file": "server.crt",
    "key_file": "server.key",
    "skip_verify": false,
    "client_cert_file": "",
    "client_key_file": "",
    "root_ca_file": ""
  }
}
```

### Configuration Options Reference

| Option | Description |
|--------|-------------|
| `listen_address` | Address and port the proxy listens on (e.g., `:8080` all interfaces, `10.203.51.101:8080` specific ip/interface) |
| `target_host` | Target host to proxy requests to (e.g., `https://my-livestream-origin.example.com`) |
| `headers` | Map of headers to add to all proxied requests |
| `rewrite_rules` | List of URL path rewrite rules (regex pattern and replacement) |
| `content_rewrites` | List of response content rewrite rules (see below) |
| `log_requests` | Boolean flag to enable request logging |
| `log_responses` | Boolean flag to enable response logging |
| `timeout` | Request timeout in seconds |
| `tls` | TLS configuration settings (see below) |

### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `-config <file>` | Path to configuration file |
| `-target <url>` | Target host URL (overrides config file) |
| `-listen <addr>` | Address to listen on (overrides config file) |
| `-header <name:value>` | Add header to requests (can be specified multiple times) |
| `-log-requests` | Enable request logging |
| `-log <file>` | Log to file instead of standard output |
| `-tls` | Enable TLS for the proxy server |
| `-tls-cert <file>` | Path to TLS certificate file |
| `-tls-key <file>` | Path to TLS private key file |
| `-skip-tls-verify` | Skip verification of target origin certificate |
| `-client-cert <file>` | Client certificate for mutual TLS with target |
| `-client-key <file>` | Client key for mutual TLS with target |
| `-root-ca <file>` | Custom CA roots file for target verification |
| `-content-rewrite <pattern:replacement[:content-type]>` | Add content rewrite rule |
| `-global-rewrite` | Apply content rewrite globally (all occurrences) |

## Feature Details

### URL Rewrite Rules

URL path rewriting allows you to transform the request path using regular expressions. Each rule consists of a pattern and a replacement.

```json
"rewrite_rules": [
  {
    "pattern": "^/local/(.*\\.m3u8)$",
    "replacement": "/streams/$1"
  }
]
```

This rule will rewrite a request path like `/local/stream.m3u8` to `/streams/stream.m3u8`.

### Content Rewrite Rules

The proxy can modify response content using regular expressions. This is particularly useful for HLS manifests where you might need to rewrite URLs or adjust parameters.

Each content rewrite rule consists of:

- **Pattern**: A regular expression pattern to match in the response content
- **Replacement**: The replacement string (can include capture groups from the pattern)
- **Content Types** (optional): List of content types to apply the rule to
- **Global**: Whether to replace all occurrences (true) or just the first one (false)

Example configuration:

```json
"content_rewrites": [
  {
    "pattern": "https://cdn\\.example\\.com/([^\"\\s]+)",
    "replacement": "http://localhost:8080/local/$1",
    "content_types": ["application/vnd.apple.mpegurl", "application/x-mpegurl"],
    "global": true
  },
  {
    "pattern": "#EXT-X-MEDIA-SEQUENCE:(\\d+)",
    "replacement": "#EXT-X-MEDIA-SEQUENCE:1",
    "content_types": ["application/vnd.apple.mpegurl"],
    "global": false
  }
]
```

This example:
1. Rewrites all URLs from `https://cdn.example.com/path/file.ts` to `http://localhost:8080/local/path/file.ts` in HLS manifests
2. Changes the media sequence number to 1 in HLS manifests

Command-line example:

```bash
./hls-proxy -content-rewrite "https://cdn\.example\.com/([^\"\\s]+):http://localhost:8080/local/\$1:application/vnd.apple.mpegurl" -global-rewrite
```

### TLS Support

The proxy supports TLS for both incoming connections (proxy server) and outgoing connections (to target origin).

#### Server TLS Configuration

To enable TLS for the proxy server:

```json
"tls": {
  "enabled": true,
  "cert_file": "server.crt",
  "key_file": "server.key"
}
```

Command-line example:
```bash
./hls-proxy -tls -tls-cert server.crt -tls-key server.key
```

#### Client TLS Configuration for Target Origin

When connecting to an HTTPS target origin, you can:

1. **Skip Certificate Verification** (not recommended for production):
   ```json
   "tls": {
     "skip_verify": true
   }
   ```

2. **Use Custom CA Roots** for target verification:
   ```json
   "tls": {
     "root_ca_file": "custom-ca.pem"
   }
   ```

3. **Use Client Certificates** for mutual TLS authentication with the target:
   ```json
   "tls": {
     "client_cert_file": "client.crt",
     "client_key_file": "client.key"
   }
   ```

#### Self-Signed Certificate Generation

For testing purposes, you can generate self-signed certificates using OpenSSL:

```bash
# Generate a private key
openssl genrsa -out server.key 2048

# Generate a self-signed certificate (valid for 365 days)
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=localhost"
```

## Usage Examples

### Basic Usage with Authentication Header

```bash
./hls-proxy -target https://stream.example.com -listen :8080 -header "X-CDN-Auth:test"
```

### Using URL Rewrite Rules

```bash
./hls-proxy -target https://stream.example.com -listen :8080 -header "X-CDN-Auth:test" -config config.json
```

Where config.json contains URL path rewrite rules.

### Using Content Rewrite Rules for HLS Manifests

```bash
./hls-proxy -target https://stream.example.com -header "X-CDN-Auth:test" \
  -content-rewrite "https://cdn\.example\.com/([^\"\\s]+):http://localhost:8080/local/\$1:application/vnd.apple.mpegurl" \
  -global-rewrite
```

This example rewrites all URLs in HLS manifests from the CDN domain to the local proxy.

### Using with Apple's mediastreamvalidator

1. Start the proxy with both URL and content rewrites:
   ```bash
   ./hls-proxy -config config.json
   ```

2. Use mediastreamvalidator with the proxy:
   ```bash
   mediastreamvalidator http://localhost:8080/path/to/master.m3u8
   ```

### Using with TLS

```bash
./hls-proxy -target https://secure.example.com -tls -tls-cert server.crt -tls-key server.key \
  -header "X-CDN-Auth:test" -config config.json
```

## Troubleshooting

### Common Issues

1. **Connection refused**: Make sure the target host is accessible from the proxy server.
2. **Invalid URL**: Ensure the target host URL is valid and includes the protocol (http:// or https://).
3. **Regex errors**: If you see errors about invalid patterns, check your rewrite rules for valid regular expressions.
4. **TLS certificate issues**: Ensure certificates and keys are in the correct format and accessible.
5. **Content rewrite not working**: Verify that the content type matches and that your regex pattern is correct.

### Debugging

Enable request and response logging to see what's happening:

```bash
./hls-proxy -config config.json -log-requests -log proxy.log
```

Look for:
- Request headers to ensure auth headers are being set
- Response status codes and content types
- Regex pattern matching errors

## Docker Support

The tool includes a Dockerfile for easy containerization:

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o hls-proxy .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/hls-proxy .
RUN mkdir -p /app/config /app/certs
VOLUME ["/app/certs"]
EXPOSE 8080 8443
ENTRYPOINT ["/app/hls-proxy"]
CMD ["-config", "/app/config/config.json"]
```

Build and run the Docker container:

```bash
# Build the image
docker build -t hls-proxy .

# Run the container
docker run -p 8080:8080 -v $(pwd)/config.json:/app/config/config.json hls-proxy

# With TLS certificates
docker run -p 8443:8443 -v $(pwd)/certs:/app/certs -v $(pwd)/config.json:/app/config/config.json hls-proxy -tls -tls-cert /app/certs/server.crt -tls-key /app/certs/server.key
```

## License

MIT License
