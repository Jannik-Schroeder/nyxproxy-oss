# NyxProxy Core

A flexible proxy server that supports both SOCKS5 and HTTPS protocols, capable of accepting both IPv4 and IPv6 connections while forwarding through a specific IP protocol version.

## Features

- Supports both SOCKS5 and HTTPS proxy protocols
- Accepts both IPv4 and IPv6 incoming connections
- Can force outgoing connections to use either IPv4 or IPv6
- Configurable through environment variables
- Graceful shutdown handling

## Configuration

The proxy is configured through environment variables:

```env
PROXY_LISTEN_ADDRESS=0.0.0.0     # Address to listen on (default: 0.0.0.0)
PROXY_LISTEN_PORT=8080           # Port to listen on (default: 8080)
PROXY_PROTOCOL=4                 # Outgoing protocol version (4 or 6, default: 4)
PROXY_TYPE=socks5               # Proxy type (socks5 or https, default: socks5)
PROXY_ENABLE_LOGGING=true       # Enable detailed logging (default: true)
```

## Project Structure

```
nyxproxy-core/
├── cmd/
│   └── proxy/                  # Main application entry point
├── internal/
│   ├── config/                # Configuration management
│   └── logger/                # Logging utilities
├── pkg/
│   ├── socks5/               # SOCKS5 proxy implementation
│   └── https/                # HTTPS proxy implementation
└── README.md
```

## Building and Running

1. Build the project:
```bash
go build -o nyxproxy ./cmd/proxy
```

2. Run the proxy:
```bash
# Run as SOCKS5 proxy with IPv4 outgoing connections
PROXY_TYPE=socks5 PROXY_PROTOCOL=4 ./nyxproxy

# Run as HTTPS proxy with IPv6 outgoing connections
PROXY_TYPE=https PROXY_PROTOCOL=6 ./nyxproxy
```

## Examples

1. Run a SOCKS5 proxy that accepts both IPv4/IPv6 but only forwards through IPv4:
```bash
PROXY_TYPE=socks5 PROXY_PROTOCOL=4 PROXY_LISTEN_PORT=1080 ./nyxproxy
```

2. Run an HTTPS proxy that accepts both IPv4/IPv6 but only forwards through IPv6:
```bash
PROXY_TYPE=https PROXY_PROTOCOL=6 PROXY_LISTEN_PORT=8080 ./nyxproxy
```