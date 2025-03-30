# NyxProxy Core

A lightweight, high-performance HTTP/HTTPS reverse proxy written in Go.

## Features

- Simple and efficient HTTP/HTTPS forward proxy
- Dynamic request forwarding based on client requests
- Graceful shutdown handling
- Configurable through environment variables
- Minimal dependencies (only standard library)

## Configuration

The proxy is configured through environment variables:

- `HTTP_PROXY_LISTEN_ADDR`: (Optional) The address to listen on (default: `:8080`)

## Building

```bash
go build -o nyxproxy ./cmd/proxy
```

## Running

Run the proxy:
```bash
./nyxproxy
```

Or using `go run`:
```bash
go run ./cmd/proxy
```

## Testing

You can test the proxy using curl. For example, to access https://example.com through the proxy:

```bash
curl -v -x http://localhost:8080 https://example.com
```

Or any other URL:
```bash
curl -v -x http://localhost:8080 https://api.github.com
```

## Architecture

The proxy is designed with a clean architecture:

- `cmd/proxy/`: Contains the main application entry point
- `pkg/proxy/`: Contains the core proxy implementation
  - `config.go`: Configuration handling
  - `proxy.go`: Proxy server implementation

## Best Practices

- Graceful shutdown handling
- Proper error handling and logging
- Clean separation of concerns
- Environment-based configuration
- Reasonable timeouts for all operations
- Custom headers for tracking and debugging

## License

MIT License 