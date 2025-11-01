# NyxProxy-OSS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev/)

A flexible, high-performance proxy server supporting both SOCKS5 and HTTPS protocols with advanced network interface control and built-in monitoring.

## ✨ Features

- **Multiple Proxy Protocols**: Choose between SOCKS5 or HTTPS proxy
- **Dual Stack Support**: Full IPv4 and IPv6 support with per-interface configuration
- **Network Interface Selection**: Bind to specific network interfaces or auto-detect
- **Authentication**: Username/password authentication for both proxy types
- **Monitoring**: Built-in HTTP monitoring endpoints for health checks and statistics
- **Easy Setup**: Interactive setup wizard for first-time configuration
- **YAML Configuration**: Simple, readable configuration files
- **Cross-Platform**: Runs on Linux (amd64 and arm64)

## 🚀 Quick Start

### 1. Download

Download the latest release from the [Releases](https://github.com/jannik-schroeder/nyxproxy-oss/releases) page:

```bash
# For amd64
wget https://github.com/jannik-schroeder/nyxproxy-oss/releases/latest/download/nyxproxy-linux-amd64
wget https://github.com/jannik-schroeder/nyxproxy-oss/releases/latest/download/nyxproxy-setup-linux-amd64

# For arm64
wget https://github.com/jannik-schroeder/nyxproxy-oss/releases/latest/download/nyxproxy-linux-arm64
wget https://github.com/jannik-schroeder/nyxproxy-oss/releases/latest/download/nyxproxy-setup-linux-arm64

# Make executable
chmod +x nyxproxy-linux-* nyxproxy-setup-linux-*

# Rename for convenience
mv nyxproxy-linux-amd64 nyxproxy
mv nyxproxy-setup-linux-amd64 nyxproxy-setup
```

### 2. Run Setup Wizard

The setup wizard will guide you through the configuration:

```bash
./nyxproxy-setup
```

This will create a `config.yaml` file with your settings.

### 3. Start the Proxy

```bash
./nyxproxy
```

That's it! Your proxy is now running.

## 📖 Configuration

### Interactive Setup

The easiest way to configure NyxProxy-OSS is using the interactive setup wizard:

```bash
./nyxproxy-setup
```

The wizard will guide you through:
1. Proxy type selection (SOCKS5 or HTTPS)
2. Network interface selection
3. IP protocol configuration (IPv4, IPv6, or both)
4. Authentication credentials
5. Listen address and port
6. Monitoring setup
7. Logging level

### Manual Configuration

Alternatively, create a `config.yaml` file manually:

```yaml
proxy:
  type: socks5                    # or "https"
  listen_address: 0.0.0.0
  listen_port: 1080
  username: admin
  password: your_secure_password

network:
  interface_name: ""              # empty = auto-detect, or specify like "eth0"
  ipv4_enabled: true
  ipv6_enabled: false

monitoring:
  enabled: true
  port: 9090
  allow_remote: false             # true = accessible from other hosts

logging:
  debug_level: 1                  # 0=none, 1=basic, 2=detailed
```

### Environment Variables (Legacy)

For backward compatibility, you can also use environment variables:

```bash
export PROXY_TYPE=socks5
export PROXY_LISTEN_ADDRESS=0.0.0.0
export PROXY_LISTEN_PORT=1080
export PROXY_USERNAME=admin
export PROXY_PASSWORD=your_password
export PROXY_PROTOCOL=4           # 4=IPv4, 6=IPv6
export MONITORING_ENABLED=true
export DEBUG_LEVEL=1

./nyxproxy
```

## 🔍 Monitoring

When monitoring is enabled, NyxProxy-OSS provides HTTP endpoints for health checks and statistics.

### Health Check

```bash
curl http://localhost:9090/health
```

Response:
```json
{
  "status": "ok",
  "uptime": "2h15m30s",
  "version": "1.0.0"
}
```

### Statistics

```bash
curl http://localhost:9090/stats
```

Response:
```json
{
  "uptime": "2h15m30s",
  "active_connections": 42,
  "total_connections": 1337,
  "bytes_sent": 1048576,
  "bytes_received": 2097152,
  "interface": "eth0"
}
```

### Configuration

```bash
curl http://localhost:9090/config
```

Returns the current configuration (excluding sensitive data like passwords).

## 🌐 Network Interface Selection

NyxProxy-OSS allows you to select which network interface to use for outgoing connections.

### Auto-detect (Default)

Leave `interface_name` empty in the config to automatically detect the best interface:

```yaml
network:
  interface_name: ""
```

### Specific Interface

Specify an interface name to bind to that interface:

```yaml
network:
  interface_name: "eth0"
```

To list available interfaces, use the setup wizard or check with:

```bash
ip addr show
```

## 🔐 Authentication

Both SOCKS5 and HTTPS proxies require authentication.

### SOCKS5 Client Configuration

```bash
# Command line tools
curl --proxy socks5://admin:password@localhost:1080 https://example.com

# Firefox
# Settings → Network Settings → Manual proxy configuration
# SOCKS Host: localhost, Port: 1080
# Username: admin, Password: password
```

### HTTPS Client Configuration

```bash
# Command line tools
curl --proxy http://admin:password@localhost:8080 https://example.com

# Browser
# Set HTTP proxy to localhost:8080
# Username: admin, Password: password
```

## 📊 Use Cases

- **Privacy**: Route traffic through specific network interfaces
- **IPv6 Testing**: Test applications with IPv6-only connections
- **Development**: Local proxy for testing applications
- **Monitoring**: Track connection statistics and bandwidth usage
- **Multi-homed Systems**: Control which network interface handles proxy traffic

## 🛠️ Building from Source

### Prerequisites

- Go 1.21 or later
- Linux (Windows and macOS support coming soon)

### Build

```bash
# Clone the repository
git clone https://github.com/jannik-schroeder/nyxproxy-oss.git
cd nyxproxy-oss

# Build the proxy
go build -o nyxproxy ./cmd/proxy

# Build the setup tool
go build -o nyxproxy-setup ./cmd/setup

# Run
./nyxproxy-setup
./nyxproxy
```

## 📝 Command Line Options

### Proxy Server

```bash
./nyxproxy --version    # Show version information
./nyxproxy              # Start with config.yaml or environment variables
```

### Setup Tool

```bash
./nyxproxy-setup        # Run interactive setup wizard
```

## 🔧 Troubleshooting

### Port Already in Use

If the proxy fails to start with "address already in use":

```bash
# Check what's using the port
sudo lsof -i :1080

# Change the port in config.yaml
# OR kill the other process
```

### Permission Denied

If you get permission errors when binding to ports below 1024:

```bash
# Option 1: Use a higher port (recommended)
# Edit config.yaml and set listen_port: 8080

# Option 2: Run with sudo (not recommended)
sudo ./nyxproxy
```

### Interface Not Found

If the specified interface doesn't exist:

```bash
# List available interfaces
ip addr show

# Update config.yaml with a valid interface name
# OR set interface_name: "" for auto-detect
```

### Authentication Not Working

Ensure your client is sending credentials:

```bash
# Test SOCKS5
curl -v --proxy socks5://admin:password@localhost:1080 https://example.com

# Test HTTPS
curl -v --proxy http://admin:password@localhost:8080 https://example.com
```

## 📚 Documentation

- [Configuration Reference](docs/CONFIG.md) - Detailed configuration options
- [Monitoring Guide](docs/MONITORING.md) - Monitoring and metrics integration

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [go-socks5](https://github.com/armon/go-socks5)
- Inspired by the need for flexible proxy solutions

## 📧 Support

- GitHub Issues: [Report a bug](https://github.com/jannik-schroeder/nyxproxy-oss/issues)
- Discussions: [Ask questions](https://github.com/jannik-schroeder/nyxproxy-oss/discussions)

---

Made with ❤️ by [Jannik Schroeder](https://github.com/jannik-schroeder)
