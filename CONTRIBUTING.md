# Contributing to NyxProxy-OSS

Thank you for your interest in contributing to NyxProxy-OSS! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, inclusive, and constructive in all interactions.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check existing [issues](https://github.com/jannik-schroeder/nyxproxy-oss/issues)
2. Verify you're using the latest version
3. Collect relevant information (logs, config, system details)

Create a bug report with:
- Clear title and description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Go version, etc.)
- Relevant logs and configuration (remove sensitive data!)

### Suggesting Features

Feature requests are welcome! Please:
1. Check if it's already requested
2. Explain the use case
3. Describe the proposed solution
4. Consider backward compatibility

### Pull Requests

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR-USERNAME/nyxproxy-oss.git
   cd nyxproxy-oss
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Write clean, readable code
   - Follow existing code style
   - Add tests if applicable
   - Update documentation

4. **Test Your Changes**
   ```bash
   go build ./cmd/proxy
   go build ./cmd/setup
   ./nyxproxy-setup
   ./nyxproxy
   ```

5. **Commit**
   ```bash
   git add .
   git commit -m "Add feature: description"
   ```

   Good commit messages:
   - Use present tense ("Add feature" not "Added feature")
   - Be descriptive but concise
   - Reference issues if applicable (#123)

6. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   
   Then create a Pull Request on GitHub.

## Development Setup

### Prerequisites

- Go 1.21 or later
- Linux environment (or WSL on Windows)
- Git

### Build and Run

```bash
# Clone the repository
git clone https://github.com/jannik-schroeder/nyxproxy-oss.git
cd nyxproxy-oss

# Install dependencies
go mod download

# Build
go build -o nyxproxy ./cmd/proxy
go build -o nyxproxy-setup ./cmd/setup

# Run
./nyxproxy-setup
./nyxproxy
```

### Project Structure

```
nyxproxy-oss/
├── cmd/
│   ├── proxy/          # Main proxy application
│   └── setup/          # Interactive setup wizard
├── internal/
│   └── config/         # Configuration management
├── pkg/
│   ├── https/          # HTTPS proxy implementation
│   ├── socks5/         # SOCKS5 proxy implementation
│   ├── network/        # Network interface utilities
│   ├── metrics/        # Metrics collection
│   └── monitoring/     # HTTP monitoring server
├── docs/               # Documentation
├── .github/
│   └── workflows/      # CI/CD workflows
├── config.example.yaml # Example configuration
├── go.mod              # Go module definition
└── README.md           # Main documentation
```

## Coding Standards

### Go Style

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Use `gofmt` for formatting
- Use meaningful variable names
- Add comments for exported functions
- Keep functions focused and small

### Code Example

```go
// GetOutboundIP returns the preferred outbound IP for the given interface and protocol
func GetOutboundIP(interfaceName string, protocol int) (net.IP, error) {
    if interfaceName == "" {
        return getAutoOutboundIP(protocol)
    }
    
    // Implementation...
}
```

### Error Handling

Always handle errors explicitly:

```go
// Good
if err != nil {
    return fmt.Errorf("failed to create proxy: %w", err)
}

// Bad
_ = someFunction() // ignoring errors
```

### Configuration Changes

When adding configuration options:
1. Update `internal/config/config.go`
2. Update `config.example.yaml`
3. Update `docs/CONFIG.md`
4. Add to setup wizard in `cmd/setup/main.go`

## Testing

Currently, testing is manual. Automated tests are welcome contributions!

### Manual Testing Checklist

- [ ] SOCKS5 proxy works
- [ ] HTTPS proxy works
- [ ] Authentication works
- [ ] Interface selection works
- [ ] IPv4/IPv6 selection works
- [ ] Monitoring endpoints respond
- [ ] Setup wizard completes successfully
- [ ] Config file is generated correctly

## Documentation

When contributing, please update:
- Code comments
- README.md (if user-facing changes)
- docs/CONFIG.md (if config changes)
- docs/MONITORING.md (if monitoring changes)

## Release Process

Maintainers handle releases. The process:

1. Update version in code
2. Create git tag: `git tag v1.0.0`
3. Push tag: `git push origin v1.0.0`
4. GitHub Actions builds and creates release
5. Update release notes on GitHub

## Questions?

Feel free to:
- Open an issue for questions
- Start a discussion
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to NyxProxy-OSS! 🎉
