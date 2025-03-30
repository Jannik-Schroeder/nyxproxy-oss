package proxy

import "os"

// Config holds the proxy configuration
type Config struct {
	ListenAddr string
}

// NewConfig creates a new proxy configuration from environment variables
func NewConfig() *Config {
	// Default listen address if not specified
	listenAddr := os.Getenv("HTTP_PROXY_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	return &Config{
		ListenAddr: listenAddr,
	}
}
