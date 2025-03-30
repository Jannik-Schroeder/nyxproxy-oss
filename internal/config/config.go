package config

import (
	"os"
	"strconv"
)

// ProxyConfig holds the configuration for the proxy server
type ProxyConfig struct {
	// ListenAddress is the address where the proxy will listen for incoming connections
	ListenAddress string
	// ListenPort is the port where the proxy will listen
	ListenPort int
	// ProxyProtocol defines which protocol to use for outgoing connections (4 or 6)
	ProxyProtocol int
	// ProxyType defines the type of proxy (socks5 or https)
	ProxyType string
	// UpstreamURL is the URL of the upstream proxy (if any)
	UpstreamURL string
	// EnableLogging enables detailed logging
	EnableLogging bool
}

// LoadConfig loads the configuration from environment variables
func LoadConfig() (*ProxyConfig, error) {
	config := &ProxyConfig{
		ListenAddress: getEnvOrDefault("PROXY_LISTEN_ADDRESS", "0.0.0.0"),
		ListenPort:    getEnvAsIntOrDefault("PROXY_LISTEN_PORT", 8080),
		ProxyProtocol: getEnvAsIntOrDefault("PROXY_PROTOCOL", 4), // 4 for IPv4, 6 for IPv6
		ProxyType:     getEnvOrDefault("PROXY_TYPE", "socks5"),   // socks5 or https
		UpstreamURL:   getEnvOrDefault("PROXY_UPSTREAM_URL", ""),
		EnableLogging: getEnvAsBoolOrDefault("PROXY_ENABLE_LOGGING", true),
	}

	return config, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBoolOrDefault(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
