package config

import (
	"fmt"
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
	// EnableLogging enables detailed logging
	EnableLogging bool
	// DebugLevel controls the level of debug output
	DebugLevel int // 0 = none, 1 = basic, 2 = detailed
	// Password for proxy authentication
	Password string
}

// LoadConfig loads the configuration from environment variables
func LoadConfig() (*ProxyConfig, error) {
	cfg := &ProxyConfig{
		ListenAddress: getEnvString("PROXY_LISTEN_ADDRESS", "0.0.0.0"),
		ListenPort:    getEnvInt("PROXY_LISTEN_PORT", 8080),
		ProxyType:     getEnvString("PROXY_TYPE", "https"),
		ProxyProtocol: getEnvInt("PROXY_PROTOCOL", 4),
		DebugLevel:    getEnvInt("DEBUG_LEVEL", 0),
		EnableLogging: getEnvAsBoolOrDefault("PROXY_ENABLE_LOGGING", true),
		Password:      getEnvString("PROXY_PASSWORD", ""),
	}

	// Validate proxy type
	if cfg.ProxyType != "https" && cfg.ProxyType != "socks5" {
		return nil, fmt.Errorf("invalid proxy type: %s (must be 'https' or 'socks5')", cfg.ProxyType)
	}

	// Validate protocol version
	if cfg.ProxyProtocol != 4 && cfg.ProxyProtocol != 6 {
		return nil, fmt.Errorf("invalid protocol version: %d (must be 4 or 6)", cfg.ProxyProtocol)
	}

	// Validate password
	if cfg.Password == "" {
		return nil, fmt.Errorf("PROXY_PASSWORD must be set")
	}

	return cfg, nil
}

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
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
