package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// ProxyConfig holds the configuration for the proxy server
type ProxyConfig struct {
	// Proxy settings
	Proxy ProxySettings `yaml:"proxy"`
	// Network settings
	Network NetworkSettings `yaml:"network"`
	// Monitoring settings
	Monitoring MonitoringSettings `yaml:"monitoring"`
	// Logging settings
	Logging LoggingSettings `yaml:"logging"`
}

// ProxySettings contains proxy-specific configuration
type ProxySettings struct {
	// Type defines the type of proxy (socks5 or https)
	Type string `yaml:"type"`
	// ListenAddress is the address where the proxy will listen
	ListenAddress string `yaml:"listen_address"`
	// ListenPort is the port where the proxy will listen
	ListenPort int `yaml:"listen_port"`
	// Username for proxy authentication
	Username string `yaml:"username"`
	// Password for proxy authentication
	Password string `yaml:"password"`
}

// NetworkSettings contains network-specific configuration
type NetworkSettings struct {
	// InterfaceName is the name of the network interface to use
	InterfaceName string `yaml:"interface_name"`
	// IPv4Enabled enables IPv4 for outgoing connections
	IPv4Enabled bool `yaml:"ipv4_enabled"`
	// IPv6Enabled enables IPv6 for outgoing connections
	IPv6Enabled bool `yaml:"ipv6_enabled"`
	// IPv6Subnet is the IPv6 subnet for rotating IPs (e.g., "2a05:f480:1800:25db::/64")
	IPv6Subnet string `yaml:"ipv6_subnet"`
	// RotateIPv6 enables rotating IPv6 addresses from the subnet
	RotateIPv6 bool `yaml:"rotate_ipv6"`
}

// MonitoringSettings contains monitoring endpoint configuration
type MonitoringSettings struct {
	// Enabled enables the monitoring endpoint
	Enabled bool `yaml:"enabled"`
	// Port is the port for the monitoring endpoint
	Port int `yaml:"port"`
	// AllowRemote allows remote access to monitoring (false = localhost only)
	AllowRemote bool `yaml:"allow_remote"`
}

// LoggingSettings contains logging configuration
type LoggingSettings struct {
	// DebugLevel controls the level of debug output (0=none, 1=basic, 2=detailed)
	DebugLevel int `yaml:"debug_level"`
}

// Legacy fields for backward compatibility
func (c *ProxyConfig) GetListenAddress() string {
	return c.Proxy.ListenAddress
}

func (c *ProxyConfig) GetListenPort() int {
	return c.Proxy.ListenPort
}

func (c *ProxyConfig) GetProxyType() string {
	return c.Proxy.Type
}

func (c *ProxyConfig) GetUsername() string {
	return c.Proxy.Username
}

func (c *ProxyConfig) GetPassword() string {
	return c.Proxy.Password
}

func (c *ProxyConfig) GetDebugLevel() int {
	return c.Logging.DebugLevel
}

func (c *ProxyConfig) GetProxyProtocol() int {
	// Determine protocol based on enabled flags
	if c.Network.IPv6Enabled && !c.Network.IPv4Enabled {
		return 6
	}
	return 4 // Default to IPv4
}

// LoadConfig loads the configuration from YAML file or environment variables
func LoadConfig() (*ProxyConfig, error) {
	cfg := &ProxyConfig{}

	// Try to load from config.yaml first
	if _, err := os.Stat("config.yaml"); err == nil {
		if err := loadFromYAML("config.yaml", cfg); err != nil {
			return nil, fmt.Errorf("failed to load config.yaml: %v", err)
		}
	} else {
		// Fall back to environment variables
		loadFromEnv(cfg)
	}

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadFromYAML loads configuration from a YAML file
func loadFromYAML(filename string, cfg *ProxyConfig) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return err
	}

	return nil
}

// loadFromEnv loads configuration from environment variables (backward compatibility)
func loadFromEnv(cfg *ProxyConfig) {
	cfg.Proxy.ListenAddress = getEnvString("PROXY_LISTEN_ADDRESS", "0.0.0.0")
	cfg.Proxy.ListenPort = getEnvInt("PROXY_LISTEN_PORT", 8080)
	cfg.Proxy.Type = getEnvString("PROXY_TYPE", "https")
	cfg.Proxy.Username = getEnvString("PROXY_USERNAME", "admin")
	cfg.Proxy.Password = getEnvString("PROXY_PASSWORD", "")

	protocol := getEnvInt("PROXY_PROTOCOL", 4)
	cfg.Network.InterfaceName = getEnvString("NETWORK_INTERFACE", "")
	cfg.Network.IPv4Enabled = protocol == 4
	cfg.Network.IPv6Enabled = protocol == 6

	cfg.Monitoring.Enabled = getEnvBool("MONITORING_ENABLED", true)
	cfg.Monitoring.Port = getEnvInt("MONITORING_PORT", 9090)
	cfg.Monitoring.AllowRemote = getEnvBool("MONITORING_ALLOW_REMOTE", false)

	cfg.Logging.DebugLevel = getEnvInt("DEBUG_LEVEL", 0)
}

// validateConfig validates the configuration
func validateConfig(cfg *ProxyConfig) error {
	// Validate proxy type
	if cfg.Proxy.Type != "https" && cfg.Proxy.Type != "socks5" {
		return fmt.Errorf("invalid proxy type: %s (must be 'https' or 'socks5')", cfg.Proxy.Type)
	}

	// Validate authentication credentials
	if cfg.Proxy.Username == "" {
		return fmt.Errorf("PROXY_USERNAME or proxy.username must be set")
	}
	if cfg.Proxy.Password == "" {
		return fmt.Errorf("PROXY_PASSWORD or proxy.password must be set")
	}

	// Validate network settings
	if !cfg.Network.IPv4Enabled && !cfg.Network.IPv6Enabled {
		return fmt.Errorf("at least one of IPv4 or IPv6 must be enabled")
	}

	// Validate ports
	if cfg.Proxy.ListenPort < 1 || cfg.Proxy.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d (must be 1-65535)", cfg.Proxy.ListenPort)
	}
	if cfg.Monitoring.Enabled && (cfg.Monitoring.Port < 1 || cfg.Monitoring.Port > 65535) {
		return fmt.Errorf("invalid monitoring port: %d (must be 1-65535)", cfg.Monitoring.Port)
	}

	return nil
}

// Helper functions for environment variables
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

func getEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
