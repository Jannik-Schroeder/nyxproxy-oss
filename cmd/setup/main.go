package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/jannik-schroeder/nyxproxy-oss/pkg/network"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Config represents the configuration structure
type Config struct {
	Proxy struct {
		Type          string `yaml:"type"`
		ListenAddress string `yaml:"listen_address"`
		ListenPort    int    `yaml:"listen_port"`
		Username      string `yaml:"username"`
		Password      string `yaml:"password"`
	} `yaml:"proxy"`
	Network struct {
		InterfaceName string `yaml:"interface_name"`
		IPv4Enabled   bool   `yaml:"ipv4_enabled"`
		IPv6Enabled   bool   `yaml:"ipv6_enabled"`
		IPv6Subnet    string `yaml:"ipv6_subnet"`
		RotateIPv6    bool   `yaml:"rotate_ipv6"`
	} `yaml:"network"`
	Monitoring struct {
		Enabled     bool `yaml:"enabled"`
		Port        int  `yaml:"port"`
		AllowRemote bool `yaml:"allow_remote"`
	} `yaml:"monitoring"`
	Logging struct {
		DebugLevel int `yaml:"debug_level"`
	} `yaml:"logging"`
}

func main() {
	fmt.Println("╔═══════════════════════════════════════════════╗")
	fmt.Println("║       NyxProxy-OSS Interactive Setup         ║")
	fmt.Println("╚═══════════════════════════════════════════════╝")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	cfg := &Config{}

	// 1. Proxy Type
	fmt.Println("1️⃣  Proxy Type Selection")
	fmt.Println("   Choose the type of proxy server:")
	fmt.Println("   [1] SOCKS5 (recommended for most use cases)")
	fmt.Println("   [2] HTTPS")
	proxyType := readChoice(reader, "Select proxy type", []string{"1", "2"}, "1")
	if proxyType == "1" {
		cfg.Proxy.Type = "socks5"
	} else {
		cfg.Proxy.Type = "https"
	}
	fmt.Printf("   ✓ Selected: %s\n\n", cfg.Proxy.Type)

	// 2. Network Interface
	fmt.Println("2️⃣  Network Interface Selection")
	interfaces, err := network.GetUsableInterfaces()
	if err != nil {
		fmt.Printf("   ❌ Error: Failed to get network interfaces: %v\n", err)
		os.Exit(1)
	}

	if len(interfaces) == 0 {
		fmt.Println("   ❌ Error: No usable network interfaces found")
		os.Exit(1)
	}

	fmt.Println("   Available interfaces:")
	for i, iface := range interfaces {
		fmt.Printf("   [%d] %s\n", i+1, iface.Name)
		if len(iface.IPv4Addresses) > 0 {
			fmt.Printf("       IPv4: %s\n", strings.Join(iface.IPv4Addresses, ", "))
		}
		if len(iface.IPv6Addresses) > 0 {
			fmt.Printf("       IPv6: %s\n", strings.Join(iface.IPv6Addresses, ", "))
		}
	}
	fmt.Println("   [0] Auto-detect (recommended)")

	choices := make([]string, len(interfaces)+1)
	choices[0] = "0"
	for i := range interfaces {
		choices[i+1] = strconv.Itoa(i + 1)
	}

	interfaceChoice := readChoice(reader, "Select network interface", choices, "0")
	if interfaceChoice == "0" {
		cfg.Network.InterfaceName = ""
		fmt.Println("   ✓ Auto-detect enabled\n")
	} else {
		idx, _ := strconv.Atoi(interfaceChoice)
		cfg.Network.InterfaceName = interfaces[idx-1].Name
		fmt.Printf("   ✓ Selected: %s\n\n", cfg.Network.InterfaceName)
	}

	// 3. IP Protocol Selection
	fmt.Println("3️⃣  IP Protocol Selection")
	fmt.Println("   [1] IPv4 only")
	fmt.Println("   [2] IPv6 only")
	fmt.Println("   [3] Both IPv4 and IPv6")
	ipChoice := readChoice(reader, "Select IP protocol", []string{"1", "2", "3"}, "1")
	switch ipChoice {
	case "1":
		cfg.Network.IPv4Enabled = true
		cfg.Network.IPv6Enabled = false
		fmt.Println("   ✓ IPv4 only\n")
	case "2":
		cfg.Network.IPv4Enabled = false
		cfg.Network.IPv6Enabled = true
		fmt.Println("   ✓ IPv6 only\n")
	case "3":
		cfg.Network.IPv4Enabled = true
		cfg.Network.IPv6Enabled = true
		fmt.Println("   ✓ Both IPv4 and IPv6\n")
	}

	// 3a. IPv6 Rotation (if IPv6 is enabled)
	if cfg.Network.IPv6Enabled {
		fmt.Println("3a. IPv6 Rotation Setup")
		fmt.Println("   Enable rotating IPv6 addresses from your /64 subnet?")
		fmt.Println("   This provides a different IPv6 for each connection.")
		fmt.Println("   ⚠️  Requires provider support (Vultr, OVH, Hetzner Dedicated, etc.)")
		rotateChoice := readChoice(reader, "Enable IPv6 rotation?", []string{"y", "n"}, "n")
		cfg.Network.RotateIPv6 = rotateChoice == "y"

		if cfg.Network.RotateIPv6 {
			// Try to auto-detect the IPv6 subnet
			detectedSubnet, err := network.DetectIPv6Subnet(cfg.Network.InterfaceName)
			if err == nil && detectedSubnet != "" {
				fmt.Printf("   🔍 Auto-detected subnet: %s\n", detectedSubnet)
				useDetected := readChoice(reader, "Use detected subnet?", []string{"y", "n"}, "y")
				if useDetected == "y" {
					cfg.Network.IPv6Subnet = detectedSubnet
					fmt.Printf("   ✓ Using detected subnet: %s\n\n", cfg.Network.IPv6Subnet)
				} else {
					cfg.Network.IPv6Subnet = readString(reader, "Enter IPv6 subnet manually (e.g., 2a05:f480:1800:25db::/64)", "")
					for cfg.Network.IPv6Subnet == "" {
						fmt.Println("   ❌ IPv6 subnet is required for rotation")
						cfg.Network.IPv6Subnet = readString(reader, "IPv6 subnet", "")
					}
					fmt.Printf("   ✓ IPv6 rotation enabled for %s\n\n", cfg.Network.IPv6Subnet)
				}
			} else {
				fmt.Println("   ⚠️  Could not auto-detect subnet:", err)
				fmt.Println("   Enter your IPv6 /64 subnet (e.g., 2a05:f480:1800:25db::/64)")
				fmt.Println("   You can find this with: ip -6 addr show")
				cfg.Network.IPv6Subnet = readString(reader, "IPv6 subnet", "")
				for cfg.Network.IPv6Subnet == "" {
					fmt.Println("   ❌ IPv6 subnet is required for rotation")
					cfg.Network.IPv6Subnet = readString(reader, "IPv6 subnet", "")
				}
				fmt.Printf("   ✓ IPv6 rotation enabled for %s\n\n", cfg.Network.IPv6Subnet)
			}
		} else {
			fmt.Println("   ✓ Using static IPv6 address\n")
		}
	}

	// 4. Authentication
	fmt.Println("4️⃣  Authentication Setup")
	cfg.Proxy.Username = readString(reader, "Enter username", "admin")
	fmt.Printf("   ✓ Username: %s\n", cfg.Proxy.Username)

	cfg.Proxy.Password = readPassword("Enter password")
	confirmPassword := readPassword("Confirm password")
	for cfg.Proxy.Password != confirmPassword {
		fmt.Println("   ❌ Passwords do not match. Please try again.")
		cfg.Proxy.Password = readPassword("Enter password")
		confirmPassword = readPassword("Confirm password")
	}
	fmt.Println("   ✓ Password set\n")

	// 5. Listen Address & Port
	fmt.Println("5️⃣  Listen Configuration")
	cfg.Proxy.ListenAddress = readString(reader, "Listen address (0.0.0.0 for all interfaces)", "0.0.0.0")
	defaultPort := "1080"
	if cfg.Proxy.Type == "https" {
		defaultPort = "8080"
	}
	portStr := readString(reader, fmt.Sprintf("Listen port (default: %s)", defaultPort), defaultPort)
	cfg.Proxy.ListenPort, _ = strconv.Atoi(portStr)
	fmt.Printf("   ✓ Listen on %s:%d\n\n", cfg.Proxy.ListenAddress, cfg.Proxy.ListenPort)

	// 6. Monitoring
	fmt.Println("6️⃣  Monitoring Setup")
	monitoringChoice := readChoice(reader, "Enable monitoring endpoint?", []string{"y", "n"}, "y")
	cfg.Monitoring.Enabled = monitoringChoice == "y"
	if cfg.Monitoring.Enabled {
		portStr := readString(reader, "Monitoring port", "9090")
		cfg.Monitoring.Port, _ = strconv.Atoi(portStr)
		remoteChoice := readChoice(reader, "Allow remote access to monitoring?", []string{"y", "n"}, "n")
		cfg.Monitoring.AllowRemote = remoteChoice == "y"
		fmt.Printf("   ✓ Monitoring enabled on port %d\n\n", cfg.Monitoring.Port)
	} else {
		fmt.Println("   ✓ Monitoring disabled\n")
	}

	// 7. Logging
	fmt.Println("7️⃣  Logging Configuration")
	fmt.Println("   [0] No debug output")
	fmt.Println("   [1] Basic logging")
	fmt.Println("   [2] Detailed logging")
	debugChoice := readChoice(reader, "Select debug level", []string{"0", "1", "2"}, "1")
	cfg.Logging.DebugLevel, _ = strconv.Atoi(debugChoice)
	fmt.Printf("   ✓ Debug level: %d\n\n", cfg.Logging.DebugLevel)

	// 8. Save Configuration
	fmt.Println("8️⃣  Save Configuration")
	filename := readString(reader, "Config filename", "config.yaml")

	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("   ❌ Error: Failed to marshal config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		fmt.Printf("   ❌ Error: Failed to write config file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   ✓ Configuration saved to %s\n\n", filename)

	// Summary
	fmt.Println("╔═══════════════════════════════════════════════╗")
	fmt.Println("║           Configuration Summary              ║")
	fmt.Println("╚═══════════════════════════════════════════════╝")
	fmt.Printf("Proxy Type:      %s\n", cfg.Proxy.Type)
	fmt.Printf("Listen Address:  %s:%d\n", cfg.Proxy.ListenAddress, cfg.Proxy.ListenPort)
	fmt.Printf("Username:        %s\n", cfg.Proxy.Username)
	if cfg.Network.InterfaceName != "" {
		fmt.Printf("Interface:       %s\n", cfg.Network.InterfaceName)
	} else {
		fmt.Println("Interface:       Auto-detect")
	}
	fmt.Printf("IPv4:            %v\n", cfg.Network.IPv4Enabled)
	fmt.Printf("IPv6:            %v\n", cfg.Network.IPv6Enabled)
	if cfg.Network.RotateIPv6 {
		fmt.Printf("IPv6 Rotation:   Enabled (%s)\n", cfg.Network.IPv6Subnet)
	}
	fmt.Printf("Monitoring:      %v\n", cfg.Monitoring.Enabled)
	fmt.Printf("Debug Level:     %d\n", cfg.Logging.DebugLevel)
	fmt.Println()

	if cfg.Network.RotateIPv6 {
		fmt.Println("⚠️  Important: IPv6 Rotation Enabled")
		fmt.Println("   Make sure your firewall allows port", cfg.Proxy.ListenPort)
		fmt.Println("   Example for ufw: sudo ufw allow", cfg.Proxy.ListenPort)
		fmt.Println()
	}

	fmt.Println("✓ Setup complete! You can now start the proxy with:")
	fmt.Println("  ./nyxproxy")
	fmt.Println()
}

func readString(reader *bufio.Reader, prompt, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("   %s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Printf("   %s: ", prompt)
	}

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" && defaultValue != "" {
		return defaultValue
	}
	return input
}

func readChoice(reader *bufio.Reader, prompt string, choices []string, defaultChoice string) string {
	for {
		input := readString(reader, prompt, defaultChoice)
		for _, choice := range choices {
			if input == choice {
				return input
			}
		}
		fmt.Printf("   ❌ Invalid choice. Please select one of: %s\n", strings.Join(choices, ", "))
	}
}

func readPassword(prompt string) string {
	fmt.Printf("   %s: ", prompt)
	password, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(password)
}
