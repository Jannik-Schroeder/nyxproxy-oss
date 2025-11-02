package network

import (
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// IPv6Manager manages dynamic IPv6 address generation
type IPv6Manager struct {
	mu            sync.Mutex
	interfaceName string
	subnet        *net.IPNet
}

// NewIPv6Manager creates a new IPv6 manager
func NewIPv6Manager(interfaceName string, subnet string) (*IPv6Manager, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %v", err)
	}

	// Auto-detect interface if not provided
	if interfaceName == "" {
		fmt.Printf("⚠️  WARNING: No interface specified, attempting auto-detection...\n")
		iface, err := getDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to auto-detect network interface: %v\n"+
				"Please specify interface_name in config.yaml or set NETWORK_INTERFACE environment variable", err)
		}
		interfaceName = iface.Name
		fmt.Printf("✓ Auto-detected interface: %s\n", interfaceName)
		fmt.Printf("⚠️  For production use, please set 'interface_name: \"%s\"' in config.yaml\n\n", interfaceName)
	}

	// Verify the interface exists and is up
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("network interface '%s' not found: %v\n"+
			"Run 'ip link show' to see available interfaces", interfaceName, err)
	}

	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("network interface '%s' is down\n"+
			"Run 'ip link set %s up' to enable it", interfaceName, interfaceName)
	}

	mgr := &IPv6Manager{
		interfaceName: interfaceName,
		subnet:        ipnet,
	}

	// Check if ndppd is running (warning only, not fatal)
	WarnIfNdppdNotRunning()

	fmt.Printf("✓ IPv6 rotation mode: Direct binding (no IP assignment needed)\n")
	fmt.Printf("  Interface: %s\n", interfaceName)
	fmt.Printf("  Subnet: %s\n\n", ipnet.String())

	return mgr, nil
}

// GetRandomIPv6 generates a random IPv6 address from the subnet
// With ip_nonlocal_bind=1, we can bind to any IP in the routed subnet without adding it to the interface
// This is much faster and more efficient than adding/removing IPs
func (m *IPv6Manager) GetRandomIPv6() (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate random IPv6 in the subnet
	ip := m.generateRandomIPv6()

	// No need to add IP to interface - we use ip_nonlocal_bind
	// ndppd will handle NDP responses for the entire /64 subnet

	return ip, nil
}

// generateRandomIPv6 generates a random IPv6 address within the subnet
func (m *IPv6Manager) generateRandomIPv6() net.IP {
	// Start with the subnet base
	ip := make(net.IP, len(m.subnet.IP))
	copy(ip, m.subnet.IP)

	// For a /64 subnet, randomize the last 64 bits (bytes 8-15)
	for i := 8; i < 16; i++ {
		ip[i] = byte(rand.Intn(256))
	}

	// Avoid special addresses
	if ip[15] == 0 || ip[15] == 1 {
		ip[15] = byte(rand.Intn(254) + 2)
	}

	return ip
}

// assignIPToInterface adds the IP address to the network interface
func (m *IPv6Manager) assignIPToInterface(ip net.IP) error {
	// ip -6 addr add <ip>/128 dev <interface>
	cmd := exec.Command("ip", "-6", "addr", "add", fmt.Sprintf("%s/128", ip.String()), "dev", m.interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		// Check if error is because IP already exists - this is OK
		if strings.Contains(outputStr, "File exists") || strings.Contains(outputStr, "RTNETLINK answers: File exists") {
			return nil
		}
		// For any other error, return it
		if len(outputStr) > 0 {
			return fmt.Errorf("failed to add IP %s: %v, output: %s", ip.String(), err, outputStr)
		}
		return fmt.Errorf("failed to add IP %s: %v", ip.String(), err)
	}
	return nil
}

// removeIPFromInterface removes the IP address from the network interface
func (m *IPv6Manager) removeIPFromInterface(ip string) error {
	// ip -6 addr del <ip>/128 dev <interface>
	cmd := exec.Command("ip", "-6", "addr", "del", fmt.Sprintf("%s/128", ip), "dev", m.interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove IP: %v, output: %s", err, string(output))
	}
	return nil
}

// Stop stops the IPv6 manager (no cleanup needed with direct binding)
func (m *IPv6Manager) Stop() {
	// Nothing to clean up - we don't add IPs to the interface
}
