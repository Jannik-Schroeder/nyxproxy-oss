package network

import (
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// IPv6Manager manages dynamic IPv6 address rotation with pre-populated IP pool
type IPv6Manager struct {
	mu            sync.Mutex
	interfaceName string
	subnet        *net.IPNet
	ipPool        []net.IP  // Pre-populated pool of IPs
	poolIndex     int       // Current position in the pool
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
		ipPool:        make([]net.IP, 0),
		poolIndex:     0,
	}

	// Check if ndppd is running (warning only, not fatal)
	WarnIfNdppdNotRunning()

	fmt.Printf("✓ IPv6 rotation mode: IP Pool (pre-populated)\n")
	fmt.Printf("  Interface: %s\n", interfaceName)
	fmt.Printf("  Subnet: %s\n", ipnet.String())
	fmt.Printf("  Initializing IP pool...\n")

	// Pre-populate IP pool (default: 200 IPs)
	poolSize := 200
	if err := mgr.populateIPPool(poolSize); err != nil {
		return nil, fmt.Errorf("failed to populate IP pool: %v", err)
	}

	fmt.Printf("✓ IP pool ready with %d addresses\n\n", poolSize)

	return mgr, nil
}

// GetRandomIPv6 returns a random IPv6 address from the pre-populated pool
// This is fast because all IPs are already added to the interface
func (m *IPv6Manager) GetRandomIPv6() (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.ipPool) == 0 {
		return nil, fmt.Errorf("IP pool is empty")
	}

	// Round-robin through the pool for even distribution
	ip := m.ipPool[m.poolIndex]
	m.poolIndex = (m.poolIndex + 1) % len(m.ipPool)

	return ip, nil
}

// populateIPPool generates and adds a pool of IPs to the interface
// This is done once at startup, so subsequent requests are fast
func (m *IPv6Manager) populateIPPool(size int) error {
	fmt.Printf("  Adding %d IPv6 addresses to interface (this may take 10-30 seconds)...\n", size)

	for i := 0; i < size; i++ {
		ip := m.generateRandomIPv6()

		// Add IP to interface
		if err := m.assignIPToInterface(ip); err != nil {
			// Ignore "already exists" errors
			errStr := err.Error()
			if !strings.Contains(errStr, "File exists") && !strings.Contains(errStr, "RTNETLINK answers") {
				return fmt.Errorf("failed to add IP %s: %v", ip.String(), err)
			}
		}

		m.ipPool = append(m.ipPool, ip)

		// Progress indicator every 50 IPs
		if (i+1)%50 == 0 {
			fmt.Printf("  Progress: %d/%d IPs added\n", i+1, size)
		}
	}

	return nil
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

// Stop stops the IPv6 manager and cleans up the IP pool
func (m *IPv6Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Printf("Cleaning up IP pool (%d addresses)...\n", len(m.ipPool))

	// Remove all IPs from the interface
	for _, ip := range m.ipPool {
		m.removeIPFromInterface(ip.String())
	}

	m.ipPool = nil
	fmt.Printf("✓ IP pool cleaned up\n")
}
