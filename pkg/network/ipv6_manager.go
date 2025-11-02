package network

import (
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"sync"
	"time"
)

// IPv6Manager manages dynamic IPv6 address assignment
type IPv6Manager struct {
	mu            sync.Mutex
	interfaceName string
	subnet        *net.IPNet
	assignedIPs   map[string]time.Time
	cleanupTicker *time.Ticker
}

// NewIPv6Manager creates a new IPv6 manager
func NewIPv6Manager(interfaceName string, subnet string) (*IPv6Manager, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %v", err)
	}

	mgr := &IPv6Manager{
		interfaceName: interfaceName,
		subnet:        ipnet,
		assignedIPs:   make(map[string]time.Time),
	}

	// Start cleanup goroutine to remove old IPs
	mgr.cleanupTicker = time.NewTicker(5 * time.Minute)
	go mgr.cleanupLoop()

	return mgr, nil
}

// GetRandomIPv6 generates a random IPv6 address from the subnet
// For /64 subnets, most hosting providers route the entire subnet to your server,
// so you can bind to any IP in the range without explicitly adding it to the interface
func (m *IPv6Manager) GetRandomIPv6() (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate random IPv6 in the subnet
	ip := m.generateRandomIPv6()

	// Track the IP (for monitoring/cleanup if needed)
	m.assignedIPs[ip.String()] = time.Now()

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
		// Ignore error if IP already exists
		if string(output) == "" || len(output) == 0 {
			return nil
		}
		return fmt.Errorf("failed to add IP: %v, output: %s", err, string(output))
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

// cleanupLoop periodically cleans up old IP entries from tracking (older than 10 minutes)
// Since we don't add IPs to the interface, we just remove them from our tracking map
func (m *IPv6Manager) cleanupLoop() {
	for range m.cleanupTicker.C {
		m.mu.Lock()
		now := time.Now()
		for ip, assignedTime := range m.assignedIPs {
			if now.Sub(assignedTime) > 10*time.Minute {
				// Remove from tracking map
				delete(m.assignedIPs, ip)
			}
		}
		m.mu.Unlock()
	}
}

// Stop stops the IPv6 manager and cleans up
func (m *IPv6Manager) Stop() {
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
	}

	// Clear tracking map
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assignedIPs = make(map[string]time.Time)
}
