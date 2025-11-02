package network

import (
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// IPStats tracks usage statistics for each IP in the pool
type IPStats struct {
	usageCount int       // How many times this IP was used
	lastUsed   time.Time // When was it last used
	addedAt    time.Time // When was it added to the pool
}

// IPv6Manager manages dynamic IPv6 address rotation with pre-populated IP pool
type IPv6Manager struct {
	mu            sync.Mutex
	interfaceName string
	subnet        *net.IPNet
	ipPool        []net.IP            // Pre-populated pool of IPs
	ipStats       map[string]*IPStats // Usage statistics per IP
	poolIndex     int                 // Current position in the pool
	maxUsageCount int                 // Max times an IP can be used before rotation
	maxAge        time.Duration       // Max age of an IP before rotation
	rotationStop  chan bool           // Channel to stop the rotation goroutine
}

// NewIPv6Manager creates a new IPv6 manager with configurable rotation settings
func NewIPv6Manager(interfaceName string, subnet string, poolSize, maxUsage, maxAgeMinutes int) (*IPv6Manager, error) {
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

	// Apply defaults if values are 0 or negative
	if poolSize <= 0 {
		poolSize = 200
	}
	if maxUsage <= 0 {
		maxUsage = 100
	}
	if maxAgeMinutes <= 0 {
		maxAgeMinutes = 30
	}

	mgr := &IPv6Manager{
		interfaceName: interfaceName,
		subnet:        ipnet,
		ipPool:        make([]net.IP, 0),
		ipStats:       make(map[string]*IPStats),
		poolIndex:     0,
		maxUsageCount: maxUsage,
		maxAge:        time.Duration(maxAgeMinutes) * time.Minute,
		rotationStop:  make(chan bool),
	}

	// Check if ndppd is running (warning only, not fatal)
	WarnIfNdppdNotRunning()

	fmt.Printf("✓ IPv6 rotation mode: IP Pool with dynamic rotation\n")
	fmt.Printf("  Interface: %s\n", interfaceName)
	fmt.Printf("  Subnet: %s\n", ipnet.String())
	fmt.Printf("  Pool size: %d IPs\n", poolSize)
	fmt.Printf("  Rotation: Every %d uses or %v\n", mgr.maxUsageCount, mgr.maxAge)
	fmt.Printf("  Initializing IP pool...\n")

	// Pre-populate IP pool
	if err := mgr.populateIPPool(poolSize); err != nil {
		return nil, fmt.Errorf("failed to populate IP pool: %v", err)
	}

	fmt.Printf("✓ IP pool ready with %d addresses\n", poolSize)

	// Start background rotation goroutine
	go mgr.rotateOldIPs()
	fmt.Printf("✓ Background IP rotation started\n\n")

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

	// Update usage statistics
	ipStr := ip.String()
	if stats, exists := m.ipStats[ipStr]; exists {
		stats.usageCount++
		stats.lastUsed = time.Now()
	} else {
		// This shouldn't happen, but handle it gracefully
		m.ipStats[ipStr] = &IPStats{
			usageCount: 1,
			lastUsed:   time.Now(),
			addedAt:    time.Now(),
		}
	}

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

		// Initialize stats for this IP
		m.ipStats[ip.String()] = &IPStats{
			usageCount: 0,
			lastUsed:   time.Now(),
			addedAt:    time.Now(),
		}

		// Progress indicator every 50 IPs
		if (i+1)%50 == 0 {
			fmt.Printf("  Progress: %d/%d IPs added\n", i+1, size)
		}
	}

	return nil
}

// rotateOldIPs runs in background and replaces old/overused IPs with fresh ones
func (m *IPv6Manager) rotateOldIPs() {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndRotateIPs()
		case <-m.rotationStop:
			return
		}
	}
}

// checkAndRotateIPs checks all IPs and replaces old/overused ones
func (m *IPv6Manager) checkAndRotateIPs() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	rotatedCount := 0

	for i, ip := range m.ipPool {
		ipStr := ip.String()
		stats, exists := m.ipStats[ipStr]

		if !exists {
			continue
		}

		// Check if IP should be rotated
		shouldRotate := false

		if stats.usageCount >= m.maxUsageCount {
			shouldRotate = true
		} else if now.Sub(stats.addedAt) >= m.maxAge {
			shouldRotate = true
		}

		if shouldRotate {
			// Generate new IP
			newIP := m.generateRandomIPv6()

			// Remove old IP from interface
			m.removeIPFromInterface(ipStr)

			// Add new IP to interface
			if err := m.assignIPToInterface(newIP); err != nil {
				errStr := err.Error()
				if !strings.Contains(errStr, "File exists") && !strings.Contains(errStr, "RTNETLINK answers") {
					fmt.Printf("Warning: Failed to add new IP during rotation: %v\n", err)
					continue
				}
			}

			// Update pool and stats
			m.ipPool[i] = newIP
			delete(m.ipStats, ipStr)
			m.ipStats[newIP.String()] = &IPStats{
				usageCount: 0,
				lastUsed:   now,
				addedAt:    now,
			}

			rotatedCount++
		}
	}

	if rotatedCount > 0 {
		fmt.Printf("✓ Rotated %d IPs (%s)\n", rotatedCount, time.Now().Format("15:04:05"))
	}
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
	// Stop rotation goroutine
	close(m.rotationStop)

	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Printf("Cleaning up IP pool (%d addresses)...\n", len(m.ipPool))

	// Remove all IPs from the interface
	for _, ip := range m.ipPool {
		m.removeIPFromInterface(ip.String())
	}

	m.ipPool = nil
	m.ipStats = nil
	fmt.Printf("✓ IP pool cleaned up\n")
}
