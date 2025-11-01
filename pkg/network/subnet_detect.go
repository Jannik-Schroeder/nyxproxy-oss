package network

import (
	"fmt"
	"net"
	"strings"
)

// DetectIPv6Subnet automatically detects the IPv6 /64 subnet for an interface
func DetectIPv6Subnet(interfaceName string) (string, error) {
	// If no interface specified, auto-detect
	if interfaceName == "" {
		iface, err := getDefaultInterface()
		if err != nil {
			return "", err
		}
		interfaceName = iface.Name
	}

	// Get the interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %v", interfaceName, err)
	}

	// Get addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses: %v", err)
	}

	// Find first global IPv6 address and extract /64 subnet
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		// Check if it's IPv6 and not link-local
		if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
			// Create /64 subnet from this IP
			subnet := make(net.IP, len(ip))
			copy(subnet, ip)

			// Zero out the last 64 bits (host part)
			for i := 8; i < 16; i++ {
				subnet[i] = 0
			}

			// Return as CIDR notation
			return fmt.Sprintf("%s/64", subnet.String()), nil
		}
	}

	return "", fmt.Errorf("no global IPv6 address found on interface %s", interfaceName)
}

// getDefaultInterface returns the first non-loopback interface with an IPv6 address
func getDefaultInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			// Check for global IPv6
			if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface with global IPv6 address found")
}

// GetIPv6SubnetInfo returns detailed information about the IPv6 configuration
func GetIPv6SubnetInfo(interfaceName string) (map[string]string, error) {
	info := make(map[string]string)

	if interfaceName == "" {
		iface, err := getDefaultInterface()
		if err != nil {
			return nil, err
		}
		interfaceName = iface.Name
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	info["interface"] = iface.Name

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var ipv6Addrs []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		if ip.To4() == nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
			ipv6Addrs = append(ipv6Addrs, ip.String())
		}
	}

	if len(ipv6Addrs) > 0 {
		info["primary_ipv6"] = ipv6Addrs[0]
		info["ipv6_count"] = fmt.Sprintf("%d", len(ipv6Addrs))

		subnet, err := DetectIPv6Subnet(interfaceName)
		if err == nil {
			info["detected_subnet"] = subnet
		}
	}

	return info, nil
}

// NormalizeSubnet ensures the subnet is in correct /64 format
func NormalizeSubnet(subnet string) (string, error) {
	// Parse the CIDR
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet format: %v", err)
	}

	// Check if it's IPv6
	if ipNet.IP.To4() != nil {
		return "", fmt.Errorf("subnet must be IPv6")
	}

	// Get the mask size
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return "", fmt.Errorf("invalid IPv6 subnet")
	}

	// We want /64
	if ones > 64 {
		// If it's more specific than /64, extract the /64
		ip := ipNet.IP.Mask(net.CIDRMask(64, 128))
		return fmt.Sprintf("%s/64", ip.String()), nil
	} else if ones < 64 {
		// If it's less specific (like /48), we can't determine a single /64
		return "", fmt.Errorf("subnet mask /%d is too large, need /64 or more specific", ones)
	}

	// Already /64, just ensure proper formatting
	ip := ipNet.IP.Mask(net.CIDRMask(64, 128))
	return fmt.Sprintf("%s/64", ip.String()), nil
}

// IsValidIPv6Subnet checks if a string is a valid IPv6 /64 subnet
func IsValidIPv6Subnet(subnet string) bool {
	if !strings.Contains(subnet, "/64") {
		return false
	}

	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return false
	}

	// Must be IPv6
	if ipNet.IP.To4() != nil {
		return false
	}

	ones, bits := ipNet.Mask.Size()
	return ones == 64 && bits == 128
}
