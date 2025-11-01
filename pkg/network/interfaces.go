package network

import (
	"fmt"
	"net"
)

// InterfaceInfo contains information about a network interface
type InterfaceInfo struct {
	Name         string
	Index        int
	IPv4Addresses []string
	IPv6Addresses []string
	IsUp         bool
	IsLoopback   bool
}

// GetAllInterfaces returns all network interfaces on the system
func GetAllInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %v", err)
	}

	var result []InterfaceInfo

	for _, iface := range interfaces {
		info := InterfaceInfo{
			Name:       iface.Name,
			Index:      iface.Index,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		// Get IP addresses for this interface
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
			if ip.To4() != nil {
				info.IPv4Addresses = append(info.IPv4Addresses, ip.String())
			} else {
				// Filter out link-local IPv6 addresses for cleaner display
				if !ip.IsLinkLocalUnicast() {
					info.IPv6Addresses = append(info.IPv6Addresses, ip.String())
				}
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// GetUsableInterfaces returns only interfaces that are up and not loopback
func GetUsableInterfaces() ([]InterfaceInfo, error) {
	all, err := GetAllInterfaces()
	if err != nil {
		return nil, err
	}

	var usable []InterfaceInfo
	for _, iface := range all {
		if iface.IsUp && !iface.IsLoopback {
			// Only include interfaces with at least one IP address
			if len(iface.IPv4Addresses) > 0 || len(iface.IPv6Addresses) > 0 {
				usable = append(usable, iface)
			}
		}
	}

	return usable, nil
}

// GetInterfaceByName returns information about a specific interface by name
func GetInterfaceByName(name string) (*InterfaceInfo, error) {
	all, err := GetAllInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range all {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", name)
}

// GetOutboundIP returns the preferred outbound IP for the given interface and protocol
func GetOutboundIP(interfaceName string, protocol int) (net.IP, error) {
	if interfaceName == "" {
		// Auto-detect: find first suitable interface
		return getAutoOutboundIP(protocol)
	}

	// Get specific interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %v", interfaceName, err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		isIPv6 := ip.To4() == nil

		if protocol == 6 && isIPv6 {
			// For IPv6, prefer global scope addresses
			if !ip.IsLinkLocalUnicast() {
				return ip, nil
			}
		} else if protocol == 4 && !isIPv6 {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("no suitable IPv%d address found on interface %s", protocol, interfaceName)
}

// getAutoOutboundIP automatically detects the best outbound IP
func getAutoOutboundIP(protocol int) (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %v", err)
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
			isIPv6 := ip.To4() == nil

			if protocol == 6 && isIPv6 {
				if !ip.IsLinkLocalUnicast() {
					return ip, nil
				}
			} else if protocol == 4 && !isIPv6 {
				return ip, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable IPv%d address found", protocol)
}
