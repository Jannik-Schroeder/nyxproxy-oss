package socks5

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/armon/go-socks5"
	"github.com/phanes/nyxtrace/nyxproxy-core/internal/config"
)

// Proxy represents a SOCKS5 proxy server
type Proxy struct {
	config *config.ProxyConfig
	server *socks5.Server
}

// NewProxy creates a new SOCKS5 proxy server
func NewProxy(cfg *config.ProxyConfig) (*Proxy, error) {
	// Create custom dialer based on protocol version
	dialer := &net.Dialer{}
	if cfg.ProxyProtocol == 6 {
		dialer.DualStack = false // Force IPv6 only
	}

	// Create custom DNS resolver
	resolver := &net.Resolver{
		PreferGo: true, // Use pure Go resolver
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Force the DNS query to use the correct IP version
			if cfg.ProxyProtocol == 6 {
				network = "udp6"
			} else {
				network = "udp4"
			}
			// Try multiple DNS servers in case one fails
			dnsServers := []string{
				"8.8.8.8:53",        // Google DNS
				"1.1.1.1:53",        // Cloudflare DNS
				"9.9.9.9:53",        // Quad9 DNS
				"208.67.222.222:53", // OpenDNS
			}

			var lastErr error
			for _, dns := range dnsServers {
				conn, err := dialer.DialContext(ctx, network, dns)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("all DNS servers failed, last error: %v", lastErr)
		},
	}

	// Create SOCKS5 configuration
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %v", err)
			}

			// Check if the host is already an IP address
			if ip := net.ParseIP(host); ip != nil {
				// If it's an IP address, verify it matches our protocol version
				if (cfg.ProxyProtocol == 6) != (ip.To4() == nil) {
					return nil, fmt.Errorf("IP version mismatch: got %s but want IPv%d", host, cfg.ProxyProtocol)
				}
				return dialer.DialContext(ctx, network, addr)
			}

			// Use our custom resolver to look up addresses
			var ips []net.IP
			network = "tcp4"

			if cfg.ProxyProtocol == 6 {
				network = "tcp6"
				addrs, err := resolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("IPv6 DNS lookup failed for %s: %v", host, err)
				}

				// Filter for IPv6 addresses
				for _, addr := range addrs {
					if addr.IP.To4() == nil {
						ips = append(ips, addr.IP)
					}
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("no IPv6 address available for %s", host)
				}
			} else {
				addrs, err := resolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("IPv4 DNS lookup failed for %s: %v", host, err)
				}

				// Filter for IPv4 addresses
				for _, addr := range addrs {
					if addr.IP.To4() != nil {
						ips = append(ips, addr.IP)
					}
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("no IPv4 address available for %s", host)
				}
			}

			// Connect using the resolved IP
			targetAddr := net.JoinHostPort(ips[0].String(), port)
			return dialer.DialContext(ctx, network, targetAddr)
		},
		Resolver: &resolverWrapper{
			resolver: resolver,
			wantIPv6: cfg.ProxyProtocol == 6,
		},
	}

	// Create SOCKS5 server
	server, err := socks5.New(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 server: %v", err)
	}

	return &Proxy{
		config: cfg,
		server: server,
	}, nil
}

// resolverWrapper implements the socks5.NameResolver interface
type resolverWrapper struct {
	resolver *net.Resolver
	wantIPv6 bool
}

// Resolve implements the socks5.NameResolver interface
func (r *resolverWrapper) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Check if the name is already an IP
	if ip := net.ParseIP(name); ip != nil {
		// Verify IP version matches what we want
		isIPv6 := ip.To4() == nil
		if isIPv6 == r.wantIPv6 {
			return ctx, ip, nil
		}
		return ctx, nil, fmt.Errorf("IP version mismatch: got %s but want IPv%d", name, map[bool]int{true: 6, false: 4}[r.wantIPv6])
	}

	addrs, err := r.resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, fmt.Errorf("DNS lookup failed for %s: %v", name, err)
	}

	// Filter addresses based on IP version
	var matchingIPs []net.IP
	for _, addr := range addrs {
		isIPv6 := addr.IP.To4() == nil
		if isIPv6 == r.wantIPv6 {
			matchingIPs = append(matchingIPs, addr.IP)
		}
	}

	if len(matchingIPs) == 0 {
		if r.wantIPv6 {
			return ctx, nil, fmt.Errorf("no IPv6 address found for %s", name)
		}
		return ctx, nil, fmt.Errorf("no IPv4 address found for %s", name)
	}

	// Return the first matching IP
	return ctx, matchingIPs[0], nil
}

// Start starts the SOCKS5 proxy server
func (p *Proxy) Start() error {
	// Create listener address
	addr := fmt.Sprintf("%s:%d", p.config.ListenAddress, p.config.ListenPort)

	// Create listener that accepts both IPv4 and IPv6
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

	// Start serving
	return p.server.Serve(listener)
}

// lookupIPv4 looks up only IPv4 addresses for a given host
func lookupIPv4(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var ipv4s []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}
	return ipv4s, nil
}

// lookupIPv6 looks up only IPv6 addresses for a given host
func lookupIPv6(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var ipv6s []net.IP
	for _, ip := range ips {
		if ip.To4() == nil {
			ipv6s = append(ipv6s, ip)
		}
	}
	return ipv6s, nil
}

// validateAddress ensures the address is of the correct IP version
func validateAddress(addr string, wantIPv6 bool) bool {
	host := addr
	if strings.Contains(addr, ":") {
		host, _, _ = net.SplitHostPort(addr)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return true // Not an IP address, could be a hostname
	}

	isIPv6 := strings.Contains(host, ":")
	return isIPv6 == wantIPv6
}
