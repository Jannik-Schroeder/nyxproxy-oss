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

	// Create SOCKS5 configuration
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Resolve the address first to get the correct IP version
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %v", err)
			}

			// Determine network type and resolve addresses
			var ips []net.IP
			var lookupErr error
			network = "tcp4"

			if cfg.ProxyProtocol == 6 {
				network = "tcp6"
				ips, lookupErr = lookupIPv6(host)
				if lookupErr != nil || len(ips) == 0 {
					return nil, fmt.Errorf("no IPv6 address available for %s", host)
				}
			} else {
				ips, lookupErr = lookupIPv4(host)
				if lookupErr != nil || len(ips) == 0 {
					return nil, fmt.Errorf("no IPv4 address available for %s", host)
				}
			}

			// Connect using the resolved IP
			targetAddr := net.JoinHostPort(ips[0].String(), port)
			return dialer.DialContext(ctx, network, targetAddr)
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
