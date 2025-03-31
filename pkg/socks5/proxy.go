package socks5

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/phanes/nyxtrace/nyxproxy-core/internal/config"
)

// Proxy represents a SOCKS5 proxy server
type Proxy struct {
	config    *config.ProxyConfig
	server    *socks5.Server
	localAddr net.IP
	resolver  *net.Resolver
}

// getOutboundIP returns the preferred outbound IP for the given protocol
func getOutboundIP(protocol int) (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %v", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down and loopback interfaces
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
				// For IPv6, we want a global scope address (not link-local)
				if !ip.IsLinkLocalUnicast() {
					return ip, nil
				}
			} else if protocol == 4 && !isIPv6 {
				// For IPv4, any non-private address will do
				if !ip.IsPrivate() {
					return ip, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no suitable IPv%d address found", protocol)
}

// getRandomIPv6 generates a random IPv6 address within the /64 subnet
func getRandomIPv6(baseIP net.IP) net.IP {
	ip := make(net.IP, len(baseIP))
	copy(ip, baseIP)

	// Generate random values for the last 64 bits
	for i := 8; i < 16; i++ {
		ip[i] = byte(rand.Intn(256))
	}

	// Avoid ::1
	if ip[15] == 1 {
		ip[15] = 2
	}

	return ip
}

// getNextLocalAddr returns the next IPv6 address to use
func (p *Proxy) getNextLocalAddr() (net.IP, error) {
	if p.config.ProxyProtocol != 6 {
		return p.localAddr, nil
	}

	baseIP := p.localAddr.Mask(net.CIDRMask(64, 128))
	return getRandomIPv6(baseIP), nil
}

// createResolver creates a protocol-specific DNS resolver
func createResolver(localAddr net.IP, protocol int) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var dnsServers []string
			if protocol == 6 {
				network = "udp6"
				dnsServers = []string{
					"[2001:4860:4860::8888]:53", // Google
					"[2606:4700:4700::1111]:53", // Cloudflare
					"[2620:fe::fe]:53",          // Quad9
				}
			} else {
				network = "udp4"
				dnsServers = []string{
					"8.8.8.8:53", // Google
					"1.1.1.1:53", // Cloudflare
					"9.9.9.9:53", // Quad9
				}
			}

			dialer := &net.Dialer{
				LocalAddr: &net.UDPAddr{IP: localAddr},
				Timeout:   5 * time.Second,
			}

			for _, dns := range dnsServers {
				conn, err := dialer.DialContext(ctx, network, dns)
				if err == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("all DNS servers failed")
		},
	}
}

// NewProxy creates a new SOCKS5 proxy server
func NewProxy(cfg *config.ProxyConfig) (*Proxy, error) {
	rand.Seed(time.Now().UnixNano())

	localAddr, err := getOutboundIP(cfg.ProxyProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to determine outbound IP: %v", err)
	}

	proxy := &Proxy{
		config:    cfg,
		localAddr: localAddr,
		resolver:  createResolver(localAddr, cfg.ProxyProtocol),
	}

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %v", err)
			}

			// Get next local IP for this connection
			localIP, err := proxy.getNextLocalAddr()
			if err != nil {
				return nil, fmt.Errorf("failed to get local IP: %v", err)
			}

			// Create dialer with privacy settings
			dialer := &net.Dialer{
				LocalAddr: &net.TCPAddr{IP: localIP},
				Timeout:   30 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					return c.Control(func(fd uintptr) {
						if cfg.ProxyProtocol == 6 {
							syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
						}
					})
				},
			}

			// Use appropriate network type
			if cfg.ProxyProtocol == 6 {
				network = "tcp6"
				dialer.DualStack = false
			} else {
				network = "tcp4"
			}

			// Check if the host is already an IP address
			if ip := net.ParseIP(host); ip != nil {
				isIPv6 := ip.To4() == nil
				if isIPv6 != (cfg.ProxyProtocol == 6) {
					return nil, fmt.Errorf("IP version mismatch: got %s but want IPv%d", host, cfg.ProxyProtocol)
				}
				return dialer.DialContext(ctx, network, addr)
			}

			// Resolve the host using our protocol-specific resolver
			var ips []net.IP
			addrs, err := proxy.resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup failed for %s: %v", host, err)
			}

			// Filter addresses based on protocol
			for _, addr := range addrs {
				isIPv6 := addr.IP.To4() == nil
				if isIPv6 == (cfg.ProxyProtocol == 6) {
					ips = append(ips, addr.IP)
				}
			}

			if len(ips) == 0 {
				return nil, fmt.Errorf("no IPv%d addresses found for %s", cfg.ProxyProtocol, host)
			}

			// Connect using the resolved IP
			targetAddr := net.JoinHostPort(ips[0].String(), port)
			conn, err := dialer.DialContext(ctx, network, targetAddr)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to %s: %v", targetAddr, err)
			}

			return conn, nil
		},
	}

	server, err := socks5.New(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 server: %v", err)
	}

	proxy.server = server
	return proxy, nil
}

// Start starts the SOCKS5 proxy server
func (p *Proxy) Start() error {
	addr := fmt.Sprintf("%s:%d", p.config.ListenAddress, p.config.ListenPort)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

	fmt.Printf("Starting socks5 proxy on %s (Protocol: IPv%d)\n", addr, p.config.ProxyProtocol)
	return p.server.Serve(listener)
}

// Stop stops the SOCKS5 proxy server
func (p *Proxy) Stop() error {
	return nil
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
