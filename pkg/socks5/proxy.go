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

// customResolver implements the socks5.NameResolver interface
type customResolver struct {
	resolver *net.Resolver
	protocol int
}

func (r *customResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// If it's already an IP, validate it matches our protocol
	if ip := net.ParseIP(name); ip != nil {
		isIPv6 := ip.To4() == nil
		if isIPv6 == (r.protocol == 6) {
			return ctx, ip, nil
		}
		return ctx, nil, fmt.Errorf("IP version mismatch: got %s but want IPv%d", name, r.protocol)
	}

	// Resolve using our protocol-specific resolver
	addrs, err := r.resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, fmt.Errorf("DNS lookup failed for %s: %v", name, err)
	}

	// Filter for addresses matching our protocol
	var matchingIPs []net.IP
	for _, addr := range addrs {
		isIPv6 := addr.IP.To4() == nil
		if isIPv6 == (r.protocol == 6) {
			matchingIPs = append(matchingIPs, addr.IP)
		}
	}

	if len(matchingIPs) == 0 {
		return ctx, nil, fmt.Errorf("no IPv%d addresses found for %s", r.protocol, name)
	}

	return ctx, matchingIPs[0], nil
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

// debugLog prints debug messages based on debug level
func (p *Proxy) debugLog(level int, format string, args ...interface{}) {
	if p.config.DebugLevel >= level {
		fmt.Printf(format+"\n", args...)
	}
}

// getRandomIPv6 generates a random IPv6 address within the /64 subnet
func getRandomIPv6(baseIP net.IP) net.IP {
	ip := make(net.IP, len(baseIP))
	copy(ip, baseIP)
	for i := 8; i < 16; i++ {
		ip[i] = byte(rand.Intn(256))
	}
	if ip[15] == 1 { // Avoid ::1
		ip[15] = 2
	}
	return ip
}

// getNextLocalAddr returns the next IPv6 address to use
func (p *Proxy) getNextLocalAddr() (net.IP, error) {
	if p.config.ProxyProtocol != 6 {
		return getOutboundIP(p.config.ProxyProtocol)
	}

	baseIP, err := getOutboundIP(6)
	if err != nil {
		return nil, err
	}

	baseIP = baseIP.Mask(net.CIDRMask(64, 128))
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
		Resolver: &customResolver{
			resolver: proxy.resolver,
			protocol: cfg.ProxyProtocol,
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			localIP, err := proxy.getNextLocalAddr()
			if err != nil {
				return nil, fmt.Errorf("failed to get local IP: %v", err)
			}

			proxy.debugLog(2, "Using local IP: %s for connection to %s", localIP, addr)

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

			if cfg.ProxyProtocol == 6 {
				network = "tcp6"
			} else {
				network = "tcp4"
			}
			return dialer.DialContext(ctx, network, addr)
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
	p.debugLog(1, "Starting socks5 proxy on %s (Protocol: IPv%d)", addr, p.config.ProxyProtocol)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

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
