package socks5

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
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
	// If it's already an IP, convert to IPv6 if needed
	if ip := net.ParseIP(name); ip != nil {
		if r.protocol == 6 {
			if ip.To4() != nil {
				mapped := make(net.IP, 16)
				mapped[10] = 0xff
				mapped[11] = 0xff
				copy(mapped[12:], ip.To4())
				return ctx, mapped, nil
			}
			return ctx, ip, nil
		}
		if ip.To4() != nil {
			return ctx, ip, nil
		}
		return ctx, nil, fmt.Errorf("IPv6 address not allowed in IPv4 mode: %s", name)
	}

	// Resolve using our protocol-specific resolver
	addrs, err := r.resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, fmt.Errorf("DNS lookup failed for %s: %v", name, err)
	}

	if r.protocol == 6 {
		// Try native IPv6 first
		for _, addr := range addrs {
			if addr.IP.To4() == nil {
				return ctx, addr.IP, nil
			}
		}
		// Fall back to IPv4 mapped to IPv6
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				mapped := make(net.IP, 16)
				mapped[10] = 0xff
				mapped[11] = 0xff
				copy(mapped[12:], addr.IP.To4())
				return ctx, mapped, nil
			}
		}
	} else {
		// IPv4 mode
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				return ctx, addr.IP, nil
			}
		}
	}

	return ctx, nil, fmt.Errorf("no suitable IP addresses found for %s", name)
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
		log.Printf(format, args...)
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
			dnsNetwork := "udp6"
			if protocol == 6 {
				dnsServers = []string{
					"[2001:4860:4860::8888]:53", // Google
					"[2606:4700:4700::1111]:53", // Cloudflare
					"[2620:fe::fe]:53",          // Quad9
				}
			} else {
				dnsNetwork = "udp4"
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
				conn, err := dialer.DialContext(ctx, dnsNetwork, dns)
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

	// Create credentials checker
	creds := socks5.StaticCredentials{
		"nyxtrace": cfg.Password,
	}

	auth := socks5.UserPassAuthenticator{Credentials: creds}

	conf := &socks5.Config{
		AuthMethods: []socks5.Authenticator{auth},
		Credentials: creds,
		Resolver: &customResolver{
			resolver: proxy.resolver,
			protocol: cfg.ProxyProtocol,
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			localIP, err := proxy.getNextLocalAddr()
			if err != nil {
				return nil, fmt.Errorf("failed to get local IP: %v", err)
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("failed to split address: %v", err)
			}

			// Use our custom resolver to get the right IP version
			resolver := &customResolver{
				resolver: proxy.resolver,
				protocol: cfg.ProxyProtocol,
			}
			ctx, resolvedIP, err := resolver.Resolve(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve host %s: %v", host, err)
			}

			// For IPv6 mode, ensure we have a valid IPv6 address
			if cfg.ProxyProtocol == 6 && resolvedIP.To4() != nil {
				// Create IPv4-mapped IPv6 address
				mapped := make(net.IP, 16)
				mapped[10] = 0xff
				mapped[11] = 0xff
				copy(mapped[12:], resolvedIP.To4())
				resolvedIP = mapped
				proxy.debugLog(2, "Mapped IPv4 address to IPv6: %s", resolvedIP.String())
			}

			targetAddr := net.JoinHostPort(resolvedIP.String(), port)
			proxy.debugLog(2, "Using local IP: %s for connection to %s (resolved to %s)", localIP, addr, targetAddr)

			dialer := &net.Dialer{
				LocalAddr: &net.TCPAddr{IP: localIP},
				Timeout:   30 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					return c.Control(func(fd uintptr) {
						if cfg.ProxyProtocol == 6 {
							syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
						}
					})
				},
			}

			// Always use the protocol specified in config
			dialNetwork := "tcp4"
			if cfg.ProxyProtocol == 6 {
				dialNetwork = "tcp6"
			}

			return dialer.DialContext(ctx, dialNetwork, targetAddr)
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

// setSocketOptions sets socket options for Linux
func setSocketOptions(fd uintptr) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("failed to set SO_REUSEADDR: %v", err)
	}
	return nil
}

func (p *Proxy) handleConnection(conn net.Conn) {
	// ... existing code ...

	// Get the underlying file descriptor
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		log.Printf("Connection is not TCP")
		return
	}

	// Get raw connection
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		log.Printf("Failed to get raw connection: %v", err)
		return
	}

	// Set socket options
	raw.Control(func(fd uintptr) {
		if err := setSocketOptions(fd); err != nil {
			log.Printf("Failed to set socket options: %v", err)
		}
	})

	// ... existing code ...
}
