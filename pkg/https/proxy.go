package https

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/phanes/nyxtrace/nyxproxy-core/internal/config"
)

// Proxy represents an HTTPS proxy server
type Proxy struct {
	config     *config.ProxyConfig
	httpServer *http.Server
	resolver   *net.Resolver
}

// NewProxy creates a new HTTPS proxy server
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
			// Select DNS servers based on protocol version
			var dnsServers []string
			if cfg.ProxyProtocol == 6 {
				network = "udp6"
				dnsServers = []string{
					"[2001:4860:4860::8888]:53", // Google DNS IPv6
					"[2606:4700:4700::1111]:53", // Cloudflare DNS IPv6
					"[2620:fe::fe]:53",          // Quad9 DNS IPv6
					"[2620:119:35::35]:53",      // OpenDNS IPv6
				}
			} else {
				network = "udp4"
				dnsServers = []string{
					"8.8.8.8:53",        // Google DNS IPv4
					"1.1.1.1:53",        // Cloudflare DNS IPv4
					"9.9.9.9:53",        // Quad9 DNS IPv4
					"208.67.222.222:53", // OpenDNS IPv4
				}
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

	proxy := &Proxy{
		config:   cfg,
		resolver: resolver,
	}

	// Create the proxy handler
	handler := http.HandlerFunc(proxy.handleRequest)

	// Create HTTP server
	proxy.httpServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.ListenPort),
		Handler: handler,
	}

	return proxy, nil
}

// resolveHost resolves a hostname to an IP address based on the configured protocol
func (p *Proxy) resolveHost(ctx context.Context, host string) (string, error) {
	// If it's already an IP, validate and return it
	if ip := net.ParseIP(host); ip != nil {
		isIPv6 := ip.To4() == nil
		if (p.config.ProxyProtocol == 6) != isIPv6 {
			return "", fmt.Errorf("IP version mismatch: got %s but want IPv%d", host, p.config.ProxyProtocol)
		}
		return host, nil
	}

	// Lookup IP addresses
	addrs, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed for %s: %v", host, err)
	}

	// Filter addresses based on protocol
	var matchingIPs []net.IP
	for _, addr := range addrs {
		isIPv6 := addr.IP.To4() == nil
		if (p.config.ProxyProtocol == 6) == isIPv6 {
			matchingIPs = append(matchingIPs, addr.IP)
		}
	}

	if len(matchingIPs) == 0 {
		return "", fmt.Errorf("no IPv%d addresses found for %s", p.config.ProxyProtocol, host)
	}

	return matchingIPs[0].String(), nil
}

// handleRequest handles both CONNECT and regular HTTP requests
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS CONNECT tunneling
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Parse host and port
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid host format: %v", err), http.StatusBadGateway)
		return
	}

	// Resolve the host to the correct IP version
	resolvedIP, err := p.resolveHost(r.Context(), host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to resolve host: %v", err), http.StatusBadGateway)
		return
	}

	// Create custom dialer for the target connection
	dialer := &net.Dialer{}
	network := "tcp4"
	if p.config.ProxyProtocol == 6 {
		network = "tcp6"
		dialer.DualStack = false // Force IPv6 only
	}

	// Connect to the target server using resolved IP
	targetAddr := net.JoinHostPort(resolvedIP, port)
	targetConn, err := dialer.DialContext(r.Context(), network, targetAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send 200 OK to indicate tunnel established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Start bidirectional copy
	go func() {
		io.Copy(targetConn, clientConn)
	}()
	io.Copy(clientConn, targetConn)
}

// handleHTTP handles regular HTTP requests
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Ensure the request has a valid URL with scheme
	if !strings.HasPrefix(r.URL.String(), "http://") && !strings.HasPrefix(r.URL.String(), "https://") {
		r.URL, _ = url.Parse("http://" + r.Host + r.URL.String())
	}

	// Create custom transport for the proxy
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %v", err)
			}

			// Resolve the host to the correct IP version
			resolvedIP, err := p.resolveHost(ctx, host)
			if err != nil {
				return nil, err
			}

			// Create dialer with appropriate network type
			dialer := &net.Dialer{}
			network = "tcp4"
			if p.config.ProxyProtocol == 6 {
				network = "tcp6"
				dialer.DualStack = false
			}

			// Connect using resolved IP
			return dialer.DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
		},
	}

	// Create the proxy handler
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// The URL is already properly set above
		},
		Transport: transport,
	}

	proxy.ServeHTTP(w, r)
}

// Start starts the HTTPS proxy server
func (p *Proxy) Start() error {
	// Create listener that accepts both IPv4 and IPv6
	listener, err := net.Listen("tcp", p.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}

	// Start serving
	return p.httpServer.Serve(listener)
}

// Stop gracefully stops the HTTPS proxy server
func (p *Proxy) Stop() error {
	return p.httpServer.Close()
}
