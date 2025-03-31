package https

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phanes/nyxtrace/nyxproxy-core/internal/config"
)

// sensitiveHeaders contains all headers that should be removed for privacy
var sensitiveHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"Forwarded",
	"Via",
	"Client-IP",
	"Proxy-Client-IP",
	"WL-Proxy-Client-IP",
	"HTTP_X_FORWARDED_FOR",
	"HTTP_X_FORWARDED",
	"HTTP_X_CLUSTER_CLIENT_IP",
	"HTTP_FORWARDED_FOR",
	"HTTP_FORWARDED",
	"HTTP_VIA",
	"REMOTE_ADDR",
	"Proxy-Connection",
	"Connection",
	"Upgrade-Insecure-Requests",
	"DNT",
	"Cache-Control",
}

// debugLog prints debug information if logging is enabled
func (p *Proxy) debugLog(format string, args ...interface{}) {
	if p.config.EnableLogging {
		fmt.Printf(format+"\n", args...)
	}
}

// sanitizeHeaders removes sensitive information from headers
func sanitizeHeaders(headers http.Header) http.Header {
	newHeaders := make(http.Header)

	// Set minimal headers
	newHeaders.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	newHeaders.Set("Accept", "*/*")
	newHeaders.Set("Accept-Encoding", "identity")

	// Copy content-related headers if present
	if ct := headers.Get("Content-Type"); ct != "" {
		newHeaders.Set("Content-Type", ct)
	}
	if cl := headers.Get("Content-Length"); cl != "" {
		newHeaders.Set("Content-Length", cl)
	}

	return newHeaders
}

// Proxy represents an HTTPS proxy server
type Proxy struct {
	config     *config.ProxyConfig
	httpServer *http.Server
	resolver   *net.Resolver
	localAddr  net.IP // Local address for outbound connections
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

// NewProxy creates a new HTTPS proxy server
func NewProxy(config *config.ProxyConfig) (*Proxy, error) {
	// Initialize random number generator
	rand.Seed(time.Now().UnixNano())

	// Get local address for outbound connections
	localAddr, err := getOutboundIP(config.ProxyProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to get outbound IP: %v", err)
	}

	// Create proxy instance
	proxy := &Proxy{
		config:    config,
		localAddr: localAddr,
		resolver:  &net.Resolver{},
	}

	// Configure HTTP server
	proxy.httpServer = &http.Server{
		Addr:    net.JoinHostPort(config.ListenAddress, strconv.Itoa(config.ListenPort)),
		Handler: proxy,
	}

	return proxy, nil
}

// resolveHost resolves a hostname to an IP address based on the configured protocol
func (p *Proxy) resolveHost(ctx context.Context, host string) (string, error) {
	// If it's already an IP, only validate for outbound connections
	if ip := net.ParseIP(host); ip != nil {
		// Allow any IP version for the proxy itself
		if host == p.config.ListenAddress {
			return host, nil
		}
		// For outbound connections, enforce IP version
		isIPv6 := ip.To4() == nil
		if (p.config.ProxyProtocol == 6) != isIPv6 {
			return "", fmt.Errorf("outbound IP version mismatch: got %s but want IPv%d", host, p.config.ProxyProtocol)
		}
		return host, nil
	}

	// Lookup IP addresses
	addrs, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed for %s: %v", host, err)
	}

	// Filter addresses based on protocol for outbound connections
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

// ServeHTTP implements the http.Handler interface
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleHTTP handles regular HTTP requests
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.debugLog("=== Incoming HTTP Request ===")
	p.debugLog("Method: %s, Host: %s, URL: %s", r.Method, r.Host, r.URL)

	// Ensure the request has a valid URL with scheme
	if !strings.HasPrefix(r.URL.String(), "http://") && !strings.HasPrefix(r.URL.String(), "https://") {
		r.URL, _ = url.Parse("http://" + r.Host + r.URL.String())
	}

	// Create a clean request
	newReq := &http.Request{
		Method:        r.Method,
		URL:           r.URL,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        sanitizeHeaders(r.Header),
		Host:          r.Host,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Close:         false,
	}

	p.debugLog("=== Modified Request ===")
	p.debugLog("Headers: %v", newReq.Header)

	// Create custom transport
	transport := &http.Transport{
		DialContext:           p.dialContext,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		MaxIdleConns:          -1,
		IdleConnTimeout:       -1,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Create proxy handler
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			*req = *newReq
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			p.debugLog("=== Response Headers ===")
			p.debugLog("Original: %v", resp.Header)

			// Create clean headers
			newHeaders := sanitizeHeaders(resp.Header)

			// Add security headers
			newHeaders.Set("X-Frame-Options", "DENY")
			newHeaders.Set("X-Content-Type-Options", "nosniff")
			newHeaders.Set("X-XSS-Protection", "1; mode=block")
			newHeaders.Set("Referrer-Policy", "no-referrer")
			newHeaders.Set("Server", "")

			resp.Header = newHeaders
			p.debugLog("Modified: %v", resp.Header)
			return nil
		},
	}

	proxy.ServeHTTP(w, r)
}

// handleConnect handles HTTPS CONNECT tunneling
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid host format: %v", err), http.StatusBadGateway)
		return
	}

	localIP, err := p.getNextLocalAddr()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get local IP: %v", err), http.StatusInternalServerError)
		return
	}

	// Clean request headers
	r.Header = sanitizeHeaders(r.Header)
	r.Header.Set("X-Forwarded-For", localIP.String())

	// Resolve host
	resolvedIP, err := p.resolveHost(r.Context(), host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to resolve host: %v", err), http.StatusBadGateway)
		return
	}

	p.debugLog("=== CONNECT Request ===")
	p.debugLog("Host: %s, Port: %s, Local IP: %s", host, port, localIP)

	// Connect to target
	targetConn, err := (&net.Dialer{
		LocalAddr: &net.TCPAddr{IP: localIP},
		Timeout:   30 * time.Second,
	}).DialContext(r.Context(), "tcp", net.JoinHostPort(resolvedIP, port))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Respond to client
	w.WriteHeader(http.StatusOK)

	// Upgrade client connection
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

	// Create privacy-enhanced connections
	target := newPrivacyConn(targetConn, localIP)
	client := newPrivacyConn(clientConn, localIP)

	// Start proxying with error handling
	errChan := make(chan error, 2)
	go func() {
		_, err := io.CopyBuffer(target, client, make([]byte, 8192))
		if tcpConn, ok := target.Conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		errChan <- err
	}()
	go func() {
		_, err := io.CopyBuffer(client, target, make([]byte, 8192))
		if tcpConn, ok := client.Conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		errChan <- err
	}()

	// Wait for both copies to complete
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil && err != io.EOF {
			p.debugLog("Copy error: %v", err)
		}
	}
}

// privacyConn wraps a net.Conn to ensure privacy
type privacyConn struct {
	net.Conn
	localIP net.IP
	buf     []byte
}

func newPrivacyConn(conn net.Conn, localIP net.IP) *privacyConn {
	return &privacyConn{
		Conn:    conn,
		localIP: localIP,
		buf:     make([]byte, 64*1024), // 64KB buffer
	}
}

func (pc *privacyConn) Read(b []byte) (n int, err error) {
	n, err = pc.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	if isTextData(b[:n]) {
		copy(pc.buf, b[:n])
		content := pc.sanitizeContent(string(pc.buf[:n]))
		return copy(b, content), nil
	}

	return n, nil
}

func (pc *privacyConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if isTextData(b) {
		content := pc.sanitizeContent(string(b))
		data := []byte(content)

		// Write in smaller chunks
		remaining := len(data)
		written := 0
		for remaining > 0 {
			size := remaining
			if size > 8192 { // 8KB chunks
				size = 8192
			}
			w, err := pc.Conn.Write(data[written : written+size])
			if err != nil {
				if written > 0 {
					return written, nil
				}
				return 0, err
			}
			written += w
			remaining -= w
		}
		return len(b), nil
	}

	return pc.Conn.Write(b)
}

// isTextData checks if the data appears to be text
func isTextData(data []byte) bool {
	// Quick check for common HTTP headers
	if bytes.Contains(data, []byte("HTTP/")) ||
		bytes.Contains(data, []byte(": ")) ||
		bytes.Contains(data, []byte("Content-")) {
		return true
	}

	// Check if data is mostly printable characters
	printable := 0
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.85
}

// sanitizeContent removes sensitive information from text content
func (pc *privacyConn) sanitizeContent(content string) string {
	// Remove IP addresses
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	content = ipv4Regex.ReplaceAllString(content, "0.0.0.0")

	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	content = ipv6Regex.ReplaceAllString(content, "::1")

	// Remove headers
	for _, header := range sensitiveHeaders {
		pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(header) + `:[^\r\n]*\r?\n?`)
		content = pattern.ReplaceAllString(content, "")
	}

	return content
}

func (pc *privacyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: pc.localIP}
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

// getRandomIPv6 generates a random IPv6 address within the /64 subnet
func getRandomIPv6(baseIP net.IP) net.IP {
	ip := make(net.IP, len(baseIP))
	copy(ip, baseIP)

	// Generate random values for the last 64 bits
	for i := 8; i < 16; i++ {
		ip[i] = byte(rand.Intn(256))
	}

	return ip
}

// getNextLocalAddr returns the next IPv6 address to use
func (p *Proxy) getNextLocalAddr() (net.IP, error) {
	if p.config.ProxyProtocol != 6 {
		return p.localAddr, nil
	}

	baseIP := p.localAddr.Mask(net.CIDRMask(64, 128))
	newIP := getRandomIPv6(baseIP)

	// Avoid ::1
	if newIP[15] == 1 {
		newIP[15] = 2
	}

	p.debugLog("Generated IPv6: %s", newIP.String())
	return newIP, nil
}

// dialContext creates a new connection with privacy settings
func (p *Proxy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	p.debugLog("=== New Connection ===")
	p.debugLog("Dialing: network=%s, addr=%s", network, addr)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %v", err)
	}

	// Get next local IP address
	localIP, err := p.getNextLocalAddr()
	if err != nil {
		return nil, fmt.Errorf("failed to get local IP: %v", err)
	}

	// Resolve the host
	resolvedIP, err := p.resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}

	p.debugLog("Local IP: %s, Resolved IP: %s", localIP, resolvedIP)

	// Create dialer with privacy settings
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: localIP},
		Timeout:   30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if p.config.ProxyProtocol == 6 {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 0)
				}
			})
		},
	}

	// Use appropriate network type
	if p.config.ProxyProtocol == 6 {
		network = "tcp6"
		dialer.DualStack = false
	} else {
		network = "tcp4"
	}

	// Connect to target
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
	if err != nil {
		p.debugLog("Connection error: %v", err)
		return nil, err
	}

	p.debugLog("Connection established: %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
	return newPrivacyConn(conn, localIP), nil
}
