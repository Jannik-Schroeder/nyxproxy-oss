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

// handleConnect handles HTTPS CONNECT tunneling
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Parse host and port
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid host format: %v", err), http.StatusBadGateway)
		return
	}

	// Clean all request headers and connection info
	r.Header = make(http.Header)
	r.RemoteAddr = ""
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("X-Forwarded-For", p.localAddr.String())

	// Resolve the host to the correct IP version
	resolvedIP, err := p.resolveHost(r.Context(), host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to resolve host: %v", err), http.StatusBadGateway)
		return
	}

	// Create custom dialer for the target connection with strict socket options
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: p.localAddr,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if p.config.ProxyProtocol == 6 {
					// Force IPv6 only mode
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
					// Set traffic class to 0
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 0)
				}
				// Set IP options to none
				syscall.SetsockoptString(int(fd), syscall.IPPROTO_IP, syscall.IP_OPTIONS, "")
				fmt.Printf("===========================\n")
			})
		},
		Timeout:   30 * time.Second,
		KeepAlive: -1, // Disable keep-alive
	}

	network := "tcp4"
	if p.config.ProxyProtocol == 6 {
		network = "tcp6"
		dialer.DualStack = false
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

	// Send 200 OK with minimal headers
	response := []string{
		"HTTP/1.1 200 Connection Established",
		"Proxy-Agent: NyxProxy",
		"X-Forwarded-For: " + p.localAddr.String(),
		"",
		"",
	}
	_, err = clientConn.Write([]byte(strings.Join(response, "\r\n")))
	if err != nil {
		return
	}

	// Create a clean pipe with buffer and privacy wrapper
	clientReader := io.Reader(clientConn)
	clientWriter := io.Writer(clientConn)
	targetReader := io.Reader(newPrivacyConn(targetConn, p.localAddr))
	targetWriter := io.Writer(newPrivacyConn(targetConn, p.localAddr))

	// Start bidirectional copy with clean pipe
	done := make(chan bool, 2)
	go func() {
		io.Copy(targetWriter, clientReader)
		done <- true
	}()
	go func() {
		io.Copy(clientWriter, targetReader)
		done <- true
	}()

	// Wait for either direction to finish
	<-done
}

// handleHTTP handles regular HTTP requests
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("\n=== Incoming Request Debug ===\n")
	fmt.Printf("Original Request Headers:\n")
	for k, v := range r.Header {
		fmt.Printf("  %s: %v\n", k, v)
	}
	fmt.Printf("RemoteAddr: %s\n", r.RemoteAddr)
	fmt.Printf("Method: %s\n", r.Method)
	fmt.Printf("Host: %s\n", r.Host)
	fmt.Printf("URL: %s\n", r.URL)
	fmt.Printf("===========================\n")

	// Ensure the request has a valid URL with scheme
	if !strings.HasPrefix(r.URL.String(), "http://") && !strings.HasPrefix(r.URL.String(), "https://") {
		r.URL, _ = url.Parse("http://" + r.Host + r.URL.String())
	}

	// Create a completely new request with zero client information
	newReq := &http.Request{
		Method:        r.Method,
		URL:           r.URL,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Host:          r.Host,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		RemoteAddr:    "",
		Close:         false,
	}

	// Set minimal headers with no identifying information
	newReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	newReq.Header.Set("Accept", "*/*")
	newReq.Header.Set("Accept-Encoding", "identity")
	// Remove all forwarding headers
	newReq.Header.Del("X-Forwarded-For")
	newReq.Header.Del("X-Real-IP")
	newReq.Header.Del("Forwarded")
	newReq.Header.Del("Via")
	newReq.Header.Del("Proxy-Connection")
	newReq.Header.Del("Connection")
	newReq.Header.Del("Upgrade-Insecure-Requests")
	newReq.Header.Del("DNT")
	newReq.Header.Del("Cache-Control")

	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		newReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		newReq.Header.Set("Content-Length", r.Header.Get("Content-Length"))
	}

	fmt.Printf("\n=== Modified Request Debug ===\n")
	fmt.Printf("New Request Headers:\n")
	for k, v := range newReq.Header {
		fmt.Printf("  %s: %v\n", k, v)
	}
	fmt.Printf("New RemoteAddr: %s\n", newReq.RemoteAddr)
	fmt.Printf("===========================\n")

	// Create custom transport with strict privacy settings
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

	// Create the proxy handler with strict response modification
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			*req = *newReq
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			fmt.Printf("\n=== Response Debug ===\n")
			fmt.Printf("Original Response Headers:\n")
			for k, v := range resp.Header {
				fmt.Printf("  %s: %v\n", k, v)
			}

			// Create completely new headers
			newHeaders := make(http.Header)

			// Copy only essential headers
			if resp.ContentLength > 0 {
				newHeaders.Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
			}
			if ctype := resp.Header.Get("Content-Type"); ctype != "" {
				newHeaders.Set("Content-Type", ctype)
			}

			// Set privacy-enhancing headers
			newHeaders.Set("X-Frame-Options", "DENY")
			newHeaders.Set("X-Content-Type-Options", "nosniff")
			newHeaders.Set("X-XSS-Protection", "1; mode=block")
			newHeaders.Set("Referrer-Policy", "no-referrer")
			newHeaders.Set("Server", "")

			// Remove all forwarding headers
			newHeaders.Del("X-Forwarded-For")
			newHeaders.Del("X-Real-IP")
			newHeaders.Del("Forwarded")
			newHeaders.Del("Via")

			// Replace all headers with our clean set
			resp.Header = newHeaders

			fmt.Printf("\nModified Response Headers:\n")
			for k, v := range resp.Header {
				fmt.Printf("  %s: %v\n", k, v)
			}
			fmt.Printf("===========================\n")

			return nil
		},
	}

	proxy.ServeHTTP(w, r)
}

// privacyConn wraps a net.Conn to ensure privacy
type privacyConn struct {
	net.Conn
	localIP net.IP
}

func newPrivacyConn(conn net.Conn, localIP net.IP) *privacyConn {
	return &privacyConn{
		Conn:    conn,
		localIP: localIP,
	}
}

func (pc *privacyConn) Read(b []byte) (n int, err error) {
	// Read from the underlying connection
	n, err = pc.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	// Only process if it looks like text data
	if !isTextData(b[:n]) {
		return n, nil
	}

	// Create a copy of the buffer to work with
	buf := make([]byte, n)
	copy(buf, b[:n])

	// Process the data to remove any potential IP leaks
	content := string(buf)
	content = pc.sanitizeContent(content)

	// Copy back to the buffer, ensuring we don't exceed the buffer size
	processed := []byte(content)
	if len(processed) > len(b) {
		processed = processed[:len(b)]
	}
	n = copy(b, processed)
	return n, nil
}

func (pc *privacyConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Only process if it looks like text data
	if !isTextData(b) {
		return pc.Conn.Write(b)
	}

	// Create a copy of the data to work with
	buf := make([]byte, len(b))
	copy(buf, b)

	// Process the data to remove any potential IP leaks
	content := string(buf)
	content = pc.sanitizeContent(content)

	// Write the processed data
	processed := []byte(content)
	written := 0
	for written < len(processed) {
		n, err := pc.Conn.Write(processed[written:])
		if err != nil {
			if written == 0 {
				return 0, err
			}
			return written, err
		}
		written += n
	}
	return len(b), nil
}

// isTextData checks if the data looks like text
func isTextData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for common HTTP patterns
	if bytes.Contains(data, []byte("HTTP/")) ||
		bytes.Contains(data, []byte("Host:")) ||
		bytes.Contains(data, []byte("User-Agent:")) {
		return true
	}

	// Count printable characters
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.85
}

func (pc *privacyConn) sanitizeContent(content string) string {
	// Remove any IP addresses except our local IP
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)

	content = ipv4Regex.ReplaceAllStringFunc(content, func(ip string) string {
		if ip == pc.localIP.String() {
			return ip
		}
		return ""
	})

	content = ipv6Regex.ReplaceAllStringFunc(content, func(ip string) string {
		if ip == pc.localIP.String() {
			return ip
		}
		return ""
	})

	// Remove sensitive headers
	headers := []string{
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
	}

	for _, header := range headers {
		content = removeHeader(content, header)
	}

	return content
}

func removeHeader(content, header string) string {
	pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(header) + `:[^\r\n]*\r?\n?`)
	return pattern.ReplaceAllString(content, "")
}

func (pc *privacyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: pc.localIP, Port: 0}
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
	// Make a copy of the base IP
	ip := make(net.IP, len(baseIP))
	copy(ip, baseIP)

	// Generate random values for the last 64 bits (8 bytes)
	for i := 8; i < 16; i++ {
		ip[i] = byte(rand.Intn(256))
	}

	return ip
}

// getNextLocalAddr returns the next IPv6 address to use
func (p *Proxy) getNextLocalAddr() net.IP {
	if p.config.ProxyProtocol != 6 {
		return p.localAddr
	}

	// Get base /64 subnet
	baseIP := p.localAddr.Mask(net.CIDRMask(64, 128))
	return getRandomIPv6(baseIP)
}

// DialContext creates a new connection with privacy settings
func (p *Proxy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	fmt.Printf("\n=== Connection Debug ===\n")
	fmt.Printf("Dialing: network=%s, addr=%s\n", network, addr)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %v", err)
	}

	// Get next local IP address
	localIP := p.getNextLocalAddr()
	fmt.Printf("Using Local IP: %s\n", localIP)
	fmt.Printf("Protocol: IPv%d\n", p.config.ProxyProtocol)

	// Resolve the host to the correct IP version
	resolvedIP, err := p.resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Resolved IP: %s\n", resolvedIP)

	// Create a dialer with strict privacy settings
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: localIP,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				fmt.Printf("\n=== Socket Options Debug ===\n")
				if p.config.ProxyProtocol == 6 {
					// Force IPv6 only mode
					err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
					fmt.Printf("Setting IPV6_V6ONLY=1: %v\n", err)
					// Set traffic class to 0
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 0)
					fmt.Printf("Setting IPV6_TCLASS=0: %v\n", err)
				}
				// Set IP options to none
				err := syscall.SetsockoptString(int(fd), syscall.IPPROTO_IP, syscall.IP_OPTIONS, "")
				fmt.Printf("Setting IP_OPTIONS='': %v\n", err)
				fmt.Printf("===========================\n")
			})
		},
		Timeout:   30 * time.Second,
		KeepAlive: -1, // Disable keep-alive completely
	}

	network = "tcp4"
	if p.config.ProxyProtocol == 6 {
		network = "tcp6"
		dialer.DualStack = false
	}

	// Connect directly to the target
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolvedIP, port))
	if err != nil {
		fmt.Printf("Connection error: %v\n", err)
		return nil, err
	}
	fmt.Printf("Connection established: %s -> %s\n", conn.LocalAddr(), conn.RemoteAddr())
	fmt.Printf("===========================\n")

	// Wrap the connection with our privacy layer
	return newPrivacyConn(conn, localIP), nil
}
