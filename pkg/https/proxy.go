package https

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"encoding/base64"

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

// debugLog prints debug messages based on debug level
func (p *Proxy) debugLog(level int, format string, args ...interface{}) {
	if p.config.DebugLevel >= level {
		fmt.Printf(format+"\n", args...)
	}
}

// sanitizeHeaders removes sensitive information from headers
func sanitizeHeaders(headers http.Header) http.Header {
	clean := make(http.Header)
	for k, v := range headers {
		switch strings.ToLower(k) {
		case "proxy-connection", "connection", "keep-alive", "proxy-authenticate",
			"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			continue
		default:
			clean[k] = v
		}
	}
	return clean
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
func NewProxy(cfg *config.ProxyConfig) (*Proxy, error) {
	rand.Seed(time.Now().UnixNano())

	// Get local address for outbound connections
	localAddr, err := getOutboundIP(cfg.ProxyProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to get outbound IP: %v", err)
	}

	// Create proxy instance
	proxy := &Proxy{
		config:    cfg,
		localAddr: localAddr,
		resolver:  &net.Resolver{},
	}

	// Configure HTTP server
	proxy.httpServer = &http.Server{
		Addr:    net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.ListenPort)),
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

// checkAuth verifies the proxy authentication
func (p *Proxy) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}

	return credentials[0] == "proxy" && credentials[1] == p.config.Password
}

// requireAuth sends a proxy authentication required response
func (p *Proxy) requireAuth(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"NyxProxy\"")
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}

// ServeHTTP implements the http.Handler interface
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check authentication first
	if !p.checkAuth(r) {
		p.requireAuth(w)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// bodyReader wraps an io.Reader with privacy features
type bodyReader struct {
	r       io.Reader
	localIP net.IP
	buf     []byte
}

func (br *bodyReader) Read(p []byte) (n int, err error) {
	n, err = br.r.Read(p)
	if err != nil || n == 0 {
		return n, err
	}

	if isTextData(p[:n]) {
		copy(br.buf, p[:n])
		content := sanitizeContent(string(br.buf[:n]), br.localIP)
		return copy(p, content), nil
	}

	return n, nil
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
		buf:     make([]byte, 32*1024),
	}
}

func (pc *privacyConn) Read(b []byte) (n int, err error) {
	n, err = pc.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	if isTextData(b[:n]) {
		copy(pc.buf, b[:n])
		content := sanitizeContent(string(pc.buf[:n]), pc.localIP)
		return copy(b, content), nil
	}

	return n, nil
}

func (pc *privacyConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if isTextData(b) {
		content := sanitizeContent(string(b), pc.localIP)
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

func (pc *privacyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: pc.localIP}
}

// privacyReader wraps an io.Reader with privacy features
type privacyReader struct {
	r       io.Reader
	localIP net.IP
	buf     []byte
}

func (pr *privacyReader) Read(p []byte) (n int, err error) {
	n, err = pr.r.Read(p)
	if err != nil || n == 0 {
		return n, err
	}

	if isTextData(p[:n]) {
		copy(pr.buf, p[:n])
		content := sanitizeContent(string(pr.buf[:n]), pr.localIP)
		return copy(p, content), nil
	}

	return n, nil
}

// sanitizeContent removes sensitive information from text content
func sanitizeContent(content string, localIP net.IP) string {
	// Remove IP addresses except our local IP
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	content = ipv4Regex.ReplaceAllStringFunc(content, func(ip string) string {
		if ip == localIP.String() {
			return ip
		}
		return "0.0.0.0"
	})

	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	content = ipv6Regex.ReplaceAllStringFunc(content, func(ip string) string {
		if ip == localIP.String() {
			return ip
		}
		return "::1"
	})

	// Remove headers
	for _, header := range sensitiveHeaders {
		pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(header) + `:[^\r\n]*\r?\n?`)
		content = pattern.ReplaceAllString(content, "")
	}

	return content
}

// simpleConn wraps a net.Conn with basic privacy features
type simpleConn struct {
	net.Conn
	localIP net.IP
}

func (sc *simpleConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: sc.localIP}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.debugLog(2, "Handling HTTP request: %s %s", r.Method, r.URL)

	if !strings.HasPrefix(r.URL.String(), "http://") && !strings.HasPrefix(r.URL.String(), "https://") {
		r.URL, _ = url.Parse("http://" + r.Host + r.URL.String())
	}

	localIP, err := p.getNextLocalAddr()
	if err != nil {
		http.Error(w, "Failed to get local IP", http.StatusInternalServerError)
		return
	}

	p.debugLog(2, "Using local IP: %s", localIP)

	outReq := &http.Request{
		Method:        r.Method,
		URL:           r.URL,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        sanitizeHeaders(r.Header),
		Body:          r.Body,
		ContentLength: r.ContentLength,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				LocalAddr: &net.TCPAddr{IP: localIP},
				Timeout:   30 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					return c.Control(func(fd uintptr) {
						if p.config.ProxyProtocol == 6 {
							syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
						}
					})
				},
			}

			if p.config.ProxyProtocol == 6 {
				network = "tcp6"
			} else {
				network = "tcp4"
			}

			p.debugLog(2, "Dialing: %s %s", network, addr)
			return dialer.DialContext(ctx, network, addr)
		},
		DisableKeepAlives:  true,
		DisableCompression: true,
		MaxIdleConns:       -1,
	}

	resp, err := (&http.Client{Transport: transport}).Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range sanitizeHeaders(resp.Header) {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleConnect handles HTTPS CONNECT tunneling
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	p.debugLog(2, "Handling CONNECT request: %s", r.Host)

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "Invalid host", http.StatusBadGateway)
		return
	}

	localIP, err := p.getNextLocalAddr()
	if err != nil {
		http.Error(w, "Failed to get local IP", http.StatusInternalServerError)
		return
	}

	p.debugLog(2, "Using local IP: %s", localIP)

	targetConn, err := (&net.Dialer{
		LocalAddr: &net.TCPAddr{IP: localIP},
		Timeout:   30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if p.config.ProxyProtocol == 6 {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
				}
			})
		},
	}).Dial(func() string {
		if p.config.ProxyProtocol == 6 {
			return "tcp6"
		}
		return "tcp4"
	}(), net.JoinHostPort(host, port))

	if err != nil {
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	w.WriteHeader(http.StatusOK)

	clientConn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	done := make(chan bool, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		targetConn.(*net.TCPConn).CloseWrite()
		done <- true
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		clientConn.(*net.TCPConn).CloseWrite()
		done <- true
	}()

	<-done
	<-done
}

// Start starts the HTTPS proxy server
func (p *Proxy) Start() error {
	addr := fmt.Sprintf("%s:%d", p.config.ListenAddress, p.config.ListenPort)
	p.debugLog(1, "Starting https proxy on %s (Protocol: IPv%d)", addr, p.config.ProxyProtocol)

	return p.httpServer.ListenAndServe()
}

// Stop gracefully stops the HTTPS proxy server
func (p *Proxy) Stop() error {
	return p.httpServer.Close()
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
