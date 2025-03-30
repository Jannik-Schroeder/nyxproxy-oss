package https

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/phanes/nyxtrace/nyxproxy-core/internal/config"
)

// Proxy represents an HTTPS proxy server
type Proxy struct {
	config     *config.ProxyConfig
	httpServer *http.Server
}

// NewProxy creates a new HTTPS proxy server
func NewProxy(cfg *config.ProxyConfig) (*Proxy, error) {
	proxy := &Proxy{
		config: cfg,
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
	// Create custom dialer for the target connection
	dialer := &net.Dialer{}
	network := "tcp4"
	if p.config.ProxyProtocol == 6 {
		network = "tcp6"
		dialer.DualStack = false // Force IPv6 only
	}

	// Connect to the target server
	targetConn, err := dialer.DialContext(r.Context(), network, r.Host)
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
	// Create custom transport for the proxy
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			if p.config.ProxyProtocol == 6 {
				network = "tcp6"
				dialer.DualStack = false
			} else {
				network = "tcp4"
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	// Create the proxy handler
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if p.config.UpstreamURL != "" {
				target, err := url.Parse(p.config.UpstreamURL)
				if err != nil {
					return
				}
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
			}
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
