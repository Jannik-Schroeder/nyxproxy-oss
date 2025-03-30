package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// Proxy represents the HTTP proxy server
type Proxy struct {
	config *Config
	server *http.Server
}

// New creates a new proxy instance
func New(config *Config) *Proxy {
	return &Proxy{
		config: config,
	}
}

// Start starts the proxy server
func (p *Proxy) Start() error {
	p.server = &http.Server{
		Addr:         p.config.ListenAddr,
		Handler:      p,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf("Starting proxy server on %s\n", p.config.ListenAddr)
	return p.server.ListenAndServe()
}

// Stop gracefully stops the proxy server
func (p *Proxy) Stop(ctx context.Context) error {
	if p.server != nil {
		return p.server.Shutdown(ctx)
	}
	return nil
}

// ServeHTTP implements the http.Handler interface
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleTunneling handles HTTPS tunneling
func (p *Proxy) handleTunneling(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go p.transfer(destConn, clientConn)
	go p.transfer(clientConn, destConn)
}

// transfer handles the bidirectional copy of data
func (p *Proxy) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

// handleHTTP handles regular HTTP requests
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// The URL is already properly set by the client's proxy request
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("X-Proxy-Server", "nyxproxy-core")
			return nil
		},
	}
	proxy.ServeHTTP(w, r)
}
