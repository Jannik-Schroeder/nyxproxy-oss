package monitoring

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/jannik-schroeder/nyxproxy-oss/internal/config"
	"github.com/jannik-schroeder/nyxproxy-oss/pkg/metrics"
)

// Server represents the monitoring HTTP server
type Server struct {
	config  *config.ProxyConfig
	metrics *metrics.Metrics
	server  *http.Server
	version string
}

// New creates a new monitoring server
func New(cfg *config.ProxyConfig, m *metrics.Metrics, version string) *Server {
	return &Server{
		config:  cfg,
		metrics: m,
		version: version,
	}
}

// Start starts the monitoring server
func (s *Server) Start() error {
	if !s.config.Monitoring.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/config", s.handleConfig)

	// Determine listen address
	listenAddr := "127.0.0.1"
	if s.config.Monitoring.AllowRemote {
		listenAddr = "0.0.0.0"
	}

	addr := net.JoinHostPort(listenAddr, fmt.Sprintf("%d", s.config.Monitoring.Port))

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("Starting monitoring server on %s", addr)

	return s.server.ListenAndServe()
}

// Stop stops the monitoring server
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := s.metrics.GetStats()

	response := map[string]interface{}{
		"status":  "ok",
		"uptime":  stats.Uptime,
		"version": s.version,
	}

	json.NewEncoder(w).Encode(response)
}

// handleStats handles statistics requests
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := s.metrics.GetStats()
	json.NewEncoder(w).Encode(stats)
}

// handleConfig handles configuration requests (sanitized)
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"proxy": map[string]interface{}{
			"type":           s.config.GetProxyType(),
			"listen_address": s.config.GetListenAddress(),
			"listen_port":    s.config.GetListenPort(),
			"username":       s.config.GetUsername(),
		},
		"network": map[string]interface{}{
			"interface_name": s.config.Network.InterfaceName,
			"ipv4_enabled":   s.config.Network.IPv4Enabled,
			"ipv6_enabled":   s.config.Network.IPv6Enabled,
		},
		"monitoring": map[string]interface{}{
			"enabled":      s.config.Monitoring.Enabled,
			"port":         s.config.Monitoring.Port,
			"allow_remote": s.config.Monitoring.AllowRemote,
		},
		"logging": map[string]interface{}{
			"debug_level": s.config.GetDebugLevel(),
		},
	}

	json.NewEncoder(w).Encode(response)
}
