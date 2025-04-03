package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/phanes/nyxtrace/nyxproxy-core/internal/config"
	"github.com/phanes/nyxtrace/nyxproxy-core/pkg/https"
	"github.com/phanes/nyxtrace/nyxproxy-core/pkg/socks5"
	"github.com/phanes/nyxtrace/nyxproxy-core/pkg/version"
)

const (
	heartbeatInterval = 60 * time.Second
	heartbeatTimeout  = 10 * time.Second
)

func main() {
	// Version flag
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Println("NyxProxy Core", version.GetVersionInfo())
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Start heartbeat sender in a background goroutine
	go startHeartbeatSender(cfg)

	// Create proxy based on type
	var proxy interface {
		Start() error
	}

	switch cfg.ProxyType {
	case "socks5":
		proxy, err = socks5.NewProxy(cfg)
	case "https":
		proxy, err = https.NewProxy(cfg)
	default:
		log.Fatalf("Unsupported proxy type: %s", cfg.ProxyType)
	}

	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start proxy in a goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("Starting %s proxy on %s:%d (Protocol: IPv%d)",
			cfg.ProxyType,
			cfg.ListenAddress,
			cfg.ListenPort,
			cfg.ProxyProtocol)

		if err := proxy.Start(); err != nil {
			errChan <- fmt.Errorf("proxy error: %v", err)
		}
	}()

	// Wait for signal or error
	select {
	case <-sigChan:
		log.Println("Received shutdown signal")
	case err := <-errChan:
		log.Printf("Error: %v", err)
	}

	// If the proxy implements Stop(), call it
	if stoppable, ok := proxy.(interface{ Stop() error }); ok {
		if err := stoppable.Stop(); err != nil {
			log.Printf("Error stopping proxy: %v", err)
		}
	}
}

// startHeartbeatSender sends periodic heartbeats to the NyxTrace API
func startHeartbeatSender(cfg *config.ProxyConfig) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	// Create a reusable HTTP client
	client := &http.Client{
		Timeout: heartbeatTimeout,
	}

	heartbeatUrl := fmt.Sprintf("%s/api/v1/health/heartbeat", cfg.NyxTraceApiUrl)
	bearerToken := fmt.Sprintf("Bearer %s", cfg.HealthCheckToken)

	log.Printf("Starting heartbeat sender for proxy %s to %s every %s", cfg.ProxyId, heartbeatUrl, heartbeatInterval)

	for {
		<-ticker.C // Wait for the next tick

		// Prepare request body
		body := map[string]string{"proxyId": cfg.ProxyId}
		jsonBody, err := json.Marshal(body)
		if err != nil {
			log.Printf("Heartbeat Error: Failed to marshal request body: %v", err)
			continue // Skip this tick
		}

		// Create request
		req, err := http.NewRequest("POST", heartbeatUrl, bytes.NewBuffer(jsonBody))
		if err != nil {
			log.Printf("Heartbeat Error: Failed to create request: %v", err)
			continue // Skip this tick
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", bearerToken)

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Heartbeat Error: Failed to send request to %s: %v", heartbeatUrl, err)
			continue // Skip this tick
		}

		// Check response status
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if cfg.DebugLevel > 0 { // Log success only if debug enabled
				log.Printf("Heartbeat sent successfully for proxy %s (Status: %d)", cfg.ProxyId, resp.StatusCode)
			}
		} else {
			log.Printf("Heartbeat Error: Received non-success status code %d from %s", resp.StatusCode, heartbeatUrl)
			// Optionally read response body for more details if needed
			// bodyBytes, _ := io.ReadAll(resp.Body)
			// log.Printf("Heartbeat Error Body: %s", string(bodyBytes))
		}

		resp.Body.Close() // Important to close the response body
	}
}
