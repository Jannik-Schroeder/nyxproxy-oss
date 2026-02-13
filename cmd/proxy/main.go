package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jannik-schroeder/nyxproxy-oss/internal/config"
	"github.com/jannik-schroeder/nyxproxy-oss/pkg/https"
	"github.com/jannik-schroeder/nyxproxy-oss/pkg/metrics"
	"github.com/jannik-schroeder/nyxproxy-oss/pkg/monitoring"
	"github.com/jannik-schroeder/nyxproxy-oss/pkg/network"
	"github.com/jannik-schroeder/nyxproxy-oss/pkg/socks5"
	"github.com/jannik-schroeder/nyxproxy-oss/pkg/version"
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

	// Create metrics collector
	interfaceName := cfg.Network.InterfaceName
	if interfaceName == "" {
		interfaceName = "auto-detect"
	}
	metricsCollector := metrics.New(interfaceName)

	// Start monitoring server if enabled
	if cfg.Monitoring.Enabled {
		monitoringServer := monitoring.New(cfg, metricsCollector, version.GetVersionInfo())
		go func() {
			if err := monitoringServer.Start(); err != nil && err != http.ErrServerClosed {
				log.Printf("Monitoring server error: %v", err)
			}
		}()
	}

	// Create proxy based on type
	var proxy interface {
		Start() error
	}

	switch cfg.GetProxyType() {
	case "socks5":
		proxy, err = socks5.NewProxy(cfg)
	case "https":
		proxy, err = https.NewProxy(cfg)
	default:
		log.Fatalf("Unsupported proxy type: %s", cfg.GetProxyType())
	}

	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Start a goroutine to periodically update IPv6 stats in metrics
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			var mgr *network.IPv6Manager
			switch cfg.GetProxyType() {
			case "socks5":
				mgr = socks5.GetIPv6Manager()
			case "https":
				mgr = https.GetIPv6Manager()
			}
			if mgr != nil {
				metricsCollector.SetIPPoolSize(mgr.GetPoolSize())
				metricsCollector.SetIPsRotated(mgr.GetTotalRotated())
			}
		}
	}()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start proxy in a goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("Starting %s proxy on %s:%d (Protocol: IPv%d)",
			cfg.GetProxyType(),
			cfg.GetListenAddress(),
			cfg.GetListenPort(),
			cfg.GetProxyProtocol())

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
