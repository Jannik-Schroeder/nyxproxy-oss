package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/phanes/nyxtrace/nyxproxy-core/internal/config"
	"github.com/phanes/nyxtrace/nyxproxy-core/pkg/https"
	"github.com/phanes/nyxtrace/nyxproxy-core/pkg/socks5"
	"github.com/phanes/nyxtrace/nyxproxy-core/pkg/version"
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
