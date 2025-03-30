package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nyxproxy-core/pkg/proxy"
)

func main() {
	// Create proxy configuration
	config := proxy.NewConfig()

	// Create and start proxy
	proxyServer := proxy.New(config)

	// Handle shutdown gracefully
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := proxyServer.Start(); err != nil {
			log.Printf("Error starting proxy server: %v", err)
			stop <- os.Interrupt
		}
	}()

	// Wait for interrupt signal
	<-stop
	log.Println("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := proxyServer.Stop(ctx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}
