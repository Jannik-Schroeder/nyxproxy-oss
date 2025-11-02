package network

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// CheckNdppdService checks if ndppd service is running (Linux only)
// Returns nil if running or if not on Linux, error otherwise
func CheckNdppdService() error {
	// Only check on Linux
	if runtime.GOOS != "linux" {
		return nil
	}

	// Check if systemctl is available
	if _, err := exec.LookPath("systemctl"); err != nil {
		// systemctl not available, skip check
		return nil
	}

	// Check if ndppd service is active
	cmd := exec.Command("systemctl", "is-active", "ndppd")
	output, err := cmd.Output()

	if err != nil {
		// Service is not active
		return fmt.Errorf("ndppd service is not running\n" +
			"IPv6 rotation requires ndppd to be running.\n" +
			"To set up ndppd, run: sudo ./scripts/setup-ipv6-rotation.sh\n" +
			"Or start it manually: sudo systemctl start ndppd")
	}

	status := strings.TrimSpace(string(output))
	if status != "active" {
		return fmt.Errorf("ndppd service status: %s (expected: active)\n"+
			"Start it with: sudo systemctl start ndppd", status)
	}

	return nil
}

// WarnIfNdppdNotRunning checks ndppd and prints a warning if not running
// This is a non-fatal check that just warns the user
func WarnIfNdppdNotRunning() {
	if err := CheckNdppdService(); err != nil {
		fmt.Printf("⚠️  WARNING: %v\n\n", err)
	}
}
