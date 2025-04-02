package version

// Version information
var (
	// Version holds the current version number
	Version = "0.1.0"

	// Commit holds the current git commit hash
	Commit = "unknown"

	// BuildTime holds the build timestamp
	BuildTime = "unknown"
)

// GetVersionInfo returns a formatted string with version information
func GetVersionInfo() string {
	return Version + " (commit: " + Commit + ", built at: " + BuildTime + ")"
}
