package metrics

import (
	"sync"
	"time"
)

// Metrics holds runtime statistics for the proxy
type Metrics struct {
	mu                sync.RWMutex
	startTime         time.Time
	activeConnections int64
	totalConnections  int64
	bytesSent         int64
	bytesReceived     int64
	interfaceName     string
	ipPoolSize        int
	ipsRotated        int64
}

// New creates a new Metrics instance
func New(interfaceName string) *Metrics {
	return &Metrics{
		startTime:     time.Now(),
		interfaceName: interfaceName,
	}
}

// ConnectionStarted increments the connection counters
func (m *Metrics) ConnectionStarted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeConnections++
	m.totalConnections++
}

// ConnectionEnded decrements the active connection counter
func (m *Metrics) ConnectionEnded() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeConnections--
}

// AddBytesSent adds to the bytes sent counter
func (m *Metrics) AddBytesSent(bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytesSent += bytes
}

// AddBytesReceived adds to the bytes received counter
func (m *Metrics) AddBytesReceived(bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytesReceived += bytes
}

// SetIPPoolSize sets the IP pool size
func (m *Metrics) SetIPPoolSize(size int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipPoolSize = size
}

// IncrementIPsRotated increments the IPs rotated counter
func (m *Metrics) IncrementIPsRotated(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipsRotated += count
}

// SetIPsRotated sets the IPs rotated counter to a specific value
func (m *Metrics) SetIPsRotated(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipsRotated = count
}

// GetStats returns current statistics
func (m *Metrics) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return Stats{
		Uptime:            time.Since(m.startTime).String(),
		ActiveConnections: m.activeConnections,
		TotalConnections:  m.totalConnections,
		TotalRequests:     m.totalConnections, // Alias for compatibility with docs
		BytesSent:         m.bytesSent,
		BytesReceived:     m.bytesReceived,
		Interface:         m.interfaceName,
		IPPoolSize:        m.ipPoolSize,
		IPsRotated:        m.ipsRotated,
	}
}

// Stats represents current proxy statistics
type Stats struct {
	Uptime            string `json:"uptime"`
	ActiveConnections int64  `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
	TotalRequests     int64  `json:"total_requests"`
	BytesSent         int64  `json:"bytes_sent"`
	BytesReceived     int64  `json:"bytes_received"`
	Interface         string `json:"interface"`
	IPPoolSize        int    `json:"ip_pool_size"`
	IPsRotated        int64  `json:"ips_rotated"`
}
