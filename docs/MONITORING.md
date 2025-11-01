# Monitoring Guide

NyxProxy-OSS includes built-in monitoring capabilities through HTTP endpoints. This guide covers how to use and integrate with monitoring tools.

## Overview

The monitoring server provides three main endpoints:

- `/health` - Health check and uptime
- `/stats` - Connection and bandwidth statistics
- `/config` - Current configuration (sanitized)

## Enabling Monitoring

Enable monitoring in your `config.yaml`:

```yaml
monitoring:
  enabled: true
  port: 9090
  allow_remote: false  # Only accessible from localhost
```

Or via environment variables:

```bash
export MONITORING_ENABLED=true
export MONITORING_PORT=9090
export MONITORING_ALLOW_REMOTE=false
```

## Endpoints

### GET /health

Health check endpoint for uptime monitoring.

**Request**:
```bash
curl http://localhost:9090/health
```

**Response**:
```json
{
  "status": "ok",
  "uptime": "5h23m15s",
  "version": "1.0.0"
}
```

**Response Fields**:
- `status` - Always "ok" if the server is running
- `uptime` - How long the proxy has been running
- `version` - Current version of NyxProxy-OSS

**Use Cases**:
- Docker health checks
- Kubernetes liveness probes
- Uptime monitoring services

### GET /stats

Statistics about proxy usage.

**Request**:
```bash
curl http://localhost:9090/stats
```

**Response**:
```json
{
  "uptime": "5h23m15s",
  "active_connections": 12,
  "total_connections": 4523,
  "bytes_sent": 1048576000,
  "bytes_received": 524288000,
  "interface": "eth0"
}
```

**Response Fields**:
- `uptime` - How long the proxy has been running
- `active_connections` - Currently active proxy connections
- `total_connections` - Total connections since startup
- `bytes_sent` - Total bytes sent through the proxy
- `bytes_received` - Total bytes received through the proxy
- `interface` - Network interface being used (or "auto-detect")

**Use Cases**:
- Performance monitoring
- Capacity planning
- Usage analytics
- Billing/metering

### GET /config

Current proxy configuration (passwords excluded).

**Request**:
```bash
curl http://localhost:9090/config
```

**Response**:
```json
{
  "proxy": {
    "type": "socks5",
    "listen_address": "0.0.0.0",
    "listen_port": 1080,
    "username": "admin"
  },
  "network": {
    "interface_name": "eth0",
    "ipv4_enabled": true,
    "ipv6_enabled": false
  },
  "monitoring": {
    "enabled": true,
    "port": 9090,
    "allow_remote": false
  },
  "logging": {
    "debug_level": 1
  }
}
```

**Security Note**: Passwords are never exposed through this endpoint.

**Use Cases**:
- Configuration verification
- Debugging
- Automated configuration management

## Integration Examples

### Prometheus

Example `prometheus.yml` configuration:

```yaml
scrape_configs:
  - job_name: 'nyxproxy'
    metrics_path: '/stats'
    static_configs:
      - targets: ['localhost:9090']
```

**Note**: Currently, the stats are in JSON format. For native Prometheus metrics, you can use a JSON exporter or the planned future support for Prometheus format.

### Docker Health Check

Add to your `Dockerfile`:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:9090/health || exit 1
```

Or in `docker-compose.yml`:

```yaml
services:
  nyxproxy:
    image: nyxproxy-oss
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9090/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
```

### Kubernetes

Liveness and readiness probes:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nyxproxy
spec:
  containers:
  - name: nyxproxy
    image: nyxproxy-oss:latest
    livenessProbe:
      httpGet:
        path: /health
        port: 9090
      initialDelaySeconds: 5
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /health
        port: 9090
      initialDelaySeconds: 5
      periodSeconds: 5
```

### Grafana Dashboard

Create a JSON API data source pointing to `http://localhost:9090/stats` and use the following queries:

- Active Connections: `$.active_connections`
- Total Connections: `$.total_connections`
- Bytes Sent: `$.bytes_sent`
- Bytes Received: `$.bytes_received`

### Custom Monitoring Script

Simple bash script to check stats:

```bash
#!/bin/bash

STATS=$(curl -s http://localhost:9090/stats)

ACTIVE=$(echo $STATS | jq -r '.active_connections')
TOTAL=$(echo $STATS | jq -r '.total_connections')
SENT=$(echo $STATS | jq -r '.bytes_sent')
RECEIVED=$(echo $STATS | jq -r '.bytes_received')

echo "=== NyxProxy Stats ==="
echo "Active: $ACTIVE"
echo "Total: $TOTAL"
echo "Sent: $(numfmt --to=iec-i --suffix=B $SENT)"
echo "Received: $(numfmt --to=iec-i --suffix=B $RECEIVED)"
```

### Systemd Service with Health Monitoring

```ini
[Unit]
Description=NyxProxy-OSS
After=network.target

[Service]
Type=simple
User=proxy
Group=proxy
WorkingDirectory=/opt/nyxproxy
ExecStart=/opt/nyxproxy/nyxproxy
ExecStartPost=/bin/sleep 2
ExecStartPost=/usr/bin/curl -f http://localhost:9090/health
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Security Considerations

### Local Only Access (Default)

By default, monitoring endpoints are only accessible from localhost (127.0.0.1):

```yaml
monitoring:
  allow_remote: false
```

This is secure for most use cases where monitoring runs on the same host.

### Remote Access

If you need remote access for monitoring:

```yaml
monitoring:
  allow_remote: true
```

**Recommendations when enabling remote access**:

1. **Firewall Rules**: Restrict access to specific monitoring IPs
   ```bash
   # Allow only from monitoring server
   sudo ufw allow from 10.0.0.100 to any port 9090
   ```

2. **Reverse Proxy**: Put the monitoring endpoint behind a reverse proxy with authentication
   ```nginx
   location /nyxproxy/ {
       auth_basic "Monitoring";
       auth_basic_user_file /etc/nginx/.htpasswd;
       proxy_pass http://localhost:9090/;
   }
   ```

3. **VPN**: Access monitoring only through a VPN

4. **Network Isolation**: Run monitoring on a separate management network

## Troubleshooting

### Monitoring Server Not Starting

Check the logs for errors:

```bash
./nyxproxy 2>&1 | grep -i monitoring
```

Common issues:
- Port already in use
- Permission denied (ports < 1024 require root)

### Can't Access Monitoring Endpoints

1. Check if monitoring is enabled:
   ```bash
   curl http://localhost:9090/config | jq '.monitoring'
   ```

2. Verify the port:
   ```bash
   netstat -tlnp | grep 9090
   # or
   ss -tlnp | grep 9090
   ```

3. Check firewall rules:
   ```bash
   sudo ufw status
   # or
   sudo iptables -L
   ```

### Remote Access Not Working

Ensure `allow_remote` is enabled and restart the proxy:

```yaml
monitoring:
  allow_remote: true
```

Then test from the remote host:

```bash
curl http://<proxy-ip>:9090/health
```

## Planned Features

Future versions may include:

- **Prometheus Native Format**: Direct Prometheus metrics endpoint (`/metrics`)
- **Webhook Alerts**: Send alerts when thresholds are exceeded
- **Historical Data**: Store and query historical statistics
- **Per-Connection Stats**: Detailed per-connection metrics
- **Authentication**: Optional authentication for monitoring endpoints

## Best Practices

1. **Regular Health Checks**: Poll `/health` every 30-60 seconds
2. **Stats Collection**: Collect `/stats` every 1-5 minutes
3. **Alerting**: Set up alerts for:
   - Proxy down (health check fails)
   - High connection count
   - Unusual bandwidth usage
4. **Log Monitoring**: Monitor proxy logs for errors
5. **Resource Monitoring**: Monitor CPU, memory, and network I/O of the proxy process

## Example Monitoring Stack

Complete monitoring setup with Prometheus, Grafana, and Alertmanager:

```yaml
# docker-compose.yml
version: '3.8'

services:
  nyxproxy:
    build: .
    ports:
      - "1080:1080"
      - "9090:9090"
    volumes:
      - ./config.yaml:/app/config.yaml

  prometheus:
    image: prom/prometheus
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana

volumes:
  prometheus-data:
  grafana-data:
```

This provides a complete monitoring solution for NyxProxy-OSS.
