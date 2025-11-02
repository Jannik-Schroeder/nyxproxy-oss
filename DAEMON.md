# Running NyxProxy as a System Service (Daemon)

This guide explains how to run NyxProxy as a systemd service that starts automatically on boot.

---

## 📋 Table of Contents

- [Why Run as a Service?](#why-run-as-a-service)
- [Automated Installation](#automated-installation)
- [Manual Installation](#manual-installation)
- [Service Management](#service-management)
- [Logs and Monitoring](#logs-and-monitoring)
- [Troubleshooting](#troubleshooting)
- [Uninstalling](#uninstalling)

---

## 🎯 Why Run as a Service?

Running NyxProxy as a systemd service provides:

- ✅ **Auto-start on boot** - NyxProxy starts automatically when your server boots
- ✅ **Auto-restart on failure** - Automatically restarts if it crashes
- ✅ **Centralized logging** - Logs are managed by systemd/journald
- ✅ **Easy management** - Standard `systemctl` commands
- ✅ **Resource limits** - Optional memory and CPU limits
- ✅ **Security hardening** - Run with restricted permissions

---

## 🚀 Automated Installation

### Using the Install Script

The easiest way to install NyxProxy as a service:

```bash
# 1. Make sure NyxProxy is set up and working
./nyxproxy  # Test it first (Ctrl+C to stop)

# 2. Run the install script
sudo ./scripts/install-service.sh
```

**What the script does:**
1. ✅ Detects your NyxProxy installation location
2. ✅ Creates systemd service file
3. ✅ Enables auto-start on boot
4. ✅ Optionally starts the service immediately

**Expected output:**
```
╔═══════════════════════════════════════╗
║   NyxProxy Service Installer          ║
╚═══════════════════════════════════════╝

[1/4] Detected installation
  Binary: /root/nyxproxy
  Working directory: /root

[2/4] Creating systemd service file
  ✓ Service file created: /etc/systemd/system/nyxproxy.service

[3/4] Enabling service
  ✓ Service enabled (will start on boot)

[4/4] Service configuration
Start NyxProxy service? (Y/n) y
  ✓ Service started successfully

╔═══════════════════════════════════════╗
║     Installation Complete! ✓          ║
╚═══════════════════════════════════════╝
```

---

## 🔧 Manual Installation

### 1. Create Service File

```bash
sudo tee /etc/systemd/system/nyxproxy.service <<'EOF'
[Unit]
Description=NyxProxy IPv6 Rotating Proxy Server
Documentation=https://github.com/Jannik-Schroeder/nyxproxy-oss
After=network-online.target ndppd.service
Wants=network-online.target
Requires=ndppd.service

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/root/nyxproxy
Restart=on-failure
RestartSec=10
StartLimitInterval=5min
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nyxproxy

# Security hardening (optional)
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

**Customize the service file:**
- Change `WorkingDirectory` if NyxProxy is not in `/root`
- Change `ExecStart` to your NyxProxy binary path
- Change `User` if you want to run as a non-root user (advanced)

### 2. Reload Systemd

```bash
sudo systemctl daemon-reload
```

### 3. Enable Service

```bash
# Enable auto-start on boot
sudo systemctl enable nyxproxy

# Start service now
sudo systemctl start nyxproxy
```

---

## 📊 Service Management

### Basic Commands

```bash
# Start service
sudo systemctl start nyxproxy

# Stop service
sudo systemctl stop nyxproxy

# Restart service
sudo systemctl restart nyxproxy

# Check status
sudo systemctl status nyxproxy

# Enable auto-start on boot
sudo systemctl enable nyxproxy

# Disable auto-start on boot
sudo systemctl disable nyxproxy

# Check if service is enabled
systemctl is-enabled nyxproxy

# Check if service is running
systemctl is-active nyxproxy
```

### Service Status

```bash
# Detailed status
sudo systemctl status nyxproxy

# Example output:
● nyxproxy.service - NyxProxy IPv6 Rotating Proxy Server
     Loaded: loaded (/etc/systemd/system/nyxproxy.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2025-11-02 14:00:00 UTC; 2h 15min ago
       Docs: https://github.com/Jannik-Schroeder/nyxproxy-oss
   Main PID: 12345 (nyxproxy)
      Tasks: 15 (limit: 4915)
     Memory: 45.2M
        CPU: 1.234s
     CGroup: /system.slice/nyxproxy.service
             └─12345 /root/nyxproxy
```

---

## 📋 Logs and Monitoring

### View Logs

```bash
# Real-time logs (follow mode)
sudo journalctl -u nyxproxy -f

# Last 50 lines
sudo journalctl -u nyxproxy -n 50

# Today's logs
sudo journalctl -u nyxproxy --since today

# Logs from the last hour
sudo journalctl -u nyxproxy --since "1 hour ago"

# Logs between dates
sudo journalctl -u nyxproxy --since "2025-11-01" --until "2025-11-02"

# Export logs to file
sudo journalctl -u nyxproxy > nyxproxy.log
```

### Log Output Examples

**Successful startup:**
```
Nov 02 14:00:00 server nyxproxy[12345]: ✓ IPv6 rotation mode: IP Pool with dynamic rotation
Nov 02 14:00:00 server nyxproxy[12345]:   Interface: enp1s0
Nov 02 14:00:00 server nyxproxy[12345]:   Subnet: 2a05:f480:1800:25db::/64
Nov 02 14:00:00 server nyxproxy[12345]:   Pool size: 200 IPs
Nov 02 14:00:00 server nyxproxy[12345]:   Rotation: Every 100 uses or 30m0s
Nov 02 14:00:25 server nyxproxy[12345]: ✓ IP pool ready with 200 addresses
Nov 02 14:00:25 server nyxproxy[12345]: Starting https proxy on 0.0.0.0:8080 (Protocol: IPv6)
```

**IP rotation:**
```
Nov 02 15:05:00 server nyxproxy[12345]: ✓ Rotated 12 IPs (15:05:00)
Nov 02 15:35:00 server nyxproxy[12345]: ✓ Rotated 8 IPs (15:35:00)
```

### Monitoring Endpoint

If monitoring is enabled in `config.yaml`:

```bash
# Check proxy stats
curl http://localhost:9090/stats

# Example output:
{
  "status": "running",
  "uptime": "2h15m",
  "active_connections": 23,
  "total_requests": 8543,
  "ip_pool_size": 200,
  "ips_rotated_total": 38
}
```

---

## 🔧 Troubleshooting

### Service Won't Start

**Check status:**
```bash
sudo systemctl status nyxproxy
```

**Common issues:**

#### 1. Config file not found
```
Error: failed to load config: open config.yaml: no such file or directory
```

**Solution:**
```bash
# Make sure config.yaml exists in WorkingDirectory
ls -la /root/config.yaml

# Or create it
cd /root
./nyxproxy-setup
```

#### 2. Binary not found
```
Failed to execute command: No such file or directory
```

**Solution:**
```bash
# Check binary exists and is executable
ls -la /root/nyxproxy
chmod +x /root/nyxproxy
```

#### 3. ndppd not running
```
Warning: ndppd service is not running
```

**Solution:**
```bash
# Start ndppd
sudo systemctl start ndppd
sudo systemctl enable ndppd

# Restart NyxProxy
sudo systemctl restart nyxproxy
```

#### 4. Permission denied
```
Permission denied when accessing network interface
```

**Solution:**
```bash
# Service must run as root for IPv6 rotation
# Edit service file to ensure User=root
sudo nano /etc/systemd/system/nyxproxy.service

# Then reload
sudo systemctl daemon-reload
sudo systemctl restart nyxproxy
```

---

### Service Keeps Restarting

**Check logs:**
```bash
sudo journalctl -u nyxproxy -n 100
```

**Common causes:**
- Configuration error in `config.yaml`
- Network interface not available
- IPv6 subnet not properly configured
- ndppd not running

---

### High Memory Usage

**Check resource usage:**
```bash
systemctl status nyxproxy
```

**Add memory limits to service file:**
```bash
sudo nano /etc/systemd/system/nyxproxy.service

# Add under [Service]:
MemoryLimit=500M
MemoryMax=1G

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart nyxproxy
```

---

## 🗑️ Uninstalling

### Remove Service

```bash
# 1. Stop and disable service
sudo systemctl stop nyxproxy
sudo systemctl disable nyxproxy

# 2. Remove service file
sudo rm /etc/systemd/system/nyxproxy.service

# 3. Reload systemd
sudo systemctl daemon-reload

# 4. Remove binary and config (optional)
rm /root/nyxproxy
rm /root/config.yaml
```

---

## 🌟 Advanced Configuration

### Running as Non-Root User

**⚠️ Warning:** IPv6 rotation requires `CAP_NET_ADMIN` capability or root access to add IPs to the interface.

If you want to run as a non-root user, you need to grant capabilities:

```bash
# Create a dedicated user
sudo useradd -r -s /bin/false nyxproxy

# Give the binary capabilities
sudo setcap cap_net_admin,cap_net_bind_service=+ep /usr/local/bin/nyxproxy

# Update service file
sudo nano /etc/systemd/system/nyxproxy.service

# Change:
User=nyxproxy
Group=nyxproxy
WorkingDirectory=/opt/nyxproxy
```

---

### Multiple Service Instances

Run multiple NyxProxy instances on different ports:

```bash
# Create second service file
sudo cp /etc/systemd/system/nyxproxy.service /etc/systemd/system/nyxproxy-8081.service

# Edit it
sudo nano /etc/systemd/system/nyxproxy-8081.service

# Change:
Description=NyxProxy IPv6 Rotating Proxy Server (Port 8081)
WorkingDirectory=/opt/nyxproxy-8081
ExecStart=/opt/nyxproxy-8081/nyxproxy

# Enable and start
sudo systemctl enable nyxproxy-8081
sudo systemctl start nyxproxy-8081
```

---

### Resource Limits

Add resource limits to prevent abuse:

```bash
sudo nano /etc/systemd/system/nyxproxy.service

# Add under [Service]:
# File descriptor limit
LimitNOFILE=65536

# Process limit
LimitNPROC=4096

# Memory limits
MemoryLimit=500M
MemoryMax=1G

# CPU quota (50% of one core)
CPUQuota=50%

# Reload
sudo systemctl daemon-reload
sudo systemctl restart nyxproxy
```

---

### Auto-Restart on Config Change

Automatically restart when config.yaml changes:

```bash
sudo nano /etc/systemd/system/nyxproxy.service

# Add under [Service]:
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Add a path unit
sudo tee /etc/systemd/system/nyxproxy-config.path <<'EOF'
[Unit]
Description=Watch NyxProxy config file

[Path]
PathChanged=/root/config.yaml

[Install]
WantedBy=multi-user.target
EOF

# Enable path unit
sudo systemctl enable nyxproxy-config.path
sudo systemctl start nyxproxy-config.path
```

---

## 📞 Support

For more help:
- **GitHub Issues**: [Report issues](https://github.com/jannik-schroeder/nyxproxy-oss/issues)
- **Main Documentation**: See [README.md](README.md)
- **German Documentation**: See [SETUP_DE.md](SETUP_DE.md)

---

**Happy proxying! 🚀**
