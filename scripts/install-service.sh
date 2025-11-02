#!/bin/bash

# NyxProxy Systemd Service Installer
# This script installs NyxProxy as a systemd service for automatic startup

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NyxProxy Service Installer          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ This script must be run as root${NC}"
    echo "  Run: sudo $0"
    exit 1
fi

# Check if NyxProxy binary exists
if [ ! -f "nyxproxy" ] && [ ! -f "/root/nyxproxy" ]; then
    echo -e "${RED}✗ nyxproxy binary not found${NC}"
    echo "  Please download it first:"
    echo "  wget https://github.com/Jannik-Schroeder/nyxproxy-oss/releases/latest/download/nyxproxy-linux-amd64 -O nyxproxy"
    exit 1
fi

# Determine installation directory
if [ -f "nyxproxy" ]; then
    INSTALL_DIR=$(pwd)
    BINARY_PATH="$INSTALL_DIR/nyxproxy"
elif [ -f "/root/nyxproxy" ]; then
    INSTALL_DIR="/root"
    BINARY_PATH="/root/nyxproxy"
fi

echo -e "${BLUE}[1/4] Detected installation${NC}"
echo "  Binary: $BINARY_PATH"
echo "  Working directory: $INSTALL_DIR"
echo

# Check if config.yaml exists
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    echo -e "${YELLOW}⚠️  Warning: config.yaml not found in $INSTALL_DIR${NC}"
    echo "  The service will fail to start without a config file."
    echo
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled. Please create config.yaml first."
        exit 0
    fi
fi

echo -e "${BLUE}[2/4] Creating systemd service file${NC}"

# Create systemd service file
cat > /etc/systemd/system/nyxproxy.service <<EOF
[Unit]
Description=NyxProxy IPv6 Rotating Proxy Server
Documentation=https://github.com/Jannik-Schroeder/nyxproxy-oss
After=network-online.target ndppd.service
Wants=network-online.target
Requires=ndppd.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$BINARY_PATH
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

# Resource limits (optional)
# LimitNOFILE=65536
# LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

echo "  ✓ Service file created: /etc/systemd/system/nyxproxy.service"
echo

echo -e "${BLUE}[3/4] Enabling service${NC}"

# Reload systemd daemon
systemctl daemon-reload

# Enable service
systemctl enable nyxproxy.service

echo "  ✓ Service enabled (will start on boot)"
echo

echo -e "${BLUE}[4/4] Service configuration${NC}"
echo
echo "Would you like to start the service now?"
read -p "Start NyxProxy service? (Y/n) " -n 1 -r
echo

if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${YELLOW}Service not started${NC}"
    echo "You can start it later with: sudo systemctl start nyxproxy"
else
    echo "Starting NyxProxy service..."
    systemctl start nyxproxy.service

    sleep 2

    if systemctl is-active --quiet nyxproxy.service; then
        echo -e "${GREEN}✓ Service started successfully${NC}"
    else
        echo -e "${RED}✗ Service failed to start${NC}"
        echo "Check logs with: sudo journalctl -u nyxproxy -n 50"
        exit 1
    fi
fi

echo
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Installation Complete! ✓          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo
echo -e "${GREEN}Service Commands:${NC}"
echo "  Start:   sudo systemctl start nyxproxy"
echo "  Stop:    sudo systemctl stop nyxproxy"
echo "  Restart: sudo systemctl restart nyxproxy"
echo "  Status:  sudo systemctl status nyxproxy"
echo "  Logs:    sudo journalctl -u nyxproxy -f"
echo
echo -e "${GREEN}Service Status:${NC}"
systemctl status nyxproxy.service --no-pager || true
echo
echo -e "${YELLOW}Note:${NC} The service will automatically start on system boot."
echo
