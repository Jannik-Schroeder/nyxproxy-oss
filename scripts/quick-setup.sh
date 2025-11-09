#!/bin/bash

# NyxProxy Quick Setup Script
# One-command setup for IPv6 rotating proxy on Debian/Ubuntu

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NyxProxy Quick Setup (Debian)       ║${NC}"
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ This script must be run as root${NC}"
    echo "  Run: sudo $0"
    exit 1
fi

# Check if on Linux
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}✗ This script only works on Linux${NC}"
    exit 1
fi

# Check if config.yaml already exists
if [ -f "../config.yaml" ]; then
    echo -e "${YELLOW}⚠️  config.yaml already exists${NC}"
    read -p "Do you want to reconfigure? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled. Using existing config.yaml"
        exit 0
    fi
    mv ../config.yaml ../config.yaml.backup
    echo "✓ Backed up existing config to config.yaml.backup"
    echo
fi

echo -e "${BLUE}[1/5] Detecting network configuration...${NC}"

# Detect interface
INTERFACE=$(ip -6 route | grep default | awk '{print $5}' | head -n 1)
if [ -z "$INTERFACE" ]; then
    echo -e "${RED}✗ Could not detect network interface${NC}"
    echo "  Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print "    - " $2}' | sed 's/:$//'
    exit 1
fi
echo "  ✓ Interface: $INTERFACE"

# Detect IPv6 subnet
IPV6_ADDR=$(ip -6 addr show dev "$INTERFACE" | grep "inet6.*scope global" | grep -v "temporary\|deprecated" | head -n 1 | awk '{print $2}' | cut -d'/' -f1)
if [ -z "$IPV6_ADDR" ]; then
    echo -e "${RED}✗ No IPv6 address found on $INTERFACE${NC}"
    exit 1
fi

IPV6_BASE=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
IPV6_SUBNET="${IPV6_BASE}::/64"
echo "  ✓ IPv6 Subnet: $IPV6_SUBNET"
echo

echo -e "${BLUE}[2/5] Installing dependencies...${NC}"

# Update package list
apt-get update -qq

# Install ndppd if not present
if ! command -v ndppd &> /dev/null; then
    echo "  Installing ndppd..."
    apt-get install -y -qq ndppd > /dev/null
    echo "  ✓ ndppd installed"
else
    echo "  ✓ ndppd already installed"
fi
echo

echo -e "${BLUE}[3/5] Configuring system for IPv6 rotation...${NC}"

# Configure kernel parameters
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
sysctl -w net.ipv6.conf.all.proxy_ndp=1 > /dev/null
sysctl -w net.ipv6.conf.$INTERFACE.proxy_ndp=1 > /dev/null
sysctl -w net.ipv6.ip_nonlocal_bind=1 > /dev/null

# Make persistent
cat > /etc/sysctl.d/99-nyxproxy-ipv6.conf <<EOF
# NyxProxy IPv6 Rotation
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.proxy_ndp=1
net.ipv6.conf.$INTERFACE.proxy_ndp=1
net.ipv6.ip_nonlocal_bind=1
EOF

echo "  ✓ Kernel parameters configured"

# Configure ndppd
cat > /etc/ndppd.conf <<EOF
# NyxProxy NDP Proxy Configuration
route-ttl 30000

proxy $INTERFACE {
    router no
    timeout 500
    ttl 30000

    rule $IPV6_SUBNET {
        auto
    }
}
EOF

echo "  ✓ ndppd configured"

# Start ndppd
systemctl enable ndppd > /dev/null 2>&1
systemctl restart ndppd

if systemctl is-active --quiet ndppd; then
    echo "  ✓ ndppd service running"
else
    echo -e "${RED}  ✗ ndppd failed to start${NC}"
    echo "    Check: journalctl -u ndppd -n 20"
    exit 1
fi
echo

echo -e "${BLUE}[4/5] Creating NyxProxy configuration...${NC}"

# Get proxy credentials
echo -n "  Proxy username [admin]: "
read PROXY_USER
PROXY_USER=${PROXY_USER:-admin}

echo -n "  Proxy password: "
read -s PROXY_PASS
echo

while [ -z "$PROXY_PASS" ]; do
    echo -e "${RED}  Password cannot be empty${NC}"
    echo -n "  Proxy password: "
    read -s PROXY_PASS
    echo
done

# Ask for rotation settings
echo
echo "  IPv6 Rotation Settings:"
echo -n "  IP Pool size [200]: "
read POOL_SIZE
POOL_SIZE=${POOL_SIZE:-200}

echo -n "  Max uses per IP before rotation [100]: "
read MAX_USAGE
MAX_USAGE=${MAX_USAGE:-100}

echo -n "  Max age in minutes before rotation [30]: "
read MAX_AGE
MAX_AGE=${MAX_AGE:-30}

# Create config.yaml in current directory
cat > config.yaml <<EOF
# NyxProxy Configuration
# Auto-generated on $(date)

proxy:
  type: https
  listen_address: "0.0.0.0"
  listen_port: 8080
  username: "$PROXY_USER"
  password: "$PROXY_PASS"

network:
  interface_name: "$INTERFACE"
  ipv4_enabled: false
  ipv6_enabled: true
  rotate_ipv6: true
  ipv6_subnet: "$IPV6_SUBNET"
  ipv6_pool_size: $POOL_SIZE
  ipv6_max_usage: $MAX_USAGE
  ipv6_max_age: $MAX_AGE

monitoring:
  enabled: true
  port: 9090
  allow_remote: false

logging:
  debug_level: 0
EOF

echo "  ✓ config.yaml created"
echo

echo -e "${BLUE}[5/7] Testing configuration...${NC}"

# Test IP binding
TEST_IP="${IPV6_BASE}::9999"
if timeout 2 bash -c "exec 3<>/dev/tcp/[::1]/80 2>&1" 2>/dev/null; then
    :
fi
echo "  ✓ IPv6 stack operational"
echo

echo -e "${BLUE}[6/7] Downloading NyxProxy executable...${NC}"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH_NAME="amd64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    *)
        echo -e "${RED}✗ Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac
echo "  ✓ Detected architecture: $ARCH_NAME"

# Get latest release version
REPO="jannik-schroeder/nyxproxy-oss"
RELEASE_URL="https://api.github.com/repos/$REPO/releases/latest"

echo "  Fetching latest release info..."
LATEST_RELEASE=$(curl -s $RELEASE_URL)
VERSION=$(echo "$LATEST_RELEASE" | grep -Po '"tag_name": "\K.*?(?=")')

if [ -z "$VERSION" ]; then
    echo -e "${RED}✗ Could not fetch latest release${NC}"
    echo "  You can manually download from: https://github.com/$REPO/releases"
    exit 1
fi

echo "  ✓ Latest version: $VERSION"

# Download binary
BINARY_NAME="nyxproxy-linux-${ARCH_NAME}"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY_NAME"

echo "  Downloading $BINARY_NAME..."
if ! curl -L -o nyxproxy "$DOWNLOAD_URL" 2>/dev/null; then
    echo -e "${RED}✗ Failed to download binary${NC}"
    echo "  Download URL: $DOWNLOAD_URL"
    exit 1
fi

chmod +x nyxproxy
echo "  ✓ Downloaded and installed nyxproxy"
echo

echo -e "${BLUE}[7/7] Daemon setup...${NC}"
echo -n "  Do you want to install NyxProxy as a systemd service? (y/N) "
read -n 1 -r DAEMON_CHOICE
echo
echo

if [[ $DAEMON_CHOICE =~ ^[Yy]$ ]]; then
    # Get current directory (where the binary is)
    INSTALL_DIR=$(pwd)

    # Create systemd service file
    cat > /etc/systemd/system/nyxproxy.service <<EOF
[Unit]
Description=NyxProxy IPv6 Rotating Proxy
After=network.target ndppd.service
Requires=ndppd.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/nyxproxy
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    echo "  ✓ Systemd service created"

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable nyxproxy > /dev/null 2>&1
    echo "  ✓ Service enabled (auto-start on boot)"

    # Ask if should start now
    echo -n "  Start NyxProxy now? (Y/n) "
    read -n 1 -r START_NOW
    echo

    if [[ ! $START_NOW =~ ^[Nn]$ ]]; then
        systemctl start nyxproxy

        # Wait a moment and check status
        sleep 2
        if systemctl is-active --quiet nyxproxy; then
            echo "  ✓ NyxProxy service is running"
        else
            echo -e "${RED}  ✗ Service failed to start${NC}"
            echo "    Check logs: journalctl -u nyxproxy -n 20"
        fi
    else
        echo "  Service installed but not started"
        echo "  Start with: systemctl start nyxproxy"
    fi
else
    echo "  ✓ Skipped daemon installation"
fi
echo

echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Setup Complete! ✓              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo
echo -e "${GREEN}Configuration:${NC}"
echo "  Interface:    $INTERFACE"
echo "  IPv6 Subnet:  $IPV6_SUBNET"
echo "  Proxy Type:   HTTPS"
echo "  Listen Port:  8080"
echo "  Username:     $PROXY_USER"
echo "  Binary:       $(pwd)/nyxproxy"
echo

if [[ $DAEMON_CHOICE =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Service Management:${NC}"
    echo "  Status:       systemctl status nyxproxy"
    echo "  Start:        systemctl start nyxproxy"
    echo "  Stop:         systemctl stop nyxproxy"
    echo "  Restart:      systemctl restart nyxproxy"
    echo "  Logs:         journalctl -u nyxproxy -f"
    echo
    echo -e "${GREEN}ndppd Service:${NC}"
    echo "  Status:       systemctl status ndppd"
    echo "  Logs:         journalctl -u ndppd -f"
else
    echo -e "${YELLOW}Manual Start:${NC}"
    echo "  Start proxy:  ./nyxproxy"
    echo
    echo -e "${YELLOW}Service Management:${NC}"
    echo "  Check ndppd:  systemctl status ndppd"
    echo "  View logs:    journalctl -u ndppd -f"
fi
echo
echo -e "${GREEN}Test your proxy:${NC}"
echo "  curl --proxy http://$PROXY_USER:***@YOUR_SERVER_IP:8080 https://api6.ipify.org"
echo
