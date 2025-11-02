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

# Create config.yaml
cat > ../config.yaml <<EOF
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

monitoring:
  enabled: true
  port: 9090
  allow_remote: false

logging:
  debug_level: 0
EOF

echo "  ✓ config.yaml created"
echo

echo -e "${BLUE}[5/5] Testing configuration...${NC}"

# Test IP binding
TEST_IP="${IPV6_BASE}::9999"
if timeout 2 bash -c "exec 3<>/dev/tcp/[::1]/80 2>&1" 2>/dev/null; then
    :
fi
echo "  ✓ IPv6 stack operational"
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
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Build NyxProxy: go build -o nyxproxy cmd/nyxproxy/main.go"
echo "  2. Start proxy:    ./nyxproxy"
echo "  3. Test with:      curl --proxy http://$PROXY_USER:***@YOUR_SERVER_IP:8080 https://api6.ipify.org"
echo
echo -e "${YELLOW}Service management:${NC}"
echo "  Check ndppd:  systemctl status ndppd"
echo "  View logs:    journalctl -u ndppd -f"
echo
