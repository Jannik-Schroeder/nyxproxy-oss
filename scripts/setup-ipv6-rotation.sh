#!/bin/bash

# NyxProxy IPv6 Rotation Setup Script
# This script configures Linux systems to support IPv6 rotation with /64 subnets

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

echo -e "${GREEN}NyxProxy IPv6 Rotation Setup${NC}"
echo "=============================="
echo

# Detect interface and IPv6 subnet
echo -e "${YELLOW}Detecting network configuration...${NC}"
INTERFACE=$(ip -6 route | grep default | awk '{print $5}' | head -n 1)

if [ -z "$INTERFACE" ]; then
    echo -e "${RED}Error: Could not detect network interface${NC}"
    exit 1
fi

echo "Detected interface: $INTERFACE"

# Get IPv6 subnet
IPV6_SUBNET=$(ip -6 addr show dev "$INTERFACE" | grep "inet6.*scope global" | grep -v "temporary\|deprecated" | head -n 1 | awk '{print $2}' | cut -d'/' -f1)

if [ -z "$IPV6_SUBNET" ]; then
    echo -e "${RED}Error: No IPv6 address found on $INTERFACE${NC}"
    exit 1
fi

# Extract /64 subnet
IPV6_BASE=$(echo "$IPV6_SUBNET" | cut -d':' -f1-4)
IPV6_SUBNET_CIDR="${IPV6_BASE}::/64"

echo "Detected IPv6 subnet: $IPV6_SUBNET_CIDR"
echo

# Ask for confirmation
read -p "Configure IPv6 rotation for subnet $IPV6_SUBNET_CIDR on interface $INTERFACE? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Setup cancelled."
    exit 0
fi

echo
echo -e "${YELLOW}Step 1: Configuring kernel parameters...${NC}"

# Enable IPv6 forwarding and other necessary parameters
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.proxy_ndp=1
sysctl -w net.ipv6.conf.$INTERFACE.proxy_ndp=1
sysctl -w net.ipv6.ip_nonlocal_bind=1

# Make changes persistent
cat > /etc/sysctl.d/99-nyxproxy-ipv6.conf <<EOF
# NyxProxy IPv6 Rotation Configuration
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.proxy_ndp=1
net.ipv6.conf.$INTERFACE.proxy_ndp=1
net.ipv6.ip_nonlocal_bind=1
EOF

echo -e "${GREEN}✓ Kernel parameters configured${NC}"
echo

echo -e "${YELLOW}Step 2: Installing ndppd (NDP Proxy Daemon)...${NC}"

# Check if ndppd is installed
if ! command -v ndppd &> /dev/null; then
    echo "Installing ndppd..."

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y ndppd
    elif command -v yum &> /dev/null; then
        yum install -y ndppd
    elif command -v dnf &> /dev/null; then
        dnf install -y ndppd
    else
        echo -e "${RED}Error: Could not detect package manager${NC}"
        echo "Please install ndppd manually:"
        echo "  - Debian/Ubuntu: apt-get install ndppd"
        echo "  - CentOS/RHEL: yum install ndppd"
        exit 1
    fi
else
    echo "ndppd is already installed"
fi

echo -e "${GREEN}✓ ndppd installed${NC}"
echo

echo -e "${YELLOW}Step 3: Configuring ndppd...${NC}"

# Create ndppd configuration
cat > /etc/ndppd.conf <<EOF
# NyxProxy NDP Proxy Configuration
# This allows the system to respond to NDP requests for the entire /64 subnet

route-ttl 30000

proxy $INTERFACE {
    router no
    timeout 500
    ttl 30000

    rule $IPV6_SUBNET_CIDR {
        auto
    }
}
EOF

echo -e "${GREEN}✓ ndppd configured${NC}"
echo

echo -e "${YELLOW}Step 4: Starting and enabling ndppd service...${NC}"

# Enable and start ndppd
systemctl enable ndppd
systemctl restart ndppd

# Check if service is running
if systemctl is-active --quiet ndppd; then
    echo -e "${GREEN}✓ ndppd service is running${NC}"
else
    echo -e "${RED}✗ ndppd service failed to start${NC}"
    echo "Check logs with: journalctl -u ndppd -n 50"
    exit 1
fi

echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}IPv6 Rotation Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo "Configuration summary:"
echo "  Interface: $INTERFACE"
echo "  IPv6 Subnet: $IPV6_SUBNET_CIDR"
echo "  ndppd: Running"
echo
echo "You can now configure NyxProxy with:"
echo "  network:"
echo "    interface_name: \"$INTERFACE\""
echo "    rotate_ipv6: true"
echo "    ipv6_subnet: \"$IPV6_SUBNET_CIDR\""
echo
echo -e "${YELLOW}Testing configuration...${NC}"
echo

# Test by trying to bind to a random IP in the subnet
TEST_IP="${IPV6_BASE}::1234"
echo "Testing bind to $TEST_IP..."

if timeout 5 bash -c "nc -6 -l -p 0 -s $TEST_IP 2>&1 | grep -q 'Cannot assign'" 2>/dev/null; then
    echo -e "${RED}✗ Bind test failed - configuration may need adjustment${NC}"
    echo "Wait a few seconds for ndppd to initialize, then try starting NyxProxy"
else
    echo -e "${GREEN}✓ Configuration appears to be working${NC}"
fi

echo
echo "To check ndppd status: systemctl status ndppd"
echo "To view ndppd logs: journalctl -u ndppd -f"
echo
