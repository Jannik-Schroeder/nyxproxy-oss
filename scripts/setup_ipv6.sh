#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Get the main interface name
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
if [ -z "$INTERFACE" ]; then
    echo "Could not determine default interface"
    exit 1
fi

# Get the IPv6 subnet from environment or use default
IPV6_SUBNET=${IPV6_SUBNET:-"2a01:4f8:1c1a:cba4::/64"}

echo "Using interface: $INTERFACE"
echo "Using IPv6 subnet: $IPV6_SUBNET"

# Add route for the IPv6 subnet
echo "Adding IPv6 route..."
ip route add local $IPV6_SUBNET dev $INTERFACE || {
    echo "Failed to add IPv6 route"
    exit 1
}

# Enable non-local bind
echo "Enabling non-local bind..."
sysctl -w net.ipv6.ip_nonlocal_bind=1 || {
    echo "Failed to enable non-local bind"
    exit 1
}

# Make non-local bind persistent
echo "net.ipv6.ip_nonlocal_bind=1" > /etc/sysctl.d/99-ipv6-nonlocal.conf

# Install ndppd if not present
if ! command -v ndppd &> /dev/null; then
    echo "Installing ndppd..."
    apt-get update
    apt-get install -y ndppd || {
        echo "Failed to install ndppd"
        exit 1
    }
fi

# Configure ndppd
echo "Configuring ndppd..."
cat > /etc/ndppd.conf << EOF
route-ttl 30000

proxy $INTERFACE {
    router no
    timeout 500
    ttl 30000

    rule $IPV6_SUBNET {
        static
    }
}
EOF

# Restart ndppd
echo "Restarting ndppd..."
systemctl restart ndppd || {
    echo "Failed to restart ndppd"
    exit 1
}

# Test the setup
echo "Testing IPv6 setup..."
TEST_IP="${IPV6_SUBNET%::*}::1"
if curl --interface "$TEST_IP" -s ipv6.ip.sb | grep -q "$TEST_IP"; then
    echo "IPv6 setup successful!"
    echo "Test IP ($TEST_IP) is working"
else
    echo "IPv6 setup might have issues. Please check manually."
fi

echo "Setup complete!" 