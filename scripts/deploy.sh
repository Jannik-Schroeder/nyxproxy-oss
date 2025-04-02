#!/bin/bash

# Configuration
GITHUB_TOKEN=""  # Will be passed as an environment variable
REPO_OWNER="NyxTrace"
REPO_NAME="nyxproxy-core"
PROXY_SERVICE_NAME="nyxproxy"
PROXY_USER="nyxproxy"
INSTALL_DIR="/opt/nyxproxy"

# Function to print error and exit
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to setup systemd service
setup_systemd_service() {
    local config_file="$1"
    cat > "/etc/systemd/system/${PROXY_SERVICE_NAME}.service" <<EOF
[Unit]
Description=NyxProxy Core Service
After=network.target

[Service]
Type=simple
User=${PROXY_USER}
Group=${PROXY_USER}
ExecStart=${INSTALL_DIR}/nyxproxy -config ${INSTALL_DIR}/config.env
Restart=always
RestartSec=5
StandardOutput=append:/var/log/nyxproxy.log
StandardError=append:/var/log/nyxproxy.error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${PROXY_SERVICE_NAME}"
    systemctl start "${PROXY_SERVICE_NAME}"
}

# Main deployment function
deploy_proxy() {
    local host="$1"
    local ssh_key="$2"
    local config_file="$3"
    local domain="$4"

    # Check required arguments
    [[ -z "$host" ]] && error_exit "Host is required"
    [[ -z "$ssh_key" ]] && error_exit "SSH key is required"
    [[ -z "$config_file" ]] && error_exit "Config file is required"
    [[ -z "$GITHUB_TOKEN" ]] && error_exit "GITHUB_TOKEN is required"

    # Get latest release info
    local latest_release=$(curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
        "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest")
    
    # Get download URL for Linux binary
    local arch=$(ssh -i "$ssh_key" "$host" "uname -m")
    local binary_name=""
    case "$arch" in
        x86_64) binary_name="nyxproxy-linux-amd64" ;;
        aarch64) binary_name="nyxproxy-linux-arm64" ;;
        *) error_exit "Unsupported architecture: $arch" ;;
    esac

    local download_url=$(echo "$latest_release" | grep -o "https://.*${binary_name}" | head -n1)
    [[ -z "$download_url" ]] && error_exit "Could not find download URL for $binary_name"

    # Deploy to remote server
    echo "Deploying to $host..."
    
    ssh -i "$ssh_key" "$host" bash -s <<EOF
        set -e

        # Install required packages
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y curl systemd
        else
            error_exit "Unsupported package manager. Only apt-get is supported."
        fi

        # Create proxy user
        sudo useradd -r -s /bin/false ${PROXY_USER} 2>/dev/null || true

        # Create installation directory
        sudo mkdir -p ${INSTALL_DIR}
        sudo chown ${PROXY_USER}:${PROXY_USER} ${INSTALL_DIR}

        # Download and install binary
        echo "Downloading proxy binary..."
        sudo curl -L -o ${INSTALL_DIR}/nyxproxy "${download_url}"
        sudo chmod +x ${INSTALL_DIR}/nyxproxy
        sudo chown ${PROXY_USER}:${PROXY_USER} ${INSTALL_DIR}/nyxproxy

        # Copy config file
        echo "Setting up configuration..."
        sudo cp "$config_file" ${INSTALL_DIR}/config.env
        sudo chown ${PROXY_USER}:${PROXY_USER} ${INSTALL_DIR}/config.env
        sudo chmod 600 ${INSTALL_DIR}/config.env

        # Setup systemd service
        echo "Setting up systemd service..."
        $(declare -f setup_systemd_service)
        setup_systemd_service "$config_file"

        # Setup domain if provided
        if [[ -n "$domain" ]]; then
            echo "Setting up domain $domain..."
            # Here you can add domain setup logic (e.g., nginx configuration)
            if ! command_exists nginx; then
                sudo apt-get install -y nginx
            fi
            
            # Create nginx config
            sudo tee /etc/nginx/sites-available/${domain}.conf <<NGINX
server {
    listen 80;
    server_name ${domain};

    location / {
        proxy_pass http://localhost:8080;  # Adjust port as needed
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
NGINX

            # Enable site
            sudo ln -sf /etc/nginx/sites-available/${domain}.conf /etc/nginx/sites-enabled/
            sudo nginx -t && sudo systemctl reload nginx
        fi

        echo "Deployment completed successfully!"
EOF
}

# Usage
if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <host> <ssh_key_path> <config_file> [domain]"
    exit 1
fi

deploy_proxy "$1" "$2" "$3" "$4" 