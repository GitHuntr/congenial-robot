#!/bin/bash

# CCAF Installation Script for Linux
# This script installs CCAF with all dependencies and sets up the system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CCAF_USER="ccaf"
CCAF_HOME="/opt/ccaf"
SERVICE_NAME="ccaf"

echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}CCAF Installation Script${NC}"
echo -e "${BLUE}=================================${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS version${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS $VER${NC}"

# Install system dependencies
install_dependencies() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    
    if [[ "$OS" =~ "Ubuntu" ]] || [[ "$OS" =~ "Debian" ]]; then
        apt-get update
        apt-get install -y python3 python3-pip python3-venv iptables-persistent \
                          sqlite3 curl wget git supervisor nginx
    elif [[ "$OS" =~ "CentOS" ]] || [[ "$OS" =~ "Red Hat" ]] || [[ "$OS" =~ "Fedora" ]]; then
        yum update -y
        yum install -y python3 python3-pip python3-venv iptables-services \
                      sqlite curl wget git supervisor nginx
    else
        echo -e "${RED}Unsupported OS: $OS${NC}"
        exit 1
    fi
}

# Create CCAF user
create_user() {
    echo -e "${YELLOW}Creating CCAF user...${NC}"
    
    if ! id "$CCAF_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$CCAF_HOME" "$CCAF_USER"
        echo -e "${GREEN}User $CCAF_USER created${NC}"
    else
        echo -e "${YELLOW}User $CCAF_USER already exists${NC}"
    fi
}

# Setup CCAF directory
setup_directory() {
    echo -e "${YELLOW}Setting up CCAF directory...${NC}"
    
    mkdir -p "$CCAF_HOME"
    mkdir -p "$CCAF_HOME/data/database"
    mkdir -p "$CCAF_HOME/data/logs"
    mkdir -p "$CCAF_HOME/data/backups"
    mkdir -p "$CCAF_HOME/configs"
    
    chown -R "$CCAF_USER:$CCAF_USER" "$CCAF_HOME"
    chmod 755 "$CCAF_HOME"
}

# Install CCAF
install_ccaf() {
    echo -e "${YELLOW}Installing CCAF...${NC}"
    
    cd "$CCAF_HOME"
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install CCAF (assuming we're in the source directory)
    if [ -f "setup.py" ]; then
        pip install -e .
    else
        # Install from PyPI when available
        # pip install ccaf
        echo -e "${RED}Please copy CCAF source code to $CCAF_HOME${NC}"
        exit 1
    fi
    
    # Create default configuration
    cat > configs/production.json << 'EOF'
{
  "database": {
    "path": "/opt/ccaf/data/database/ccaf.db"
  },
  "security": {
    "secret_key": "GENERATE_A_SECURE_KEY_HERE"
  },
  "web": {
    "host": "0.0.0.0",
    "port": 5000,
    "enable_ssl": false
  },
  "logging": {
    "level": "INFO",
    "file_path": "/opt/ccaf/data/logs/ccaf.log"
  },
  "modules": {
    "intrusion_detection": true,
    "bandwidth_control": true,
    "content_filter": true,
    "vpn_integration": false,
    "threat_intelligence": true
  }
}
EOF
    
    chown -R "$CCAF_USER:$CCAF_USER" "$CCAF_HOME"
}

# Create systemd service
create_service() {
    echo -e "${YELLOW}Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/ccaf.service << EOF
[Unit]
Description=CCAF - Centralized Context-Aware Firewall
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$CCAF_HOME
Environment=PATH=$CCAF_HOME/venv/bin
ExecStart=$CCAF_HOME/venv/bin/python app.py --env production
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable ccaf
}

# Setup firewall rules
setup_firewall() {
    echo -e "${YELLOW}Setting up firewall rules...${NC}"
    
    # Allow CCAF web interface
    if command -v ufw &> /dev/null; then
        ufw allow 5000/tcp
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=5000/tcp
        firewall-cmd --reload
    fi
}

# Main installation
main() {
    install_dependencies
    create_user
    setup_directory
    install_ccaf
    create_service
    setup_firewall
    
    echo -e "${GREEN}=================================${NC}"
    echo -e "${GREEN}CCAF Installation Complete!${NC}"
    echo -e "${GREEN}=================================${NC}"
    echo -e "${YELLOW}To start CCAF:${NC}"
    echo -e "  sudo systemctl start ccaf"
    echo -e "${YELLOW}To check status:${NC}"
    echo -e "  sudo systemctl status ccaf"
    echo -e "${YELLOW}To view logs:${NC}"
    echo -e "  sudo journalctl -u ccaf -f"
    echo -e "${YELLOW}Web interface will be available at:${NC}"
    echo -e "  http://$(hostname -I | awk '{print $1}'):5000"
    echo -e "${RED}Default login: admin / admin123${NC}"
    echo -e "${RED}Please change the default password!${NC}"
}

main "$@"