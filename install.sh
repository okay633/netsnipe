#!/bin/bash

# NetSnipe Installation Script
# Enhanced version with advanced features

echo "========================================="
echo "      NetSnipe Enhanced Installation"
echo "========================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "Warning: Running as root. Some features may require non-root privileges."
fi

# Create installation directory
INSTALL_DIR="/opt/netsnipe"
if [[ ! -d "$INSTALL_DIR" ]]; then
    echo "Creating installation directory: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown $USER:$USER "$INSTALL_DIR"
fi

# Install system dependencies
echo "Installing system dependencies..."
if command -v apt-get > /dev/null; then
    # Ubuntu/Debian
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv git nmap traceroute dnsutils
elif command -v yum > /dev/null; then
    # CentOS/RHEL
    sudo yum install -y python3 python3-pip git nmap traceroute bind-utils
elif command -v pacman > /dev/null; then
    # Arch Linux
    sudo pacman -S python python-pip git nmap traceroute bind-tools
else
    echo "Unsupported package manager. Please install manually: python3, pip, git, nmap, traceroute, dig"
fi

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Copy files to installation directory
echo "Copying NetSnipe files..."
cp netsnipe.py "$INSTALL_DIR/"
cp netsnipe_utils.py "$INSTALL_DIR/"
cp vuln_db.json "$INSTALL_DIR/"
cp config.json "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

# Make scripts executable
chmod +x "$INSTALL_DIR/netsnipe.py"
chmod +x "$INSTALL_DIR/netsnipe_utils.py"

# Create symlinks for global access
echo "Creating global command links..."
sudo ln -sf "$INSTALL_DIR/netsnipe.py" /usr/local/bin/netsnipe
sudo ln -sf "$INSTALL_DIR/netsnipe_utils.py" /usr/local/bin/netsnipe-utils

# Create activation wrapper
cat > "$INSTALL_DIR/activate_netsnipe.sh" << 'EOF'
#!/bin/bash
source /opt/netsnipe/venv/bin/activate
cd /opt/netsnipe
echo "NetSnipe environment activated"
echo "Available commands:"
echo "  netsnipe - Main scanning tool"
echo "  netsnipe-utils - Utility functions"
echo "  deactivate - Exit NetSnipe environment"
bash
EOF

chmod +x "$INSTALL_DIR/activate_netsnipe.sh"

# Create desktop entry (if GUI environment)
if [[ "$DISPLAY" ]]; then
    echo "Creating desktop entry..."
    cat > ~/.local/share/applications/netsnipe.desktop << EOF
[Desktop Entry]
Name=NetSnipe
Comment=Advanced Network Security Scanner
Exec=gnome-terminal -- $INSTALL_DIR/activate_netsnipe.sh
Icon=network-workgroup
Terminal=true
Type=Application
Categories=Network;Security;
EOF
fi

# Create log directory
mkdir -p "$INSTALL_DIR/logs"

# Set up log rotation
echo "Setting up log rotation..."
sudo tee /etc/logrotate.d/netsnipe > /dev/null << EOF
$INSTALL_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
}
EOF

# Create systemd service for monitoring (optional)
cat > "$INSTALL_DIR/netsnipe-monitor.service" << EOF
[Unit]
Description=NetSnipe Network Monitor
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/netsnipe_utils.py --monitor 192.168.1.1 --monitor-interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "To install monitoring service:"
echo "  sudo cp $INSTALL_DIR/netsnipe-monitor.service /etc/systemd/system/"
echo "  sudo systemctl enable netsnipe-monitor"
echo "  sudo systemctl start netsnipe-monitor"

# Create bash completion
echo "Setting up bash completion..."
cat > "$INSTALL_DIR/netsnipe-completion.bash" << 'EOF'
_netsnipe_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    opts="--help -h --ports -p --scan-type -t --stealth -s --output -o --format -f --discover --traceroute --dns-enum --update-db --show-history --service-type"
    
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
    
    case "${prev}" in
        --scan-type|-t)
            COMPREPLY=( $(compgen -W "tcp syn udp" -- ${cur}) )
            return 0
            ;;
        --format|-f)
            COMPREPLY=( $(compgen -W "json html csv" -- ${cur}) )
            return 0
            ;;
        --service-type)
            COMPREPLY=( $(compgen -W "web ssh ftp telnet smtp dns dhcp pop3 imap snmp ldap smb database rdp vnc" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _netsnipe_completion netsnipe
EOF

# Install bash completion
if [[ -d /etc/bash_completion.d ]]; then
    sudo cp "$INSTALL_DIR/netsnipe-completion.bash" /etc/bash_completion.d/netsnipe
fi

# Create configuration wizard
cat > "$INSTALL_DIR/setup_wizard.py" << 'EOF'
#!/usr/bin/env python3
import json
import os
import sys

def setup_wizard():
    print("NetSnipe Configuration Wizard")
    print("=============================")
    
    config = {
        'timeout': 2,
        'max_threads': 100,
        'stealth_delay': [0.1, 0.5],
        'report_format': 'json',
        'auto_update_db': False,
        'scan_history_limit': 100,
        'output_settings': {
            'color_output': True,
            'verbose': False,
            'timestamps': True,
            'progress_bar': True
        },
        'notification_settings': {
            'email_alerts': False,
            'webhook_url': '',
            'slack_webhook': '',
            'discord_webhook': ''
        }
    }
    
    # Basic settings
    print("\n1. Basic Settings")
    timeout = input(f"Scan timeout in seconds [{config['timeout']}]: ")
    if timeout:
        config['timeout'] = int(timeout)
    
    threads = input(f"Maximum threads [{config['max_threads']}]: ")
    if threads:
        config['max_threads'] = int(threads)
    
    # Notification settings
    print("\n2. Notification Settings")
    email_alerts = input("Enable email alerts? (y/n) [n]: ").lower() == 'y'
    config['notification_settings']['email_alerts'] = email_alerts
    
    webhook = input("Webhook URL for alerts [empty]: ")
    if webhook:
        config['notification_settings']['webhook_url'] = webhook
    
    # Save configuration
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("\nConfiguration saved to config.json")
    print("NetSnipe is ready to use!")

if __name__ == '__main__':
    setup_wizard()
EOF

chmod +x "$INSTALL_DIR/setup_wizard.py"

# Final setup
echo ""
echo "========================================="
echo "      Installation Complete!"
echo "========================================="
echo ""
echo "NetSnipe has been installed to: $INSTALL_DIR"
echo ""
echo "Usage:"
echo "  netsnipe <target> [options]      - Run network scan"
echo "  netsnipe-utils [options]         - Utility functions"
echo "  $INSTALL_DIR/activate_netsnipe.sh - Activate NetSnipe environment"
echo "  $INSTALL_DIR/setup_wizard.py     - Run configuration wizard"
echo ""
echo "Examples:"
echo "  netsnipe 192.168.1.1 -p 22,80,443 -f html -o report.html"
echo "  netsnipe 192.168.1.0/24 --discover --service-type web"
echo "  netsnipe-utils --monitor 192.168.1.1 --monitor-interval 300"
echo "  netsnipe-utils --update-vulns"
echo ""
echo "Configuration files:"
echo "  $INSTALL_DIR/config.json         - Main configuration"
echo "  $INSTALL_DIR/vuln_db.json       - Vulnerability database"
echo ""
echo "To get started:"
echo "  1. Run: $INSTALL_DIR/setup_wizard.py"
echo "  2. Test with: netsnipe --help"
echo "  3. Try: netsnipe 127.0.0.1 -p 22,80,443"
echo ""

# Set environment variable for NVD API key
echo "Optional: Set NVD API key for vulnerability database updates:"
echo "  export NVD_API_KEY='your-api-key-here'"
echo "  Add to ~/.bashrc to make permanent"
echo ""

echo "Installation complete! Happy scanning!"