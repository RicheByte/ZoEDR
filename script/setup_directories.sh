#!/bin/bash
# setup_directories.sh - Create proper directory structure for ZoEDR

echo "📁 Setting up ZoEDR directory structure..."

# Define paths (consistent with zoedr_common.h)
INSTALL_DIR="/opt/zoedr"
LOG_DIR="/var/log/zoedr"
CONFIG_DIR="/etc/zoedr"
LOGROTATE_CONFIG="/etc/logrotate.d/zoedr"

if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root, motherfucker!"
    exit 1
fi

echo "Creating core directories: $INSTALL_DIR, $LOG_DIR, $CONFIG_DIR..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p /usr/sbin # Ensure /usr/sbin exists for binary placement
mkdir -p /etc/systemd/system # Ensure systemd directory exists

# Set proper permissions
echo "Setting permissions for directories..."
chmod 755 "$INSTALL_DIR"
chmod 755 "$LOG_DIR"
chmod 755 "$CONFIG_DIR"

# Create initial empty alert log file if it doesn't exist
touch "$LOG_DIR/alerts.json"
chmod 640 "$LOG_DIR/alerts.json" # Restrict write to root, read by others

# Create logrotate configuration
echo "Creating logrotate configuration for ZoEDR..."
cat > "$LOGROTATE_CONFIG" << EOF
$LOG_DIR/*.json
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 root root
    postrotate
        systemctl reload zoedr_advanced.service >/dev/null 2>&1 || true
    endscript
}
EOF

echo "✅ Directory structure created and permissions set."
