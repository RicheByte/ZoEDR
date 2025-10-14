#!/bin/bash
# uninstall.sh - Complete removal of ZoEDR from system

echo "🗑️  Uninstalling ZoEDR-Linux - Complete Removal..."

if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root, motherfucker!"
    exit 1
fi

# Define paths (consistent with install.sh and zoedr_common.h)
ZOEDR_BINARY_NAME="zoedr_advanced"
ZOEDR_KERNEL_MODULE_NAME="zoedr_kernel"
DASHBOARD_SCRIPT_NAME="zoedr_dashboard_advanced.py"

INSTALL_DIR="/opt/zoedr"
BIN_DEST_PATH="/usr/sbin/$ZOEDR_BINARY_NAME"
LOG_DIR="/var/log/zoedr"
CONFIG_DIR="/etc/zoedr"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/${ZOEDR_BINARY_NAME}.service"
SYSTEMD_DASHBOARD_SERVICE_FILE="/etc/systemd/system/zoedr_dashboard.service"
MODULES_LOAD_CONF="/etc/modules-load.d/$ZOEDR_KERNEL_MODULE_NAME.conf"
LOGROTATE_CONFIG="/etc/logrotate.d/zoedr"

echo "🛑 Stopping ZoEDR services..."
systemctl stop "${ZOEDR_BINARY_NAME}.service" 2>/dev/null
systemctl disable "${ZOEDR_BINARY_NAME}.service" 2>/dev/null
systemctl stop zoedr_dashboard.service 2>/dev/null
systemctl disable zoedr_dashboard.service 2>/dev/null

echo "🧠 Unloading kernel module..."
rmmod "$ZOEDR_KERNEL_MODULE_NAME" 2>/dev/null || true # Ignore errors if not loaded
rm -f "$MODULES_LOAD_CONF"

echo "🗑️  Removing system files..."
# Remove binaries
rm -f "$BIN_DEST_PATH"
rm -f /usr/local/bin/"$ZOEDR_BINARY_NAME" # In case it was copied here by older version

# Remove configuration
rm -f "$BASELINE_HASH_FILE"
rm -f "$SYSTEMD_SERVICE_FILE"
rm -f "$SYSTEMD_DASHBOARD_SERVICE_FILE"
rm -rf "$CONFIG_DIR" # This removes /etc/zoedr

echo "📁 Removing installation directory..."
rm -rf "$INSTALL_DIR" # This removes /opt/zoedr and its contents including dashboard/recover scripts

echo "📊 Removing log files and logrotate configuration..."
rm -rf "$LOG_DIR" # This removes /var/log/zoedr
rm -f /var/log/zoedr_alerts.json # In case the old path was used
rm -f "$LOGROTATE_CONFIG"

echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

echo "🧹 Cleaning any remaining build artifacts in current directory..."
rm -f "$ZOEDR_BINARY_NAME" "${ZOEDR_KERNEL_MODULE_NAME}.ko" *.o *.mod.* modules.order Module.symvers

echo "✅ ZoEDR completely uninstalled from system."
echo "💀 All traces removed. System is clean."
