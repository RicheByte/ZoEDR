#!/bin/bash
# recover.sh - ZoEDR Self-Healing Recovery Script

echo "🛠️  Running ZoEDR Recovery..."

if [ "$EUID" -ne 0 ]; then
    echo "❌ Recovery script must be run as root!"
    exit 1
fi

# Define paths (consistent with install.sh and zoedr_common.h)
ZOEDR_BINARY_NAME="zoedr_advanced"
ZOEDR_KERNEL_MODULE_NAME="zoedr_kernel"
INSTALL_DIR="/opt/zoedr"
BIN_DEST_PATH="/usr/sbin/$ZOEDR_BINARY_NAME"
CONFIG_DIR="/etc/zoedr"
BASELINE_HASH_FILE="$CONFIG_DIR/${ZOEDR_BINARY_NAME}.sha256"
MODULES_LOAD_CONF="/etc/modules-load.d/$ZOEDR_KERNEL_MODULE_NAME.conf"

echo "1. Ensuring ZoEDR daemon is stopped for safe recovery..."
systemctl stop "${ZOEDR_BINARY_NAME}.service" 2>/dev/null || true

echo "2. Restoring main binary from backup or reinstalling if tampered..."
# Check if a corrupted binary backup exists and restore it
if [ -f "${BIN_DEST_PATH}.corrupted" ]; then
    echo "💀 Detected corrupted binary backup. Restoring..."
    mv -f "${BIN_DEST_PATH}.corrupted" "$BIN_DEST_PATH"
    chmod +x "$BIN_DEST_PATH"
elif [ -f "$INSTALL_DIR/$ZOEDR_BINARY_NAME" ]; then
    # If no corrupted backup, check against baseline hash and restore from install dir if needed
    if [ -f "$BASELINE_HASH_FILE" ]; then
        CURRENT_HASH=$(sha256sum "$BIN_DEST_PATH" 2>/dev/null | awk '{print $1}')
        BASELINE_HASH=$(cat "$BASELINE_HASH_FILE" 2>/dev/null)
        if [ "$CURRENT_HASH" != "$BASELINE_HASH" ]; then
            echo "🚨 Main binary hash mismatch. Restoring from '$INSTALL_DIR/$ZOEDR_BINARY_NAME'..."
            cp "$INSTALL_DIR/$ZOEDR_BINARY_NAME" "$BIN_DEST_PATH"
            chmod +x "$BIN_DEST_PATH"
        else
            echo "✅ Main binary integrity good, no restore needed."
        fi
    else
        echo "⚠️ No baseline hash file found. Cannot verify integrity, skipping binary restore."
    fi
else
    echo "❌ Cannot find a clean binary to restore from. Please run 'install.sh' again."
fi

echo "3. Reloading kernel module..."
# Ensure the module is configured to load on boot
if [ ! -f "$MODULES_LOAD_CONF" ]; then
    echo "$ZOEDR_KERNEL_MODULE_NAME" | tee "$MODULES_LOAD_CONF" > /dev/null
fi
# Remove and insert module to ensure it's fresh
rmmod "$ZOEDR_KERNEL_MODULE_NAME" 2>/dev/null || true
if [ -f "$INSTALL_DIR/${ZOEDR_KERNEL_MODULE_NAME}.ko" ]; then
    insmod "$INSTALL_DIR/${ZOEDR_KERNEL_MODULE_NAME}.ko" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "✅ Kernel module reloaded successfully."
    else
        echo "❌ Failed to reload kernel module. Check dmesg for errors."
    fi
else
    echo "⚠️ Kernel module file not found in $INSTALL_DIR. Cannot reload."
fi

echo "4. Restarting ZoEDR daemon service..."
systemctl start "${ZOEDR_BINARY_NAME}.service"
if systemctl is-active --quiet "${ZOEDR_BINARY_NAME}.service"; then
    echo "✅ ZoEDR daemon service restarted."
else
    echo "❌ Failed to restart ZoEDR daemon service. Check 'journalctl -u ${ZOEDR_BINARY_NAME}.service'."
fi

echo "5. Restarting ZoEDR Dashboard service (if installed)..."
systemctl start zoedr_dashboard.service 2>/dev/null || true
if systemctl is-active --quiet "zoedr_dashboard.service"; then
    echo "✅ ZoEDR Dashboard service restarted."
else
    echo "⚠️ ZoEDR Dashboard service not running or failed to restart. Check 'journalctl -u zoedr_dashboard.service'."
fi

echo "✅ Recovery complete. Check system status."
