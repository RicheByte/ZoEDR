#!/bin/bash
# install.sh - ZoEDR Phase 4 Deployment - Multi-Distribution Support

echo "🦠 Installing ZoEDR Phase 4 - Persistence & Anti-Tampering with Advanced Dashboard..."

if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root, motherfucker!"
    exit 1
fi

# Define paths (consistent with zoedr_common.h)
ZOEDR_BINARY_NAME="zoedr_advanced"
ZOEDR_KERNEL_MODULE_NAME="zoedr_kernel"

INSTALL_DIR="/opt/zoedr"
BIN_DEST_PATH="/usr/sbin/$ZOEDR_BINARY_NAME"
LOG_DIR="/var/log/zoedr"
CONFIG_DIR="/etc/zoedr"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/${ZOEDR_BINARY_NAME}.service"
BASELINE_HASH_FILE="$CONFIG_DIR/${ZOEDR_BINARY_NAME}.sha256"
MODULES_LOAD_CONF="/etc/modules-load.d/$ZOEDR_KERNEL_MODULE_NAME.conf"
LOGROTATE_CONFIG="/etc/logrotate.d/zoedr"
DASHBOARD_SCRIPT_NAME="zoedr_dashboard_advanced.py"
DASHBOARD_SRC_PATH="./dashboard/$DASHBOARD_SCRIPT_NAME"

# Detect package manager and install dependencies
echo "📦 Detecting package manager and installing system dependencies..."

if command -v apt-get >/dev/null 2>&1; then
    # Debian/Ubuntu
    echo "🔧 Detected apt-based system (Debian/Ubuntu)"
    apt-get update -y > /dev/null 2>&1
    apt-get install -y build-essential libcurl4-openssl-dev libssl-dev linux-headers-$(uname -r) curl python3 python3-pip > /dev/null 2>&1
    
elif command -v dnf >/dev/null 2>&1; then
    # Fedora/RHEL
    echo "🔧 Detected dnf-based system (Fedora/RHEL)"
    dnf update -y > /dev/null 2>&1
    dnf install -y gcc make kernel-devel libcurl-devel openssl-devel curl python3 python3-pip > /dev/null 2>&1
    
elif command -v pacman >/dev/null 2>&1; then
    # Arch Linux
    echo "🔧 Detected pacman-based system (Arch/Manjaro)"
    pacman -Sy --noconfirm > /dev/null 2>&1
    pacman -S --noconfirm base-devel linux-headers curl python python-pip > /dev/null 2>&1
    
elif command -v zypper >/dev/null 2>&1; then
    # openSUSE
    echo "🔧 Detected zypper-based system (openSUSE)"
    zypper refresh > /dev/null 2>&1
    zypper install -y gcc make kernel-devel libcurl-devel libopenssl-devel curl python3 python3-pip > /dev/null 2>&1
    
else
    echo "❌ Unsupported package manager. Please install dependencies manually:"
    echo "   - build-essential / base-devel"
    echo "   - linux-headers-$(uname -r) / kernel-devel"
    echo "   - libcurl development libraries"
    echo "   - openssl development libraries"
    echo "   - python3 and python3-pip"
    exit 1
fi

if [ $? -ne 0 ]; then
    echo "❌ System dependencies installation failed. You may need to install manually."
    echo "💡 Try running the appropriate command for your distribution:"
    echo "   Debian/Ubuntu: sudo apt-get install build-essential libcurl4-openssl-dev libssl-dev linux-headers-$(uname -r) curl python3 python3-pip"
    echo "   Fedora/RHEL: sudo dnf install gcc make kernel-devel libcurl-devel openssl-devel curl python3 python3-pip"
    echo "   Arch: sudo pacman -S base-devel linux-headers curl python python-pip"
    exit 1
fi

echo "🐍 Installing Python dependencies for dashboard..."
pip3 install --upgrade pip > /dev/null 2>&1
pip3 install dash dash-bootstrap-components pandas plotly > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "❌ Python dependencies installation failed. Dashboard might not work."
    echo "💡 Try: sudo pip3 install dash dash-bootstrap-components pandas plotly"
fi

echo "📁 Creating ZoEDR directory structure..."
mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"
chmod 755 "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"

echo "🔧 Building userspace daemon: ${ZOEDR_BINARY_NAME}..."
# Check if we're in the right directory with source files
if [ ! -f "src/zoedr_advanced.c" ]; then
    echo "❌ Source files not found! Make sure you're in the zoedr directory."
    echo "💡 Current directory: $(pwd)"
    exit 1
fi

gcc -o "$ZOEDR_BINARY_NAME" src/zoedr_advanced.c -lpthread -lcurl -lcrypto -O2 -Wall -Wextra -Isrc/

if [ $? -ne 0 ]; then
    echo "❌ Userspace daemon compilation failed. Aborting."
    exit 1
fi

echo "🧠 Building kernel module: ${ZOEDR_KERNEL_MODULE_NAME}.ko..."
# Check if we have kernel headers and build environment
if [ -d "/lib/modules/$(uname -r)/build" ]; then
    make -C /lib/modules/"$(uname -r)"/build M="$(pwd)" obj-m="${ZOEDR_KERNEL_MODULE_NAME}.o" modules > /dev/null 2>&1
else
    echo "⚠️ Kernel headers not found at /lib/modules/$(uname -r)/build"
    echo "💡 Install kernel headers for your distribution:"
    echo "   Debian/Ubuntu: sudo apt-get install linux-headers-$(uname -r)"
    echo "   Fedora/RHEL: sudo dnf install kernel-devel"
    echo "   Arch: sudo pacman -S linux-headers"
fi

KERNEL_MODULE_COMPILED=0
if [ -f "${ZOEDR_KERNEL_MODULE_NAME}.ko" ]; then
    echo "✅ Kernel module compiled successfully."
    KERNEL_MODULE_COMPILED=1
else
    echo "⚠️ Kernel module compilation failed (continuing without it)."
    echo "💡 Check if kernel headers are installed and try: make"
fi

echo "💾 Installing ZoEDR binaries..."
cp "$ZOEDR_BINARY_NAME" "$BIN_DEST_PATH"
chmod 755 "$BIN_DEST_PATH"

if [ $KERNEL_MODULE_COMPILED -eq 1 ]; then
    echo "💾 Installing kernel module..."
    cp "${ZOEDR_KERNEL_MODULE_NAME}.ko" "$INSTALL_DIR/"
    echo "$ZOEDR_KERNEL_MODULE_NAME" | tee "$MODULES_LOAD_CONF" > /dev/null
    # Try to load the module
    if insmod "$INSTALL_DIR/${ZOEDR_KERNEL_MODULE_NAME}.ko" 2>/dev/null; then
        echo "✅ Kernel module loaded successfully."
    else
        echo "⚠️ Could not load kernel module. Check dmesg for errors."
        echo "💡 Try: sudo insmod $INSTALL_DIR/${ZOEDR_KERNEL_MODULE_NAME}.ko"
    fi
fi

echo "🔒 Generating baseline hash for integrity protection..."
sha256sum "$BIN_DEST_PATH" | awk '{print $1}' > "$BASELINE_HASH_FILE"
chmod 600 "$BASELINE_HASH_FILE"
echo "Baseline hash stored at $BASELINE_HASH_FILE"

echo "⚙️ Creating systemd service for ZoEDR daemon..."
cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=ZoEDR Linux EDR Advanced Daemon
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=$BIN_DEST_PATH
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${ZOEDR_BINARY_NAME}.service" > /dev/null 2>&1
systemctl start "${ZOEDR_BINARY_NAME}.service" > /dev/null 2>&1

if systemctl is-active --quiet "${ZOEDR_BINARY_NAME}.service"; then
    echo "✅ ZoEDR daemon service enabled and started."
else
    echo "⚠️ ZoEDR daemon service started but may not be active. Check: systemctl status ${ZOEDR_BINARY_NAME}.service"
fi

echo "📊 Deploying advanced dashboard..."
if [ -f "$DASHBOARD_SRC_PATH" ]; then
    cp "$DASHBOARD_SRC_PATH" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$DASHBOARD_SCRIPT_NAME"

    # Create systemd service for the dashboard
    cat > "/etc/systemd/system/zoedr_dashboard.service" << EOF
[Unit]
Description=ZoEDR Web Dashboard
After=network.target zoedr_advanced.service

[Service]
Type=simple
Restart=always
RestartSec=5
User=root
ExecStart=/usr/bin/python3 $INSTALL_DIR/$DASHBOARD_SCRIPT_NAME
WorkingDirectory=$INSTALL_DIR
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable zoedr_dashboard.service > /dev/null 2>&1
    systemctl start zoedr_dashboard.service > /dev/null 2>&1
    
    if systemctl is-active --quiet "zoedr_dashboard.service"; then
        echo "✅ ZoEDR Dashboard service enabled and started."
        echo "🌐 Access at: http://$(hostname -I | awk '{print $1}'):8888"
    else
        echo "⚠️ Dashboard service started but may not be active. Check: systemctl status zoedr_dashboard.service"
    fi
else
    echo "❌ Dashboard script not found at $DASHBOARD_SRC_PATH. Skipping dashboard deployment."
fi

echo "🎯 Creating recovery script..."
cp scripts/recover.sh "$INSTALL_DIR/" 2>/dev/null || echo "⚠️ Could not copy recover.sh"
chmod +x "$INSTALL_DIR/recover.sh" 2>/dev/null || echo "⚠️ Could not make recover.sh executable"

echo "📝 Setting up logrotate for ZoEDR logs..."
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
        systemctl reload ${ZOEDR_BINARY_NAME}.service >/dev/null 2>&1 || true
    endscript
}
EOF

# Create initial alert log file
touch "$LOG_DIR/alerts.json"
chmod 644 "$LOG_DIR/alerts.json"

# Cleanup build artifacts
echo "🧹 Cleaning up build artifacts..."
rm -f "$ZOEDR_BINARY_NAME" "${ZOEDR_KERNEL_MODULE_NAME}.ko" *.o *.mod.* modules.order Module.symvers 2>/dev/null

echo ""
echo "✅ ZoEDR Phase 4 deployed successfully!"
echo ""
echo "🐲 IMMORTAL DEFENSE ACTIVATED:"
echo "   • Self-healing watchdog monitoring"
echo "   • Binary integrity protection"
echo "   • Kernel-level persistence"
echo "   • Auto-recovery mechanisms"
echo "   • Advanced live dashboard"
echo ""
echo "📊 Check status: systemctl status ${ZOEDR_BINARY_NAME}.service"
echo "🌐 Access dashboard at http://$(hostname -I | awk '{print $1}'):8888"
echo "🔄 Manual recovery: $INSTALL_DIR/recover.sh"
echo "🔬 Run comprehensive tests: scripts/test.sh"
echo ""
echo "🐉 ZETA REALM SECURED - ZERO FUCKING ERRORS"