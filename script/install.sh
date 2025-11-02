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

DEPS_FAILED=0

if command -v apt-get >/dev/null 2>&1; then
    # Debian/Ubuntu/Kali
    echo "🔧 Detected apt-based system (Debian/Ubuntu/Kali)"
    echo "📡 Updating package lists..."
    apt-get update -y > /dev/null 2>&1
    
    # Install core dependencies first (without kernel headers)
    echo "🔨 Installing build essentials and libraries..."
    apt-get install -y build-essential libcurl4-openssl-dev libssl-dev curl python3 python3-pip 2>&1 | grep -v "^Get:" | grep -v "^Reading"
    
    # Try to install kernel headers, but don't fail if unavailable
    echo "🧠 Attempting to install kernel headers..."
    KERNEL_VERSION=$(uname -r)
    
    # Try multiple header package patterns for Kali/Debian compatibility
    if apt-get install -y linux-headers-${KERNEL_VERSION} > /dev/null 2>&1; then
        echo "✅ Kernel headers installed for ${KERNEL_VERSION}"
    elif apt-get install -y linux-headers-amd64 > /dev/null 2>&1; then
        echo "✅ Generic kernel headers installed"
    elif apt-get install -y linux-headers-$(uname -r | sed 's/-amd64//') > /dev/null 2>&1; then
        echo "✅ Alternative kernel headers installed"
    else
        echo "⚠️ Kernel headers not available for ${KERNEL_VERSION}"
        echo "💡 Kernel module compilation will be skipped (userspace daemon will still work)"
    fi
    
elif command -v dnf >/dev/null 2>&1; then
    # Fedora/RHEL
    echo "🔧 Detected dnf-based system (Fedora/RHEL)"
    dnf update -y > /dev/null 2>&1
    dnf install -y gcc make kernel-devel libcurl-devel openssl-devel curl python3 python3-pip 2>&1 | grep -v "^Last metadata"
    DEPS_FAILED=$?
    
elif command -v pacman >/dev/null 2>&1; then
    # Arch Linux
    echo "🔧 Detected pacman-based system (Arch/Manjaro)"
    pacman -Sy --noconfirm > /dev/null 2>&1
    pacman -S --noconfirm base-devel linux-headers curl python python-pip 2>&1 | grep -v "checking"
    DEPS_FAILED=$?
    
elif command -v zypper >/dev/null 2>&1; then
    # openSUSE
    echo "🔧 Detected zypper-based system (openSUSE)"
    zypper refresh > /dev/null 2>&1
    zypper install -y gcc make kernel-devel libcurl-devel libopenssl-devel curl python3 python3-pip 2>&1 | grep -v "Loading"
    DEPS_FAILED=$?
    
else
    echo "❌ Unsupported package manager. Please install dependencies manually:"
    echo "   - build-essential / base-devel"
    echo "   - linux-headers-$(uname -r) / kernel-devel (optional for kernel module)"
    echo "   - libcurl development libraries"
    echo "   - openssl development libraries"
    echo "   - python3 and python3-pip"
    exit 1
fi

# Check if core dependencies were installed (python, gcc, etc.)
if ! command -v gcc >/dev/null 2>&1; then
    echo "❌ GCC not found. Core dependencies installation failed."
    echo "💡 Try manually: sudo apt-get install build-essential libcurl4-openssl-dev libssl-dev curl python3 python3-pip"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Python3 not found. Core dependencies installation failed."
    echo "💡 Try manually: sudo apt-get install python3 python3-pip"
    exit 1
fi

echo "✅ Core dependencies installed successfully"

echo "✅ Core dependencies installed successfully"

echo "🐍 Installing Python dependencies for dashboard..."
if command -v pip3 >/dev/null 2>&1; then
    # Check if we're on a system with PEP 668 restrictions (like Kali Linux)
    if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
        echo "   Detected externally-managed Python environment (Kali/Debian)"
        echo "   Using --break-system-packages flag for system-wide installation..."
        pip3 install --upgrade pip --quiet --break-system-packages 2>&1 | grep -v "Requirement already" | head -5
        pip3 install dash dash-bootstrap-components pandas plotly numpy --quiet --break-system-packages 2>&1 | grep -v "Requirement already" | grep -v "Successfully installed" || echo "   Installing: dash, plotly, pandas, numpy..."
    else
        # Older systems without PEP 668
        pip3 install --upgrade pip --quiet 2>&1 | grep -v "Requirement already" | head -5
        pip3 install dash dash-bootstrap-components pandas plotly numpy --quiet 2>&1 | grep -v "Requirement already" | grep -v "Successfully installed" || echo "   Installing: dash, plotly, pandas, numpy..."
    fi
    
    if python3 -c "import dash" 2>/dev/null; then
        echo "✅ Python dashboard dependencies installed successfully"
    else
        echo "⚠️ Python dependencies may have issues. Dashboard might not work."
        echo "💡 Try manually: sudo pip3 install dash dash-bootstrap-components pandas plotly numpy --break-system-packages"
    fi
else
    echo "⚠️ pip3 not found. Skipping Python dependencies."
    echo "💡 Install manually: sudo apt-get install python3-pip"
fi

echo "📁 Creating ZoEDR directory structure..."
mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"
chmod 755 "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"

# Change to the correct directory if we're in script/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ ! -f "src/zoedr_advanced.c" ]; then
    if [ -f "$PROJECT_ROOT/src/zoedr_advanced.c" ]; then
        echo "📂 Changing to project root directory..."
        cd "$PROJECT_ROOT" || exit 1
    fi
fi

echo "🔧 Building userspace daemon: ${ZOEDR_BINARY_NAME}..."
# Check if we're in the right directory with source files
if [ ! -f "src/zoedr_advanced.c" ]; then
    echo "❌ Source files not found! Make sure you're in the zoedr directory."
    echo "💡 Current directory: $(pwd)"
    echo "💡 Expected file: src/zoedr_advanced.c"
    echo "💡 Try running from: $PROJECT_ROOT"
    exit 1
fi

gcc -o "$ZOEDR_BINARY_NAME" src/zoedr_advanced.c -lpthread -lcurl -lcrypto -O2 -Wall -Wextra -Isrc/

if [ $? -ne 0 ]; then
    echo "❌ Userspace daemon compilation failed. Aborting."
    exit 1
fi

echo "🧠 Building kernel module: ${ZOEDR_KERNEL_MODULE_NAME}.ko..."
# Check if we have kernel headers and build environment
KERNEL_MODULE_COMPILED=0

if [ -d "/lib/modules/$(uname -r)/build" ]; then
    echo "   Found kernel build directory, compiling module..."
    make -C /lib/modules/"$(uname -r)"/build M="$(pwd)" obj-m="${ZOEDR_KERNEL_MODULE_NAME}.o" modules > /dev/null 2>&1
    
    if [ -f "${ZOEDR_KERNEL_MODULE_NAME}.ko" ]; then
        echo "✅ Kernel module compiled successfully."
        KERNEL_MODULE_COMPILED=1
    else
        echo "⚠️ Kernel module compilation failed (userspace daemon will still work)."
    fi
else
    echo "⚠️ Kernel build directory not found at /lib/modules/$(uname -r)/build"
    echo "💡 Kernel module will not be built - userspace daemon will run without kernel module"
    echo "   To enable kernel module support, install kernel headers:"
    echo "   • Debian/Ubuntu/Kali: sudo apt-get install linux-headers-amd64"
    echo "   • Fedora/RHEL: sudo dnf install kernel-devel"
    echo "   • Arch: sudo pacman -S linux-headers"
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
# Check multiple possible locations for the dashboard
DASHBOARD_FOUND=0
POSSIBLE_PATHS=(
    "./Dashboard/$DASHBOARD_SCRIPT_NAME"
    "../Dashboard/$DASHBOARD_SCRIPT_NAME"
    "./dashboard/$DASHBOARD_SCRIPT_NAME"
    "../dashboard/$DASHBOARD_SCRIPT_NAME"
    "$PROJECT_ROOT/Dashboard/$DASHBOARD_SCRIPT_NAME"
    "$PROJECT_ROOT/dashboard/$DASHBOARD_SCRIPT_NAME"
)

for path in "${POSSIBLE_PATHS[@]}"; do
    if [ -f "$path" ]; then
        DASHBOARD_SRC_PATH="$path"
        DASHBOARD_FOUND=1
        break
    fi
done

if [ $DASHBOARD_FOUND -eq 1 ]; then
    echo "   Found dashboard at: $DASHBOARD_SRC_PATH"
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
        LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        if [ -n "$LOCAL_IP" ]; then
            echo "🌐 Access at: http://${LOCAL_IP}:8888"
        else
            echo "🌐 Access at: http://localhost:8888"
        fi
    else
        echo "⚠️ Dashboard service started but may not be active."
        echo "💡 Check logs: sudo journalctl -u zoedr_dashboard.service -n 50"
        echo "💡 Verify Python deps: python3 -c 'import dash, plotly, pandas'"
    fi
else
    echo "⚠️ Dashboard script not found. Skipping dashboard deployment."
    echo "💡 Expected locations:"
    for path in "${POSSIBLE_PATHS[@]}"; do
        echo "   - $path"
    done
fi

echo "🎯 Creating recovery script..."
RECOVERY_FOUND=0
RECOVERY_PATHS=(
    "./scripts/recover.sh"
    "../scripts/recover.sh"
    "./script/recover.sh"
    "../script/recover.sh"
    "./recover.sh"
    "$PROJECT_ROOT/script/recover.sh"
    "$PROJECT_ROOT/scripts/recover.sh"
)

for path in "${RECOVERY_PATHS[@]}"; do
    if [ -f "$path" ]; then
        cp "$path" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/recover.sh"
        RECOVERY_FOUND=1
        echo "✅ Recovery script installed"
        break
    fi
done

if [ $RECOVERY_FOUND -eq 0 ]; then
    echo "⚠️ Recovery script not found, skipping"
fi

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
if [ $KERNEL_MODULE_COMPILED -eq 1 ]; then
    echo "   • Kernel-level persistence ✅"
else
    echo "   • Kernel-level persistence ⚠️  (module not compiled)"
fi
echo "   • Auto-recovery mechanisms"
echo "   • Advanced live dashboard"
echo ""
echo "📊 Check daemon status: systemctl status ${ZOEDR_BINARY_NAME}.service"
echo "📊 Check dashboard status: systemctl status zoedr_dashboard.service"
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$LOCAL_IP" ]; then
    echo "🌐 Access dashboard: http://${LOCAL_IP}:8888"
else
    echo "🌐 Access dashboard: http://localhost:8888"
fi
if [ -f "$INSTALL_DIR/recover.sh" ]; then
    echo "🔄 Manual recovery: $INSTALL_DIR/recover.sh"
fi
echo "� View logs: sudo journalctl -u ${ZOEDR_BINARY_NAME}.service -f"
echo "📋 Alert log: tail -f $LOG_DIR/alerts.json"
echo ""
echo "🐉 ZETA REALM SECURED"