#!/bin/bash
# install_ubuntu.sh - ZoEDR Installation for Ubuntu WSL2

echo "🦠 Installing ZoEDR Phase 4 on Ubuntu WSL2..."

if [ "$EUID" -ne 0 ]; then
    echo "❌ Run as root!"
    exit 1
fi

echo "🔧 Ubuntu 24.04 WSL2 Detected"

# Define paths
ZOEDR_BINARY_NAME="zoedr_advanced"
INSTALL_DIR="/opt/zoedr"
BIN_DEST_PATH="/usr/sbin/$ZOEDR_BINARY_NAME"
LOG_DIR="/var/log/zoedr"
CONFIG_DIR="/etc/zoedr"

echo "📁 Creating directory structure..."
mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"
chmod 755 "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"

echo "🔧 Building userspace daemon..."
# Check if we're in the zoedr directory with src files
if [ ! -f "src/zoedr_advanced.c" ]; then
    echo "❌ Source files not found!"
    echo "💡 Make sure you're in the zoedr directory containing src/ folder"
    echo "📁 Current directory: $(pwd)"
    ls -la
    exit 1
fi

# Compile the main daemon
gcc -o "$ZOEDR_BINARY_NAME" src/zoedr_advanced.c -lpthread -lcurl -lcrypto -O2 -Wall -Wextra -Isrc/

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed!"
    exit 1
fi

echo "💾 Installing binary..."
cp "$ZOEDR_BINARY_NAME" "$BIN_DEST_PATH"
chmod 755 "$BIN_DEST_PATH"

# Skip kernel module on WSL2
echo "⚠️ Skipping kernel module on WSL2"

echo "🔒 Generating baseline hash..."
sha256sum "$BIN_DEST_PATH" | awk '{print $1}' > "$CONFIG_DIR/${ZOEDR_BINARY_NAME}.sha256"
chmod 600 "$CONFIG_DIR/${ZOEDR_BINARY_NAME}.sha256"

echo "⚙️ Setting up system services..."
# Create systemd service
cat > "/etc/systemd/system/${ZOEDR_BINARY_NAME}.service" << EOF
[Unit]
Description=ZoEDR Linux EDR Advanced Daemon
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=$BIN_DEST_PATH
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF

echo "📊 Deploying dashboard..."
if [ -f "dashboard/zoedr_dashboard_advanced.py" ]; then
    cp "dashboard/zoedr_dashboard_advanced.py" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/zoedr_dashboard_advanced.py"
    
    # Create dashboard service
    cat > "/etc/systemd/system/zoedr_dashboard.service" << EOF
[Unit]
Description=ZoEDR Web Dashboard
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
User=root
ExecStart=/usr/bin/python3 $INSTALL_DIR/zoedr_dashboard_advanced.py
WorkingDirectory=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ Dashboard deployed"
else
    echo "⚠️ Dashboard script not found"
fi

# Create manual start scripts for WSL2
echo "🎯 Creating manual start scripts..."
cat > "$INSTALL_DIR/start_manual.sh" << 'EOF'
#!/bin/bash
echo "🚀 Starting ZoEDR manually..."
/usr/sbin/zoedr_advanced
EOF

cat > "$INSTALL_DIR/start_dashboard_manual.sh" << 'EOF'
#!/bin/bash
echo "🌐 Starting ZoEDR Dashboard manually..."
cd /opt/zoedr
python3 zoedr_dashboard_advanced.py --host=0.0.0.0 --port=8888
EOF

chmod +x "$INSTALL_DIR/start_manual.sh"
chmod +x "$INSTALL_DIR/start_dashboard_manual.sh"

# Create log file
touch "$LOG_DIR/alerts.json"
chmod 644 "$LOG_DIR/alerts.json"

# Reload systemd
systemctl daemon-reload 2>/dev/null || echo "⚠️ systemd daemon-reload skipped"

echo ""
echo "✅ ZoEDR Installation Complete!"
echo ""
echo "🚀 START OPTIONS:"
echo "   1. Systemd (if available):"
echo "      sudo systemctl start zoedr_advanced.service"
echo "      sudo systemctl start zoedr_dashboard.service"
echo ""
echo "   2. Manual (WSL2 recommended):"
echo "      sudo $INSTALL_DIR/start_manual.sh"
echo "      sudo $INSTALL_DIR/start_dashboard_manual.sh"
echo ""
echo "🌐 Dashboard URL: http://localhost:8888"
echo ""
echo "💡 WSL2 Notes:"
echo "   - Use manual start scripts for best results"
echo "   - Kernel module disabled (WSL2 limitation)"
echo "   - Check logs: tail -f /var/log/zoedr/alerts.json"