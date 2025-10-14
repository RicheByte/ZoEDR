#!/bin/bash
# test.sh - ZoEDR System Testing

echo "🧪 ZoEDR System Tests - Phase 4 Validation"

# Define paths (consistent with install.sh and zoedr_common.h)
ZOEDR_BINARY_NAME="zoedr_advanced"
ZOEDR_KERNEL_MODULE_NAME="zoedr_kernel"
INSTALL_DIR="/opt/zoedr"
BIN_DEST_PATH="/usr/sbin/$ZOEDR_BINARY_NAME"
LOG_DIR="/var/log/zoedr"
ALERT_LOG_FILE="$LOG_DIR/alerts.json"
DASHBOARD_SCRIPT_NAME="zoedr_dashboard_advanced.py"

# --- Test 1: Root Check ---
if [ "$EUID" -ne 0 ]; then
    echo "❌ Test script must be run as root. Exiting."
    exit 1
fi

# --- Test 2: Service Status ---
echo "1. Testing ZoEDR daemon service status..."
systemctl is-active --quiet "${ZOEDR_BINARY_NAME}.service"
if [ $? -eq 0 ]; then
    echo "✅ Daemon service is running."
else
    echo "❌ Daemon service is NOT running."
fi

# --- Test 3: Kernel Module Status ---
echo "2. Testing kernel module status..."
lsmod | grep -q "$ZOEDR_KERNEL_MODULE_NAME"
if [ $? -eq 0 ]; then
    echo "✅ Kernel module '${ZOEDR_KERNEL_MODULE_NAME}' loaded."
else
    echo "⚠️ Kernel module '${ZOEDR_KERNEL_MODULE_NAME}' not loaded (may be intentional if compilation failed)."
fi

# --- Test 4: Binary Integrity Verification ---
echo "3. Testing binary integrity using verify_hash.sh..."
./scripts/verify_hash.sh
INTEGRITY_RESULT=$?
if [ $INTEGRITY_RESULT -eq 0 ]; then
    echo "✅ Binary integrity verified."
else
    echo "❌ Binary integrity compromised!"
fi

# --- Test 5: Alert Log File Check ---
echo "4. Checking alert log file ($ALERT_LOG_FILE)..."
if [ -f "$ALERT_LOG_FILE" ]; then
    echo "✅ Alert log file exists."
    ALERT_COUNT=$(wc -l < "$ALERT_LOG_FILE" 2>/dev/null || echo "0")
    echo "📊 Alerts recorded: $ALERT_COUNT"
else
    echo "❌ No alert log file found. Daemon might not be logging."
fi

# --- Test 6: Dashboard Service Status ---
echo "5. Testing dashboard service status..."
systemctl is-active --quiet "zoedr_dashboard.service"
if [ $? -eq 0 ]; then
    echo "✅ Dashboard service is running."
else
    echo "❌ Dashboard service is NOT running."
fi

# --- Test 7: Recovery Script Availability ---
echo "6. Testing recovery script availability..."
if [ -f "$INSTALL_DIR/recover.sh" ]; then
    echo "✅ Recovery script available at '$INSTALL_DIR/recover.sh'."
else
    echo "❌ Recovery script missing at '$INSTALL_DIR/recover.sh'."
fi

# --- Test 8: Simulate Threat (and check for alert in log) ---
echo "7. Simulating a suspicious process to trigger an alert..."
# Create a dummy high-CPU process
TEMP_MINER_SCRIPT="/tmp/zoedr_test_miner.sh"
echo '#!/bin/bash' > "$TEMP_MINER_SCRIPT"
echo 'while true; do dd if=/dev/zero of=/dev/null &>/dev/null; done' >> "$TEMP_MINER_SCRIPT"
chmod +x "$TEMP_MINER_SCRIPT"

LAST_ALERT_COUNT=$(wc -l < "$ALERT_LOG_FILE" 2>/dev/null || echo "0")
echo "Starting dummy high-CPU process..."
"$TEMP_MINER_SCRIPT" &
MINER_PID=$!
echo "Dummy miner PID: $MINER_PID"
sleep 5 # Give ZoEDR time to detect

CURRENT_ALERT_COUNT=$(wc -l < "$ALERT_LOG_FILE" 2>/dev/null || echo "0")

if (( CURRENT_ALERT_COUNT > LAST_ALERT_COUNT )); then
    echo "✅ New alert(s) detected in log file after simulation."
    # Optionally display the new alerts
    # tail -n $((CURRENT_ALERT_COUNT - LAST_ALERT_COUNT)) "$ALERT_LOG_FILE"
else
    echo "❌ No new alerts detected in log file after simulation. ZoEDR might not be detecting threats."
fi

# Cleanup simulated threat
kill -9 "$MINER_PID" 2>/dev/null
rm -f "$TEMP_MINER_SCRIPT"
echo "Cleaned up dummy miner process."

echo ""
echo "🧪 TEST SUMMARY:"
if [ $INTEGRITY_RESULT -eq 0 ]; then
    echo "✅ Integrity: PASS"
else
    echo "❌ Integrity: FAIL"
fi
systemctl is-active --quiet "${ZOEDR_BINARY_NAME}.service" && echo "✅ Daemon Service: RUNNING" || echo "❌ Daemon Service: NOT RUNNING"
systemctl is-active --quiet "zoedr_dashboard.service" && echo "✅ Dashboard Service: RUNNING" || echo "❌ Dashboard Service: NOT RUNNING"
lsmod | grep -q "$ZOEDR_KERNEL_MODULE_NAME" && echo "✅ Kernel Module: LOADED" || echo "⚠️ Kernel Module: NOT LOADED"

echo "🎯 Testing complete. Review logs in $LOG_DIR and check dashboard for details."
