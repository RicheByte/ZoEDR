#!/bin/bash
# verify_hash.sh - Manual integrity verification for ZoEDR binary

echo "🔒 ZoEDR Binary Integrity Verification"

# Define paths (consistent with install.sh and zoedr_common.h)
ZOEDR_BINARY_NAME="zoedr_advanced"
BIN_DEST_PATH="/usr/sbin/$ZOEDR_BINARY_NAME"
CONFIG_DIR="/etc/zoedr"
BASELINE_HASH_FILE="$CONFIG_DIR/${ZOEDR_BINARY_NAME}.sha256"

if [ ! -f "$BASELINE_HASH_FILE" ]; then
    echo "❌ No baseline hash found at '$BASELINE_HASH_FILE'. Is ZoEDR installed?"
    exit 1
fi

if [ ! -f "$BIN_DEST_PATH" ]; then
    echo "❌ ZoEDR binary not found at '$BIN_DEST_PATH'. Is ZoEDR installed correctly?"
    exit 1
fi

echo "📦 Computing current hash of '$BIN_DEST_PATH'..."
CURRENT_HASH=$(sha256sum "$BIN_DEST_PATH" | awk '{print $1}')
BASELINE_HASH=$(cat "$BASELINE_HASH_FILE")

echo "🔍 Current Hash:  $CURRENT_HASH"
echo "📋 Baseline Hash: $BASELINE_HASH"

if [ "$CURRENT_HASH" = "$BASELINE_HASH" ]; then
    echo "✅ INTEGRITY VERIFIED - Binary is authentic."
    exit 0
else
    echo "🚨 INTEGRITY COMPROMISED - Binary has been modified!"
    echo "💀 Hash mismatch detected - possible tampering."
    exit 1
fi
