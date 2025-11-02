#!/bin/bash
# Quick start script for ZoEDR Dashboard

echo "🐉 ZoEDR Threat Intelligence Dashboard"
echo "======================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip."
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install -r ../requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies."
    exit 1
fi

echo ""
echo "✅ Dependencies installed successfully!"
echo ""

# Check if alert file exists
ALERT_FILE="/var/log/zoedr/alerts.json"
if [ ! -f "$ALERT_FILE" ]; then
    echo "⚠️  Warning: Alert file not found at $ALERT_FILE"
    echo "   The dashboard will run but show no data until alerts are generated."
    echo ""
fi

# Start the dashboard
echo "🚀 Starting dashboard on http://0.0.0.0:8888"
echo "   Press Ctrl+C to stop the dashboard"
echo ""

python3 zoedr_dashboard_advanced.py
