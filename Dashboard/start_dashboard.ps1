# ZoEDR Dashboard Quick Start (Windows)
# Run this script in PowerShell

Write-Host "🐉 ZoEDR Threat Intelligence Dashboard" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python 3 is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python is not installed. Please install Python 3.8 or higher." -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host ""
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
pip install -r ..\requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to install dependencies." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "✅ Dependencies installed successfully!" -ForegroundColor Green
Write-Host ""

# Note about alert file (Windows path may differ)
Write-Host "⚠️  Note: This dashboard reads from /var/log/zoedr/alerts.json" -ForegroundColor Yellow
Write-Host "   On Windows, you may need to adjust the ALERT_FILE path in the script." -ForegroundColor Yellow
Write-Host "   For testing, you can create a sample alerts.json file." -ForegroundColor Yellow
Write-Host ""

# Start the dashboard
Write-Host "🚀 Starting dashboard on http://localhost:8888" -ForegroundColor Green
Write-Host "   Press Ctrl+C to stop the dashboard" -ForegroundColor Yellow
Write-Host ""

python zoedr_dashboard_advanced.py
