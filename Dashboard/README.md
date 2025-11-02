# ZoEDR Threat Intelligence Dashboard

A real-time, comprehensive security monitoring dashboard for the ZoEDR (Zero-trust Endpoint Detection & Response) system.

## 🎯 Features

### Real-time Monitoring
- **Auto-refresh every 5 seconds** to display the latest security alerts
- **Live threat intelligence** updates from `/var/log/zoedr/alerts.json`

### Key Performance Indicators (KPIs)
- **Total Alerts**: Overall count of detected threats
- **Critical Alerts**: Count of high-severity incidents requiring immediate attention
- **Monitored Hosts**: Number of unique endpoints being protected
- **Average Threat Score**: Mean threat score across all alerts

### Advanced Visualizations

#### 1. Threat Activity Timeline
- Area chart showing alert volume over time
- Color-coded by severity level (info, low, medium, high, critical)
- 1-minute granularity for precise trend analysis

#### 2. Severity Distribution
- Donut chart displaying the proportion of alerts by severity
- Quick visual assessment of threat landscape severity

#### 3. Top Attack Vectors
- Horizontal bar chart of the top 10 most common attack types
- Gradient coloring for easy identification of prevalent threats

#### 4. Top Flagged Processes
- Top 10 processes triggering the most alerts
- Helps identify potentially compromised or malicious processes

#### 5. Activity Heatmap
- Hour × Day heatmap showing temporal patterns
- Identifies peak attack times and patterns
- Useful for scheduling maintenance and staffing

#### 6. Most Targeted Hosts
- Ranked list of hosts receiving the most alerts
- Shows critical alert counts and average threat scores
- Quick identification of compromised or vulnerable systems

#### 7. Recent Alerts Feed
- Live scrolling feed of the latest 50 alerts
- Color-coded by severity with detailed metadata
- Includes host, PID, process name, threat score, and details

## 🎨 Design Features

### Modern Cybersecurity Aesthetic
- **Dark theme** optimized for SOC (Security Operations Center) environments
- **Custom color palette** with cyberpunk-inspired accent colors
- **Professional typography** and spacing for extended viewing sessions

### Color Coding
- **Critical**: Deep red (#d50000) - Immediate action required
- **High**: Bright red (#ff5252) - High priority
- **Medium**: Orange (#ffa726) - Moderate concern
- **Low**: Cyan (#26c6da) - Minor issues
- **Info**: Sky blue (#00d4ff) - Informational

### Icons & Visual Hierarchy
- FontAwesome icons for intuitive navigation
- Clear card-based layout with visual separation
- Consistent border accents for severity indication

## 🚀 Installation & Usage

### Prerequisites
```bash
pip install -r ../requirements.txt
```

### Running the Dashboard

#### Development Mode
```bash
python3 zoedr_dashboard_advanced.py
```

#### Production Mode (with Gunicorn)
```bash
gunicorn -w 4 -b 0.0.0.0:8888 zoedr_dashboard_advanced:server
```

### Access
Open your browser and navigate to:
```
http://localhost:8888
```

For remote access (ensure firewall allows):
```
http://<your-server-ip>:8888
```

## 📊 Data Source

The dashboard reads from:
```
/var/log/zoedr/alerts.json
```

Expected JSON format per line:
```json
{
  "timestamp": "2025-11-02 14:30:45",
  "host": "server-01",
  "alert_type": "PROCESS_INJECTION",
  "pid": 1234,
  "process_name": "suspicious.exe",
  "threat_score_total": 85,
  "severity": "high",
  "details": "Suspicious process injection detected"
}
```

## ⚙️ Configuration

Edit the following constants in `zoedr_dashboard_advanced.py`:

```python
ALERT_FILE = "/var/log/zoedr/alerts.json"  # Path to alerts file
REFRESH_INTERVAL_MS = 5000                  # Refresh interval (milliseconds)
MAX_ALERTS_DISPLAY = 50                     # Number of alerts in feed
```

## 🔧 Customization

### Changing Colors
Modify the `COLOR_PALETTE` dictionary to customize the theme:
```python
COLOR_PALETTE = {
    'background': '#0a0e27',
    'card_bg': '#1a1f3a',
    # ... more colors
}
```

### Adding New Metrics
1. Add new callback function with `@app.callback` decorator
2. Create corresponding Output element in layout
3. Process data from `load_alerts()` DataFrame

## 🐛 Troubleshooting

### Dashboard shows "No data"
- Verify ZoEDR is running and generating alerts
- Check that `ALERT_FILE` path is correct
- Ensure the dashboard has read permissions for the alerts file

### Graphs not updating
- Check browser console for JavaScript errors
- Verify the interval component is working
- Ensure alerts.json file is being written to

### Performance issues
- Reduce `REFRESH_INTERVAL_MS` if updates are too frequent
- Limit `MAX_ALERTS_DISPLAY` for better performance
- Consider using a database instead of JSON file for large deployments

## 📝 License

Part of the ZoEDR project. See main LICENSE file.

## 🤝 Contributing

Contributions welcome! Please ensure:
- Code follows existing style patterns
- New visualizations are responsive and accessible
- Color choices maintain WCAG contrast standards
- Performance impact is minimal

## 📧 Support

For issues related to the dashboard, please open an issue in the ZoEDR repository.

---

**Built with ❤️ for the cybersecurity community**
