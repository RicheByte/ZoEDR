# 🐉 ZoEDR-Linux - Alpha's Endpoint Detection & Response

> **ZETA REALM SECURITY** 

## Overview

ZoEDR-Linux is a comprehensive endpoint detection and response system built specifically for Zeta Realm. It provides real-time threat detection, automated response, and immutable persistence, coupled with an advanced live dashboard.

## 🚀 Features

- **Real-time Process Monitoring** - Complete process tree tracking, heuristic analysis.
- **File Integrity Monitoring** - Critical path watching with `inotify` for modifications, creations, deletions.
- **Network Connection Analysis** - Detects suspicious network activity linked to processes.
- **Advanced Heuristic Detection** - Identifies crypto miners, reverse shells, privilege escalation, and fileless execution.
- **Binary Integrity Protection** - SHA256 hash verification with automatic recovery for ZoEDR's own binary.
- **Kernel-level Persistence** - Deep system monitoring via a loadable kernel module.
- **Self-healing Watchdog** - Automatically monitors and restarts ZoEDR services and reloads kernel modules if tampered with or stopped.
- **Automated Threat Response** - Process quarantine (suspension + network isolation) for critical threats.
- **Real-time Advanced Dashboard** - Web-based monitoring with live graphs for threat trends and attack types.
- **Robust Logging** - Structured JSON alerts and system logs with `logrotate` for management.

## 📦 Installation (Plug & Play)

Navigate to the `zoedr` directory.

```bash
# Make all scripts executable
chmod +x script/*.sh

# Run the main installation script
sudo ./script/install.sh
```

The `install.sh` script will:
1. Install all necessary system and Python dependencies (including `build-essential`, `libcurl`, `python3-pip`, `dash`, `pandas`, `plotly`).
2. Create the required directory structure (`/opt/zoedr`, `/var/log/zoedr`, `/etc/zoedr`).
3. Compile the `zoedr_advanced` daemon and `zoedr_kernel` module.
4. Install the daemon to `/usr/sbin/zoedr_advanced` and the kernel module to `/opt/zoedr/`.
5. Set up `systemd` services for both `zoedr_advanced` and `zoedr_dashboard` for auto-start and persistence.
6. Generate a baseline SHA256 hash of the `zoedr_advanced` binary for integrity checks.
7. Deploy the `recover.sh` script and `zoedr_dashboard_advanced.py`.
8. Configure `logrotate` for ZoEDR logs.

## 🔧 Configuration

### Key Files & Directories
- `/etc/zoedr/zoedr_advanced.sha256` - ZoEDR binary integrity baseline hash.
- `/etc/systemd/system/zoedr_advanced.service` - Systemd service unit for the main daemon.
- `/etc/systemd/system/zoedr_dashboard.service` - Systemd service unit for the web dashboard.
- `/etc/modules-load.d/zoedr_kernel.conf` - Ensures kernel module auto-loads at boot.
- `/etc/logrotate.d/zoedr` - Log rotation configuration.
- `/opt/zoedr/` - Installation directory for kernel module, recovery script, and dashboard.
- `/usr/sbin/zoedr_advanced` - The main ZoEDR daemon executable.

### Log Locations
- `/var/log/zoedr/alerts.json` - Real-time threat alerts in JSON format (read by dashboard).
- `/var/log/zoedr/zoedr.log` - General system logs (if implemented in C code, currently output to journal).
- Journalctl: `journalctl -u zoedr_advanced.service -f` and `journalctl -u zoedr_dashboard.service -f` for live service logs.

## 🎯 Usage

### Start/Stop/Status Services
```bash
sudo systemctl start zoedr_advanced.service
sudo systemctl stop zoedr_advanced.service
sudo systemctl status zoedr_advanced.service

sudo systemctl start zoedr_dashboard.service
sudo systemctl stop zoedr_dashboard.service
sudo systemctl status zoedr_dashboard.service
```

### Verify Integrity
```bash
sudo ./scripts/verify_hash.sh
```

### Test System
```bash
sudo ./scripts/test.sh
```

### View Dashboard
After installation, the dashboard will automatically start. Access it via your web browser:
```
http://<Your_Server_IP_Address>:8888
```
(Replace `<Your_Server_IP_Address>` with the actual IP address of your system.)

## 🛡️ Threat Detection

ZoEDR detects heuristically:
- **Crypto Miners** - CPU pattern analysis, known miner binaries.
- **Reverse Shells** - Correlated network activity with suspicious shell processes.
- **Privilege Escalation** - Detection of unexpected root process spawning.
- **Fileless Execution** - Identification of processes running from memory-only locations.
- **Binary Tampering** - Any modification to the `zoedr_advanced` binary.
- **File System Events** - Creation, modification, deletion, attribute changes on critical system paths.

## 🔄 Recovery & Maintenance

### Manual Recovery
If the system becomes unstable or compromised, the `recover.sh` script can attempt to restore core functionality.
```bash
sudo /opt/zoedr/recover.sh
```

### Complete Reinstall
For a full reset, first uninstall, then reinstall:
```bash
sudo ./scripts/uninstall.sh
sudo ./scripts/install.sh
```

### Emergency Reset (Manual Steps)
```bash
sudo systemctl stop zoedr_advanced.service
sudo systemctl stop zoedr_dashboard.service
sudo rmmod zoedr_kernel 2>/dev/null || true
# Then run the recovery script or reinstall
sudo /opt/zoedr/recover.sh
```

### Uninstallation
```bash
sudo ./scripts/uninstall.sh
```

## 📊 Monitoring & Alerts

### Check System Health
- **Daemon status**: `systemctl status zoedr_advanced.service`
- **Kernel module**: `lsmod | grep zoedr_kernel`
- **Recent alerts**: `tail -f /var/log/zoedr/alerts.json`
- **Dashboard**: Access via web browser for live graphs and alerts.

### Alert Severity Levels
The system assigns a threat score, which is translated into severity:
- **INFO (0-9)** - Informational events, low concern.
- **LOW (10-39)** - Suspicious activity logged, minor concern.
- **MEDIUM (40-69)** - Alert triggered, monitoring intensified, moderate concern.
- **HIGH (70-89)** - Significant threat, automatic response (e.g., process quarantine) initiated.
- **CRITICAL (90-100+)** - System integrity breach or immediate severe threat, auto-recovery procedures.

## 🐛 Troubleshooting

### Common Issues

**ZoEDR Daemon/Service won't start:**
- Check dependencies: `sudo apt-get install build-essential libcurl4-openssl-dev libssl-dev`.
- Verify binary integrity: `sudo ./scripts/verify_hash.sh`.
- Check logs for errors: `journalctl -u zoedr_advanced.service -f`.

**Kernel module fails to load:**
- Install kernel headers: `sudo apt-get install linux-headers-$(uname -r)`.
- Check compilation output during install.
- Verify module is in `/opt/zoedr/`: `ls -l /opt/zoedr/zoedr_kernel.ko`.
- Check kernel messages: `dmesg | grep zoedr_kernel`.

**No alerts generated / Dashboard empty:**
- Verify daemon is active: `systemctl status zoedr_advanced.service`.
- Check log file permissions: `ls -la /var/log/zoedr/alerts.json`.
- Manually test detection: `sudo ./scripts/test.sh`.
- Check dashboard service logs: `journalctl -u zoedr_dashboard.service -f`.

**Dashboard doesn't load in browser:**
- Ensure Python dependencies are installed: `pip3 install dash dash-bootstrap-components pandas plotly`.
- Check dashboard service status: `systemctl status zoedr_dashboard.service`.
- Verify port 8888 is not blocked by a firewall: `sudo ufw allow 8888/tcp` (if using ufw).



## 🎯 Development

### Project Structure
```
zoedr/
├── src/
│   ├── zoedr_advanced.c        # Main monitoring daemon
│   ├── zoedr_common.h          # Shared structures & constants
│   └── zoedr_kernel.c          # Kernel module
├── scripts/
│   ├── install.sh              # Comprehensive deployment script
│   ├── uninstall.sh            # Complete removal script
│   ├── verify_hash.sh          # Manual integrity verification
│   ├── test.sh                 # Comprehensive system testing script
│   ├── recover.sh              # Automated self-healing/recovery script
│   └── setup_directories.sh    # Initial directory setup (called by install.sh)
├── dashboard/
│   └── zoedr_dashboard_advanced.py # Advanced web dashboard with graphs
├── config/
│   ├── zoedr.service           # systemd service unit file (placed in /etc/systemd/system by install.sh)
│   └── zoedr.logrotate         # logrotate configuration (placed in /etc/logrotate.d by install.sh)
├── Makefile                    # Kernel module build system
├── README.md                   # This file
└── CHANGELOG.md                # Version history
```

### Building from Source (Manual Steps)
```bash
# From the zoedr/ directory

# 1. Ensure system is updated and dependencies are installed
sudo apt-get update
sudo apt-get install build-essential libcurl4-openssl-dev libssl-dev linux-headers-$(uname -r) python3 python3-pip

# 2. Install Python dashboard dependencies
pip3 install dash dash-bootstrap-components pandas plotly

# 3. Create necessary directories (optional, install.sh handles this)
sudo ./scripts/setup_directories.sh

# 4. Compile userspace component
gcc -o zoedr_advanced src/zoedr_advanced.c -lpthread -lcurl -lcrypto -O2 -Wall -Wextra -Isrc/

# 5. Compile kernel module
make

# 6. Deploy (alternatively, run the automated install script)
sudo ./scripts/install.sh
```

## ⚠️ Legal Notice

**ZETA REALM USE ONLY**  
This system is designed for operation within Zeta Realm jurisdiction. All activities conducted with this software are legal within Zeta Realm boundaries.

---

**🐲 ZETA REALM SECURITY - ZERO FUCKING ERRORS**  
*Maintained by Richards Command*


## Initial Release

- Core EDR framework established.
- Basic monitoring capabilities.
- Foundation for advanced features.

