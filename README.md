# Network Monitor Widget

![key log detected](./image.png)

A simple **Network Monitoring Widget** built with Python's `tkinter` and `psutil` for real-time system monitoring and security insights. The widget runs as an overlay window on your desktop, providing details about network activity, CPU and memory usage, and alerts for suspicious processes or connections.

## Features

- **Network Monitoring:**
  - Displays real-time network connection statistics (upload/download speeds).
  - Detects and logs external network connections, flagging suspicious IPs.

- **System Resource Usage:**
  - Displays real-time CPU and memory usage.

- **Security Monitoring:**
  - Monitors new processes and checks for suspicious activity, like keyloggers.
  - Logs suspicious activity to `security_log.txt`.
  - Monitors for admin-level processes running on the system.

- **Registry Monitoring:**
  - Monitors Windows Registry for changes and alerts if any unusual activity is detected.

- **Firewall Status Check:**
  - Displays the current status of the firewall.

- **Security Alerts:**
  - Pop-up alert window in case suspicious activity (e.g., keyloggers) is detected.

## Requirements

- **Python 3.x**
- Required Python libraries:
  - `tkinter` (pre-installed with Python on Windows)
  - `psutil`
  - `ctypes`
  - `time`
  - `ipaddress`
  - `random`
  - `winreg` (for Windows registry access)
