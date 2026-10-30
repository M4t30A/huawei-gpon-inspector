# Huawei GPON ONT Inspector & Auditor

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight CLI tool to authenticate, audit, and extract diagnostic metrics (Optical Power levels, Wi-Fi 6 status, UPnP, DNS/DHCP, and ACL security) from modern Huawei GPON ONTs (such as the **EchoLife HG8145X6-10 / EG8145X6** and similar models running modern ISP firmware).

---

## Features

- **Automated CSRF & Session Handshake:** Handles `/asp/GetRandCount.asp` token retrieval (including invisible UTF-8 BOM `\ufeff` stripping), Base64 encoding, and cookie persistence.
- **Optical Fiber Diagnostics:**
  - Received Optical Power (Rx in dBm) with health status.
  - Transmitted Optical Power (Tx in dBm) and OLT Tx power.
  - Laser Temperature (°C), Voltage (V), and Bias current (mA).
  - Optical packet counters, discards, and frame error checks.
- **Wi-Fi 6 (`802.11ax`) Audit:**
  - Active SSIDs on 2.4 GHz and 5 GHz.
  - Real-time Channel and Bandwidth (`20`, `40`, `80`, `160 MHz`).
  - Security modes (`WPA2/WPA3-SAE`, `AES`, `802.11w` PMF).
  - Client Isolation status and WPS exposure flags.
- **Network Services & Access Control (ACL):**
  - UPnP status check (whether external apps can open WAN ports).
  - DHCP pool scope, lease times, and LAN DNS servers.
  - WAN / LAN / Wi-Fi administration access rules (HTTP, Telnet, FTP).
- **Configuration Backup:** Option to trigger and download a full `.cfg` backup from CLI.
- **Zero Heavy Dependencies:** Built on pure `requests` and Python standard library (no Selenium or headless browsers required).

---

## Supported Devices

- **Huawei EchoLife HG8145X6-10 / HG8145X6**
- **Huawei EchoLife EG8145X6**
- **Huawei EchoLife HS8546V5 / HG8245W5** (and other ONTs sharing the `TELECOM2`, `COMMON`, or similar web UI frames)

---

## Requirements

- Python 3.8+
- Dependencies:
  ```bash
  pip install -r requirements.txt
  ```

---

## Usage

### 1. Basic Inspection
Run interactively (prompts securely for username and password with hidden input):
```bash
python3 gpon_inspector.py
```

### 2. Custom Router IP
If your router uses a non-standard gateway IP:
```bash
python3 gpon_inspector.py --url http://192.168.0.1
```

### 3. Non-Interactive / Scripting Mode
You can provide credentials via environment variables:
```bash
export GPON_USER="admin"
export GPON_PASS="YourSecurePasswordHere"
python3 gpon_inspector.py
```

### 4. Download Router Configuration Backup
```bash
python3 gpon_inspector.py --backup
```
Saves `backup_gpon.cfg` in the local directory.

### 5. CLI Options
```text
options:
  -h, --help    Show this help message and exit
  --url URL     Router base URL (default: http://192.168.1.1)
  --user USER   Admin username (default: prompted or 'admin')
  --backup      Download a backup configuration file (.cfg)
  --save-dumps  Save raw ASP page dumps to dumps/ folder for debugging
  --no-cache    Ignore cached session cookies and force a new login
```

---

## Example Output

```text
[*] Probing router connectivity...
[+] Router reachable at: http://192.168.1.1
[+] Active session reused from local cache.

===========================================================================
 1. OPTICAL FIBER DIAGNOSTICS (/html/amp/opticinfo/opticinfo.asp)
===========================================================================
  • Link Status           : ok
  • Rx Optical Power      : -17.57 dBm  [OPTIMAL (Great signal margin)]
  • Tx Optical Power      : 1.81 dBm  [Normal: 0.5 to 5.0 dBm]
  • Laser Temperature     : 44 °C
  • Supply Voltage        : 3.415 V
  • Laser Bias Current    : 9 mA
  • OLT Tx Power (Class)  : 5.1 dBm (Class C+)
  • Optical Frame Errors  : Rx: 0 | Tx: 0 | Discards: 0

===========================================================================
 2. WI-FI NETWORK STATUS & AUDIT (2.4 GHz & 5 GHz)
===========================================================================
  Total Active SSIDs: 2

  [SSID #1] 'MyHomeNetwork' (2.4GHz)
    - Standard / Channel  : 11ax | Channel 6 (20 MHz)
    - Visibility          : YES (Hidden SSID)
    - Security Mode       : WPA2/WPA3 (PSKandSAEAuthentication)
    - Client Isolation    : DISABLED
    - WPS Status          : DISABLED

  [SSID #2] 'MyHomeNetwork-5G' (5GHz)
    - Standard / Channel  : 11ax | Channel 149 (Auto 20/40/80 MHz)
    - Visibility          : YES (Hidden SSID)
    - Security Mode       : WPA2/WPA3 (PSKandSAEAuthentication)
    - Client Isolation    : DISABLED
    - WPS Status          : DISABLED

===========================================================================
 3. SERVICES, DHCP, DNS & ACCESS CONTROL (SECURITY)
===========================================================================
  • UPnP Status           : DISABLED
  • DHCP Scope            : 192.168.1.2  -->  192.168.1.99 (Lease: 86400s)
  • Primary DNS Server    : 1.1.1.1
  • Secondary DNS Server  : 8.8.8.8
  • Device Access Control (ACL):
      - WAN Web Access    : CLOSED (Secure)
      - Wi-Fi HTTP Access : ALLOWED
      - Wi-Fi TELNET      : CLOSED
      - LAN FTP           : CLOSED

===========================================================================
 [+] Inspection completed successfully.
===========================================================================
```

---

## Security & Privacy Note

- **Never commit `dumps/`, `.gpon_session_cookies.json`, or `.cfg` files.** The included `.gitignore` already protects these files by default.
- Always change the default administrative password on production routers.

---

## License

This project is licensed under the [MIT License](LICENSE).
