#!/usr/bin/env python3
"""
Huawei GPON ONT Inspector & Auditor
===================================
A lightweight CLI tool to authenticate, audit, and extract real-time diagnostic
metrics (Optical Power, Wi-Fi 6 status, UPnP, DNS/DHCP, and ACL security)
from Huawei GPON ONTs (e.g. HG8145X6-10 / EG8145X6 series).
"""

import argparse
import base64
import getpass
import json
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests
import urllib3

# Suppress self-signed certificate warnings from local router interfaces
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WORKDIR = os.path.dirname(os.path.abspath(__file__))
COOKIE_CACHE_FILE = os.path.join(WORKDIR, ".gpon_session_cookies.json")
DUMPS_DIR = os.path.join(WORKDIR, "dumps")


class RouterHTMLParser(HTMLParser):
    """Extracts links, frames, scripts and titles from router HTML pages."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.frames = []
        self.scripts = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self.links.append((attr_dict.get("id", ""), attr_dict["href"]))
        elif tag in ("frame", "iframe") and "src" in attr_dict:
            self.frames.append((attr_dict.get("name", attr_dict.get("id", "")), attr_dict["src"]))
        elif tag == "script" and "src" in attr_dict:
            self.scripts.append(attr_dict["src"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()


def get_credentials(cli_user=None):
    """Reads credentials from CLI args, environment variables or interactive prompt."""
    username = cli_user or os.environ.get("GPON_USER")
    password = os.environ.get("GPON_PASS")

    if not username:
        username = input("Router Username [admin]: ").strip() or "admin"
    if not password:
        password = getpass.getpass(f"Password for '{username}': ")

    return username, password


def save_session_cookies(session: requests.Session):
    """Persists authenticated session cookies locally to avoid redundant logins."""
    try:
        data = requests.utils.dict_from_cookiejar(session.cookies)
        with open(COOKIE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(COOKIE_CACHE_FILE, 0o600)
    except OSError:
        pass


def load_session_cookies(session: requests.Session, base_url: str) -> bool:
    """Verifies and reuses existing session cookies if still active."""
    if not os.path.exists(COOKIE_CACHE_FILE):
        return False
    try:
        with open(COOKIE_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data:
            return False
        session.cookies.update(data)
        resp = session.get(urljoin(base_url, "/index.asp"), timeout=5)
        if resp.status_code == 200 and "frame.asp" in resp.text and "SubmitFormPwd" not in resp.text:
            print("[+] Active session reused from local cache.")
            return True
        session.cookies.clear()
    except Exception:
        session.cookies.clear()
    return False


def resolve_base_url(session: requests.Session, initial_url: str) -> str:
    """Checks whether router answers on HTTP or HTTPS with auto-fallback."""
    parsed = urlparse(initial_url)
    host = parsed.netloc or parsed.path
    candidates = (
        [f"http://{host}", f"https://{host}"]
        if parsed.scheme == "http"
        else [f"https://{host}", f"http://{host}"]
    )

    for candidate in candidates:
        try:
            test_url = urljoin(candidate, "/admin.html")
            resp = session.get(test_url, timeout=5)
            if resp.status_code < 500:
                print(f"[+] Router reachable at: {candidate}")
                return candidate
        except requests.exceptions.RequestException:
            pass

    raise ConnectionError(f"Could not connect to router at {candidates}")


def fetch_rand_token(session: requests.Session, base_url: str, endpoint: str = "/asp/GetRandCount.asp") -> str:
    """
    Fetches CSRF token from router.
    Note: Huawei firmware prepends a UTF-8 BOM (\\ufeff) to the token that must be stripped.
    """
    token_url = urljoin(base_url, endpoint)
    resp = session.post(
        token_url,
        headers={
            "Referer": urljoin(base_url, "/index.asp"),
            "X-Requested-With": "XMLHttpRequest",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.text.lstrip("\ufeff").strip()


def login_huawei_ont(session: requests.Session, base_url: str, username: str, password: str) -> requests.Response:
    """Performs the full authentication handshake against /login.cgi."""
    admin_url = urljoin(base_url, "/admin.html")
    token = fetch_rand_token(session, base_url, "/asp/GetRandCount.asp")
    print(f"[+] CSRF token obtained: {token[:12]}... (length: {len(token)})")

    b64_password = base64.b64encode(password.encode("utf-8")).decode("ascii")
    login_url = urljoin(base_url, "/login.cgi")
    payload = {
        "UserName": username,
        "PassWord": b64_password,
        "x.X_HW_Token": token,
    }
    headers = {
        "Referer": admin_url,
        "Origin": base_url.rstrip("/"),
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": "Cookie=body:Language:english:id=-1",
    }

    resp = session.post(login_url, data=payload, headers=headers, timeout=10, allow_redirects=True)
    resp.raise_for_status()
    return resp


def decode_js_escapes(text: str) -> str:
    """Decodes JavaScript hexadecimal escapes like \\x2d, \\x20, \\x2f."""
    if not text:
        return text
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)


def fetch_page(session: requests.Session, base_url: str, rel_path: str, save_dump: bool = False, filename: str = None) -> str:
    """Fetches a subpage from router, decodes JS escapes, and optionally caches dump."""
    full_url = urljoin(base_url, rel_path)
    resp = session.get(
        full_url,
        headers={"Referer": urljoin(base_url, "/index.asp")},
        timeout=10,
    )
    resp.raise_for_status()
    content = resp.text.lstrip("\ufeff")
    if save_dump and filename:
        os.makedirs(DUMPS_DIR, exist_ok=True)
        out_path = os.path.join(DUMPS_DIR, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(content)
    return content


def extract_st_objects(js_text: str, struct_name: str):
    """
    Extracts JavaScript constructor signatures `function stXxx(...)` and instances `new stXxx(...)`
    from Huawei ASP pages, returning a structured list of dictionaries.
    """
    decoded = decode_js_escapes(js_text)

    fn_match = re.search(rf"function\s+{re.escape(struct_name)}\s*\(([^)]*)\)", decoded)
    field_names = []
    if fn_match:
        field_names = [arg.strip() for arg in fn_match.group(1).split(",") if arg.strip()]

    instances = []
    for inst_match in re.finditer(rf"new\s+{re.escape(struct_name)}\s*\((.*?)\)(?=\s*[,;\]\)])", decoded, re.DOTALL):
        raw_args = inst_match.group(1)
        vals = [
            m.group(1) if m.group(1) is not None else (m.group(2) if m.group(2) is not None else m.group(3).strip())
            for m in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\'|([^,]+)', raw_args)
        ]
        if field_names and len(field_names) == len(vals):
            instances.append(dict(zip(field_names, vals)))
        elif field_names:
            mapped = {}
            for idx, v in enumerate(vals):
                key = field_names[idx] if idx < len(field_names) else f"arg_{idx}"
                mapped[key] = v
            instances.append(mapped)
        else:
            instances.append({f"arg_{i}": v for i, v in enumerate(vals)})

    return instances


# ==============================================================================
# AUDIT SECTIONS
# ==============================================================================

def audit_optic_info(session: requests.Session, base_url: str, save_dumps: bool):
    print("\n" + "=" * 75)
    print(" 1. OPTICAL FIBER DIAGNOSTICS (/html/amp/opticinfo/opticinfo.asp)")
    print("=" * 75)
    html = fetch_page(session, base_url, "/html/amp/opticinfo/opticinfo.asp", save_dumps, "opticinfo.asp.html")
    optics = extract_st_objects(html, "stOpticInfo")
    olt_optics = extract_st_objects(html, "stOLTOpticInfo")
    stats = extract_st_objects(html, "stStats")

    if optics:
        op = optics[0]
        rx = float(op.get("revOpticPower", -99))
        tx = float(op.get("transOpticPower", -99))
        temp = op.get("temperature", "--")
        volt = op.get("voltage", "--")
        bias = op.get("bias", "--")
        link = op.get("LinkStatus", "--")

        rx_eval = "OPTIMAL (Great signal margin)" if -25 <= rx <= -12 else "MARGINAL/CHECK"
        volt_v = f"{float(volt) / 1000.0:.3f} V" if volt.isdigit() else volt

        print(f"  • Link Status           : {link}")
        print(f"  • Rx Optical Power      : {rx:.2f} dBm  [{rx_eval}]")
        print(f"  • Tx Optical Power      : {tx:.2f} dBm  [Normal: 0.5 to 5.0 dBm]")
        print(f"  • Laser Temperature     : {temp} °C")
        print(f"  • Supply Voltage        : {volt_v}")
        print(f"  • Laser Bias Current    : {bias} mA")

    if olt_optics:
        olt = olt_optics[0]
        print(f"  • OLT Tx Power (Class)  : {olt.get('TxPower', '--')} dBm ({olt.get('BudgetClass', '--')})")

    if stats:
        st = stats[0]
        err_rx = st.get("ErrorsReceived", "0")
        err_tx = st.get("ErrorsSent", "0")
        discard = st.get("DiscardPacketsReceived", "0")
        print(f"  • Optical Frame Errors  : Rx: {err_rx} | Tx: {err_tx} | Discards: {discard}")


def audit_wlan_info(session: requests.Session, base_url: str, save_dumps: bool):
    print("\n" + "=" * 75)
    print(" 2. WI-FI NETWORK STATUS & AUDIT (2.4 GHz & 5 GHz)")
    print("=" * 75)
    html = fetch_page(session, base_url, "/html/amp/wlaninfo/wlaninfo.asp", save_dumps, "wlaninfo.asp.html")
    wlan_objs = extract_st_objects(html, "stWlan")
    wlan_list_html = fetch_page(session, base_url, "/html/amp/common/wlan_list.asp", save_dumps, "wlan_list.asp.html")
    basic_2g_html = fetch_page(session, base_url, "/html/amp/wlanbasic/WlanBasic.asp?2G", save_dumps, "WlanBasic_2G.asp.html")

    wps_objs = extract_st_objects(basic_2g_html, "stWpsPin")
    wps_map = {obj.get("domain", ""): obj.get("Enable", "0") for obj in wps_objs}

    channel_width_map = {
        "0": "Auto 20/40 MHz",
        "1": "20 MHz",
        "2": "40 MHz",
        "3": "Auto 20/40/80 MHz",
        "4": "Auto 20/40/80/160 MHz",
        "5": "80+80 MHz",
        "6": "80 MHz",
    }

    active_ssids = [w for w in wlan_objs if w.get("enable") == "1"]
    print(f"  Total Active SSIDs: {len(active_ssids)}")

    for idx, w in enumerate(active_ssids, 1):
        ssid = w.get("ssid", "Unknown")
        band = w.get("X_HW_RFBand", "--")
        channel = w.get("Channel", "--")
        width_code = w.get("X_HW_HT20", "1")
        width_str = channel_width_map.get(width_code, f"Mode {width_code}")
        std = w.get("X_HW_Standard", "Unknown")
        beacon = w.get("BeaconType", "--")
        auth = w.get("WPAand11iAuth", w.get("IEEE11iAuth", "--"))
        hidden = "YES (Hidden SSID)" if w.get("wlHide") == "0" else "NO (Broadcast/Public)"
        isolation = "ENABLED" if w.get("IsolationEnable") == "1" else "DISABLED"

        domain = w.get("domain", "")
        wps_status = "ENABLED" if wps_map.get(f"{domain}.WPS") == "1" else "DISABLED"

        print(f"\n  [SSID #{idx}] '{ssid}' ({band})")
        print(f"    - Standard / Channel  : {std} | Channel {channel} ({width_str})")
        print(f"    - Visibility          : {hidden}")
        print(f"    - Security Mode       : {beacon} ({auth})")
        print(f"    - Client Isolation    : {isolation}")
        print(f"    - WPS Status          : {wps_status}")


def audit_services_and_dhcp(session: requests.Session, base_url: str, save_dumps: bool):
    print("\n" + "=" * 75)
    print(" 3. SERVICES, DHCP, DNS & ACCESS CONTROL (SECURITY)")
    print("=" * 75)
    # UPnP
    upnp_html = fetch_page(session, base_url, "/html/bbsp/upnp/upnp.asp", save_dumps, "upnp.asp.html")
    upnp_match = re.search(r"var\s+enblMainUpnp\s*=\s*'([^']+)';", upnp_html)
    upnp_state = "ENABLED (Warning: LAN apps can map external ports)" if upnp_match and upnp_match.group(1) == "1" else "DISABLED"
    print(f"  • UPnP Status           : {upnp_state}")

    # DHCP & DNS
    dhcp_html = fetch_page(session, base_url, "/html/bbsp/dhcpservercfg/dhcp2.asp", save_dumps, "dhcp2.asp.html")
    dhcp_ranges = extract_st_objects(dhcp_html, "dhcpmainst")
    if dhcp_ranges:
        d = dhcp_ranges[0]
        start_ip = d.get("startip", "--")
        end_ip = d.get("endip", "--")
        lease = d.get("leasetime", "--")
        dns_pri = d.get("MainPriDNS", "") or "ISP Default (Router Proxy 192.168.1.1)"
        dns_sec = d.get("MainSecDNS", "") or "ISP Default"
        print(f"  • DHCP Scope            : {start_ip}  -->  {end_ip} (Lease: {lease}s)")
        print(f"  • Primary DNS Server    : {dns_pri}")
        print(f"  • Secondary DNS Server  : {dns_sec}")

    # ACL
    acl_html = fetch_page(session, base_url, "/html/bbsp/acl/acl.asp", save_dumps, "acl.asp.html")
    acl_objs = extract_st_objects(acl_html, "stAclInfo")
    if acl_objs:
        a = acl_objs[0]
        print("  • Device Access Control (ACL):")
        print(f"      - WAN Web Access    : {'OPEN' if a.get('HttpWanEnable') == '1' else 'CLOSED (Secure)'}")
        print(f"      - Wi-Fi HTTP Access : {'ALLOWED' if a.get('HTTPWifiEnable') == '1' else 'BLOCKED'}")
        print(f"      - Wi-Fi TELNET      : {'OPEN (Warning)' if a.get('TELNETWifiEnable') == '1' else 'CLOSED'}")
        print(f"      - LAN FTP           : {'OPEN' if a.get('FtpLanEnable') == '1' else 'CLOSED'}")


def download_backup_config(session: requests.Session, base_url: str):
    print("\n" + "=" * 75)
    print(" 4. BACKUP CONFIGURATION DOWNLOAD")
    print("=" * 75)
    cfg_html = fetch_page(session, base_url, "/html/ssmp/cfgfile/cfgfile.asp")
    token_match = re.search(r'id=["\']hwonttoken["\'][^>]*value=["\']([^"\']+)["\']', cfg_html)
    ont_token = token_match.group(1) if token_match else None

    # Step 1: Trigger StartFileLoad.asp
    try:
        session.post(
            urljoin(base_url, "/html/ssmp/common/StartFileLoad.asp"),
            headers={"Referer": urljoin(base_url, "/html/ssmp/cfgfile/cfgfile.asp")},
            timeout=10,
        )
    except Exception:
        pass

    # Step 2: Download configuration
    dl_url = urljoin(base_url, "/html/ssmp/cfgfile/cfgfiledown.cgi?&RequestFile=html/ssmp/cfgfile/cfgfile.asp")
    try:
        payload = {"x.X_HW_Token": ont_token} if ont_token else {}
        resp = session.post(
            dl_url,
            data=payload,
            headers={"Referer": urljoin(base_url, "/html/ssmp/cfgfile/cfgfile.asp")},
            timeout=15,
        )
        if resp.status_code == 200 and len(resp.content) > 1024:
            out_file = os.path.join(WORKDIR, "backup_gpon.cfg")
            with open(out_file, "wb") as bf:
                bf.write(resp.content)
            print(f"  [+] Backup successfully downloaded: {out_file} ({len(resp.content)} bytes)")
        else:
            print(f"  [*] Backup endpoint returned HTTP {resp.status_code} ({len(resp.content)} bytes).")
    except Exception as e:
        print(f"  [-] Failed to download backup: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Huawei GPON ONT Inspector & Security Auditor (e.g. HG8145X6-10 / EG8145X6)"
    )
    parser.add_argument("--url", default="http://192.168.1.1", help="Router base URL (default: http://192.168.1.1)")
    parser.add_argument("--user", default=None, help="Admin username (default: prompted or 'admin')")
    parser.add_argument("--backup", action="store_true", help="Download a backup configuration file (.cfg)")
    parser.add_argument("--save-dumps", action="store_true", help="Save raw ASP page dumps to dumps/ folder")
    parser.add_argument("--no-cache", action="store_true", help="Ignore cached session cookies and force re-login")

    args = parser.parse_args()

    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    })

    print("[*] Probing router connectivity...")
    base_url = resolve_base_url(session, args.url)

    if args.no_cache or not load_session_cookies(session, base_url):
        username, password = get_credentials(args.user)
        print(f"[*] Authenticating against {base_url} as '{username}'...")
        resp = login_huawei_ont(session, base_url, username, password)

        if not resp.url.endswith("/index.asp") and ("SubmitFormPwd" not in resp.text):
            resp = session.get(urljoin(base_url, "/index.asp"), timeout=10)

        if "SubmitFormPwd" in resp.text and "txt_Username" in resp.text:
            print("[!] Authentication failed: invalid credentials or session rejected.")
            sys.exit(1)

        save_session_cookies(session)

    # Execute audits
    audit_optic_info(session, base_url, args.save_dumps)
    audit_wlan_info(session, base_url, args.save_dumps)
    audit_services_and_dhcp(session, base_url, args.save_dumps)

    if args.backup:
        download_backup_config(session, base_url)

    print("\n" + "=" * 75)
    print(" [+] Inspection completed successfully.")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
