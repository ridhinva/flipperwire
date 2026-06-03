"""
FlipperWire — Common Utilities
Shared helper functions for all modules.
"""

import subprocess
import os
import re
import sys
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path("/root/flipperwire")


def log(msg, level="INFO"):
    """Timestamped logging."""
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{level:8s}] {msg}"
    print(line)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    log_file = OUTPUT_DIR / "flipperwire.log"
    with open(log_file, "a") as f:
        f.write(line + "\n")


def check_root():
    if os.geteuid() != 0:
        log("Root required. Run with sudo.", "ERROR")
        sys.exit(1)


def run_cmd(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1


def check_tool(name):
    _, _, rc = run_cmd(f"which {name}")
    return rc == 0


def get_wifi_interface(driver_hint="mt7921"):
    """Find wireless interface, preferring MT7921."""
    out, _, _ = run_cmd("iw dev 2>/dev/null | grep Interface | awk '{print $2}'")
    if out:
        for iface in out.strip().split("\n"):
            drv, _, _ = run_cmd(f"readlink /sys/class/net/{iface}/device/driver 2>/dev/null")
            if driver_hint in drv.lower():
                return iface
        return out.strip().split("\n")[0]
    out, _, _ = run_cmd("ls /sys/class/net/ | grep -E 'wlan|wlx' | head -1")
    return out.strip() if out else None


def get_bt_interface():
    """Find Bluetooth HCI interface."""
    out, _, _ = run_cmd("hciconfig -a 2>/dev/null | grep -B1 'Bus: USB' | head -1")
    m = re.search(r'(hci\d+)', out)
    if m:
        return m.group(1)
    out, _, _ = run_cmd("hcitool dev 2>/dev/null | awk 'NR>1{print $2}'")
    return out.strip().split("\n")[0] if out else None


def parse_airodump_csv(csv_path):
    """Parse airodump-ng CSV into list of network dicts."""
    networks = []
    try:
        with open(csv_path) as f:
            content = f.read()
        sections = content.split("\r\n\r\n")
        if not sections:
            return networks
        for line in sections[0].split("\n")[2:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 14:
                networks.append({
                    "bssid": parts[0], "channel": parts[3],
                    "encryption": parts[5], "power": parts[8],
                    "essid": parts[13] if len(parts) > 13 else "",
                })
    except Exception as e:
        log(f"CSV parse error: {e}", "WARN")
    return networks
