# FlipperWire — Flipper One Wireless Exploitation Toolkit

> **WiFi 6E & Bluetooth 5.2 Offensive Security Toolkit**
> for the MediaTek MT7921AUN chipset on Flipper One

![Platform](https://img.shields.io/badge/platform-Flipper%20One%20%7C%20RK3576%20SBCs-blue)
![Chipset](https://img.shields.io/badge/chipset-MediaTek%20MT7921AUN-green)
![WiFi](https://img.shields.io/badge/WiFi-6E%20802.11ax-orange)
![Bluetooth](https://img.shields.io/badge/Bluetooth-5.2-purple)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## Overview

FlipperWire is a comprehensive wireless exploitation toolkit purpose-built for the **Flipper One** portable security device. It targets the **MediaTek MT7921AUN** combo chip (Wi-Fi 6E 802.11ax + Bluetooth 5.2) and covers the full attack surface from reconnaissance to exploitation.

The toolkit is also compatible with any **Rockchip RK3576-based board** running Flipper OS (Armsom Sige5, Luckfox Omni3576, FireFly ROC-RK3576-PC, Radxa ROCK 4D).

## Vulnerability Coverage

### WiFi (802.11ax / Wi-Fi 6E)

| ID | Severity | Description |
|----|----------|-------------|
| CVE-2022-3564 | HIGH | Buffer overflow in 802.11ax management frame handling |
| CVE-2022-4355 | MEDIUM | OOB read in HE capability parsing |
| CVE-2023-32233 | CRITICAL | Use-after-free in mt7921e_disconnect() |
| CVE-2023-52654 | HIGH | NULL pointer dereference in station statistics |
| FragAttacks | HIGH | Frame injection via fragmented 802.11ax frames |
| PMKID Capture | MEDIUM | Offline password cracking from single EAPOL |
| Dragonblood | HIGH | WPA3 SAE downgrade, timing side-channel, reflection |
| Evil Twin | HIGH | 6GHz band AP cloning / credential theft |

### Bluetooth 5.2

| ID | Severity | Description |
|----|----------|-------------|
| CVE-2019-9506 (KNOB) | HIGH | Key Negotiation of Downgrade — force 1-byte entropy |
| CVE-2020-15802 (BLUR) | HIGH | Cross-Transport Key Derivation bypass |
| CVE-2023-1078 | MEDIUM | HCI command processing race condition |
| L2CAP Flood | MEDIUM | Denial of service via connection flooding |
| SDP Enumeration | LOW | Service discovery and fingerprinting |

## Repository Structure

```
flipperwire/
├── src/
│   ├── flipperwire.py          # Main toolkit (10 attack modes)
│   ├── mt7921_vuln_scanner.py  # Firmware/driver vulnerability scanner
│   ├── dragonblood_sae.py      # WPA3 SAE Dragonblood exploitation
│   └── common/
│       └── utils.py            # Shared utilities
├── docs/
│   ├── HARDWARE.md             # MT7921AUN hardware deep-dive
│   ├── ATTACK_SURFACE.md       # Full attack surface analysis
│   └── CVE_DATABASE.md         # Detailed CVE references
├── references/
│   └── mt7921_datasheet_notes.md
├── README.md
└── LICENSE
```

## Quick Start

### Prerequisites

```bash
# On Flipper One (or any RK3576 board running Flipper OS)
sudo apt update
sudo apt install -y aircrack-ng hcxdumptool bluez scapy python3-scapy

# Verify MT7921AUN is detected
lsusb | grep -i mediatek
# Should show: 14c3:7961 MediaTek MT7921AUN
```

### Installation

```bash
git clone https://github.com/ridhinva/flipperwire.git
cd flipperwire
# No pip install needed — pure Python + system tools
```

### Usage

```bash
# Full wireless audit
sudo python3 src/flipperwire.py --mode full_audit

# WiFi reconnaissance only
sudo python3 src/flipperwire.py --mode wifi_scan

# Bluetooth reconnaissance
sudo python3 src/flipperwire.py --mode bt_scan

# Deauthentication attack
sudo python3 src/flipperwire.py --mode deauth --target AA:BB:CC:DD:EE:FF

# PMKID capture
sudo python3 src/flipperwire.py --mode pmkid --target AA:BB:CC:DD:EE:FF

# KNOB attack (generates exploit script)
sudo python3 src/flipperwire.py --mode bt_knob --target AA:BB:CC:DD:EE:FF

# WPA3 SAE Dragonblood tests
sudo python3 src/dragonblood_sae.py --target AA:BB:CC:DD:EE:FF --iface wlan0

# Firmware vulnerability scan
sudo python3 src/mt7921_vuln_scanner.py
```

## Attack Modes

### Main Toolkit (`flipperwire.py`)

| Mode | Description | Tools Used |
|------|-------------|------------|
| `wifi_scan` | Full WiFi recon, driver analysis, network enumeration | iw, airodump-ng, ethtool |
| `bt_scan` | BT Classic + BLE scan, SDP enumeration | hcitool, sdptool, bluetoothctl |
| `full_audit` | Complete wireless security assessment | All |
| `deauth` | 802.11ax deauthentication | aireplay-ng |
| `pmkid` | WPA2/WPA3 PMKID capture | hcxdumptool, airodump-ng |
| `bt_knob` | KNOB attack (CVE-2019-9506) | Generated Python script |
| `bt_blur` | BLUR/CTKD attack (CVE-2020-15802) | Generated Python script |
| `bt_flood` | L2CAP flood DoS | Generated Python script |
| `sae_downgrade` | WPA3 SAE downgrade check | Scapy |
| `fingerprint` | Probe request fingerprinting | airodump-ng |

### Firmware Scanner (`mt7921_vuln_scanner.py`)

- Kernel version vs 5 known CVEs
- Driver/firmware version detection
- USB interface exposure analysis
- Monitor mode & frame injection capability
- Bluetooth security configuration
- Kernel hardening verification (KASLR, stack protector, SELinux)
- wpa_supplicant security audit
- Firmware signing verification
- Power management attack surface

### Dragonblood Module (`dragonblood_sae.py`)

- SAE invalid group commit (CVE-2019-9494)
- SAE reflection attack
- Timing side-channel analysis (CVE-2019-9496)
- Anti-clogging token bypass (CVE-2019-9497)
- WPA2/WPA3 transition mode downgrade

## Target Hardware

### Flipper One
- **SoC:** Rockchip RK3576 (8-core, Mali G52, 6 TOPS NPU)
- **MCU:** Raspberry Pi RP2350 (FreeRTOS)
- **WiFi/BT:** MediaTek MT7921AUN (USB 3.0)
- **OS:** Flipper OS (Debian-based)
- **Status:** Prototype (not yet for sale)

### Compatible Boards
- Armsom Sige5 / Banana Pi BPI-M5 Pro (recommended)
- FireFly ROC-RK3576-PC
- Luckfox Omni3576
- Radxa ROCK 4D

## Legal

This toolkit is for **authorized security testing only**. Only use on devices and networks you own or have explicit written permission to test. The authors are not responsible for misuse.

## References

- [Flipper One Documentation](https://docs.flipper.net/one)
- [MT7921AUN Linux Driver (mt7921e)](https://github.com/torvalds/linux/tree/master/drivers/net/wireless/mediatek/mt7921)
- [Dragonblood Paper](https://wpa3.mathyvanhoef.com/)
- [KNOB Attack Paper](https://francozappa.github.io/about-btle/)
- [BLUR Attack Paper](https://hexhive.epfl.ch/ctkd/)

## Author

**Ridhin V A** — [@ridhinva](https://github.com/ridhinva)
