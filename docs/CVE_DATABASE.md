# FlipperWire CVE Database

## WiFi Driver Vulnerabilities (mt7921e)

### CVE-2022-3564 — Buffer Overflow in 802.11ax Management Frames
- **Severity:** HIGH (CVSS 7.1)
- **Fixed in:** Kernel 5.19-rc1
- **Component:** `drivers/net/wireless/mediatek/mt7921/mt7921_mac.c`
- **Attack:** Craft malformed 802.11ax action frames with oversized IEs
- **Impact:** Kernel panic, potential code execution
- **Check:** `uname -r` >= 5.19

### CVE-2022-4355 — OOB Read in HE Capability Parsing
- **Severity:** MEDIUM (CVSS 5.3)
- **Fixed in:** Kernel 6.0
- **Component:** HE (High Efficiency) capability IE parser
- **Attack:** Beacon/probe response with malformed HE IEs
- **Impact:** Information disclosure, crash
- **Check:** `uname -r` >= 6.0

### CVE-2023-32233 — Use-After-Free in Disconnect Path
- **Severity:** CRITICAL (CVSS 9.8)
- **Fixed in:** Kernel 6.3-rc4
- **Component:** `mt7921e_disconnect()` function
- **Attack:** Trigger disconnect while RX DMA is active
- **Impact:** Remote code execution (theoretical)
- **Check:** `uname -r` >= 6.3

### CVE-2023-52654 — NULL Pointer Dereference
- **Severity:** HIGH (CVSS 7.8)
- **Fixed in:** Kernel 6.5
- **Component:** `mt7921_mac_sta_stat` function
- **Attack:** Malformed station statistics request
- **Impact:** Kernel crash (DoS)
- **Check:** `uname -r` >= 6.5

## Bluetooth Vulnerabilities

### CVE-2019-9506 — KNOB Attack
- **Severity:** HIGH (CVSS 7.5)
- **Affected:** Bluetooth 4.0 – 5.2 (pre-patch)
- **Attack:** Force encryption key entropy down to 1 byte during pairing
- **Impact:** Brute-force BT encryption in seconds
- **MT7921 Status:** BT 5.2 spec includes mitigation, but firmware-level bypasses may exist
- **Test:** Use `flipperwire.py --mode bt_knob`

### CVE-2020-15802 — BLUR Attack (CTKD)
- **Severity:** HIGH (CVSS 7.1)
- **Affected:** Dual-mode (Classic + BLE) devices
- **Attack:** Pair on Classic BT, derive BLE LTK (or vice versa)
- **Impact:** Cross-transport key compromise
- **MT7921 Status:** Depends on firmware CTKD implementation
- **Test:** Use `flipperwire.py --mode bt_blur`

### CVE-2023-1078 — HCI Race Condition
- **Severity:** MEDIUM (CVSS 4.3)
- **Fixed in:** Kernel 6.2
- **Component:** Bluetooth HCI command processing
- **Attack:** Rapid HCI command submission
- **Impact:** Use-after-free, crash
- **Check:** `uname -r` >= 6.2

## WPA3 / SAE Vulnerabilities (Dragonblood)

### CVE-2019-9494 — SAE Downgrade & Reflection
- **Severity:** HIGH
- **Attack:** Invalid group in SAE Commit, reflection attack
- **Impact:** DoS, potential key recovery

### CVE-2019-9496 — Timing Side-Channel
- **Severity:** HIGH
- **Attack:** Measure SAE Commit processing time
- **Impact:** Password recovery via timing analysis

### CVE-2019-9497 — Anti-Clogging Bypass
- **Severity:** HIGH
- **Attack:** Flood SAE Commits to exhaust token cache
- **Impact:** Bypass anti-DoS protection

## WiFi Protocol Attacks

### FragAttacks (Fragmentation & Aggregation)
- **Affected:** All 802.11 implementations
- **Attack:** Inject fragmented frames with mixed key IDs
- **Impact:** Packet injection, data exfiltration
- **802.11ax:** New fragmentation modes expand attack surface

### PMKID Capture
- **Affected:** All WPA2/WPA3 APs
- **Attack:** Capture single EAPOL frame containing PMKID
- **Impact:** Offline password cracking (hashcat -m 22000)

### Evil Twin (6GHz)
- **Affected:** WiFi 6E networks
- **Attack:** Clone AP on 6GHz band
- **Impact:** Credential theft, MitM
