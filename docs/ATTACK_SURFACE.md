# Flipper One Wireless Attack Surface Analysis

## Overview

This document maps the complete wireless attack surface of the Flipper One device, focusing on the MediaTek MT7921AUN chipset and its integration with the Rockchip RK3576 platform.

## Attack Surface Map

```
┌─────────────────────────────────────────────────────────────┐
│                    FLIPPER ONE ATTACK SURFACE                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   WiFi 6E    │    │ Bluetooth 5.2│    │   6GHz Band  │  │
│  │  802.11ax    │    │  Classic+LE  │    │   Wi-Fi 6E   │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘  │
│         │                   │                   │          │
│  ┌──────┴───────┐    ┌──────┴───────┐    ┌──────┴───────┐  │
│  │  mgmt frames │    │  HCI / L2CAP │    │  beacon/probe│  │
│  │  data frames │    │  SDP / ATT   │    │  action frames│  │
│  │  ctrl frames │    │  SMP / GAP   │    │  SAR/DFS     │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘  │
│         │                   │                   │          │
│  ┌──────┴───────────────────┴───────────────────┴───────┐  │
│  │              MT7921AUN Firmware / Driver              │  │
│  └──────────────────────┬────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────┴────────────────────────────────┐  │
│  │            USB 3.0 Bus (RK3576 ↔ MT7921AUN)          │  │
│  └──────────────────────┬────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────┴────────────────────────────────┐  │
│  │         Linux Kernel (mt7921e driver + btusb)         │  │
│  └──────────────────────┬────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────┴────────────────────────────────┐  │
│  │              Flipper OS Userspace                      │  │
│  │    wpa_supplicant / bluetoothd / iw / hostapd         │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## WiFi Attack Vectors

### Management Frame Attacks
- **Deauthentication** (802.11w bypass if PMF not enforced)
- **Beacon flooding** (spam fake APs with 6GHz capabilities)
- **Probe request/response manipulation**
- **Action frame injection** (spectrum management, QoS)

### Data Frame Attacks
- **Fragment injection** (FragAttacks on 802.11ax)
- **Key ID confusion** (mixed WPA2/WPA3 key usage)
- **Aggregate frame manipulation** (A-MSDU/A-MPDU)

### Authentication Attacks
- **WPA2 4-way handshake capture** → PMKID or full handshake
- **WPA3 SAE downgrade** (Dragonblood)
- **EAPOL-Start flood** (DoS)
- **Transition mode abuse** (force WPA2 on WPA2/WPA3 APs)

### Firmware/Driver Attacks
- **Malformed IEs** → driver crash (CVE-2022-3564, CVE-2022-4355)
- **Trigger disconnect during RX** → UaF (CVE-2023-32233)
- **Invalid station stats request** → NULL deref (CVE-2023-52654)

## Bluetooth Attack Vectors

### Pairing Attacks
- **KNOB (CVE-2019-9506):** Force 1-byte encryption entropy
- **BLUR (CVE-2020-15802):** Cross-transport key derivation
- **SSP (Secure Simple Pairing) downgrade** to legacy pairing

### Protocol Attacks
- **L2CAP flood:** Exhaust device resources
- **SDP enumeration:** Service fingerprinting
- **ATT (Attribute Protocol) exploitation:** GATT service abuse
- **HCI command injection:** Firmware-level attacks

### BLE-Specific Attacks
- **Extended advertising abuse** (BLE 5.x features)
- **Connection parameter manipulation**
- **BLESA (BLE Spoofing Attack)**
- **BlueBleed** (memory corruption via BLE)

## USB Bus Attack Surface

The MT7921AUN connects via USB 3.0, creating additional attack vectors:
- **USB descriptor manipulation** (if DFU mode exposed)
- **Firmware extraction** via USB debug interface
- **USB autospoof** (BadUSB-style attacks through GPIO USB pins)
- **Power analysis** via USB power monitoring (INA219 accessible)

## Kernel Attack Surface

### Wireless Stack (cfg80211/mac80211)
- **Netlink message injection** (if permissions misconfigured)
- **DebugFS abuse** (/sys/kernel/debug/ieee80211/)
- **NL80211 command manipulation**

### Bluetooth Stack
- **HCI socket abuse**
- **SCO/eSCO stream manipulation**
- **SCO routing (PCM vs. HCI) confusion**

## Userspace Attack Surface

### wpa_supplicant
- **Configuration file parsing** (if writable)
- **D-Bus interface** (if exposed)
- **WPS PIN brute-force** (if WPS enabled)

### bluetoothd
- **D-Bus interface abuse**
- **SDP cache poisoning**
- **Agent spoofing**

## Hardware-Level Attack Surface

### GPIO Header USB Pins
The GPIO header exposes USB 2.0 D+/D- pins (repurposed from the MT7921AUN connection):
- **BadUSB attacks** through the GPIO header
- **USB device emulation** via GPIO

### M.2 Port
- **Cellular modem exploitation** (via M.2 slot)
- **NVMe SSD attacks** (if NVMe connected)
- **SDR module integration** (software-defined radio)

### Debug Interfaces
- **UART console** (MCU ↔ CPU interconnect)
- **SPI bus** (display frame buffer)
- **I2C bus** (input events)
