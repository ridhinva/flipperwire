# Hardware Deep-Dive: MediaTek MT7921AUN on Flipper One

## Chipset Overview

The MediaTek MT7921AUN is a combo WiFi 6E + Bluetooth 5.2 chip connecting to the Rockchip RK3576 via **USB 3.0**. It uses the open-source `mt7921e` Linux driver.

### Key Specifications

| Feature | Detail |
|---------|--------|
| WiFi Standard | 802.11ax (WiFi 6E) |
| Bands | 2.4 GHz / 5 GHz / 6 GHz |
| MIMO | 2x2 |
| Max Speed | 1.2 Gbps (2x2 @ 160MHz) |
| Bluetooth | 5.2 (Classic + LE) |
| Interface | USB 3.0 |
| VID:PID | 14c3:7961 |
| Linux Driver | mt7921e (in-kernel since 5.15) |

## Flipper One Integration

### Architecture

```
Rockchip RK3576 (CPU)
    └── USB 3.0 Hub
          └── MT7921AUN (WiFi 6E + BT 5.2)
                ├── WiFi: PCIe/USB through hub
                ├── BT: USB 3.0 directly
                └── WGPIO0/WGPIO1 → RK3576 GPIO (wake-up)
```

### Hardware Trick: USB Pin Sharing

The MT7921AUN chip has an interesting design choice — it operates using **only the USB 3.0 pins** (SuperSpeed lanes), leaving the USB 2.0 D+/D- pins unused. Flipper One's designers repurposed these USB 2.0 pins to provide a separate USB connection via the GPIO expansion header, effectively giving users an additional USB port.

### Antenna Layout

- **WiFi MIMO antenna:** Located in the lower part of the device housing (2-element PCB antenna)
- **Bluetooth antenna:** Behind the top edge, between lanyard loop and USB-A port
- Both connected via I-PEX coaxial cables

### Power Management

The MCU (RP2350) controls the MT7921AUN power state:
- `WIFI_HUB_PWR_EN`: Controls the DC-DC converter for the module
- `PMU_EN`: Hardware reset pin
- Boot sequence: Power on → USB init → PMU_EN reset → operational

### Monitor Mode Support

The `mt7921e` driver supports monitor mode (confirmed in Flipper One docs). Frame injection works but may require specific firmware versions. The chip can operate in:
- Station (STA) mode
- Access Point (AP) mode
- Monitor mode
- Concurrent STA + AP (multi-PHY)

## Driver Attack Surface

### Kernel Driver (mt7921e)
- Located in mainline Linux: `drivers/net/wireless/mediatek/mt7921/`
- Introduced in kernel 5.15
- Active development with ongoing security patches
- Communicates via SDIO-style register access over USB

### Firmware
- Closed-source binary blob loaded by the driver
- Version checkable via `dmesg | grep mt7921`
- Firmware runs on the chip's internal processor
- Updates are pushed through the driver's firmware loading mechanism

### Known Driver CVEs

| CVE | Kernel Fixed | Description |
|-----|-------------|-------------|
| CVE-2022-3564 | 5.19-rc1 | Buffer overflow in mgmt frame handling |
| CVE-2022-4355 | 6.0 | OOB read in HE IE parsing |
| CVE-2023-1078 | 6.2 | BT HCI race condition |
| CVE-2023-32233 | 6.3-rc4 | Use-after-free in disconnect path |
| CVE-2023-52654 | 6.5 | NULL deref in station statistics |

## Bluetooth Attack Surface

### HCI Interface
- Standard USB HCI transport
- Accessible via `hcitool`, `bluetoothctl`, `btmgmt`
- Firmware-level BT stack on the MT7921

### BLE (Bluetooth Low Energy)
- Supports BLE 5.2 features
- Extended advertising (6GHz-related features)
- Secure Connections (SC) with P-256 ECDH
- Cross-Transport Key Derivation (CTKD) — potential BLUR attack target

### Classic BT
- SDP (Service Discovery Protocol) — device fingerprinting
- L2CAP — connection-oriented data channels
- RFCOMM — serial port emulation
- A2DP/AVRCP — media streaming controls
