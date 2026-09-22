# PiAP — leak-proof, VPN-backed Wi‑Fi networks on a Raspberry Pi

Turns a Raspberry Pi into several Wi‑Fi access points, **each bound to its own physical radio and its own exit**. A device that joins an SSID reaches the internet only through the exit assigned to that SSID — a WireGuard tunnel, or the LAN when you deliberately choose that. With a tunnel selected, there is no way out except that tunnel: if it drops, while it is being re-established, during boot, or after a configuration mistake, **no packet leaves through the home connection**.

Management works through three doors that share one core:

| Door | When | Where |
|---|---|---|
| **Web panel** | Day-to-day | `https://<pi>:8443`, LAN only |
| **PiAP Manager** (macOS) | When the Pi has no network access | Bluetooth LE, end-to-end encrypted |
| **`ap-ctl`** | SSH / scripting | `sudo ap-ctl …` |

```
                    ┌──────────────────────────── Raspberry Pi ────────────────────────────┐
  📱 client ──WiFi──►  SSID A (wlan0)  ─►  10.99.0.0/24  ─►  table 51820  ─►  wg0  ──►  VPN server A
                    │        ▲                                   │ blackhole                            │
                    │   ap_isolate=1                       kill switch (FORWARD DROP)                   │
  📱 client ──WiFi──►  SSID B (wlan1)  ─►  10.98.0.0/24  ─►  table 51821  ─►  wg1  ──►  VPN server B
                    │                                                                                    │
                    │   eth0 (LAN) ── the Pi's own traffic, Docker, SSH, web panel — isolated from APs   │
                    └────────────────────────────────────────────────────────────────────────────────────┘
```

## Why

Off-the-shelf "VPN router" setups usually give you one tunnel, one network, and a vague answer to "what happens when the tunnel goes down?". PiAP is designed around different goals:

- **One radio, one network, one exit.** A slot is bound to the *physical* adapter (its MAC), not to a kernel name like `wlan1`. Re-plug it and it keeps its subnet, SSID and exit; plug in a *different* adapter and it gets its own slot — it never inherits another one's VPN. Cross-traffic between two SSIDs is impossible at the packet level: there is no `wlan0 → wg1` rule, so it falls through to the default DROP.
- **Two exit modes, both explicit.** `vpn` (default): clients exit **only** through that slot's tunnel; no tunnel means no internet at all. `direct`: the SSID works with no VPN and exits through the LAN — useful for a plain guest network. Switching between them is a confirmed operation that is written into the slot's pin, so a VPN-backed SSID can never fall back to the local network by accident.
- **Leak prevention is structural, not a feature.** If the kill switch depended on a script running, a script that fails to run would leak. Here the SSID simply *never comes up* unless two conditions hold: the firewall self-check has passed, and the SSID's VPN assignment matches its pinned record.
- **The Pi itself is untouched.** Tunnels are brought up with `Table = off`; the Pi's own traffic, SSH, Docker and other services keep using the LAN. `ap-verify` proves this as its very first check.
- **Assignments cannot change by accident.** Which tunnel an SSID exits through (SSID ↔ profile ↔ server key ↔ radio) is pinned; changing it requires typing the affected SSID. Drift is detected and the SSID is stopped.

## What it prevents

| Leak vector | Mitigation |
|---|---|
| Tunnel down → traffic exits via the home connection | Per-SSID routing table plus a `blackhole` rule; an empty table never falls through to `main`. In addition, everything except `AP → its own exit` is DROPped in FORWARD |
| A VPN-backed SSID silently falling back to the LAN | The exit mode is pinned. A `vpn` slot has no LAN default route and no `AP → LAN` rule, the self-check refuses to finish if either appears, and `ap-verify` tests for both |
| A swapped Wi‑Fi adapter inheriting someone else's VPN | The slot is pinned to the radio's MAC; a different adapter keeps the SSID down until you give it its own slot |
| DNS queries reach the ISP | One dnsmasq instance per SSID, bound to the tunnel's source address for upstream (`server=1.1.1.1@<wg-address>`). Attempts to use another resolver are redirected to the local dnsmasq |
| IPv6 escapes the tunnel | IPv6 fully disabled on AP interfaces, plus `ip6tables` DROP |
| Physical location via Wi‑Fi positioning databases | SSIDs end with `_nomap` |
| Clients see each other or the Pi | `ap_isolate=1`; only DHCP and DNS are reachable on the Pi, RFC1918 destinations are DROPped |
| MTU/MSS "connected but nothing loads" | MSS clamped to `MTU − 40` in both directions |
| Docker restart wipes the rules | Own chains (`AP-VPN-*`), a `DOCKER-USER` hook and an `ExecStartPost` drop-in for Docker |
| Inbound access from the VPN server | New connections from tunnel interfaces are DROPped |

It is equally important to know what is **not** covered: PiAP isolates the network layer. The client device itself — location services, accounts, hardware identifiers — is a separate matter; see [docs/security.md](docs/security.md).

## Quick start

```bash
git clone https://github.com/Mithat3313/piap.git && cd piap/pi
sudo ./install.sh                        # packages, services, web password, BLE access key
sudo ap-ctl devices                      # every radio: interface, MAC, driver, AP capability, owning slot
sudo ap-slot-new.sh ap0 wlan0 5          # built-in radio, 5 GHz → prints SSID, password and the MAC it binds to
sudo ap-ctl vpn add server-a ~/a.conf    # WireGuard client .conf from your server
sudo ap-ctl --slot ap0 vpn activate server-a --confirm 'PiAP-ap0_nomap'
sudo ap-ctl --slot ap0 verify            # 38 checks, all must PASS
```

For a second SSID, plug in a USB Wi‑Fi adapter and run `sudo ap-slot-new.sh ap1 wlan1 2.4` (add `--mode direct` for an SSID with no VPN at all). Details in [docs/installation.md](docs/installation.md).

## Layout

```
pi/
  install.sh                  installer (idempotent)
  opt/ap-vpn/bin/
    ap-firewall.sh            per-slot policy routing + iptables; self-check at the end (exit 1 on failure)
    ap-swap-peer.sh           profile activation: sanitises the .conf, brings the tunnel up, waits for a handshake, rolls back
    ap-pin.sh                 assignment pinning checks: SSID ↔ mode ↔ profile ↔ server key ↔ radio
    ap-ifsync.sh              resolves a slot's radio by MAC and keeps the config on that device
    ap-verify.sh              38 checks, each backed by a command's output (read-only)
    ap-watchdog.sh            stale-tunnel recovery + route integrity (every minute)
    ap-bootcheck.sh           on boot: if the LAN never comes up, detach the AP hooks (never lose access to the Pi)
    ap-slot-new.sh            creates a new SSID slot
    ap-ble-agent.py           Bluetooth LE GATT agent (protocol v2, AEAD)
    ap-web.py                 web panel (Flask, HTTPS)
    ap-uninstall.sh           complete removal
  opt/ap-vpn/lib/apctl.py     shared core + the `ap-ctl` command line
  opt/ap-vpn/web/index.html   single-file panel
  opt/ap-vpn/templates/       ap.env, slot.env, dnsmasq, hostapd (5 / 2.4 GHz), NetworkManager
  systemd/                    ap-ifsync@, ap-wlan@, ap-dnsmasq@, ap-hostapd@, ap-firewall, ap-watchdog, ap-bootcheck, ap-web, ap-ble-agent
tests/                        hardware-free dry runs: firewall-dryrun.sh (both exit modes, 44 assertions),
                              device-dryrun.sh (re-plugs, swaps, foreign adapters), confirm-dryrun.sh
macos/                        PiAP Manager — SwiftUI + CoreBluetooth (macOS 14+)
docs/
  architecture.md             slot model, routing, firewall chains, self-checks
  security.md                 threat model, kill-switch layers, assignment pinning, BLE/web hardening
  installation.md             step-by-step setup, second radio, profile management
  usage.md                    ap-ctl reference, web panel, macOS app
  troubleshooting.md          pitfalls encountered and how they were solved
```

## Hardware notes

- **Raspberry Pi 5**, built-in radio (CYW43455): 5 GHz, a single AP (`#{AP} <= 1`), WPA2. WireGuard ceiling is ~2 Gbit/s; the bottleneck is always the home line.
- **Second SSID** via USB: Ralink RT5370 (rt2800usb, 2.4 GHz, up to 8 APs) is tested; MediaTek MT7612U (mt76) is recommended for 5 GHz.
- One radio is one slot; the number of slots is bounded by the number of radios.

## License

MIT — see [LICENSE](LICENSE).
