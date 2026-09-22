# Usage

## `ap-ctl` (command line)

`sudo ap-ctl [--slot apN] <command>`. Output is JSON. Without `--slot` the first slot is used.

| Command | Description |
|---|---|
| `status` | All slots, LAN, services, kill-switch and pin state, temperature, load |
| `slots` | Detailed per-slot status |
| `clients` | Connected clients: MAC, IP, hostname, signal, rate, connected time |
| `kick <mac>` | Disconnect a client |
| `wifi get` / `wifi set --ssid NAME --psk PASSWORD` | SSID/password (only that SSID's clients are dropped) |
| `vpn list` | Profiles and which slot holds each |
| `vpn add <name> [file]` | Add a profile (stdin if no file); `--overwrite` cannot replace a profile in use |
| `vpn remove <name>` | Delete, if not in use |
| `vpn activate <name> --confirm '<SSID>'` | Assign the profile to `--slot`. If the profile is on another slot: `--force` and `--confirm '<target SSID> / <other SSID>'` |
| `vpn swap apA apB --confirm '<SSID A> / <SSID B>'` | Exchange the profiles of two slots |
| `slot enable` / `slot disable` | Turn an SSID on/off (SSID, DHCP and tunnel together) |
| `slot pin --confirm '<SSID>'` | Pin the current state (after a violation, once the state is verified) |
| `exitip` | Exit IP as seen through the tunnel |
| `verify` | `ap-verify.sh --slot` |
| `system logs [-n 80] [-u unit]` | Journal |
| `system firewall` | Re-apply the firewall |
| `system reboot` | Reboot |
| `web password [value]` | Web password (generates and prints one if no value is given) |
| `ble token [--regen]` | BLE access key |
| `ble setname <name>` | BLE advertising name |
| `ble pair [seconds]` | Open a pairing window (default 120 s) |

The typed confirmation (`--confirm`) is mandatory for every operation that changes the SSID↔VPN mapping; if it is missing or wrong, the command is refused and the expected text is printed.

## Web panel

`https://<pi-address>:8443` — from the LAN only. The browser warns about the self-signed certificate; accept it once.

**SSIDs:** one card per slot. SSID, band/channel, client count; VPN profile drop-down and **Apply**; **⇄ swap** when two slots exist; **Query** for the exit IP; the **On/Off** switch in the top-right corner; kill-switch and 🔒 pin badges. On a pin violation the card shows a red box with **Re-pin**.

Operations that change the mapping open a prompt and ask you to type the affected SSIDs verbatim. Wrong text sends no request at all.

**Clients:** clients of all SSIDs, signal, rate, IP; **Kick**.
**Wi‑Fi:** SSID/password per slot (show/copy), **Apply**.
**VPN profiles:** list, upload a `.conf` (file or text), delete, which slot holds it.
**Log:** recent lines.

Bottom buttons: Refresh, Full verification, Re-apply firewall, Web password, Reboot.

## PiAP Manager (macOS)

Works over Bluetooth, so the Pi can be managed even when it has no network (moved to another network, LAN down).

**Build:**

```bash
cd macos && ./make-app.sh        # Swift 5.9+, macOS 14+; produces an ad-hoc signed PiAPManager.app
open PiAPManager.app
```

macOS asks for Bluetooth permission on first launch. Because the ad-hoc signature changes with every build, the permission may be requested again; if it gets stuck: `tccutil reset BluetoothAlways com.mithat.piapmanager`.

**First connection:**

1. Open a pairing window on the Pi: `sudo ap-ctl ble pair 120` (if no device is bonded yet, a 10-minute window opens automatically at boot).
2. The app scans; pick the device, enter the access key (`sudo ap-ctl ble token`) and optionally a nickname. The key is stored per device in the macOS keychain.
3. Once connected, the main window opens: SSIDs, Clients, Wi‑Fi, VPN, Log.

The SSIDs screen offers the same functions as the web panel; mapping changes open a text field and the button is enabled only once the expected SSID has been typed.

Only one central can be connected: while the app is connected, a second device cannot attach. The app closes the connection cleanly on quit.

## Changing profiles and swapping

An SSID's VPN can be changed in three ways:

- **Unassigned profile → SSID:** `Apply` / `vpn activate`. The tunnel is rebuilt; that SSID's clients lose connectivity for a few seconds (nothing leaks).
- **Taking a profile from another SSID:** marked "— taken from apX" in the menu. Once confirmed, the profile is detached from that SSID (which stays without a tunnel until you assign a new one; the kill switch holds) and given to this one.
- **Swap:** the two SSIDs exchange profiles; order: B is detached → A gets B's profile → B gets A's old profile. Takes 1–3 minutes; both SSIDs are verified.

All three update the pin; the confirmation text is the affected SSIDs.

## Temporarily turning an SSID off

The **On/Off** switch in the panel or `ap-ctl --slot apN slot disable`: the SSID goes down, clients are dropped, DHCP and the tunnel stop. The other SSID is unaffected. The pin is kept; when turned back on it comes up with the same tunnel.

## When you see a pin violation

The card shows "ASSIGNMENT VIOLATION — SSID stopped" in red and the message says what does not match (e.g. `PROFILE='x' pinned='y'`, `wg0.conf server key differs from pin`, `RADIO DIFFERS`). If you did not make this change, investigate first: `journalctl -t ap-pin`, the slot env file, `/etc/wireguard/wgN.conf`. If the state is genuinely correct, **Re-pin** (typing the SSID) updates the pin and starts the SSID. An inconsistent state cannot be pinned; make it consistent first.

If you replaced the USB adapter, a `RADIO DIFFERS` violation is the expected behaviour; re-pinning accepts the new MAC.
