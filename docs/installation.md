# Installation

## Requirements

- Raspberry Pi 5 (a Pi 4 works too; the measurements are for the Pi 5), Raspberry Pi OS / Debian 12+ (developed on trixie)
- The Pi's own internet over **Ethernet** (`eth0`); the built-in radio is used as an AP
- For a second SSID, a USB Wi‑Fi adapter that supports AP mode (e.g. RT5370, MT7612U)
- One WireGuard server per SSID and the client `.conf` issued by that server
- `nftables.service` must **not** be enabled (it wipes the Docker and kill-switch rules; the installer checks this)

The server side is out of scope: any WireGuard server works (a VPS you set up yourself, `wg-easy`, the `wireguard-install` script, …). The only requirement is `AllowedIPs = 0.0.0.0/0` in the client `.conf`.

## 1. Software

```bash
git clone https://github.com/Mithat3313/piap.git
cd piap/pi
sudo ./install.sh              # the LAN interface is taken from the default route; override with --lan-if eth0
```

At the end the web password and the BLE access key are printed **once**. Keep them; later you can use `sudo ap-ctl web password` (generates a new one) and `sudo ap-ctl ble token`.

The installer does not bring up a radio; it installs and enables the services. `ap-firewall` refuses to run without any slot — that is expected at this point.

## 2. First SSID

```bash
sudo ap-slot-new.sh ap0 wlan0 5
```

The output shows the SSID and the password. Defaults: SSID `PiAP-ap0_nomap`, a random 20-character password, 5 GHz channel 36 (80 MHz), subnet `10.99.0.0/24`, country code from `iw reg get`. Options:

```
--ssid NAME      --psk PASSWORD   --channel 36|40|44|48|149…
--country TR     --net 10.99.0    --desc "description"
```

At this point the SSID is on the air but there is no tunnel: a client gets a DHCP lease and cannot reach the internet (kill switch). The panel shows the slot as "no tunnel / not pinned".

## 3. VPN profile

```bash
sudo ap-ctl vpn add server-a /home/pi/server-a.conf
sudo ap-ctl --slot ap0 vpn activate server-a --confirm 'PiAP-ap0_nomap'
```

`vpn add` validates the conf with a dry run (lines such as `DNS=`, `Table=` and `PostUp=` are stripped and listed as warnings). `activate` brings the tunnel up, waits 40 s for a handshake, points dnsmasq at the tunnel address, re-applies the firewall, measures the exit IP and runs `ap-verify`. If no handshake arrives it rolls back to the previous state.

The `--confirm` value is the typed confirmation required by assignment pinning: the affected SSID, verbatim. This first activation pins the slot (`PIN_*` and `AP_MAC` are written).

Verify:

```bash
sudo ap-ctl --slot ap0 verify      # 38 PASS, 0 FAIL
sudo ap-ctl --slot ap0 exitip      # the exit IP as seen through the tunnel
```

Join the SSID with a phone and open `ifconfig.me`; you should see the VPN server's address. On `dnsleaktest.com` the DNS server will be the Cloudflare point of presence closest to the tunnel exit (anycast; Paris for a server in Germany is normal).

## 4. Second SSID

Plug in the USB adapter, find its name with `ip link` (`wlan1`), confirm AP mode:

```bash
iw list | grep -A8 "Supported interface modes" | grep -q "\* AP" && echo "AP mode available"
sudo ap-slot-new.sh ap1 wlan1 2.4
sudo ap-ctl vpn add server-b /home/pi/server-b.conf
sudo ap-ctl --slot ap1 vpn activate server-b --confirm 'PiAP-ap1_nomap'
sudo ap-ctl --slot ap1 verify
```

`ap-slot-new.sh` derives the new table, priorities and subnet from the slot number, adds the interface to NetworkManager's `unmanaged` list and to avahi's `deny-interfaces`, and installs an `After=wg-quick@wg1` drop-in for `ap-firewall`.

**A profile cannot be assigned to two slots** — a WireGuard server keeps a single endpoint per client key. Every SSID needs its own server (or at least its own client key).

## 5. Channel and band notes

- The built-in radio (CYW43455) can run one AP at a time; on 5 GHz the non-DFS channels are 36–48 in most countries. On 2.4 GHz the default is channel 11: channel 1 overlaps Bluetooth LE advertising and was measured losing 22% of frames here against 0.4% on 11. Adjust with `--channel` for your environment (see troubleshooting for how to measure).
- The RT5370 is 2.4 GHz only; use an MT7612U (mt76) for a second 5 GHz SSID.
- The templates use 80 MHz on 5 GHz and 20 MHz on 2.4 GHz; edit `/etc/hostapd/<slot>.conf` and `sudo systemctl restart ap-hostapd@<slot>` to change. Do not edit the SSID by hand — the pin will no longer match and the SSID stops; use `ap-ctl --slot apN wifi set --ssid …` instead.

## 6. Boot behaviour

On reboot the order is: `ap-wlan@` → `wg-quick@` → `ap-firewall` (self-check) → `ap-dnsmasq@` → `ap-hostapd@` (pin check). If the firewall or the pin check fails, that SSID stays down; `journalctl -u ap-hostapd@ap0` tells you why.

`ap-bootcheck` starts watching the LAN two minutes after boot; if it sees neither a LAN address nor a fresh handshake for 10 minutes it detaches the AP hooks and, if needed, writes `/etc/ap-vpn/DISABLED` and reboots. Keep this in mind when moving the Pi to another network (including networks without DHCP); deleting the `DISABLED` file re-enables the AP.

## 7. With Docker

If Docker is detected, the installer places the `docker.service.d/10-ap-firewall.conf` drop-in. Host-network containers such as Home Assistant are unaffected; add `HOST_CHECKS="http:8123 tcp:1883"` to `ap.env` and `ap-verify` will confirm that too.

## Removal

```bash
sudo /opt/ap-vpn/bin/ap-uninstall.sh            # stops services, removes hooks, leaves files in place
sudo /opt/ap-vpn/bin/ap-uninstall.sh --purge    # moves configs/keys under /opt/ap-vpn/backup/ (never deletes them)
```

It does not touch the LAN interface, SSH or Docker's own rules, and can be run twice.

## Updating

```bash
cd piap && git pull && cd pi && sudo ./install.sh     # refreshes the files; ap.env, slots and profiles are preserved
sudo systemctl restart ap-web ap-ble-agent
sudo /opt/ap-vpn/bin/ap-firewall.sh && sudo ap-ctl verify
```
