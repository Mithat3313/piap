# Troubleshooting

Problems met during development that shaped the design. Each one became a check in `ap-verify`; if you see a similar symptom, run `sudo ap-ctl --slot apN verify` first.

## Network

**"Connected but no internet" / the browser says "online" but pages do not load**

There were three separate causes:

1. *MSS.* `--clamp-mss-to-pmtu` computed the PMTU against 1500 in the return direction and wrote 1460; the large packets of the TLS handshake were dropped. Fix: a fixed `--set-mss $((MTU−40))` in both directions (1380 for MTU 1420).
2. *dnsmasq replies went into the tunnel.* The rule `from 10.99.0.0/24 lookup 51820` also matches the Pi's AP address; with only a default route in the table, DHCP/DNS replies were written to `wg0`. Fix: the link route `10.99.0.0/24 dev wlan0` in the table, before the default route.
3. *Rule cleanup.* A script that tried to delete rules tagged with `iptables -m comment` left old rules behind because of word splitting in quoted comments. Fix: own chains, flush and rewrite every time.

**Packets reach the ISP while the table is empty**

`ip rule ... lookup TABLE` matches, but if the table is empty, evaluation moves on to the next rule and falls through to the `main` table. While `wg-quick` restarts, the interface is deleted, its routes go with it, and this state lasts for a few seconds. Fix: `from AP_NET blackhole` right after the table rule. This is the second kill-switch layer and `ap-verify` section 2 tests it separately.

**The table stays empty after a wg-quick restart**

With `Table = off`, wg-quick writes no route into the table; when the interface is recreated, the kernel deletes the device-bound routes and they do not come back — "tunnel healthy, but every client is in the blackhole". The watchdog checks for `default dev wgN` each cycle and re-applies the firewall; `ap-swap-peer.sh` also runs the firewall after a restart.

**The Pi's own traffic goes into the tunnel**

Without `Table=` in the client `.conf`, wg-quick installs `0.0.0.0/1 + 128.0.0.0/1` routes and an fwmark; everything including SSH goes into the tunnel. With `DNS=`, `/etc/resolv.conf` is overwritten host-wide (host-network containers included); if `resolvconf` is not installed, wg-quick aborts at that step and the tunnel never comes up. `ap-swap-peer.sh` strips those lines and enforces `Table = off`; `ap-firewall` refuses to run if the conf lacks `Table = off` or contains `DNS=`.

**dnsleaktest shows Paris, the exit is in Germany**

Cloudflare anycast: the DNS query goes to the Cloudflare point of presence nearest to the tunnel exit (`colo=CDG`). The `loc=` country code in `cloudflare.com/cdn-cgi/trace` reflects the VPN server's country; this is not a leak.

**The second dnsmasq does not start (port 53 in use)**

Two dnsmasq instances collide on `127.0.0.1:53` even with `bind-interfaces`. Fix: `except-interface=lo` + `listen-address=<gw>`. DHCP on `:67` is already bound per interface via `SO_BINDTODEVICE` and does not collide.

**nftables**

With `nftables.service` enabled, `/etc/nftables.conf` runs `flush ruleset` at boot and wipes all of Docker's tables and the kill switch. `ap-firewall` refuses to run in that case and `install.sh` checks for it. On Debian the `iptables` package is the `iptables-nft` layer; the project works with that, `nftables.service` is not needed.

**Rules disappear when Docker starts**

Docker may recreate the `DOCKER-USER` chain. Fix: `docker.service.d/10-ap-firewall.conf` (`ExecStartPost=ap-firewall.sh`) and `After=docker.service` in `ap-firewall.service`. After a reboot, containers with restart policy `no` do not come back either — unrelated to this project; `docker update --restart unless-stopped <name>`.

## Radio

**hostapd does not start on 5 GHz**

Depends on the country code; in TR the non-DFS channels are 36–48. Check the regulatory domain with `iw reg get` and channel permissions with `iw list`. `country_code` must be in the hostapd conf (`ieee80211d=1`).

**The built-in radio refuses a second AP**

The CYW43455 firmware reports `#{AP} <= 1`; a second AP cannot be opened on the same phy. A P2P scan by NetworkManager through `p2p-dev-wlan0` can also knock the running AP down, which is why `p2p-dev-wlanN` is in the `unmanaged-devices` list as well.

**The USB adapter became `wlan0`, the built-in radio `wlan1`**

Kernel names depend on enumeration order. Because the SSID and the tunnel live in the same slot record, the mapping cannot cross; the wrong radio is caught by the `ap-pin.sh iface` (MAC pin) check and the slot stays down. Permanent fix: pin names to MAC addresses with `/etc/systemd/network/*.link`.

**Debian's `hostapd@` template**

It derives the interface name from the unit name through `BindsTo=sys-subsystem-net-devices-%i.device`; it does not work with a slot name (`ap0`). That is why the project ships its own `ap-hostapd@` template (`hostapd /etc/hostapd/%i.conf`, in the foreground).

## Boot

**The Pi became unreachable after boot**

Almost always the LAN interface ended up in NetworkManager's `unmanaged-devices` line. `ap-slot-new.sh` refuses that; `ap-bootcheck` detaches the hooks and reloads NM if it sees no LAN for 10 minutes. From the console: `rm /etc/NetworkManager/conf.d/99-ap-unmanaged.conf && systemctl reload NetworkManager`.

**hostapd started before the firewall**

In the first version, one reboot brought the SSID up before the rules. Fix: `Requires=ap-firewall.service` + `After=` in `ap-hostapd@`. Measured: the firewall finishes 7 ms before hostapd starts.

## Bluetooth

**BlueZ D-Bus advertising fails with "Invalid Parameters"**

On kernel 6.18 + CYW43455, `LEAdvertisingManager1.RegisterAdvertisement` fails on the extended-advertising path. The agent tries D-Bus first and falls back to `btmgmt add-adv` (legacy), refreshing every 60 s.

**`btmgmt` hangs**

`btmgmt` wants a TTY; without one it waits forever. Fix: `timeout 5 script -qc "btmgmt ..." /dev/null`. The adapter must also be `connectable on` (the agent's `ExecStartPre` does that).

**The macOS app is stuck at "Preparing Bluetooth…"**

The TCC permission is bound to the ad-hoc signature, which changes with every build. Run `tccutil reset BluetoothAlways com.mithat.piapmanager`, then reopen the app and grant access. A Swift binary run from the command line without `NSBluetoothAlwaysUsageDescription` is killed silently; that is why the `.app` bundle is mandatory.

**Notifications go to every central**

A BLE notification is broadcast to every connected central; authentication does not prevent that. Protocol v2 therefore AEAD-encrypts every message with the session key and disconnects a second central while an authenticated session exists.

## Management

**"another long operation is running"**

The web panel and the BLE agent share one cross-process lock; while one is changing a tunnel, the other waits. `ap-pin.sh enforce` also holds the lock for less than a second; `apctl` retries for up to 3 s. If the lock is stuck (`/run/ap-vpn/long.lock` contains the pid), check whether that process is gone.

**The panel says "not pinned (no profile assigned)"**

The slot was detached (another slot took its profile) or never had one. Assign a profile; the pin is written together with the assignment.

**The web panel is unreachable from an SSID**

By design: management is only reachable from the LAN interface. Clients can reach the Pi for DHCP and DNS only.
