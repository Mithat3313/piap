# Architecture

## The slot model

The basic unit of the system is a **slot**. A slot ties together:

| Component | Example (ap0) | Example (ap1) |
|---|---|---|
| Radio (identity = MAC) | `wlan0` (built-in, 5 GHz) | `wlan1` (USB, 2.4 GHz) |
| Exit mode | `vpn` | `vpn` or `direct` |
| SSID | `PiAP-ap0_nomap` | `PiAP-ap1_nomap` |
| Subnet | `10.99.0.0/24`, gw `.1`, DHCP `.50–.200` | `10.98.0.0/24` |
| Tunnel | `wg0` | `wg1` |
| Routing table | `51820` | `51821` |
| `ip rule` priorities | 1000 / 1001 / 1002 | 1010 / 1011 / 1012 |
| Profile | `server-a` | `server-b` |

A slot is defined in `/etc/ap-vpn/slots/<slot>.env`; every script and `apctl` reads that file.

**The radio, not the name.** `AP_MAC` is the slot's identity. Kernel names depend on enumeration order, so `ap-ifsync.sh sync <slot>` runs before the slot comes up (unit `ap-ifsync@`): it finds the interface currently carrying that MAC and rewrites `AP_IF` plus the `interface=` lines of the slot's hostapd and dnsmasq configs. Three outcomes, all deliberate:

| Situation | Result |
|---|---|
| Same MAC, different name | The name is updated; the slot keeps its subnet, SSID and exit |
| Different MAC on the old name | Refused — the SSID stays down. A new adapter never inherits another's VPN; give it its own slot with `ap-slot-new.sh` (or rebind explicitly with `ap-ctl --slot X slot bind <mac>`) |
| The MAC is absent | `ap-ifsync` exits non-zero, so `ap-wlan@` and `ap-hostapd@` do not start (fail closed) |

**Two exit modes.** `MODE=vpn` (default) routes the slot only into its own tunnel. `MODE=direct` routes it out through the LAN with no tunnel at all — the SSID works immediately, which is what you want for a plain guest network. The mode is part of the pin (`PIN_MODE`), so a `vpn` slot cannot drift into `direct`; switching is an explicit operation that detaches the profile, stops the tunnel, rewrites the resolver and re-pins.

`ap-slot-new.sh apN …` derives the table (`51820+N`), the priorities (`1000+10N`), the tunnel name (`wgN`) and the subnet (`10.(99−N).0.0/24`) from the slot number.

Each slot has four systemd units:

```
ap-ifsync@apN    resolves the radio by MAC, aligns AP_IF and the confs (oneshot)  ← fails if the radio is absent
ap-wlan@apN      assigns the address, disables IPv6 (oneshot)    ← Requires=ap-ifsync@; ExecStartPre: ap-pin.sh iface
ap-dnsmasq@apN   DHCP+DNS for that subnet (its own conf file)
ap-hostapd@apN   the SSID                                          ← Requires=ap-firewall + ap-wlan@; ExecStartPre: ap-pin.sh check
wg-quick@wgN     the tunnel (Table = off; vpn mode only)
```

plus the global ones: `ap-firewall` (rules for all slots + self-check), `ap-watchdog.timer`, `ap-bootcheck.timer`, `ap-web`, `ap-ble-agent`.

## Packet path

When a client at `10.99.0.116` sends a packet to `1.2.3.4:443`:

1. **Policy routing.** `ip rule 1001: from 10.99.0.0/24 lookup 51820` → table 51820 contains `default dev wg0`. The source address selects the tunnel; the `main` table is never consulted.
2. **Firewall (FORWARD).** The packet enters `DOCKER-USER → AP-VPN-FWD`:
   ```
   -i wlan0 -d 10.0.0.0/8|172.16.0.0/12|192.168.0.0/16  DROP     (no access to LAN, Docker or other SSIDs)
   -i wlan0 -o wg0                                       ACCEPT   (the only permitted exit)
   -i wg0   -o wlan0  ctstate ESTABLISHED,RELATED       ACCEPT   (return traffic)
   -i wlan0                                              DROP     (← kill switch: nowhere else)
   -i wg0   -o wlan0                                     DROP     (no new connections from the tunnel)
   -i eth0  -o wlan0                                     DROP
   ```
3. **NAT.** `AP-VPN-POST`: `-s 10.99.0.0/24 -o wg0 MASQUERADE`. Inside the tunnel the source becomes `10.66.66.x`; the VPN server sees a single client. In `direct` mode the same rule masquerades to the LAN interface instead, and the RFC1918 drops above it keep the guests off the LAN's own hosts.
4. **MSS.** `AP-VPN-MSS` (mangle FORWARD): `--set-mss $((MTU−40))` for both `-i wlan0 -o wg0` and `-i wg0 -o wlan0`. A fixed value — `--clamp-mss-to-pmtu` miscalculates in the return direction (see troubleshooting).

DNS: the client asks `10.99.0.1:53` (DHCP says so; if it asks any other address, `AP-VPN-PRE` REDIRECTs it to `10.99.0.1`). dnsmasq runs with `no-resolv` and only `server=1.1.1.1@10.66.66.x`: the query leaves **from the tunnel's source address**, so `ip rule 1000: from 10.66.66.x lookup 51820` sends it into the tunnel. If the tunnel is down, binding to that address fails — the query never reaches the ISP.

## Two subtleties in the routing table

**The rewrite is not instantaneous.** `ap-firewall` deletes its old `ip rule` entries and flushes `AP-VPN-FWD` before writing the new ones. For those hundreds of milliseconds a `vpn` slot would have neither its blackhole nor its DROP rule, and a packet could fall through to `main` and out of the LAN. So the run starts by blackholing every enabled AP subnet at priority 999 — above all the normal rules — and lifts that guard only after the self-check has passed. Guests lose traffic for the length of the rewrite; nothing escapes. Every failure path leaves the guard in place, and the watchdog re-runs the firewall a minute later.

**Blackhole.** After an `ip rule` selects a table, if the table is empty (the tunnel interface was deleted, so its routes went with it), rule evaluation **continues** and the packet falls through to `main` — that is, to the home connection. What prevents this is `ip rule 1002: from 10.99.0.0/24 blackhole`, placed right after the table rule. When the table empties, the packet dies here.

**AP link route inside the table.** The rule `from 10.99.0.0/24 lookup 51820` also matches the Pi's own AP address (`10.99.0.1`). dnsmasq's DHCP/DNS replies leave from that address; if the table only held `default dev wg0`, the replies would go into the tunnel and the client would see "connected, no internet". That is why `ap-firewall` writes the link route `10.99.0.0/24 dev wlan0` into the table before the default route.

## Cross-slot isolation

For an ap0 client to exit through ap1's tunnel there would have to be a rule like `-i wlan0 -o wg1 ACCEPT`; no such rule exists, and `-i wlan0 DROP` cuts everything else. `ap-firewall` checks this explicitly in its self-check: if any `-i wlanX -o wgY ACCEPT` (X≠Y) is found, the script exits 1 and hostapd does not start. Measured at the packet level: during ap1 traffic the `wg0` counter stays at 0, during ap0 traffic `wg1` stays at 0, and `eth0` stays at 0 in both cases.

## Coexisting with Docker

Docker sets up its own chains through `iptables-nft` and may recreate `DOCKER-USER` on startup. PiAP:

- uses its own chains (`AP-VPN-FWD/IN/PRE/POST/MSS/6`) and hooks them: `DOCKER-USER → AP-VPN-FWD`, `INPUT → AP-VPN-IN`, `nat PREROUTING/POSTROUTING`, `mangle FORWARD`, `ip6tables INPUT/FORWARD`;
- adds an `ExecStartPost=ap-firewall.sh` drop-in to Docker (re-installs the hook immediately);
- orders `ap-firewall.service` `After=docker.service`;
- **refuses to run** if `nftables.service` is enabled: `/etc/nftables.conf` starts with `flush ruleset`, which wipes all of Docker's tables and the kill switch.

Without Docker the chain simply does not exist, so `ap-firewall` creates it and hooks it into `FORWARD` itself (it never flushes it: when Docker is installed, Docker's own rules live there). Everything in the filter layer hangs off that one jump, so a missing chain would quietly make all of it unreachable.

## Self-check and the structural kill switch

After writing the rules, `ap-firewall.sh` reads them back with `iptables -C` for every slot: is `-i AP DROP` there, is `-i AP -o WG ACCEPT` there, is the `DOCKER-USER` hook there, is the blackhole rule there, are there no cross rules. If anything is missing: `exit 1`.

Because `ap-hostapd@` has `Requires=ap-firewall.service`, a failing firewall means **the SSID never comes up**. Measured at boot: the firewall finishes 7 ms before hostapd starts. This closes the "SSID first, rules later" window.

The same approach is repeated for assignment pinning: `ap-hostapd@` has `ExecStartPre=ap-pin.sh check` — if the pin does not hold, the SSID does not start (see [security.md](security.md)).

## Profile activation (`ap-swap-peer.sh`)

1. The `.conf` obtained from the server is **sanitised**: `PrivateKey`, `Address`, `MTU`, `PublicKey`, `PresharedKey`, `Endpoint` and `PersistentKeepalive` are kept; `DNS=`, `Table=`, `PostUp/Down`, `FwMark` and `SaveConfig` are dropped. `Table = off` is enforced. (`DNS=` would overwrite `/etc/resolv.conf` host-wide; without `Table=`, wg-quick installs `0.0.0.0/1` routes and pushes all of the Pi's traffic into the tunnel.)
2. The key is validated in the kernel (temporary interface); the previous conf is backed up.
3. `wg-quick@wgN` is restarted and a handshake is awaited for 40 s. If none arrives: **automatic rollback**.
4. dnsmasq's `server=` lines are rewritten to the new tunnel address, `ap-dnsmasq@` is restarted, the firewall is re-applied, conntrack is flushed.
5. The exit IP is measured and `ap-verify --slot` runs.

The same server key cannot be used in two tunnels (the server keeps a single endpoint per peer; both would flap). That is why "taking" a profile from another slot leaves that slot without a tunnel — the kill switch holds, and the user confirms explicitly.

## Recovery (not protection)

- **`ap-watchdog`** (every minute): starts the tunnel interface if it is missing; re-applies the firewall if the table has no `default dev wgN`; re-applies it if the blackhole rule is missing; rebuilds the tunnel if the handshake is older than `HS_MAX_AGE` (300 s), with `RESTART_COOLDOWN` as flap protection. Each run starts with `ap-pin.sh enforce`.
- **`ap-bootcheck`** (2 minutes after boot): if for 10 minutes it sees neither an IPv4 address on the LAN interface *nor* a fresh handshake, it detaches the AP hooks and reloads NetworkManager; if that still does not help, it disables the AP persistently and reboots. Purpose: catch a wrong NetworkManager `unmanaged` line before it makes the Pi unreachable.

Protection does not depend on these scripts; if they do not run, nothing leaks — you just do not get recovery.

## Management layer

```
             web (Flask, HTTPS)     BLE agent (GATT)      ap-ctl (CLI)
                     └──────────────────┼──────────────────┘
                                   apctl.py
                        status · clients · wifi · profiles · slots
                        vpn_activate / vpn_swap / slot_pin  (typed confirmation + pin)
                                      │
                      ap-swap-peer.sh · ap-firewall.sh · ap-verify.sh · systemctl
```

Long operations (`vpn.activate`, `vpn.swap`, `wifi.set`, `verify`, `slot.enable`) are serialised with a cross-process lock (`flock /run/ap-vpn/long.lock`): the web panel and the BLE agent cannot change tunnels at the same time. `ap-pin.sh enforce` also holds the lock briefly, so it never mistakes the transient state in the middle of a change for a violation.
