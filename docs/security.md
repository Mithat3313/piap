# Security model

## Goal and assumptions

PiAP's job is to **hide the client's real IP address and location at the network layer**, and to isolate SSIDs from each other and from the Pi's own network. Encryption is not a goal; it is a by-product of WireGuard.

Threat model:

- **The client is untrusted.** A device joining an SSID may probe the Pi, the LAN, the other SSID or the home connection. Hence `ap_isolate=1`, DROP for RFC1918 destinations, and only DHCP/DNS reachable on the Pi.
- **The tunnel is not hostile, but the server side cannot reach the Pi either.** New connections arriving on tunnel interfaces are DROPped; only ICMP echo (for diagnostics) is allowed.
- **Configuration mistakes happen.** Every protection is built on "if the script misbehaves there is no SSID", never on "if the script runs correctly".
- **Management doors are attack surface.** The web panel is reachable from the LAN only; BLE has authentication, session encryption and a pairing window.

## Kill-switch layers

The layers are independent; a leak requires all of them to fail at once.

| # | Layer | What it blocks |
|---|---|---|
| 1 | `FORWARD`: `-i wlanX -o wgX ACCEPT`, then `-i wlanX DROP` | Any packet from an AP to anywhere but its tunnel |
| 2 | Per-slot routing table + `blackhole` rule | Falling through to `main` (the ISP) when the table empties |
| 3 | dnsmasq binds to the tunnel address for upstream | DNS leaving via the ISP; with the tunnel down, queries cannot leave at all |
| 4 | IPv6 disabled (sysctl + ip6tables DROP) | Exit outside the tunnel over v6 |
| 5 | `ap-hostapd@ Requires=ap-firewall` | An SSID without rules |
| 6 | `ap-hostapd@ ExecStartPre=ap-pin.sh check` | An SSID bound to the wrong tunnel |
| 7 | Watchdog `ap-pin.sh enforce` (every minute) | Drift at runtime |

Layers 1 and 2 are both required: without 1, layer 2 holds when the table empties; without 2, layer 1 holds if a rule is deleted. `ap-verify` proves each of them separately.

## Assignment pinning

Every slot carries a four-part pin:

```
PIN_SSID_HEX   the SSID (hex; safe for spaces/special characters)
PIN_PROFILE    the assigned profile name
PIN_PEER       the VPN server's public key from that profile
AP_MAC         the radio's MAC address
```

`ap-pin.sh check <slot>` compares the live state with the pin: `PROFILE` in the env, `ssid` in the hostapd conf, `PublicKey` in the profile file, `PublicKey` in `/etc/wireguard/wgN.conf`, the running tunnel's peer, and `/sys/class/net/<if>/address`. Any mismatch returns exit code 1.

Enforcement points:

- **Startup:** `ap-hostapd@` `ExecStartPre` — the SSID never comes up. `ap-wlan@` `ExecStartPre=ap-pin.sh iface` — a different adapter/name (USB re-enumerated, adapter swapped) keeps the slot down.
- **Runtime:** the watchdog runs `enforce` each cycle — on violation `ap-hostapd@<slot>` is stopped, `/run/ap-vpn/<slot>/pin-violation` is written, and both panels show a red warning. If a slot without a pin has a tunnel up, the tunnel is stopped as well.

Only operations that passed a **typed confirmation** write the pin. Every operation that changes the SSID↔VPN mapping (`vpn activate`, taking a profile from another slot, `vpn swap`, `slot pin`) requires `confirm` to equal the affected SSIDs joined with ` / `; the web panel uses a prompt, the macOS app a text field, the CLI `--confirm`. The check lives on the Pi — an outdated client cannot make an unconfirmed change.

An inconsistent state cannot be pinned: `slot pin` writes the key from the profile file, so if the live conf differs, `check` still fails. If a swap stops halfway (no handshake in step 3), the detached slot's tunnel is shut down; the same key never runs in two tunnels.

## Bluetooth LE agent

GATT service `7f2a0001-9c1e-4b7a-8d3e-5a6b7c8d9e0f` (RX `…0002` write, TX `…0003` read/notify). Framing: a 1-byte header (bit 7 FIN, bits 0–6 sequence) plus the fragment.

**Protocol v2 (application layer, independent of BLE link encryption):**

```
client → hello    {v:2, nonce_c}
Pi     → challenge{nonce_s, proof = HMAC(token, "srv|nonce_c|nonce_s"), name}   ← client authenticates the Pi
client → auth     {proof = HMAC(token, "cli|nonce_c|nonce_s")}                   ← Pi authenticates the client
K = HKDF-SHA256(token, nonce_c‖nonce_s, "piap-ble-v2")
afterwards: counter(8B) ‖ ChaCha20-Poly1305(K, nonce = direction(4B) ‖ counter, JSON)
```

- The access key (`/etc/ap-vpn/ble-token`, mode 0600) is stored per device in the macOS keychain; it never travels over BLE in clear.
- BLE notifications are broadcast to every connected central, so the payload is AEAD-encrypted and only the central holding the session key can open it. While an authenticated session exists, a second central is disconnected.
- Wrong key: per-device and global lockout (brute-force protection).
- Pairing gate: BlueZ `Pairable` is normally off; `ap-ctl ble pair [seconds]` opens a temporary window (opened automatically for 10 minutes at boot if no bonded device exists). With `BLE_ENCRYPT=1` the characteristics require a bonded link.
- The agent is `BindsTo=bluetooth.service`; if the adapter goes away, the agent stops and restarts with it.

## Web panel

- HTTPS with a self-signed EC P-256 certificate (10 years). The password is stored as PBKDF2-SHA256 (200 000 iterations).
- Session cookie `HttpOnly; Secure; SameSite=Strict`; every state-changing request must carry `X-Requested-With: piap` (CSRF).
- Login rate limit: 5 failed attempts per IP and 20 in total per 10 minutes.
- `Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- Reachable from the LAN interface only: AP clients cannot open port 8443 on the Pi (INPUT DROP), and no new connections arrive from the tunnel side.

## Location leakage

The VPN hides the IP; it does **not** hide the BSSID. A phone with location services enabled reports nearby SSIDs/BSSIDs to its positioning provider, and if they are in the database the physical location is known. The `_nomap` suffix is the opt-out convention honoured by Google, Mozilla and Apple; `ap-slot-new.sh` uses it by default. Nothing can be done about the neighbours' BSSIDs — location services must be turned off on the client device.

## What this project does **not** do

- It does not hide the identity of the client device: hardware identifiers, accounts, browser fingerprint, time zone, language.
- It offers no protection against traffic analysis or timing correlation.
- You must trust the VPN server itself; the exit IP is the server's.
- Data-centre IP ranges (Hetzner, DigitalOcean, …) are tagged "hosting" in IP reputation databases and some services treat that as a risk signal. If you run several SSIDs, spreading the exits across different providers/ASNs reduces correlation.

## Verification

`sudo ap-ctl --slot ap0 verify` (or `ap-verify.sh --slot=ap0`) runs 38 checks in 10 sections; every line is backed by a command's output:

1. Host path untouched (the Pi's default route, no tunnel in `main`, `resolv.conf`, `HOST_CHECKS`)
2. Guest path only through the tunnel (rule, blackhole, link route, default)
3. FORWARD rules and their order
4. NAT, MSS, DNS redirection
5. IPv6 disabled
6. Guest isolation (INPUT)
7. Docker/nftables compatibility
8. Tunnel health (handshake age)
9. Persistence (every unit enabled + active)
10. Assignment pinning

Zero FAILs are expected. If you see one, run that line's command by hand; the message says what is missing.
