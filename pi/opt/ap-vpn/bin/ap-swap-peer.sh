#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-swap-peer.sh /path/new-peer.conf [--apply]
#  Safely puts a WireGuard client .conf (as issued by the server) into service.
#  Without --apply it only prints what it would write (keys masked).
#  If no handshake arrives it ROLLS BACK AUTOMATICALLY: guests never sit on a dead tunnel.
# =============================================================================
set -uo pipefail
. /etc/ap-vpn/ap.env
SLOT=ap0; for _a in "$@"; do case "$_a" in --slot=*) SLOT="${_a#--slot=}";; esac; done; [ -r "/etc/ap-vpn/slots/$SLOT.env" ] && . "/etc/ap-vpn/slots/$SLOT.env"; export SLOT
SRC="${1:?usage: ap-swap-peer.sh /path/new.conf [--apply]}"
APPLY=""; for _a in "$@"; do [ "$_a" = "--apply" ] && APPLY=--apply; done
LIVE=/etc/wireguard/${WG_IF}.conf
BAK=/etc/wireguard/${WG_IF}.conf.$(date +%Y%m%d-%H%M%S).bak
[ "$(id -u)" = 0 ] || { echo "root required" >&2; exit 1; }
[ -r "$SRC" ]      || { echo "cannot read $SRC" >&2; exit 1; }
grep -q '^\[Interface\]' "$SRC" && grep -q '^\[Peer\]' "$SRC" || { echo "not a wireguard config" >&2; exit 1; }

get_i(){ sed -n "/^\[Interface\]/,/^\[Peer\]/p" "$SRC" | sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//Ip" | head -1 | tr -d '\r'; }
get_p(){ sed -n "/^\[Peer\]/,\$p"              "$SRC" | sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//Ip" | head -1 | tr -d '\r'; }

PRIV=$(get_i PrivateKey); ADDR_RAW=$(get_i Address); MTU=$(get_i MTU)
PUB=$(get_p PublicKey);   PSK=$(get_p PresharedKey); EP=$(get_p Endpoint)
KA=$(get_p PersistentKeepalive)
[ -n "$PRIV" ] || { echo "no PrivateKey" >&2; exit 1; }
[ -n "$ADDR_RAW" ] || { echo "no Address" >&2; exit 1; }
[ -n "$PUB" ] || { echo "no PublicKey" >&2; exit 1; }
[ -n "$EP" ]  || { echo "no Endpoint" >&2; exit 1; }

# --- WHAT IS STRIPPED AND WHY ---
for k in DNS Table FwMark PreUp PostUp PreDown PostDown SaveConfig; do
  v=$(get_i "$k"); [ -n "$v" ] && echo "  stripped [Interface] $k = $v" >&2
done
# DNS= : wg-quick's set_dns() runs even with Table=off and overwrites /etc/resolv.conf host-wide;
#        host-network containers inherit it too. And if resolvconf is NOT installed, wg-quick aborts
#        under pipefail and its EXIT trap deletes the interface: the tunnel never comes up.
# Table=: without it wg-quick installs 0.0.0.0/1 + 128.0.0.0/1 and an fwmark, pushing ALL host
#        traffic (SSH, apt, other services) into the tunnel.

ADDR4=$(printf '%s' "$ADDR_RAW" | tr ',' '\n' | tr -d ' ' | grep -v ':' | head -1)
[ -n "$ADDR4" ] || { echo "no IPv4 Address" >&2; exit 1; }
[ "$ADDR_RAW" != "$ADDR4" ] && echo "  stripped the IPv6 half of Address (no global v6 on the LAN)" >&2
NEWIP=${ADDR4%%/*}
[ -n "$MTU" ] || MTU=$(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*//Ip' "$LIVE" | head -1)
[ -n "$MTU" ] || MTU=1420
[ -n "$KA" ]  || KA=25
EPH=${EP%:*}; EPH=${EPH#[}; EPH=${EPH%]}

# --- REFUSE anything that collides with the AP subnet ---
py(){ python3 - "$1" "$2" <<'PY'
import ipaddress,sys
try: print(int(ipaddress.ip_address(sys.argv[1].split('/')[0]) in ipaddress.ip_network(sys.argv[2])))
except ValueError: print(0)
PY
}
[ "$(py "$NEWIP" "$AP_NET")" = 1 ] && { echo "REJECTED: the tunnel address $NEWIP is inside the AP subnet $AP_NET" >&2; exit 1; }
[ "$(py "$EPH"   "$AP_NET")" = 1 ] && { echo "REJECTED: the Endpoint $EPH is inside the AP subnet" >&2; exit 1; }

TMP=$(mktemp --suffix=.conf /etc/wireguard/.wg-XXXXXX); chmod 0600 "$TMP"
trap 'rm -f "$TMP"' EXIT
{ echo "# $LIVE - ap-swap-peer.sh $(date -Is), source: $SRC"
  echo "[Interface]"
  echo "PrivateKey = $PRIV"
  echo "Address    = $ADDR4"
  echo "MTU        = $MTU"
  echo "Table      = off"
  echo
  echo "[Peer]"
  echo "PublicKey  = $PUB"
  [ -n "$PSK" ] && echo "PresharedKey = $PSK"
  echo "Endpoint   = $EP"
  echo "AllowedIPs = 0.0.0.0/0"
  echo "PersistentKeepalive = $KA"
} > "$TMP"

# --- REAL validation: a scratch wireguard device, not a regex ---
/usr/sbin/ip link del wgcheck 2>/dev/null
/usr/sbin/ip link add wgcheck type wireguard || { echo "could not create wgcheck" >&2; exit 1; }
if ! /usr/bin/wg setconf wgcheck <(/usr/bin/wg-quick strip "$TMP"); then
  /usr/sbin/ip link del wgcheck; echo "REJECTED: the kernel did not accept the sanitised config" >&2; exit 1
fi
/usr/sbin/ip link del wgcheck

if [ "$APPLY" != "--apply" ]; then
  echo "--- DRY RUN: $LIVE would become ---"
  sed -E 's/(PrivateKey|PresharedKey)([[:space:]]*)=.*/\1\2= <hidden>/' "$TMP"
  echo "--- to apply: sudo $0 $SRC --apply ---"
  exit 0
fi

cp -a "$LIVE" "$BAK" && echo "backup: $BAK"
install -o root -g root -m 0600 "$TMP" "$LIVE"

# if the interface is up outside systemd, take ownership first
if /usr/sbin/ip link show "$WG_IF" >/dev/null 2>&1 && ! systemctl is-active --quiet "wg-quick@${WG_IF}"; then
  echo "$WG_IF is up outside systemd - taking it over"; /usr/sbin/ip link del "$WG_IF"
fi
systemctl restart "wg-quick@${WG_IF}.service"

# --- wait for a handshake ---
OK=0
for i in $(seq 1 20); do
  sleep 2
  /usr/bin/wg show "$WG_IF" latest-handshakes | awk '$2!=0{f=1} END{exit !f}' && { OK=1; break; }
done
if [ "$OK" != 1 ]; then
  echo "THE NEW PEER NEVER COMPLETED A HANDSHAKE - rolled back to $BAK" >&2
  install -m 0600 "$BAK" "$LIVE"; systemctl restart "wg-quick@${WG_IF}.service"
  sleep 3; /opt/ap-vpn/bin/ap-firewall.sh
  exit 1
fi

# --- move dnsmasq's upstream to the new tunnel address ---
sed -i -E "s/^(server=[0-9.]+)@.*/\1@${NEWIP}/" "$DNSMASQ_CONF"
grep "^server=" "$DNSMASQ_CONF"
systemctl restart "$DNSMASQ_UNIT"

# --- firewall: WG_SRC and MSS are re-derived automatically ---
/opt/ap-vpn/bin/ap-firewall.sh || { echo "ap-firewall FAILED" >&2; exit 1; }
command -v conntrack >/dev/null && conntrack -D -s "$AP_NET" >/dev/null 2>&1

# --- measure the new exit IP (from the tunnel's source address) ---
NEWEXIT=$(curl -4 -s -m 15 --interface "$NEWIP" https://api.ipify.org || true)
echo "new exit IP: ${NEWEXIT:-UNKNOWN}"

exec /opt/ap-vpn/bin/ap-verify.sh --slot=$SLOT
