#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-swap-peer.sh /yol/yeni-peer.conf [--apply]
#  Sunucudan alinan WireGuard istemci .conf'u guvenli sekilde devreye alir.
#  --apply olmadan sadece ne yazacagini gosterir (anahtarlar maskeli).
#  Handshake gelmezse OTOMATIK GERI ALIR: misafirler asla olu tunelde kalmaz.
# =============================================================================
set -uo pipefail
. /etc/ap-vpn/ap.env
SLOT=ap0; for _a in "$@"; do case "$_a" in --slot=*) SLOT="${_a#--slot=}";; esac; done; [ -r "/etc/ap-vpn/slots/$SLOT.env" ] && . "/etc/ap-vpn/slots/$SLOT.env"; export SLOT
SRC="${1:?kullanim: ap-swap-peer.sh /yol/yeni.conf [--apply]}"
APPLY=""; for _a in "$@"; do [ "$_a" = "--apply" ] && APPLY=--apply; done
LIVE=/etc/wireguard/${WG_IF}.conf
BAK=/etc/wireguard/${WG_IF}.conf.$(date +%Y%m%d-%H%M%S).bak
[ "$(id -u)" = 0 ] || { echo "root gerekli" >&2; exit 1; }
[ -r "$SRC" ]      || { echo "$SRC okunamiyor" >&2; exit 1; }
grep -q '^\[Interface\]' "$SRC" && grep -q '^\[Peer\]' "$SRC" || { echo "wireguard config degil" >&2; exit 1; }

get_i(){ sed -n "/^\[Interface\]/,/^\[Peer\]/p" "$SRC" | sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//Ip" | head -1 | tr -d '\r'; }
get_p(){ sed -n "/^\[Peer\]/,\$p"              "$SRC" | sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//Ip" | head -1 | tr -d '\r'; }

PRIV=$(get_i PrivateKey); ADDR_RAW=$(get_i Address); MTU=$(get_i MTU)
PUB=$(get_p PublicKey);   PSK=$(get_p PresharedKey); EP=$(get_p Endpoint)
KA=$(get_p PersistentKeepalive)
[ -n "$PRIV" ] || { echo "PrivateKey yok" >&2; exit 1; }
[ -n "$ADDR_RAW" ] || { echo "Address yok" >&2; exit 1; }
[ -n "$PUB" ] || { echo "PublicKey yok" >&2; exit 1; }
[ -n "$EP" ]  || { echo "Endpoint yok" >&2; exit 1; }

# --- STRIP EDILENLER ve NEDENLERI ---
for k in DNS Table FwMark PreUp PostUp PreDown PostDown SaveConfig; do
  v=$(get_i "$k"); [ -n "$v" ] && echo "  cikarildi [Interface] $k = $v" >&2
done
# DNS= : wg-quick set_dns() Table=off ile bile calisir, /etc/resolv.conf'u
#        host capinda ezer; host-network container'lar da onu miras alir. Ayrica bu makinede resolvconf KURULU DEGIL -> wg-quick
#        pipefail ile abort eder, EXIT trap wg0'i siler: tunel hic acilmaz.
# Table= : olmazsa wg-quick 0.0.0.0/1+128.0.0.0/1 + fwmark kurar ve TUM host
#        trafigini (SSH, apt, diger servisler) tunele sokar.

ADDR4=$(printf '%s' "$ADDR_RAW" | tr ',' '\n' | tr -d ' ' | grep -v ':' | head -1)
[ -n "$ADDR4" ] || { echo "IPv4 Address yok" >&2; exit 1; }
[ "$ADDR_RAW" != "$ADDR4" ] && echo "  cikarildi IPv6 Address yarisi (LAN'da global v6 yok)" >&2
NEWIP=${ADDR4%%/*}
[ -n "$MTU" ] || MTU=$(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*//Ip' "$LIVE" | head -1)
[ -n "$MTU" ] || MTU=1420
[ -n "$KA" ]  || KA=25
EPH=${EP%:*}; EPH=${EPH#[}; EPH=${EPH%]}

# --- AP subnet ile cakisma REDDI ---
py(){ python3 - "$1" "$2" <<'PY'
import ipaddress,sys
try: print(int(ipaddress.ip_address(sys.argv[1].split('/')[0]) in ipaddress.ip_network(sys.argv[2])))
except ValueError: print(0)
PY
}
[ "$(py "$NEWIP" "$AP_NET")" = 1 ] && { echo "RED: tunel adresi $NEWIP AP subneti $AP_NET icinde" >&2; exit 1; }
[ "$(py "$EPH"   "$AP_NET")" = 1 ] && { echo "RED: Endpoint $EPH AP subneti icinde" >&2; exit 1; }

TMP=$(mktemp --suffix=.conf /etc/wireguard/.wg-XXXXXX); chmod 0600 "$TMP"
trap 'rm -f "$TMP"' EXIT
{ echo "# $LIVE - ap-swap-peer.sh $(date -Is), kaynak: $SRC"
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

# --- GERCEK dogrulama: regex degil, scratch wireguard cihazi ---
/usr/sbin/ip link del wgcheck 2>/dev/null
/usr/sbin/ip link add wgcheck type wireguard || { echo "wgcheck olusturulamadi" >&2; exit 1; }
if ! /usr/bin/wg setconf wgcheck <(/usr/bin/wg-quick strip "$TMP"); then
  /usr/sbin/ip link del wgcheck; echo "RED: kernel sanitize edilmis config'i kabul etmedi" >&2; exit 1
fi
/usr/sbin/ip link del wgcheck

if [ "$APPLY" != "--apply" ]; then
  echo "--- KURU CALISMA: $LIVE su hale gelecekti ---"
  sed -E 's/(PrivateKey|PresharedKey)([[:space:]]*)=.*/\1\2= <gizlendi>/' "$TMP"
  echo "--- uygulamak icin: sudo $0 $SRC --apply ---"
  exit 0
fi

cp -a "$LIVE" "$BAK" && echo "yedek: $BAK"
install -o root -g root -m 0600 "$TMP" "$LIVE"

# wg0 systemd disinda ayaktaysa once sahiplen
if /usr/sbin/ip link show "$WG_IF" >/dev/null 2>&1 && ! systemctl is-active --quiet "wg-quick@${WG_IF}"; then
  echo "$WG_IF systemd disinda ayakta - sahipleniliyor"; /usr/sbin/ip link del "$WG_IF"
fi
systemctl restart "wg-quick@${WG_IF}.service"

# --- handshake bekle ---
OK=0
for i in $(seq 1 20); do
  sleep 2
  /usr/bin/wg show "$WG_IF" latest-handshakes | awk '$2!=0{f=1} END{exit !f}' && { OK=1; break; }
done
if [ "$OK" != 1 ]; then
  echo "YENI PEER HIC HANDSHAKE YAPMADI - $BAK'a geri donuluyor" >&2
  install -m 0600 "$BAK" "$LIVE"; systemctl restart "wg-quick@${WG_IF}.service"
  sleep 3; /opt/ap-vpn/bin/ap-firewall.sh
  exit 1
fi

# --- dnsmasq upstream'ini yeni tunel adresine tasi (K4'un DNS yarisi) ---
sed -i -E "s/^(server=[0-9.]+)@.*/\1@${NEWIP}/" "$DNSMASQ_CONF"
grep "^server=" "$DNSMASQ_CONF"
systemctl restart "$DNSMASQ_UNIT"

# --- firewall: WG_SRC + MSS otomatik yeniden turetilir ---
/opt/ap-vpn/bin/ap-firewall.sh || { echo "ap-firewall BASARISIZ" >&2; exit 1; }
command -v conntrack >/dev/null && conntrack -D -s "$AP_NET" >/dev/null 2>&1

# --- yeni cikis IP'sini olc (tunel kaynak adresinden) ---
NEWEXIT=$(curl -4 -s -m 15 --interface "$NEWIP" https://api.ipify.org || true)
echo "yeni cikis IP: ${NEWEXIT:-BELIRLENEMEDI}"

exec /opt/ap-vpn/bin/ap-verify.sh --slot=$SLOT
