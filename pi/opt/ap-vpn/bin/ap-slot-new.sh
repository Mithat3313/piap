#!/bin/bash
# =============================================================================
#  ap-slot-new.sh — creates a new SSID slot (radio + subnet + exit)
#    sudo ap-slot-new.sh <slot> <interface|MAC> <5|2.4> [--ssid NAME] [--psk PASSWORD] [--channel N]
#                        [--country XX] [--net 10.99.0] [--desc "description"] [--mode vpn|direct]
#    e.g.  sudo ap-slot-new.sh ap0 wlan0 5          (built-in radio, 5 GHz channel 36)
#          sudo ap-slot-new.sh ap1 wlan1 2.4        (USB adapter, 2.4 GHz channel 1)
#  The slot is bound to the RADIO (its MAC is written as AP_MAC), not to the interface name: plugging
#  the adapter into another port keeps this slot, and a DIFFERENT adapter never inherits it - it gets
#  its own slot, which is the point: another device means another network and another exit.
#  --mode vpn (default): no internet until a VPN profile is assigned (kill switch).
#  --mode direct       : the SSID works immediately with NO VPN, exiting through the LAN.
#  Slot names are apN; N derives the table, rule priorities, tunnel name and subnet:
#    wgN, table 51820+N, rule priorities 1000+10N.., subnet 10.(99-N).0.0/24
#  Produces: /etc/ap-vpn/slots/<slot>.env, <slot>.dnsmasq.conf, /etc/hostapd/<slot>.conf,
#  NetworkManager unmanaged list, avahi deny-interfaces, systemd units (enable+start).
#  The SSID comes up immediately but has NO TUNNEL until a profile is assigned: the kill
#  switch holds and clients cannot reach the internet. Assign one with:
#    ap-ctl vpn add <name> <conf>; ap-ctl --slot <slot> vpn activate <name> --confirm <SSID>
# =============================================================================
set -euo pipefail
T=/opt/ap-vpn/templates; S=/etc/ap-vpn/slots
die(){ echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "root required"
SLOT=${1:-}; DEV=${2:-}; BAND=${3:-}; shift 3 2>/dev/null || die "usage: ap-slot-new.sh <slot> <interface|MAC> <5|2.4> [options]"
[[ "$SLOT" =~ ^ap([0-9]+)$ ]] || die "the slot name must be apN (ap0, ap1 ...)"
IDX=${BASH_REMATCH[1]}
[ -f "$S/$SLOT.env" ] && die "slot already exists: $S/$SLOT.env"
# The device may be given as an interface name or as a MAC; the MAC is what gets stored.
if [[ "$DEV" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
  AP_MAC=$(echo "$DEV" | tr 'A-F' 'a-f'); AP_IF=""
  for i in /sys/class/net/*; do i=$(basename "$i"); [ -d "/sys/class/net/$i/phy80211" ] || continue
    [ "$(cat "/sys/class/net/$i/address" 2>/dev/null)" = "$AP_MAC" ] && { AP_IF=$i; break; }; done
  [ -n "$AP_IF" ] || die "no wireless radio with MAC $AP_MAC is present"
else
  AP_IF=$DEV
  [ -d "/sys/class/net/$AP_IF" ] || die "no such interface: $AP_IF"
  [ -d "/sys/class/net/$AP_IF/phy80211" ] || die "$AP_IF is not a wireless interface"
  AP_MAC=$(cat "/sys/class/net/$AP_IF/address")
fi
# One radio, one slot: another adapter gets its own slot (its own subnet, SSID and exit).
for f in "$S"/*.env; do [ -r "$f" ] || continue
  [ "$(sed -n 's/^AP_MAC=//p' "$f" | head -1)" = "$AP_MAC" ] && die "that radio ($AP_MAC) already belongs to slot $(basename "$f" .env)"
done
/usr/sbin/iw dev "$AP_IF" info >/dev/null 2>&1 || die "$AP_IF is not usable"

. /etc/ap-vpn/ap.env
[ "$AP_IF" != "$LAN_IF" ] || die "the AP interface cannot be the LAN interface"
SSID=""; PSK=""; CHANNEL=""; COUNTRY=""; NET=""; DESC=""; MODE=vpn
while [ $# -gt 0 ]; do case "$1" in
  --ssid) SSID=$2; shift 2;; --psk) PSK=$2; shift 2;; --channel) CHANNEL=$2; shift 2;;
  --country) COUNTRY=$2; shift 2;; --net) NET=$2; shift 2;; --desc) DESC=$2; shift 2;;
  --mode) MODE=$2; shift 2;;
  *) die "unknown option: $1";; esac; done
case "$MODE" in vpn|direct) :;; *) die "--mode must be vpn or direct";; esac
case "$BAND" in
  5)   TPL=hostapd-5ghz.conf;  CHANNEL=${CHANNEL:-36};;
  2.4) TPL=hostapd-24ghz.conf; CHANNEL=${CHANNEL:-1};;
  *) die "band must be 5 or 2.4";;
esac
case "$CHANNEL" in 36|40|44|48) SEG0=42;; 52|56|60|64) SEG0=58;; 100|104|108|112) SEG0=106;;
  116|120|124|128) SEG0=122;; 132|136|140|144) SEG0=138;; 149|153|157|161) SEG0=155;; *) SEG0=0;; esac
[ "$BAND" = 5 ] && [ "$SEG0" = 0 ] && die "supported 5 GHz channels: 36-64, 100-144, 149-161"
COUNTRY=${COUNTRY:-$(/usr/sbin/iw reg get 2>/dev/null | sed -n 's/^country \([A-Z][A-Z]\):.*/\1/p' | head -1)}
[ -n "$COUNTRY" ] && [ "$COUNTRY" != 00 ] || die "could not determine the country code; pass --country XX (e.g. --country DE)"
NET=${NET:-10.$((99-IDX)).0}
[[ "$NET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--net must be the first three octets, e.g. 10.99.0"
LAN_PFX=$(/usr/sbin/ip -4 -o addr show dev "$LAN_IF" | awk '{print $4}' | cut -d. -f1-3 | head -1)
[ "$NET" != "$LAN_PFX" ] || die "the subnet collides with the LAN ($NET)"
SSID=${SSID:-PiAP-$SLOT\_nomap}
PSK=${PSK:-$(python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(20)))')}
[ ${#PSK} -ge 8 ] && [ ${#PSK} -le 63 ] || die "the password must be 8-63 characters"
DESC=${DESC:-$AP_IF, $BAND GHz channel $CHANNEL}
TABLE=$((51820+IDX)); P0=$((1000+10*IDX)); P1=$((P0+1)); P2=$((P0+2))

echo "== $SLOT: $AP_IF ($AP_MAC), $BAND GHz channel $CHANNEL, SSID '$SSID', subnet $NET.0/24, mode $MODE =="
install -d -m 0755 "$S"
sed -e "s|__SLOT__|$SLOT|g; s|__DESC__|$DESC|g; s|__AP_IF__|$AP_IF|g; s|__AP_MAC__|$AP_MAC|g; s|__NET__|$NET|g; s|__IDX__|$IDX|g" \
    -e "s|__TABLE__|$TABLE|g; s|__PRIO0__|$P0|g; s|__PRIO1__|$P1|g; s|__PRIO2__|$P2|g; s|__MODE__|$MODE|g" "$T/slot.env" > "$S/$SLOT.env"
# vpn: the 127.0.0.1 placeholder is fail-closed - no upstream query can leave until a profile is
# assigned and activation writes the tunnel address. direct: no binding, the query goes out via the LAN.
if [ "$MODE" = direct ]; then
  sed -e "s|__SLOT__|$SLOT|g; s|__AP_IF__|$AP_IF|g; s|__NET__|$NET|g" -e "s|@__WG_SRC__||g" "$T/slot.dnsmasq.conf" > "$S/$SLOT.dnsmasq.conf"
else
  sed -e "s|__SLOT__|$SLOT|g; s|__AP_IF__|$AP_IF|g; s|__NET__|$NET|g; s|__WG_SRC__|127.0.0.1|g" "$T/slot.dnsmasq.conf" > "$S/$SLOT.dnsmasq.conf"
fi
umask 077
sed -e "s|__AP_IF__|$AP_IF|g; s|__SSID__|$SSID|g; s|__PSK__|$PSK|g; s|__CHANNEL__|$CHANNEL|g; s|__COUNTRY__|$COUNTRY|g; s|__VHT_SEG0__|$SEG0|g" \
    "$T/$TPL" > "/etc/hostapd/$SLOT.conf"
umask 022
echo "   written: $S/$SLOT.env, $S/$SLOT.dnsmasq.conf, /etc/hostapd/$SLOT.conf"

# NetworkManager: release the radio
NMC=/etc/NetworkManager/conf.d/99-ap-unmanaged.conf
if [ -d /etc/NetworkManager ]; then
  [ -f "$NMC" ] || sed "s|__LIST__||" "$T/99-ap-unmanaged.conf" > "$NMC"
  if ! grep -q "interface-name:$AP_IF;" "$NMC" && ! grep -q "interface-name:$AP_IF\$" "$NMC"; then
    sed -i "s|^unmanaged-devices=.*|&;interface-name:$AP_IF;interface-name:p2p-dev-$AP_IF|; s|=;|=|" "$NMC"
  fi
  grep -q "interface-name:$LAN_IF\b" "$NMC" && die "SAFETY: the LAN interface is listed in $NMC!"
  nmcli device set "$AP_IF" managed no 2>/dev/null || true
  systemctl reload NetworkManager 2>/dev/null || true
  echo "   NetworkManager: $AP_IF unmanaged"
fi
# avahi: no mDNS announcements on this interface
AV=/etc/avahi/avahi-daemon.conf
if [ -f "$AV" ]; then
  install -d -m 0700 /opt/ap-vpn/backup; [ -f /opt/ap-vpn/backup/avahi-daemon.conf.orig ] || cp -a "$AV" /opt/ap-vpn/backup/avahi-daemon.conf.orig
  cur=$(sed -n 's/^deny-interfaces=//p' "$AV" | head -1)
  new=$(printf '%s\n' ${cur//,/ } "$AP_IF" | sort -u | grep -v '^$' | paste -sd, -)
  if grep -q '^deny-interfaces=' "$AV"; then sed -i "s|^deny-interfaces=.*|deny-interfaces=$new|" "$AV"; else sed -i "s|^\[server\]|[server]\ndeny-interfaces=$new|" "$AV"; fi
  systemctl restart avahi-daemon 2>/dev/null || true
  echo "   avahi: deny-interfaces=$new"
fi
# the firewall must come up after this slot's tunnel
install -d /etc/systemd/system/ap-firewall.service.d
printf '[Unit]\nAfter=wg-quick@wg%s.service\n' "$IDX" > "/etc/systemd/system/ap-firewall.service.d/$SLOT.conf"
systemctl daemon-reload

echo "== services =="
systemctl enable --now "ap-ifsync@$SLOT.service" >/dev/null 2>&1 || true
systemctl enable --now "ap-wlan@$SLOT.service" >/dev/null 2>&1; echo "   ap-wlan@$SLOT: $(systemctl is-active ap-wlan@$SLOT)"
/opt/ap-vpn/bin/ap-firewall.sh >/dev/null && systemctl restart ap-firewall.service; echo "   ap-firewall: $(systemctl is-active ap-firewall)"
[ "$MODE" = vpn ] && systemctl enable "wg-quick@wg$IDX.service" >/dev/null 2>&1 || true
systemctl enable --now "ap-dnsmasq@$SLOT.service" >/dev/null 2>&1; sleep 1; echo "   ap-dnsmasq@$SLOT: $(systemctl is-active ap-dnsmasq@$SLOT)"
systemctl enable --now "ap-hostapd@$SLOT.service" >/dev/null 2>&1; sleep 3; echo "   ap-hostapd@$SLOT: $(systemctl is-active ap-hostapd@$SLOT)"
/usr/sbin/iw dev "$AP_IF" info 2>/dev/null | grep -E 'ssid|channel' | sed 's/^\s*/   /'
echo
echo "SSID:     $SSID"
echo "PASSWORD: $PSK"
echo "RADIO:    $AP_IF  $AP_MAC  (this slot follows this device, whatever the kernel names it)"
if [ "$MODE" = direct ]; then
  echo "MODE:     direct - no VPN. Clients reach the internet through the LAN, but never the LAN itself."
  echo "To put it behind a VPN later:"
  echo "       ap-ctl --slot $SLOT slot mode vpn --confirm '$SSID'"
  echo "       ap-ctl --slot $SLOT vpn activate <name> --confirm '$SSID'"
else
  echo "MODE:     vpn - NO internet until a profile is assigned (kill switch holds)."
  echo "Next:  ap-ctl vpn add <name> /path/client.conf"
  echo "       ap-ctl --slot $SLOT vpn activate <name> --confirm '$SSID'"
fi
