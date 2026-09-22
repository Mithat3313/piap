#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-uninstall.sh — TAM GERI ALMA (coklu slot)
#  Kullanim:  sudo ap-uninstall.sh            servisleri kapatir, kancalari soker, dosyalari birakir
#             sudo ap-uninstall.sh --purge    config/anahtarlari zaman damgali yedege TASIR (silmez)
#  LAN arayuzune, SSH'a, Docker'in kendi kurallarina ve Pi'nin diger servislerine DOKUNMAZ.
#  Iki kez calistirilabilir.
# =============================================================================
set -u
. /etc/ap-vpn/ap.env 2>/dev/null || true
PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1
IPT=/usr/sbin/iptables; IP6T=/usr/sbin/ip6tables; IP=/usr/sbin/ip
SLOTS=$(ls /etc/ap-vpn/slots/*.env 2>/dev/null || true)

echo "== 1. servisler (once radyolar: acik+korumasiz AP birakmamak icin) =="
for f in $SLOTS; do
  s=$(basename "$f" .env); unset AP_IF WG_IF; . "$f"
  systemctl disable --now "ap-hostapd@$s" "ap-dnsmasq@$s" 2>/dev/null
  systemctl disable --now "wg-quick@$WG_IF" 2>/dev/null
  systemctl disable --now "ap-wlan@$s" 2>/dev/null
done
systemctl disable --now ap-web ap-ble-agent ap-watchdog.timer ap-bootcheck.timer ap-firewall 2>/dev/null

echo "== 2. firewall kancalari (Docker'in kendi zincirlerine dokunulmuyor) =="
$IPT  -D INPUT       -j AP-VPN-IN  2>/dev/null
$IPT  -D DOCKER-USER -j AP-VPN-FWD 2>/dev/null
$IPT  -D FORWARD     -j AP-VPN-FWD 2>/dev/null
$IPT  -t nat -D PREROUTING  -j AP-VPN-PRE  2>/dev/null
$IPT  -t nat -D POSTROUTING -j AP-VPN-POST 2>/dev/null
$IPT  -t mangle -D FORWARD  -j AP-VPN-MSS  2>/dev/null
$IP6T -D INPUT   -j AP-VPN-6 2>/dev/null
$IP6T -D FORWARD -j AP-VPN-6 2>/dev/null
for C in AP-VPN-FWD AP-VPN-IN;   do $IPT -F $C 2>/dev/null; $IPT -X $C 2>/dev/null; done
for C in AP-VPN-POST AP-VPN-PRE; do $IPT -t nat -F $C 2>/dev/null; $IPT -t nat -X $C 2>/dev/null; done
$IPT -t mangle -F AP-VPN-MSS 2>/dev/null; $IPT -t mangle -X AP-VPN-MSS 2>/dev/null
$IP6T -F AP-VPN-6 2>/dev/null; $IP6T -X AP-VPN-6 2>/dev/null

echo "== 3. policy routing =="
for f in $SLOTS; do
  unset AP_IF AP_NET WG_IF TABLE; . "$f"
  while $IP rule del from "$AP_NET" lookup "$TABLE" 2>/dev/null; do :; done
  while $IP rule del from "$AP_NET" blackhole      2>/dev/null; do :; done
  for A in $($IP -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
    while $IP rule del from "$A" lookup "$TABLE" 2>/dev/null; do :; done
    while $IP rule del from "$A" blackhole      2>/dev/null; do :; done
  done
  $IP route flush table "$TABLE" 2>/dev/null
  $IP addr flush dev "$AP_IF" 2>/dev/null; $IP link set "$AP_IF" down 2>/dev/null
done
# 1000-1999 araligi bu projeye ayrilmisti; artik kalmasin
$IP rule show | awk -F: '$1>=1000 && $1<2000 {print $1}' | while read -r p; do $IP rule del pref "$p" 2>/dev/null; done

echo "== 4. NetworkManager / avahi / Docker drop-in =="
rm -f /etc/NetworkManager/conf.d/99-ap-unmanaged.conf
systemctl reload NetworkManager 2>/dev/null
if [ -f /opt/ap-vpn/backup/avahi-daemon.conf.orig ]; then
  install -m 0644 /opt/ap-vpn/backup/avahi-daemon.conf.orig /etc/avahi/avahi-daemon.conf && systemctl restart avahi-daemon 2>/dev/null
fi
rm -f /etc/systemd/system/docker.service.d/10-ap-firewall.conf; rmdir /etc/systemd/system/docker.service.d 2>/dev/null

if [ "$PURGE" = 1 ]; then
  echo "== 5. purge: config + anahtarlar yedege tasiniyor (SILINMIYOR) =="
  B=/opt/ap-vpn/backup/uninstall-$(date +%Y%m%d-%H%M%S); install -d -m 0700 "$B"
  for f in $SLOTS; do unset WG_IF; . "$f"; mv "/etc/wireguard/$WG_IF.conf" "$B/" 2>/dev/null; done
  mv /etc/ap-vpn "$B/ap-vpn" 2>/dev/null
  mv /etc/hostapd/ap*.conf "$B/" 2>/dev/null
  rm -f /etc/systemd/system/ap-*.service /etc/systemd/system/ap-*.timer /usr/local/sbin/ap-ctl
  echo "   tasindi: $B  (PrivateKey/PSK/token/parola iceriyor — 0700)"
fi
systemctl daemon-reload; systemctl reset-failed 2>/dev/null

echo
echo "== DOGRULAMA =="
echo "-- ip rule --";           $IP rule show
echo "-- DOCKER-USER --";       $IPT -S DOCKER-USER 2>/dev/null || echo "(Docker yok)"
echo "-- nat POSTROUTING --";   $IPT -t nat -S POSTROUTING
echo "-- adresler --";          $IP -br addr
echo "Beklenen: ip rule = 0/32766/32767; AP-VPN-* zincirleri yok; AP arayuzleri adressiz/DOWN; LAN arayuzu ve SSH etkilenmedi."
