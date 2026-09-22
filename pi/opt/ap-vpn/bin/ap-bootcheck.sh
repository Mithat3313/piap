#!/bin/bash
# =============================================================================
#  ap-bootcheck.sh (v2, tasinabilir)
#  Boot sonrasi son care. Amac: BIZIM ayarimizin (NM unmanaged, firewall) eth0'i
#  bozup Pi'yi erisilmez birakmasini yakalamak.
#
#  Sabit bir gateway'e ping atmak tasinabilir degil (baska agda veya ICMP
#  engelleyen router'da yanlis alarm). Kullanilan sinyaller:
#    SAGLIKLI = eth0'da IPv4 adresi VAR  (DHCP calisti -> NM eth0'i yonetiyor)
#            veya wg0 handshake < 5 dk (LAN kesin calisiyor)
#  AP eth0'a hic dokunmadigi icin "eth0'da IP var ama internet yok" BIZIM
#  hatamiz olamaz -> mudahale ETMEYIZ.
# =============================================================================
set -u
. /etc/ap-vpn/ap.env
IPT=/usr/sbin/iptables; IP6T=/usr/sbin/ip6tables; IP=/usr/sbin/ip
eth_has_ip(){ $IP -4 -o addr show dev "$LAN_IF" 2>/dev/null | grep -q 'inet '; }
wg_fresh(){
  local hs; hs=$(/usr/bin/wg show "$WG_IF" latest-handshakes 2>/dev/null | awk '{print $2; exit}')
  [ -n "${hs:-}" ] && [ "$hs" != 0 ] && [ $(( $(date +%s) - hs )) -lt 300 ]
}
healthy(){ eth_has_ip || wg_fresh; }

for i in $(seq 1 120); do            # 10 dk sabir (yavas ISP modemi)
  healthy && { logger -t ap-bootcheck "LAN saglikli ($LAN_IF adres var) - geri cekiliyorum"; exit 0; }
  sleep 5
done

logger -t ap-bootcheck -p daemon.err "$LAN_IF 10 dk boyunca adres alamadi - AP kancalari sokuluyor (asama 1)"
$IPT  -D INPUT       -j AP-VPN-IN  2>/dev/null || true
$IPT  -D DOCKER-USER -j AP-VPN-FWD 2>/dev/null || true
$IPT  -t nat -D PREROUTING  -j AP-VPN-PRE  2>/dev/null || true
$IPT  -t nat -D POSTROUTING -j AP-VPN-POST 2>/dev/null || true
$IPT  -t mangle -D FORWARD  -j AP-VPN-MSS  2>/dev/null || true
$IP6T -D INPUT   -j AP-VPN-6 2>/dev/null || true
$IP6T -D FORWARD -j AP-VPN-6 2>/dev/null || true
rm -f /etc/NetworkManager/conf.d/99-ap-unmanaged.conf
systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager 2>/dev/null
sleep 5
eth_has_ip || nmcli -w 20 con up "Wired connection 1" >/dev/null 2>&1
sleep 15
healthy && { logger -t ap-bootcheck "ASAMA 1 ise yaradi - $LAN_IF adres aldi"; exit 0; }

logger -t ap-bootcheck -p daemon.err "$LAN_IF hala adressiz - misafir AP kaliciya kapatiliyor ve yeniden baslatiliyor (asama 2)"
: > /etc/ap-vpn/DISABLED
for f in /etc/ap-vpn/slots/*.env; do s=$(basename "$f" .env); systemctl disable "hostapd@$s" "ap-dnsmasq@$s" "ap-wlan@$s" 2>/dev/null; done; systemctl disable ap-firewall ap-watchdog.timer 2>/dev/null
systemctl reboot
