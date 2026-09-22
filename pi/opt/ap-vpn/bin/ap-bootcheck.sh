#!/bin/bash
# =============================================================================
#  ap-bootcheck.sh — post-boot last resort (portable)
#  Purpose: catch the case where OUR configuration (NM unmanaged, firewall) breaks the
#  LAN interface and leaves the Pi unreachable.
#
#  Pinging a fixed gateway is not portable (false alarms on another network or behind a
#  router that blocks ICMP). The signals used instead:
#    HEALTHY = the LAN interface HAS an IPv4 address (DHCP worked -> NM manages it)
#           or any tunnel had a handshake < 5 min ago (the LAN is definitely working)
#  Since the AP never touches the LAN interface, "LAN has an address but no internet"
#  cannot be our fault -> we do NOT intervene.
# =============================================================================
set -u
. /etc/ap-vpn/ap.env
IPT=/usr/sbin/iptables; IP6T=/usr/sbin/ip6tables; IP=/usr/sbin/ip
lan_has_ip(){ $IP -4 -o addr show dev "$LAN_IF" 2>/dev/null | grep -q 'inet '; }
wg_fresh(){
  local f wg hs now; now=$(date +%s)
  for f in /etc/ap-vpn/slots/*.env; do
    wg=$(sed -n 's/^WG_IF=//p' "$f" | head -1); [ -n "$wg" ] || continue
    hs=$(/usr/bin/wg show "$wg" latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    [ -n "${hs:-}" ] && [ "$hs" != 0 ] && [ $((now - hs)) -lt 300 ] && return 0
  done
  return 1
}
healthy(){ lan_has_ip || wg_fresh; }

for i in $(seq 1 120); do            # 10 minutes of patience (slow ISP modems)
  healthy && { logger -t ap-bootcheck "LAN healthy ($LAN_IF has an address) - standing down"; exit 0; }
  sleep 5
done

logger -t ap-bootcheck -p daemon.err "$LAN_IF got no address for 10 minutes - detaching the AP hooks (stage 1)"
$IPT  -D INPUT       -j AP-VPN-IN  2>/dev/null || true
$IPT  -D DOCKER-USER -j AP-VPN-FWD 2>/dev/null || true
$IPT  -D FORWARD     -j AP-VPN-FWD 2>/dev/null || true
$IPT  -t nat -D PREROUTING  -j AP-VPN-PRE  2>/dev/null || true
$IPT  -t nat -D POSTROUTING -j AP-VPN-POST 2>/dev/null || true
$IPT  -t mangle -D FORWARD  -j AP-VPN-MSS  2>/dev/null || true
$IP6T -D INPUT   -j AP-VPN-6 2>/dev/null || true
$IP6T -D FORWARD -j AP-VPN-6 2>/dev/null || true
rm -f /etc/NetworkManager/conf.d/99-ap-unmanaged.conf
systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager 2>/dev/null
sleep 5
lan_has_ip || nmcli -w 20 con up "Wired connection 1" >/dev/null 2>&1
sleep 15
healthy && { logger -t ap-bootcheck "STAGE 1 worked - $LAN_IF got an address"; exit 0; }

logger -t ap-bootcheck -p daemon.err "$LAN_IF still has no address - disabling the guest APs persistently and rebooting (stage 2)"
: > /etc/ap-vpn/DISABLED
for f in /etc/ap-vpn/slots/*.env; do s=$(basename "$f" .env); systemctl disable "ap-hostapd@$s" "ap-dnsmasq@$s" "ap-wlan@$s" 2>/dev/null; done
systemctl disable ap-firewall ap-watchdog.timer 2>/dev/null
systemctl reboot
