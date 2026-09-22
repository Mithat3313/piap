#!/bin/bash
# /opt/ap-vpn/bin/ap-verify.sh - turns every claim into a command whose output is the proof.
# READ-ONLY. Exits 0 when there is no FAIL.
set -u
. /etc/ap-vpn/ap.env
SLOT=ap0; for _a in "$@"; do case "$_a" in --slot=*) SLOT="${_a#--slot=}";; esac; done; [ -r "/etc/ap-vpn/slots/$SLOT.env" ] && . "/etc/ap-vpn/slots/$SLOT.env"; export SLOT
LAN_IP=$(/usr/sbin/ip -4 -o addr show dev "$LAN_IF" 2>/dev/null | awk "{print \$4}" | cut -d/ -f1 | head -1); LAN_IP=${LAN_IP:-127.0.0.1}
LAN_GW=${LAN_GW:-$(/usr/sbin/ip -o -4 route show default 2>/dev/null | awk '{print $3; exit}')}
MODE=${MODE:-vpn}                       # vpn = exit through this slot's tunnel, direct = exit through the LAN
[ "$MODE" = direct ] && EXIT_IF=$LAN_IF || EXIT_IF=$WG_IF
IP=/usr/sbin/ip; IPT=/usr/sbin/iptables; IP6T=/usr/sbin/ip6tables; WG=/usr/bin/wg
p=0; f=0
P(){ printf '  PASS  %s\n' "$1"; p=$((p+1)); }
F(){ printf '  FAIL  %s\n' "$1"; f=$((f+1)); }
H(){ printf '\n== %s ==\n' "$1"; }

H "1. HOST PATH UNTOUCHED (the hardest constraint)"
ip route get 1.1.1.1 2>&1 | grep -q "dev $LAN_IF" \
  && P "the Pi's own default route is still $LAN_IF" \
  || F "HOST HIJACKED: $(ip route get 1.1.1.1 2>&1) - the Pi's own services are affected"
ip -4 route show table main | grep -qw "$WG_IF" \
  && F "table main contains a $WG_IF route (Table=off did not hold)" \
  || P "no $WG_IF route in table main"
$WG show "$WG_IF" fwmark 2>/dev/null | grep -qv off \
  && F "wg-quick installed an fwmark" || P "no fwmark (Table=off is in effect)"
[ "$(/usr/sbin/sysctl -n net.ipv4.conf.all.src_valid_mark 2>/dev/null)" = 0 ] \
  && P "src_valid_mark is still 0" || F "src_valid_mark was changed"
grep -q "$LAN_GW" /etc/resolv.conf \
  && P "host resolv.conf still points at $LAN_GW" || F "host resolv.conf changed (a wg-quick DNS= may have overwritten it)"
# The Pi's own services: set HOST_CHECKS="http:8123 tcp:1883" in ap.env (empty = skip)
for hc in ${HOST_CHECKS:-}; do
  hp=${hc##*:}
  case "$hc" in
    http:*) curl -s -o /dev/null -m 8 "http://${LAN_IP}:${hp}/" && P "host http:$hp answers on the LAN address" || F "host http:$hp does not answer";;
    tcp:*)  /usr/bin/ss -lntH "sport = :$hp" | grep -q ":$hp" && P "host tcp:$hp is listening" || F "host tcp:$hp is not listening";;
  esac
done
if command -v docker >/dev/null 2>&1; then
  [ "$($IPT -t nat -S POSTROUTING | grep -c '172.17.0.0/16')" = 1 ] \
    && P "Docker masquerade intact" || F "unexpected number of Docker masquerade rules"
fi

H "2. GUEST PATH: ONE EXIT ONLY ($MODE -> $EXIT_IF)"
$IP rule show | grep -q "^${PRIO_APNET}:.*from ${AP_NET} lookup ${TABLE}" \
  && P "rule ${PRIO_APNET} ($AP_NET -> $TABLE)" || F "rule ${PRIO_APNET} MISSING"
$IP rule show | grep -q "from ${AP_NET} blackhole" \
  && P "blackhole rule present (an empty table does NOT fall through to main)" \
  || F "NO BLACKHOLE = LEAK. An empty table does not stop rule evaluation; the packet falls through to main and the ISP."
$IP route show table "$TABLE" | grep -q "^${AP_NET} dev ${AP_IF}" \
  && P "AP link route is in the table (dnsmasq replies do not enter the tunnel)" \
  || F "AP link route MISSING - clients cannot resolve names"
if [ "$MODE" = direct ] || $IP link show "$WG_IF" >/dev/null 2>&1; then
  ip route get 1.1.1.1 from "$AP_TEST_SRC" iif "$AP_IF" 2>&1 | grep -q "dev $EXIT_IF" \
    && P "a guest-sourced packet is routed to $EXIT_IF" \
    || F "a guest packet does NOT reach $EXIT_IF: $(ip route get 1.1.1.1 from $AP_TEST_SRC iif $AP_IF 2>&1)"
else
  echo "  INFO  $WG_IF is absent - guest traffic sits in the blackhole (the kill switch is working)"
fi
ip route get "$AP_TEST_SRC" from "$AP_GW" 2>&1 | grep -q "dev $AP_IF" \
  && P "AP->AP replies stay on $AP_IF" || F "AP->AP replies take the wrong path"
$IPT -C DOCKER-USER -j AP-VPN-FWD 2>/dev/null && P "DOCKER-USER -> AP-VPN-FWD hooked" || F "DOCKER-USER hook MISSING"
$IPT -C FORWARD -j DOCKER-USER 2>/dev/null || command -v docker >/dev/null 2>&1 \
  && P "the DOCKER-USER chain is reachable from FORWARD" \
  || F "DOCKER-USER is not reachable from FORWARD - every filter rule below it is dead"
$IP rule show | grep -q "^999:" \
  && F "a rewrite guard (priority 999) was left behind - the last ap-firewall run did not finish" \
  || P "no leftover rewrite guard"
$IPT -C AP-VPN-FWD -i "$AP_IF" -j DROP 2>/dev/null && P "kill-switch filter rule present" || F "kill-switch filter rule MISSING"
$IPT -t nat -C AP-VPN-POST -s "$AP_NET" -o "$EXIT_IF" -j MASQUERADE 2>/dev/null \
  && P "masquerade present ($EXIT_IF)" || F "masquerade MISSING - the far end drops packets from $AP_NET"
if [ "$MODE" = vpn ]; then
  $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$LAN_IF" -j ACCEPT 2>/dev/null \
    && F "VPN MODE WITH A LAN EXIT: $AP_IF may reach the internet without the tunnel" \
    || P "no LAN exit (a vpn slot cannot get out without its tunnel)"
  $IP route show table "$TABLE" | grep -q "^default.* dev $LAN_IF" \
    && F "VPN MODE WITH A LAN DEFAULT ROUTE in table $TABLE" || P "no LAN default route in table $TABLE"
else
  bad6=0
  for g in /etc/ap-vpn/slots/*.env; do
    W=$(sed -n 's/^WG_IF=//p' "$g" | head -1); [ -n "$W" ] || continue
    $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$W" -j ACCEPT 2>/dev/null && bad6=1
  done
  [ $bad6 = 0 ] && P "no tunnel exit (a direct slot is wired to the LAN only)" || F "DIRECT MODE WITH A TUNNEL EXIT"
  [ -d "/sys/class/net/$WG_IF" ] && F "DIRECT MODE BUT $WG_IF IS UP - the tunnel must be down" || P "$WG_IF is down (direct mode)"
fi
NAT_PKT=$($IPT -t nat -vxnL AP-VPN-POST | awk '/MASQUERADE/{print $1; exit}')
[ "${NAT_PKT:-0}" -gt 0 ] 2>/dev/null && P "masquerade counter at ${NAT_PKT} packets (it is really in use)" \
  || echo "  INFO  masquerade counter is 0 - generate some guest traffic and run again"

H "3. RP_FILTER (MUST NOT BE 1)"
bad=0
for k in all default "$AP_IF" "$WG_IF" "$LAN_IF"; do
  v=$(/usr/sbin/sysctl -n "net.ipv4.conf.$k.rp_filter" 2>/dev/null)
  printf '       %-8s = %s\n' "$k" "${v:-n/a}"
  [ "${v:-0}" = 1 ] && bad=1
done
[ $bad = 0 ] && P "rp_filter is not 1 anywhere" \
  || F "rp_filter=1 (STRICT): traffic returning from $WG_IF is dropped silently; the symptom is 'handshake fresh, nothing works'"

H "4. MSS / MTU"
if [ "$MODE" = direct ]; then
  echo "       direct mode: the LAN path needs no clamp"
  [ "$($IPT -t mangle -S AP-VPN-MSS | grep -c " $WG_IF ")" = 0 ] && P "no tunnel MSS clamp for this slot" || F "a tunnel MSS clamp exists in direct mode"
else
M=$(cat /sys/class/net/$WG_IF/mtu 2>/dev/null); EXP=$((${M:-1420}-40))
printf '       %s mtu=%s expected mss=%s\n' "$WG_IF" "${M:-n/a}" "$EXP"
[ "$($IPT -t mangle -S AP-VPN-MSS | grep -c "$WG_IF .*set-mss $EXP")" = 2 ] \
  && P "MSS is $EXP in both directions (derived from the live MTU)" \
  || F "MSS clamp wrong or missing: large HTTPS downloads stall silently"
fi

H "5. IPv6 DISABLED"
[ "$(/usr/sbin/sysctl -n net.ipv6.conf.$AP_IF.disable_ipv6 2>/dev/null)" = 1 ] \
  && P "IPv6 is disabled on $AP_IF" || F "IPv6 is ENABLED on $AP_IF - a path the v4 kill switch does not cover"
[ -z "$($IP -6 addr show dev $AP_IF 2>/dev/null | grep inet6)" ] \
  && P "no IPv6 address on $AP_IF" || F "$AP_IF has an IPv6 address"
$IP6T -C INPUT   -j AP-VPN-6 2>/dev/null && P "AP-VPN-6 hooked into ip6 INPUT"   || F "AP-VPN-6 is not hooked into ip6 INPUT"
$IP6T -C FORWARD -j AP-VPN-6 2>/dev/null && P "AP-VPN-6 hooked into ip6 FORWARD" || F "AP-VPN-6 is not hooked into ip6 FORWARD"
[ "$($IP6T -S AP-VPN-6 2>/dev/null | grep -c -- "-i $AP_IF -j DROP")" = 1 ] \
  && P "ip6 DROP rule for $AP_IF" || F "no ip6 DROP rule for $AP_IF"

H "6. GUEST ISOLATION (the Pi's services)"
$IPT -C AP-VPN-IN -i "$AP_IF" -j DROP 2>/dev/null \
  && P "AP-VPN-IN ends with DROP (SSH, web panel, MQTT, mDNS and so on are closed)" || F "INPUT DROP MISSING"
for pr in 67:udp 53:udp 53:tcp; do
  pt=${pr%%:*}; pp=${pr##*:}
  $IPT -C AP-VPN-IN -i "$AP_IF" -p "$pp" --dport "$pt" -j ACCEPT 2>/dev/null \
    && P "$pp/$pt ACCEPT present before the DROP" || F "$pp/$pt ACCEPT missing - clients get no lease or no DNS"
done
grep -qE '^\s*ap_isolate=1' /etc/hostapd/$SLOT.conf \
  && P "hostapd ap_isolate=1 (client-to-client blocked in the radio)" \
  || F "ap_isolate!=1 - guests can reach each other and the firewall cannot see it (L2, it never enters the IP stack)"
if [ -f /etc/avahi/avahi-daemon.conf ]; then
  grep -qE "^\s*deny-interfaces=.*\b${AP_IF}\b" /etc/avahi/avahi-daemon.conf \
    && P "avahi does not announce on $AP_IF" || F "avahi is active on $AP_IF - it would hand guests the whole LAN inventory"
fi

H "7. NFTABLES SERVICE (MUST STAY DISABLED)"
[ "$(systemctl is-enabled nftables 2>/dev/null)" = disabled ] \
  && P "nftables.service disabled" \
  || F "nftables.service enabled: /etc/nftables.conf starts with 'flush ruleset' and wipes ALL of Docker's tables and the kill switch"

H "8. EXIT HEALTH"
if [ "$MODE" = direct ]; then
  ip route get 1.1.1.1 from "$AP_TEST_SRC" iif "$AP_IF" 2>&1 | grep -q "dev $LAN_IF" \
    && P "direct slot exits through $LAN_IF" || F "direct slot does not reach $LAN_IF"
elif $WG show "$WG_IF" >/dev/null 2>&1; then
  now=$(date +%s); best=999999
  while read -r _k t; do [ -n "${t:-}" ] || continue; [ "$t" = 0 ] && continue
    a=$((now-t)); [ $a -lt $best ] && best=$a; done < <($WG show "$WG_IF" latest-handshakes)
  [ $best -lt 999999 ] && [ $best -le "$HS_MAX_AGE" ] \
    && P "handshake ${best}s ago (<= ${HS_MAX_AGE}s)" \
    || F "handshake ${best}s - STALE (or it never happened)"
  $WG show "$WG_IF" transfer | sed 's/^/       /'
else
  echo "  INFO  $WG_IF is absent"
fi

H "9. PERSISTENCE"
bad=0
UNITS="ap-wlan@$SLOT ap-firewall $HOSTAPD_UNIT $DNSMASQ_UNIT ap-watchdog.timer ap-bootcheck.timer"
[ "$MODE" = vpn ] && UNITS="$UNITS wg-quick@$WG_IF"
for u in $UNITS; do
  e=$(systemctl is-enabled "$u" 2>&1); a=$(systemctl is-active "$u" 2>&1)
  printf '       %-22s enabled=%-10s active=%s\n' "$u" "$e" "$a"
  case "$e" in enabled|enabled-runtime|static) :;; *) bad=1;; esac
  case "$u" in *timer) :;; *) [ "$a" = active ] || bad=1;; esac
done
[ $bad = 0 ] && P "every unit is enabled and running" || F "at least one unit is not enabled/active - it will not come back after a reboot"
systemctl --failed --no-legend | sed 's/^/       /'

H "10. ASSIGNMENT PINNING (SSID <-> mode <-> profile <-> server key <-> radio)"
if grep -q '^PIN_MODE=.\+' "/etc/ap-vpn/slots/$SLOT.env"; then
  grep -q "^PIN_MODE=$MODE\$" "/etc/ap-vpn/slots/$SLOT.env" && P "the exit mode is pinned ($MODE)" || F "MODE=$MODE but the pin says otherwise"
else
  echo "  INFO  the exit mode is not pinned yet (slot created before exit modes existed): ap-ctl --slot $SLOT slot pin --confirm '<SSID>'"
fi
grep -q 'ap-ifsync.sh sync' /etc/systemd/system/ap-ifsync@.service 2>/dev/null && P "the radio is resolved by MAC before the slot comes up" || F "ap-ifsync@ unit missing"
msg=$(/opt/ap-vpn/bin/ap-pin.sh check "$SLOT") && P "the pin holds: $msg" || F "PIN VIOLATION: $msg"
if [ "$MODE" = vpn ]; then
  grep -q '^PIN_PROFILE=.\+' "/etc/ap-vpn/slots/$SLOT.env" && P "a profile is pinned (PIN_PROFILE)" \
    || echo "  INFO  no profile pinned yet - the SSID is up but nothing gets out (kill switch)"
fi
grep -q '^AP_MAC=.\+' "/etc/ap-vpn/slots/$SLOT.env" && P "radio MAC pinned (AP_MAC)" || F "AP_MAC missing"
grep -q 'ap-pin.sh check' /etc/systemd/system/ap-hostapd@.service && P "pin check runs when hostapd starts (ExecStartPre)" || F "ap-hostapd@ has NO pin check"
grep -q 'ap-pin.sh enforce' /opt/ap-vpn/bin/ap-watchdog.sh && P "the watchdog enforces the pin every cycle" || F "watchdog enforce MISSING"
[ -f "/run/ap-vpn/$SLOT/pin-violation" ] && F "a violation flag is still present: $(cat /run/ap-vpn/$SLOT/pin-violation)" || P "no violation flag"

printf '\n---- %d PASS, %d FAIL ----\n' "$p" "$f"
[ "$f" -eq 0 ]
