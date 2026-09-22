#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-watchdog.sh
#  A tunnel can be "silently dead": wgN is up, the rules match, packets go nowhere.
#  The firewall CANNOT catch that - but there is NO LEAK either: the packet enters
#  wgN and disappears, it never reaches the ISP. This script performs RECOVERY,
#  not protection. All protection is structural (blackhole + AP-VPN-FWD).
#  Notes: threshold 300 s (false alarms below that), flap protection (cooldown),
#  route validation (a wg-quick restart wipes the default route in the table!).
# =============================================================================
set -u
. /etc/ap-vpn/ap.env
# AP_WATCHDOG_SLOT_LOOP: without --slot, call ourselves once per enabled slot
if ! printf "%s\n" "$@" | grep -q "^--slot="; then /opt/ap-vpn/bin/ap-pin.sh enforce >/dev/null 2>&1; rc=0; for f in /etc/ap-vpn/slots/*.env; do grep -q "^ENABLED=1" "$f" && { "$0" --slot=$(basename "$f" .env) || rc=1; }; done; exit $rc; fi
SLOT=ap0; for _a in "$@"; do case "$_a" in --slot=*) SLOT="${_a#--slot=}";; esac; done; [ -r "/etc/ap-vpn/slots/$SLOT.env" ] && . "/etc/ap-vpn/slots/$SLOT.env"; export SLOT
MODE=${MODE:-vpn}
IP=/usr/sbin/ip
WG=/usr/bin/wg
STATE=/run/ap-vpn/$SLOT
mkdir -p "$STATE"
LASTR="$STATE/last_restart"
[ -f "$LASTR" ] || echo 0 > "$LASTR"

# --- 0a. Did the last ap-firewall run finish? Its guard rule (priority 999) is only lifted after the
# self-check passes, so finding one means the rules were torn down and left fail-closed. Retry here,
# once a minute, so a transient cause (a radio that was still appearing, a tunnel mid-restart) heals
# itself instead of needing a human.
if $IP rule show | grep -q "^999:"; then
  logger -t ap-watchdog -p daemon.warning "$SLOT: the last firewall run did not finish (guard rule present) - retrying"
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1 \
    || logger -t ap-watchdog -p daemon.err "$SLOT: ap-firewall still refuses to apply - APs stay down (fail closed)"
fi

# --- 0b. direct slots have no tunnel: only the routing needs watching ---
if [ "$MODE" = direct ]; then
  LAN_GW=$($IP -o -4 route show default | awk '{print $3; exit}')
  $IP route show table "$TABLE" | grep -q "^default via ${LAN_GW:-x} dev ${LAN_IF}" \
    || { logger -t ap-watchdog -p daemon.warning "$SLOT (direct): the LAN default route in table $TABLE is missing or stale - re-applying the firewall"; /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1; }
  $IP route show table "$TABLE" | grep -q "^${AP_NET} dev ${AP_IF}" \
    || { logger -t ap-watchdog -p daemon.warning "$SLOT (direct): AP link route missing - re-applying the firewall"; /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1; }
  $IP rule show | grep -q "from ${AP_NET} blackhole" \
    || { logger -t ap-watchdog -p daemon.err "$SLOT (direct): blackhole rule missing - re-applying the firewall"; /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1; }
  # A direct slot must never have a tunnel running: that would contradict its pin.
  [ -d "/sys/class/net/$WG_IF" ] && { logger -t ap-watchdog -p daemon.err "$SLOT (direct): $WG_IF is up - stopping it"; systemctl stop "wg-quick@$WG_IF"; }
  exit 0
fi

# --- 1. Is the tunnel interface missing entirely? ---
if [ ! -d "/sys/class/net/$WG_IF" ]; then
  logger -t ap-watchdog "$WG_IF missing - starting wg-quick@$WG_IF"
  systemctl start "wg-quick@${WG_IF}.service"
  sleep 3
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1
  exit 0
fi

# --- 2. Kill-switch integrity (routing layer) ---
# A wg-quick restart deletes and recreates wgN; device-bound routes are removed by
# the kernel and, because of Table=off, they DO NOT come back. That silently produces
# "tunnel healthy but every client is in the blackhole".
if ! $IP route show table "$TABLE" | grep -q "^default dev $WG_IF"; then
  logger -t ap-watchdog -p daemon.warning "no $WG_IF default route in table $TABLE - re-applying the firewall"
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1
fi
if ! $IP rule show | grep -q "from ${AP_NET} blackhole"; then
  logger -t ap-watchdog -p daemon.err "KILL SWITCH BROKEN: no blackhole rule - re-applying the firewall"
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1
fi
# The AP's own link route lives in the same table. It disappears whenever the AP address is flushed and
# re-added, and without it dnsmasq's replies are routed into the tunnel: clients associate, get a lease and
# then resolve nothing. Not a leak, but it looks exactly like a broken network.
if ! $IP route show table "$TABLE" | grep -q "^${AP_NET} dev ${AP_IF}"; then
  logger -t ap-watchdog -p daemon.warning "AP link route for ${AP_NET} missing in table $TABLE - re-applying the firewall"
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1
fi

# --- 3. Handshake age ---
NOW=$(date +%s)
BEST=999999
while read -r _pk t; do
  [ -n "${t:-}" ] || continue
  [ "$t" = "0" ] && continue
  a=$((NOW-t)); [ "$a" -lt "$BEST" ] && BEST=$a
done < <($WG show "$WG_IF" latest-handshakes 2>/dev/null)

if [ "$BEST" -le "$HS_MAX_AGE" ]; then
  exit 0
fi

# --- 4. Stale: restart with cooldown ---
LAST=$(cat "$LASTR" 2>/dev/null || echo 0)
if [ $((NOW-LAST)) -lt "$RESTART_COOLDOWN" ]; then
  logger -t ap-watchdog -p daemon.warning "handshake stale (${BEST}s) but cooldown is active ($((RESTART_COOLDOWN-(NOW-LAST)))s left) - no restart"
  exit 0
fi
echo "$NOW" > "$LASTR"
logger -t ap-watchdog -p daemon.err "handshake ${BEST}s (> ${HS_MAX_AGE}s) - rebuilding wg-quick@${WG_IF}"
systemctl restart "wg-quick@${WG_IF}.service" \
  || logger -t ap-watchdog -p daemon.err "wg-quick restart FAILED - guests stay fail-closed"
sleep 3
# MANDATORY: the restart may have changed the default route in the table and WG_SRC.
/opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1 \
  || logger -t ap-watchdog -p daemon.err "ap-firewall.sh FAILED after the restart"
command -v conntrack >/dev/null && conntrack -D -s "$AP_NET" >/dev/null 2>&1
logger -t ap-watchdog "rebuild complete"
exit 0
