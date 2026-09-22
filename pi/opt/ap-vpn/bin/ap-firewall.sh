#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-firewall.sh   (multi-slot, two exit modes)
#  Each slot = {AP_IF, AP_NET, WG_IF, TABLE, PRIO_*, MODE}. Slot files:
#      /etc/ap-vpn/slots/<slot>.env   (only ENABLED=1 slots are processed)
#
#  MODE=vpn    (default) clients exit ONLY through this slot's tunnel.
#              wlanX -> wgX ACCEPT, wlanX -> (anything else) DROP. The slot's routing table holds
#              exactly one default route, dev wgX; a LAN default is NEVER written into it. With no
#              tunnel the table is empty and the blackhole rule catches the packets: no exit at all.
#  MODE=direct clients exit through the LAN like any other device on it, with NO tunnel.
#              This is a deliberate, confirmed setting (it is part of the slot's pin), never a
#              fallback: a slot in vpn mode can not end up here by accident.
#  Both modes:  guests never reach RFC1918 destinations (the home LAN, Docker, the other slots),
#              they only reach the Pi for DHCP/DNS, IPv6 is off, and every slot keeps its own
#              routing table plus a blackhole rule.
#
#  The chains are shared, the rules are per slot. Idempotent: chains are flushed and rewritten.
#  A per-slot self-check runs at the end; if anything is missing, exit 1 -> ap-hostapd@* will not start.
# =============================================================================
set -u
# Paths are overridable so the whole rule set can be dry-run with mocked tools (tests/firewall-dryrun.sh).
: "${AP_ENV:=/etc/ap-vpn/ap.env}"
. "$AP_ENV"
: "${IPT:=/usr/sbin/iptables}"; : "${IP6T:=/usr/sbin/ip6tables}"; : "${IP:=/usr/sbin/ip}"; : "${SYSCTL:=/usr/sbin/sysctl}"
: "${SLOTS_DIR:=/etc/ap-vpn/slots}"; : "${WG_DIR:=/etc/wireguard}"; : "${SYSFS_NET:=/sys/class/net}"

die(){ logger -t ap-firewall -p daemon.err "ERROR: $*"; echo "ap-firewall: ERROR: $*" >&2; exit 1; }

# The interface currently carrying this MAC. AP_IF in the slot env is only a cache that ap-ifsync
# refreshes; trusting it would let a stale name (two slots briefly claiming the same interface after
# a re-plug) put one slot's clients onto another slot's exit. The MAC is the identity, so resolve it here.
resolve_ap_if(){
  local want=$1 i
  [ -n "$want" ] || return 1
  for i in "$SYSFS_NET"/*; do
    i=$(basename "$i"); [ -d "$SYSFS_NET/$i/phy80211" ] || continue
    [ "$(cat "$SYSFS_NET/$i/address" 2>/dev/null)" = "$want" ] && { echo "$i"; return 0; }
  done
  return 1
}
mkchain(){ $IPT -t "$1" -N "$2" 2>/dev/null || $IPT -t "$1" -F "$2"; }
hook(){    $IPT -t "$1" -C "$2" -j "$3" 2>/dev/null || $IPT -t "$1" -I "$2" 1 -j "$3"; }

# ------------------------------------------------------------- 0. global pre-flight
DEF_IF=$($IP -o -4 route show default | awk '{print $5; exit}')
[ -n "$DEF_IF" ] || die "no default route - refusing to touch anything"
LAN_GW=$($IP -o -4 route show default | awk '{print $3; exit}')
if systemctl is-enabled --quiet nftables.service 2>/dev/null; then
  die "nftables.service is ENABLED - /etc/nftables.conf runs flush ruleset and wipes Docker's tables and the kill switch"
fi
SLOT_FILES=$(ls "$SLOTS_DIR"/*.env 2>/dev/null) || true
[ -n "$SLOT_FILES" ] || die "no slots found ($SLOTS_DIR)"

# load the slot env in this shell (not a subshell), clearing the variables first
load_slot(){
  unset AP_IF AP_NET AP_GW AP_ADDR WG_IF TABLE PRIO_WGSRC PRIO_APNET PRIO_BLACKHOLE ENABLED PROFILE AP_TEST_SRC MODE AP_MAC
  . "$1"
  SLOT=$(basename "$1" .env)
  : "${ENABLED:=1}"
  : "${MODE:=vpn}"
  case "$MODE" in vpn|direct) :;; *) die "$SLOT: MODE must be vpn or direct (found '$MODE')";; esac
  [ "$AP_IF" != "$LAN_IF" ] || die "$SLOT: AP_IF is the same as LAN_IF"
  [ "$AP_IF" != "$DEF_IF" ]  || die "$SLOT: the default route is on $AP_IF - this would cut SSH"
  LAN_PFX=$($IP -4 -o addr show dev "$LAN_IF" 2>/dev/null | awk '{print $4}' | cut -d. -f1-3 | head -1)
  [ -z "$LAN_PFX" ] || case "$AP_NET" in "$LAN_PFX".*) die "$SLOT: AP_NET collides with the LAN network";; esac
  if [ -n "${AP_MAC:-}" ]; then
    _live=$(resolve_ap_if "$AP_MAC") && AP_IF=$_live
  fi
  DEV_PRESENT=0; [ -d "$SYSFS_NET/$AP_IF" ] && DEV_PRESENT=1
  WGCONF=$WG_DIR/${WG_IF}.conf
  if [ -r "$WGCONF" ]; then
    grep -qiE '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off' "$WGCONF" || die "$WGCONF has no 'Table = off'"
    grep -qiE '^[[:space:]]*DNS[[:space:]]*=' "$WGCONF" && die "$WGCONF contains DNS= (it would overwrite resolv.conf)"
  fi
  WG_SRC=$($IP -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  if [ -z "${WG_SRC:-}" ] && [ -r "$WGCONF" ]; then
    WG_SRC=$(sed -n 's/^[[:space:]]*[Aa]ddress[[:space:]]*=[[:space:]]*//p' "$WGCONF" | tr ',' '\n' | tr -d ' \r' | grep -v ':' | cut -d/ -f1 | head -1)
  fi
  WG_MTU=$(cat "$SYSFS_NET/$WG_IF/mtu" 2>/dev/null)
  [ -n "${WG_MTU:-}" ] || WG_MTU=$(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*//p' "$WGCONF" 2>/dev/null | tr -d ' \r' | head -1)
  [ -n "${WG_MTU:-}" ] || WG_MTU=1420
  MSS=$((WG_MTU - 40))
  # In direct mode the tunnel plays no part at all: forget it, so no rule can reference it by accident.
  [ "$MODE" = direct ] && { WG_SRC=""; EXIT_IF="$LAN_IF"; } || EXIT_IF="$WG_IF"
}

# ---- pre-flight: validate EVERY enabled slot before a single rule is written. Two slots sharing an
# interface, a subnet, a table or a tunnel would silently cross their exits, and the first matching
# ACCEPT wins - so refuse the whole run rather than build half of it.
seen_if=""; seen_net=""; seen_tbl=""; seen_wg=""
for f in $SLOT_FILES; do
  load_slot "$f"; [ "$ENABLED" = 1 ] || continue
  case " $seen_if "  in *" $AP_IF "*)  die "$SLOT: interface $AP_IF is claimed by another enabled slot";; esac
  case " $seen_net " in *" $AP_NET "*) die "$SLOT: subnet $AP_NET is claimed by another enabled slot";; esac
  case " $seen_tbl " in *" $TABLE "*)  die "$SLOT: routing table $TABLE is claimed by another enabled slot";; esac
  [ "$MODE" = vpn ] && case " $seen_wg " in *" $WG_IF "*) die "$SLOT: tunnel $WG_IF is claimed by another enabled slot";; esac
  seen_if="$seen_if $AP_IF"; seen_net="$seen_net $AP_NET"; seen_tbl="$seen_tbl $TABLE"
  [ "$MODE" = vpn ] && seen_wg="$seen_wg $WG_IF"
done

# ------------------------------------------------------------- 1. chains (once)
mkchain filter AP-VPN-FWD; mkchain filter AP-VPN-IN
mkchain nat AP-VPN-POST;   mkchain nat AP-VPN-PRE
mkchain mangle AP-VPN-MSS
$SYSCTL -qw net.ipv4.ip_forward=1

# clear our old rules (every "from ... lookup/blackhole" rule in our priority range)
$IP rule show | awk -F: '$1>=1000 && $1<2000 {print $1}' | sort -u | while read -r pref; do
  while $IP rule del pref "$pref" 2>/dev/null; do :; done
done

# ------------------------------------------------------------- 2. per-slot rules
ACTIVE=""
for f in $SLOT_FILES; do
  load_slot "$f"
  [ "$ENABLED" = 1 ] || { logger -t ap-firewall "$SLOT is disabled, skipped"; continue; }
  ACTIVE="$ACTIVE $SLOT($MODE)"
  [ "$DEV_PRESENT" = 1 ] || logger -t ap-firewall -p daemon.warning "$SLOT: radio $AP_IF absent - installing the drop rules anyway (fail closed)"

  # sysctl (only this slot's interfaces)
  $SYSCTL -qw "net.ipv4.conf.$AP_IF.rp_filter=2" 2>/dev/null || true
  [ "$MODE" = vpn ] && $SYSCTL -qw "net.ipv4.conf.$WG_IF.rp_filter=2" 2>/dev/null || true
  $SYSCTL -qw "net.ipv6.conf.$AP_IF.disable_ipv6=1" 2>/dev/null || true
  $SYSCTL -qw "net.ipv6.conf.$AP_IF.accept_ra=0" 2>/dev/null || true

  # routing: the AP's link route first (so dnsmasq replies do not leave through the exit), then the default.
  # The old default is deleted unconditionally: leaving a direct slot's LAN default behind when the slot
  # moves to vpn mode would be a way out without the tunnel (and the self-check below would then refuse
  # to finish, which takes every other slot down with it).
  $IP route replace "$AP_NET" dev "$AP_IF" scope link src "$AP_GW" table "$TABLE" 2>/dev/null || true
  for _i in 1 2 3 4 5; do $IP route del default table "$TABLE" 2>/dev/null || break; done   # bounded: never spin
  if [ "$MODE" = vpn ]; then
    if $IP link show "$WG_IF" >/dev/null 2>&1; then
      $IP route replace default dev "$WG_IF" scope link table "$TABLE" 2>/dev/null || true
    fi
  else
    # direct: the LAN default, and ONLY in a direct slot's own table. A gateway outside the LAN's own
    # subnet (some ISP routers hand one out) needs 'onlink', so fall back to that rather than silently
    # leaving the table without a default - the self-check below refuses the run if neither worked.
    if [ -n "${LAN_GW:-}" ]; then
      $IP route replace default via "$LAN_GW" dev "$LAN_IF" table "$TABLE" 2>/dev/null \
        || $IP route replace default via "$LAN_GW" dev "$LAN_IF" onlink table "$TABLE" 2>/dev/null || true
    fi
  fi
  [ -n "${WG_SRC:-}" ] && $IP rule add from "$WG_SRC" lookup "$TABLE" priority "$PRIO_WGSRC"
  $IP rule add from "$AP_NET" lookup "$TABLE" priority "$PRIO_APNET"   || die "$SLOT: rule $PRIO_APNET"
  $IP rule add from "$AP_NET" blackhole priority "$PRIO_BLACKHOLE"      || die "$SLOT: blackhole"
  [ -n "${WG_SRC:-}" ] && $IP rule add from "$WG_SRC" blackhole priority "$PRIO_BLACKHOLE"

  # NAT + forced DNS
  $IPT -t nat -A AP-VPN-POST -s "$AP_NET" -o "$EXIT_IF" -j MASQUERADE
  $IPT -t nat -A AP-VPN-PRE -i "$AP_IF" -p udp --dport 53 -j REDIRECT --to-ports 53
  $IPT -t nat -A AP-VPN-PRE -i "$AP_IF" -p tcp --dport 53 -j REDIRECT --to-ports 53

  if [ "$MODE" = vpn ]; then
    # MSS (fixed in both directions, derived from this tunnel's MTU)
    $IPT -t mangle -A AP-VPN-MSS -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
    $IPT -t mangle -A AP-VPN-MSS -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
  fi

  # FORWARD: private networks DROP -> the slot's one permitted exit -> return traffic -> EVERYTHING DROP.
  # The RFC1918 drops come first in both modes: a direct slot reaches the internet, never the home LAN.
  for N in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 169.254.0.0/16 100.64.0.0/10; do
    $IPT -A AP-VPN-FWD -i "$AP_IF" -d "$N" -j DROP
  done
  $IPT -A AP-VPN-FWD -i "$AP_IF" -o "$EXIT_IF" -j ACCEPT
  $IPT -A AP-VPN-FWD -i "$EXIT_IF" -o "$AP_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  $IPT -A AP-VPN-FWD -i "$AP_IF" -j DROP                  # KILL SWITCH + cross-slot + LAN isolation
  $IPT -A AP-VPN-FWD -i "$EXIT_IF" -o "$AP_IF" -j DROP    # no new inbound connections from the exit side
  [ "$MODE" = vpn ] && $IPT -A AP-VPN-FWD -i "$LAN_IF" -o "$AP_IF" -j DROP

  # INPUT: DHCP + DNS + ping only
  $IPT -A AP-VPN-IN -i "$AP_IF" -p udp --dport 67 -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -p udp --dport 53 -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -p tcp --dport 53 -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -p icmp --icmp-type echo-request -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -j DROP
done
[ -n "$ACTIVE" ] || die "no enabled slots"

# The tunnel side (the VPN server) cannot open NEW connections to the Pi (the web panel on 8443,
# SSH and so on are invisible from the tunnel). ESTABLISHED/RELATED traffic (upstream DNS replies,
# the exit-IP curl) is unaffected. ICMP echo stays allowed.
$IPT -A AP-VPN-IN -i wg+ -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A AP-VPN-IN -i wg+ -m conntrack --ctstate NEW -j DROP

# ------------------------------------------------------------- 3. hook up
hook filter DOCKER-USER AP-VPN-FWD
hook filter INPUT       AP-VPN-IN
hook nat    POSTROUTING AP-VPN-POST
hook nat    PREROUTING  AP-VPN-PRE
hook mangle FORWARD     AP-VPN-MSS

# ------------------------------------------------------------- 4. IPv6 (all AP interfaces)
$IP6T -N AP-VPN-6 2>/dev/null || $IP6T -F AP-VPN-6
for f in $SLOT_FILES; do
  load_slot "$f"; [ "$ENABLED" = 1 ] || continue
  $IP6T -A AP-VPN-6 -i "$AP_IF" -j DROP; $IP6T -A AP-VPN-6 -o "$AP_IF" -j DROP
done
$IP6T -C INPUT   -j AP-VPN-6 2>/dev/null || $IP6T -I INPUT   1 -j AP-VPN-6
$IP6T -C FORWARD -j AP-VPN-6 2>/dev/null || $IP6T -I FORWARD 1 -j AP-VPN-6

# ------------------------------------------------------------- 5. self-check (per slot)
fail=""
$IPT -C DOCKER-USER -j AP-VPN-FWD 2>/dev/null || fail="$fail DOCKER-USER-hook"
$IPT -C INPUT -j AP-VPN-IN        2>/dev/null || fail="$fail INPUT-hook"
$IPT -C AP-VPN-IN -i wg+ -m conntrack --ctstate NEW -j DROP 2>/dev/null || fail="$fail tunnel-input-drop"
for f in $SLOT_FILES; do
  load_slot "$f"; [ "$ENABLED" = 1 ] || continue
  $IPT -C AP-VPN-FWD -i "$AP_IF" -j DROP                       2>/dev/null || fail="$fail $SLOT:killswitch"
  $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$EXIT_IF" -j ACCEPT        2>/dev/null || fail="$fail $SLOT:fwd"
  $IPT -C AP-VPN-IN  -i "$AP_IF" -j DROP                       2>/dev/null || fail="$fail $SLOT:input-drop"
  $IPT -t nat -C AP-VPN-POST -s "$AP_NET" -o "$EXIT_IF" -j MASQUERADE 2>/dev/null || fail="$fail $SLOT:masq"
  $IP rule show | grep -q "from ${AP_NET} lookup ${TABLE}"       || fail="$fail $SLOT:rule"
  $IP rule show | grep -q "from ${AP_NET} blackhole"             || fail="$fail $SLOT:blackhole"
  [ "$DEV_PRESENT" = 1 ] && { $IP route show table "$TABLE" | grep -q "^${AP_NET} dev ${AP_IF}" || fail="$fail $SLOT:ap-route"; }
  if [ "$MODE" = vpn ]; then
    [ "$($IPT -t mangle -S AP-VPN-MSS | grep -c "$WG_IF .*set-mss $MSS")" = 2 ] || fail="$fail $SLOT:mss"
    # A vpn slot must never have a way out that is not its tunnel.
    $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$LAN_IF" -j ACCEPT 2>/dev/null && fail="$fail $SLOT:LAN-EXIT-IN-VPN-MODE"
    $IP route show table "$TABLE" | grep -q "^default.* dev $LAN_IF" && fail="$fail $SLOT:LAN-DEFAULT-IN-VPN-MODE"
    $IP route show table "$TABLE" | grep -q "^default" || true
  else
    # The direct default must point at the CURRENT gateway: a stale one (the Pi moved to another
    # network) would silently blackhole the slot while looking configured.
    [ -z "${LAN_GW:-}" ] || $IP route show table "$TABLE" | grep -q "^default via $LAN_GW dev $LAN_IF" \
      || fail="$fail $SLOT:STALE-LAN-DEFAULT"
    # A direct slot must never be wired into any tunnel.
    for g in $SLOT_FILES; do
      W=$(sed -n 's/^WG_IF=//p' "$g" | head -1); [ -n "$W" ] || continue
      $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$W" -j ACCEPT 2>/dev/null && fail="$fail $SLOT:TUNNEL-EXIT-IN-DIRECT-MODE($W)"
    done
  fi
  # CROSS-SLOT: there must be no ACCEPT from this slot's AP into ANOTHER slot's exit
  for g in $SLOT_FILES; do
    [ "$g" = "$f" ] && continue
    OTHER_WG=$(sed -n 's/^WG_IF=//p' "$g" | head -1)
    [ -z "$OTHER_WG" ] || [ "$OTHER_WG" = "$EXIT_IF" ] || \
      { $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$OTHER_WG" -j ACCEPT 2>/dev/null && fail="$fail $SLOT:CROSS($OTHER_WG)"; }
  done
done
if [ -n "$fail" ]; then
  # The rules are already in the kernel at this point, so exiting here would leave the very state the
  # check just rejected. Tear the forwarding down instead: every AP interface is dropped in both
  # directions and the NAT rules go away, so the failure mode is "no traffic", never "wrong exit".
  $IPT -F AP-VPN-FWD 2>/dev/null; $IPT -t nat -F AP-VPN-POST 2>/dev/null; $IPT -t mangle -F AP-VPN-MSS 2>/dev/null
  for f in $SLOT_FILES; do
    i=$(sed -n 's/^AP_IF=//p' "$f" | head -1); m=$(sed -n 's/^AP_MAC=//p' "$f" | head -1)
    l=$(resolve_ap_if "$m") && i=$l
    [ -n "$i" ] && { $IPT -A AP-VPN-FWD -i "$i" -j DROP; $IPT -A AP-VPN-FWD -o "$i" -j DROP; }
  done
  logger -t ap-firewall -p daemon.err "self-check failed:$fail - forwarding torn down for every AP (fail closed)"
  die "self-check failed:$fail (all AP forwarding was dropped)"
fi
logger -t ap-firewall "rules applied, slots:$ACTIVE"
echo "ap-firewall: OK slots:$ACTIVE"
exit 0
