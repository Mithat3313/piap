#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-pin.sh — ASSIGNMENT PINNING
#    (SSID <-> exit mode <-> profile <-> VPN server key <-> radio MAC)
#  Purpose: what a slot exits through cannot change unless the user changes it explicitly. The pin
#  lives in the slot env (PIN_MODE, PIN_SSID_HEX, PIN_PROFILE, PIN_PEER, AP_MAC) and only apctl
#  updates it, after a typed confirmation. This script is a read-only audit plus fail-closed
#  enforcement:
#    check <slot>   does the live state match the pin (exit 0/1; reason on stdout)  [ap-hostapd@ ExecStartPre]
#    iface <slot>   is the slot's radio present, and is it the pinned one (exit 0/1) [ap-wlan@ ExecStartPre]
#    enforce        all enabled slots; on violation hostapd is STOPPED (SSID goes down) [ap-watchdog]
#
#  MODE=vpn    the pinned profile must be assigned, its server key must match, and the live tunnel
#              (when up) must be that same server. No profile yet = fail closed, which is allowed:
#              the SSID stays up and the kill switch holds, nothing gets out.
#  MODE=direct the slot exits through the LAN on purpose. Then NO tunnel may be running for it and
#              no profile may be attached — otherwise the pin is violated and the SSID is stopped.
#  While a long operation holds /run/ap-vpn/long.lock, enforce skips the audit (transient states).
# =============================================================================
set -u
WG=/usr/bin/wg; SLOTS=/etc/ap-vpn/slots; PROFILES=/etc/ap-vpn/profiles; LOCK=/run/ap-vpn/long.lock
load(){ unset ENABLED AP_IF WG_IF PROFILE MODE PIN_MODE PIN_SSID_HEX PIN_PROFILE PIN_PEER AP_MAC HOSTAPD_UNIT
        . "$SLOTS/$1.env" || return 1
        HOSTAPD_UNIT=${HOSTAPD_UNIT:-ap-hostapd@$1}; MODE=${MODE:-vpn}; }
pubkey_of(){ sed -nE 's/^[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*([^[:space:]#]+).*/\1/p' "$1" 2>/dev/null | head -1; }
ssid_hex(){ sed -n 's/^ssid=//p' "/etc/hostapd/$1.conf" 2>/dev/null | head -1 | tr -d '\n' | od -An -v -tx1 | tr -d ' \n'; }
hex2s(){ printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
live_peer(){ $WG show "$1" peers 2>/dev/null | head -1; }
tunnel_up(){ [ -d "/sys/class/net/$1" ]; }

iface_check(){ load "$1" || { echo "cannot read slot env"; return 1; }
  [ -z "${AP_MAC:-}" ] && { echo "radio not pinned (AP_MAC empty)"; return 0; }
  local mac; mac=$(cat "/sys/class/net/$AP_IF/address" 2>/dev/null)
  [ "$mac" = "$AP_MAC" ] && { echo "radio $AP_IF=$mac pinned"; return 0; }
  # The pinned radio may simply have another name now; ap-ifsync decides, we only report.
  local now; now=$(/opt/ap-vpn/bin/ap-ifsync.sh name "$1" 2>/dev/null || true)
  [ -n "$now" ] && [ "$now" != "$AP_IF" ] \
    && { echo "RADIO MOVED: pinned $AP_MAC is now $now, config still says $AP_IF (run: ap-ctl --slot $1 slot sync)"; return 1; }
  echo "RADIO DIFFERS: $AP_IF=${mac:-missing} pinned=$AP_MAC (another adapter, or the pinned one is unplugged)"; return 1; }

check(){ load "$1" || { echo "cannot read slot env"; return 1; }
  local m; m=$(iface_check "$1") || { echo "$m"; return 1; }
  # the exit mode itself is pinned: a slot cannot drift from vpn to direct (or back) on its own
  [ -z "${PIN_MODE:-}" ] || [ "$PIN_MODE" = "$MODE" ] || { echo "MODE='$MODE' pinned='$PIN_MODE'"; return 1; }
  local sh; sh=$(ssid_hex "$1")
  if [ -n "${PIN_SSID_HEX:-}" ] && [ "$sh" != "$PIN_SSID_HEX" ]; then
    echo "SSID '$(hex2s "$sh")' pinned '$(hex2s "$PIN_SSID_HEX")'"; return 1
  fi

  if [ "$MODE" = direct ]; then
    [ -z "${PROFILE:-}" ] || { echo "direct mode but profile '$PROFILE' is still attached"; return 1; }
    [ -z "${PIN_PROFILE:-}" ] || { echo "direct mode but the pin still holds profile '$PIN_PROFILE'"; return 1; }
    tunnel_up "$WG_IF" && { echo "direct mode but $WG_IF is up - the tunnel must be down"; return 1; }
    echo "$(hex2s "$sh") -> DIRECT (no VPN, exits through the LAN) [$AP_IF $AP_MAC]"; return 0
  fi

  # --- vpn mode ---
  if [ -z "${PIN_PROFILE:-}" ]; then
    [ -z "${PROFILE:-}" ] || { echo "no pin but PROFILE=$PROFILE (pin it: ap-ctl --slot $1 slot pin)"; return 1; }
    [ -z "$(live_peer "$WG_IF")" ] || { echo "no pin but $WG_IF is up - the tunnel must be down"; return 1; }
    echo "$(hex2s "$sh") -> no profile assigned, no tunnel (kill switch holds)"; return 0
  fi
  [ "${PROFILE:-}" = "$PIN_PROFILE" ] || { echo "PROFILE='${PROFILE:-}' pinned='$PIN_PROFILE'"; return 1; }
  local pp; pp=$(pubkey_of "$PROFILES/$PIN_PROFILE.conf")
  [ -n "$pp" ] || { echo "profile file missing or has no key: $PIN_PROFILE"; return 1; }
  [ "$pp" = "$PIN_PEER" ] || { echo "server key in profile '$PIN_PROFILE' differs from the pin"; return 1; }
  local cp; cp=$(pubkey_of "/etc/wireguard/$WG_IF.conf")
  [ "$cp" = "$PIN_PEER" ] || { echo "server key in $WG_IF.conf differs from the pin"; return 1; }
  local lp; lp=$(live_peer "$WG_IF")
  [ -z "$lp" ] || [ "$lp" = "$PIN_PEER" ] || { echo "LIVE peer on $WG_IF differs from the pin"; return 1; }
  echo "$(hex2s "$sh") -> $PIN_PROFILE (${PIN_PEER:0:8}...) [$AP_IF $AP_MAC]"; return 0; }

enforce(){ mkdir -p /run/ap-vpn
  exec 9>>"$LOCK"; if ! flock -n 9; then echo "a long operation is running, audit skipped"; return 0; fi
  local rc=0 s msg r st f
  for f in "$SLOTS"/*.env; do s=$(basename "$f" .env); grep -q '^ENABLED=1' "$f" || continue
    st=/run/ap-vpn/$s; mkdir -p "$st"
    msg=$(check "$s"); r=$?; load "$s"
    if [ $r -ne 0 ]; then rc=1; echo "$msg" > "$st/pin-violation"
      if systemctl is-active --quiet "$HOSTAPD_UNIT"; then
        logger -t ap-pin -p daemon.err "$s ASSIGNMENT VIOLATION: $msg -> stopping $HOSTAPD_UNIT (fail-closed)"
        systemctl stop "$HOSTAPD_UNIT"; fi
      # a tunnel that should not be running for this slot is stopped as well
      if { [ "$MODE" = direct ] || [ -z "${PIN_PROFILE:-}" ]; } && [ -d "/sys/class/net/$WG_IF" ]; then
        logger -t ap-pin -p daemon.err "$s: $WG_IF must not be up in this state -> stopping it"; systemctl stop "wg-quick@$WG_IF"; fi
      echo "$s VIOLATION: $msg"
    else rm -f "$st/pin-violation"; echo "$s ok: $msg"; fi
  done
  flock -u 9; return $rc; }

case "${1:-}" in
  check)   [ -n "${2:-}" ] || { echo "slot?"; exit 2; }; check "$2";;
  iface)   [ -n "${2:-}" ] || { echo "slot?"; exit 2; }; iface_check "$2";;
  enforce) enforce;;
  *) echo "usage: $0 check <slot> | iface <slot> | enforce"; exit 2;;
esac
