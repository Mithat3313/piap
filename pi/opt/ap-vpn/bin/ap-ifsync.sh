#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-ifsync.sh — DEVICE IDENTITY for a slot
#    sync <slot>     resolve the slot's radio by its MAC and make the config match (exit 1 if absent)
#    name <slot>     print the interface name the slot's radio currently has
#    list            list every wireless radio: interface, MAC, driver, AP capability, owning slot
#
#  A slot belongs to a PHYSICAL RADIO, not to an interface name. Kernel names (wlan0, wlan1 …)
#  depend on enumeration order and change when a USB adapter is re-plugged or another one is added.
#  The identity is the radio's MAC address, stored as AP_MAC in the slot env:
#
#    - same MAC under a different name  -> the name is updated everywhere (env, hostapd, dnsmasq).
#      The adapter keeps its own subnet, tunnel and SSID.
#    - a different MAC on the old name  -> REFUSED. A new adapter never inherits another adapter's
#      VPN; it needs its own slot (ap-slot-new.sh), which means its own subnet and its own tunnel.
#    - the MAC is absent                -> exit 1, so ap-wlan@/ap-hostapd@ do not start (fail closed).
# =============================================================================
set -u
# Paths are overridable so the logic can be exercised against a fake sysfs (tests/device-dryrun.sh).
: "${SLOTS:=/etc/ap-vpn/slots}"; : "${SYSFS_NET:=/sys/class/net}"; : "${HOSTAPD_DIR:=/etc/hostapd}"
die(){ echo "ap-ifsync: $*" >&2; logger -t ap-ifsync -p daemon.err "$*"; exit 1; }

mac_of(){ cat "$SYSFS_NET/$1/address" 2>/dev/null; }
is_wifi(){ [ -d "$SYSFS_NET/$1/phy80211" ]; }
driver_of(){ basename "$(readlink -f "$SYSFS_NET/$1/device/driver" 2>/dev/null)" 2>/dev/null; }
ap_capable(){ /usr/sbin/iw phy "$(cat "$SYSFS_NET/$1/phy80211/name" 2>/dev/null)" info 2>/dev/null \
  | awk '/Supported interface modes/,/^\s*[A-Z]/' | grep -q '\* AP$'; }

# interface that currently carries this MAC ('' when the radio is absent).
# Two radios answering to one MAC (a cloned or randomized address) would make the binding a coin flip,
# so that is refused rather than guessed.
if_for_mac(){
  local want=$1 i found=""
  [ -n "$want" ] || return 1
  for i in "$SYSFS_NET"/*; do
    i=$(basename "$i"); is_wifi "$i" || continue
    if [ "$(mac_of "$i")" = "$want" ]; then
      [ -n "$found" ] && die "two radios carry $want ($found and $i) - refusing to guess which one is the slot's"
      found=$i
    fi
  done
  [ -n "$found" ] || return 1
  echo "$found"
}

# Same, but waits: at boot (and right after a re-plug) udev can take seconds to bring a USB radio up,
# and giving up immediately would leave the slot down until the next manual start.
if_for_mac_wait(){
  local want=$1 n=${2:-30} i r
  for i in $(seq 1 "$n"); do
    r=$(if_for_mac "$want") && { echo "$r"; return 0; }
    sleep 0.5
  done
  return 1
}

# which slot's env currently names this interface (AP_IF), other than $2
owner_of_name(){
  local want=$1 me=${2:-} f n
  for f in "$SLOTS"/*.env; do
    [ -r "$f" ] || continue
    n=$(basename "$f" .env); [ "$n" = "$me" ] && continue
    [ "$(sed -n 's/^AP_IF=//p' "$f" | head -1)" = "$want" ] && { echo "$n"; return 0; }
  done
  return 1
}

owner_of_mac(){   # which slot claims this MAC
  local want=$1 f
  for f in "$SLOTS"/*.env; do
    [ -r "$f" ] || continue
    [ "$(sed -n 's/^AP_MAC=//p' "$f" | head -1)" = "$want" ] && { basename "$f" .env; return 0; }
  done
  return 1
}

# Rewrite one 'key=value' line atomically, keeping the file's permissions. Done with a temp file and
# mv rather than 'sed -i' so a crash can never leave a half-written hostapd or dnsmasq config behind
# (and so the same code works outside GNU sed).
set_key(){ # file key value
  local f=$1 k=$2 v=$3 t
  t=$(mktemp "$(dirname "$f")/.ifsync-XXXXXX") || return 1
  if grep -q "^$k=" "$f"; then sed "s|^$k=.*|$k=$v|" "$f" > "$t"; else cp "$f" "$t"; printf '%s=%s\n' "$k" "$v" >> "$t"; fi
  chmod --reference="$f" "$t" 2>/dev/null || chmod 0644 "$t"
  mv "$t" "$f"
}

sync_slot(){
  local slot=$1 env="$SLOTS/$1.env" cur now owner
  [ -r "$env" ] || die "$slot: no slot env"
  # shellcheck disable=SC1090
  unset AP_IF AP_MAC; . "$env"
  [ -n "${AP_MAC:-}" ] || { echo "$slot: not bound to a radio yet (AP_MAC empty), using ${AP_IF:-?}"; return 0; }

  if ! now=$(if_for_mac_wait "$AP_MAC" "${IFSYNC_WAIT:-30}"); then
    local on_name; on_name=$(mac_of "${AP_IF:-}")
    [ -n "$on_name" ] && [ "$on_name" != "$AP_MAC" ] \
      && die "$slot: its radio ($AP_MAC) is gone and ${AP_IF} now carries $on_name - a different adapter does not inherit this slot (give it its own: ap-slot-new.sh)"
    die "$slot: its radio ($AP_MAC) is not present - the slot stays down"
  fi
  [ "$now" = "${AP_IF:-}" ] && { echo "$slot: $AP_IF ($AP_MAC)"; return 0; }

  # The name moved. Refuse if some OTHER slot already owns the name we are about to take.
  cur=$(mac_of "${AP_IF:-}")
  if [ -n "$cur" ] && [ "$cur" != "$AP_MAC" ]; then
    owner=$(owner_of_mac "$cur" || true)
    logger -t ap-ifsync -p daemon.warning "$slot: ${AP_IF} now carries $cur${owner:+ (slot $owner)}; this slot follows its own radio to $now"
  fi
  # Would we be taking a name another slot's config still points at? If that slot's OWN radio is the one
  # sitting there, this is a genuine conflict and we stop. If it is not (two adapters traded names, so
  # its entry is simply stale), we go ahead: that slot follows its own MAC on its next sync, and until
  # then ap-firewall refuses to build rules for two slots on one interface.
  local other other_mac; other=$(owner_of_name "$now" "$slot" || true)
  if [ -n "$other" ]; then
    other_mac=$(sed -n 's/^AP_MAC=//p' "$SLOTS/$other.env" | head -1)
    [ "$other_mac" = "$(mac_of "$now")" ] && die "$slot: $now really belongs to slot $other - refusing"
    logger -t ap-ifsync -p daemon.warning "$slot: taking $now from slot $other's stale entry; $other must be synced too"
  fi

  set_key "$env" AP_IF "$now" || die "$slot: could not update AP_IF"
  [ -f "$HOSTAPD_DIR/$slot.conf" ] && { set_key "$HOSTAPD_DIR/$slot.conf" interface "$now" || die "$slot: could not update the hostapd config"; }
  local dm="${DNSMASQ_CONF:-$SLOTS/$slot.dnsmasq.conf}"
  [ -f "$dm" ] && { set_key "$dm" interface "$now" || die "$slot: could not update the dnsmasq config"; }
  logger -t ap-ifsync "$slot: radio $AP_MAC moved ${AP_IF:-?} -> $now, config updated"
  echo "$slot: ${AP_IF:-?} -> $now ($AP_MAC)"
}

case "${1:-}" in
  sync) [ -n "${2:-}" ] || die "usage: ap-ifsync.sh sync <slot>"; sync_slot "$2";;
  name)
    [ -n "${2:-}" ] || die "usage: ap-ifsync.sh name <slot>"
    unset AP_IF AP_MAC; . "$SLOTS/$2.env" 2>/dev/null || die "$2: no slot env"
    if [ -n "${AP_MAC:-}" ]; then if_for_mac "$AP_MAC" || { echo "${AP_IF:-}"; exit 1; }; else echo "${AP_IF:-}"; fi;;
  list)
    printf '%-8s %-18s %-10s %-4s %s\n' IFACE MAC DRIVER AP SLOT
    for i in "$SYSFS_NET"/*; do
      i=$(basename "$i"); is_wifi "$i" || continue
      m=$(mac_of "$i"); s=$(owner_of_mac "$m" || echo '-')
      ap_capable "$i" && a=yes || a=no
      d=$(driver_of "$i"); [ -n "$d" ] && [ "$d" != . ] || d='-'
      printf '%-8s %-18s %-10s %-4s %s\n' "$i" "$m" "$d" "$a" "$s"
    done;;
  *) echo "usage: $0 sync <slot> | name <slot> | list" >&2; exit 2;;
esac
