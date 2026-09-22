#!/bin/bash
# =============================================================================
#  tests/device-dryrun.sh — exercise ap-ifsync.sh against a fake sysfs.
#  No root, no hardware: the radios are directories, so every re-plug, rename and swap can be staged.
#
#    ./tests/device-dryrun.sh
#
#  What it protects: a slot belongs to a PHYSICAL radio. The same adapter must keep its slot under any
#  name; a different adapter must never inherit one. Both directions are leaks of a kind — the second
#  would put a stranger's device on an SSID that is wired to someone's VPN.
# =============================================================================
set -u
HERE=$(cd "$(dirname "$0")" && pwd); SYNC="$HERE/../pi/opt/ap-vpn/bin/ap-ifsync.sh"
pass=0; fail=0
ok(){ printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }

R=/tmp/piap-dev; MAC_A=aa:aa:aa:00:00:01; MAC_B=bb:bb:bb:00:00:02
radio(){ mkdir -p "$R/sys/$1/phy80211"; echo "$2" > "$R/sys/$1/address"; echo "phy0" > "$R/sys/$1/phy80211/name"; }
slot(){ mkdir -p "$R/slots"
  cat > "$R/slots/$1.env" <<EOF
ENABLED=1
MODE=vpn
AP_IF=$2
AP_MAC=$3
AP_NET=10.99.0.0/24
WG_IF=wg0
DNSMASQ_CONF=$R/slots/$1.dnsmasq.conf
EOF
  printf 'interface=%s\nssid=test_nomap\n' "$2" > "$R/hostapd/$1.conf"
  printf 'interface=%s\nlisten-address=10.99.0.1\n' "$2" > "$R/slots/$1.dnsmasq.conf"; }
reset(){ rm -rf "$R"; mkdir -p "$R/sys" "$R/slots" "$R/hostapd"; }
run(){ SLOTS="$R/slots" SYSFS_NET="$R/sys" HOSTAPD_DIR="$R/hostapd" IFSYNC_WAIT=1 bash "$SYNC" "$@" 2>"$R/err"; }
val(){ sed -n "s/^$2=//p" "$R/slots/$1.env" | head -1; }

echo "== 1. the adapter keeps its slot when the kernel renames it =="
reset; radio wlan1 "$MAC_A"; slot ap1 wlan5 "$MAC_A"      # env still says the old name wlan5
out=$(run sync ap1); rc=$?
[ $rc = 0 ] && ok "sync succeeded: $out" || no "sync failed: $(cat "$R/err")"
[ "$(val ap1 AP_IF)" = wlan1 ] && ok "AP_IF follows the MAC (wlan5 -> wlan1)" || no "AP_IF is $(val ap1 AP_IF)"
grep -q '^interface=wlan1' "$R/hostapd/ap1.conf" && ok "hostapd interface= updated" || no "hostapd interface= not updated"
grep -q '^interface=wlan1' "$R/slots/ap1.dnsmasq.conf" && ok "dnsmasq interface= updated" || no "dnsmasq interface= not updated"
grep -q '^ssid=test_nomap' "$R/hostapd/ap1.conf" && ok "the rest of the hostapd config is untouched" || no "hostapd config damaged"

echo
echo "== 2. a DIFFERENT adapter does not inherit the slot =="
reset; radio wlan1 "$MAC_B"; slot ap1 wlan1 "$MAC_A"      # wlan1 is now someone else's radio
out=$(run sync ap1); rc=$?
[ $rc != 0 ] && ok "refused (the slot stays down): $(head -1 "$R/err")" || no "accepted a foreign radio: $out"
[ "$(val ap1 AP_IF)" = wlan1 ] && ok "config was not rewritten to the foreign device" || no "config was rewritten"

echo
echo "== 3. the pinned radio is unplugged =="
reset; radio wlan1 "$MAC_B"; slot ap0 wlan0 "$MAC_A"
run sync ap0; rc=$?
[ $rc != 0 ] && ok "exits non-zero, so ap-wlan@/ap-hostapd@ stay down (fail closed)" || no "exited 0 with the radio missing"

echo
echo "== 4. two adapters swapped: each slot follows its own MAC =="
reset; radio wlan0 "$MAC_B"; radio wlan1 "$MAC_A"         # they traded names
slot ap0 wlan0 "$MAC_A"; slot ap1 wlan1 "$MAC_B"
run sync ap0 >/dev/null; run sync ap1 >/dev/null
[ "$(val ap0 AP_IF)" = wlan1 ] && ok "ap0 followed $MAC_A to wlan1" || no "ap0 AP_IF is $(val ap0 AP_IF)"
[ "$(val ap1 AP_IF)" = wlan0 ] && ok "ap1 followed $MAC_B to wlan0" || no "ap1 AP_IF is $(val ap1 AP_IF)"
grep -q '^interface=wlan1' "$R/hostapd/ap0.conf" && grep -q '^interface=wlan0' "$R/hostapd/ap1.conf" \
  && ok "both hostapd configs point at their own radio" || no "hostapd configs crossed"

echo
echo "== 5. a radio that already belongs to another slot is refused =="
reset; radio wlan0 "$MAC_A"; slot ap0 wlan0 "$MAC_A"; slot ap1 wlan9 "$MAC_A"   # ap1 claims the same MAC
run sync ap1; rc=$?
[ $rc != 0 ] && ok "refused: $(head -1 "$R/err")" || no "two slots were allowed onto one radio"

echo
echo "== 6. listing shows which slot owns which radio =="
reset; radio wlan0 "$MAC_A"; radio wlan1 "$MAC_B"; slot ap0 wlan0 "$MAC_A"
out=$(run list)
echo "$out" | grep -q "wlan0 .*$MAC_A .*ap0" && ok "wlan0 is listed as ap0's" || no "listing wrong: $out"
echo "$out" | grep -qE "wlan1 +$MAC_B .*-$" && ok "wlan1 is listed as unowned" || no "listing wrong: $out"

echo
printf -- '---- %d PASS, %d FAIL ----\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
