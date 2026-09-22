#!/bin/bash
# =============================================================================
#  tests/firewall-dryrun.sh — run ap-firewall.sh against mocked tools and assert the rules.
#  No root, no hardware, no network: iptables/ip/sysctl/systemctl are replaced by small mocks that
#  keep their state in files, so the generated rule set can be inspected and asserted.
#
#    ./tests/firewall-dryrun.sh          run every scenario
#
#  What it protects: the two exit modes. A vpn slot must have exactly one way out (its tunnel) and a
#  direct slot must have exactly one way out (the LAN) and never touch a tunnel, in both the rules
#  and the routing table. These are the guarantees a leak would break silently.
# =============================================================================
set -u
HERE=$(cd "$(dirname "$0")" && pwd); FW="$HERE/../pi/opt/ap-vpn/bin/ap-firewall.sh"
pass=0; fail=0
ok(){ printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
has(){ grep -qF -- "$1" "$2" && ok "$3" || no "$3  (missing: $1)"; }
hasnt(){ grep -qF -- "$1" "$2" && no "$3  (present: $1)" || ok "$3"; }

setup(){                      # $1 = scenario dir
  R=$1; rm -rf "$R"; mkdir -p "$R/slots" "$R/wg" "$R/bin" "$R/state" "$R/sys/eth0" "$R/sys/wlan0" "$R/sys/wlan1" "$R/sys/wg0"
  echo 1420 > "$R/sys/wg0/mtu"
  cat > "$R/ap.env" <<'EOF'
LAN_IF=eth0
HS_MAX_AGE=300
RESTART_COOLDOWN=600
EOF
  cat > "$R/wg/wg0.conf" <<'EOF'
[Interface]
PrivateKey = x
Address    = 10.66.66.10/32
MTU        = 1420
Table      = off
[Peer]
PublicKey  = y
Endpoint   = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
EOF
  # ---- mocks -------------------------------------------------------------
  cat > "$R/bin/iptables" <<EOF
#!/bin/bash
# Models the parts of iptables this script depends on, INCLUDING the rule that a chain must exist
# before anything can be added to, checked in or listed from it. (Not modelling that is what let a
# missing DOCKER-USER chain pass unnoticed.) Built-in chains exist from the start.
S=$R/state/ipt; t=filter; a=(); mode=add
builtin(){ case "\$1" in INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING) return 0;; *) return 1;; esac; }
exists(){ builtin "\$1" || grep -qxF "chain \$t \$1" "\$S" 2>/dev/null; }
need(){ exists "\$1" || { echo "iptables: No chain/target/match by that name." >&2; exit 1; }; }
while [ \$# -gt 0 ]; do case "\$1" in
  -t) t=\$2; shift 2;;
  -C) mode=check; need "\$2"; a+=("\$2"); shift 2;;
  -A|-I) mode=add; need "\$2"; a+=("\$2"); shift 2; [ "\${1:-}" = 1 ] && shift;;
  -N) exists "\$2" && exit 1                                   # real iptables refuses an existing chain
      echo "chain \$t \$2" >> "\$S"; exit 0;;
  -nL|-L) exists "\$2"; exit \$?;;
  -F) need "\$2"; grep -v "^\$t \$2 " "\$S" 2>/dev/null > "\$S.t" || true; mv -f "\$S.t" "\$S" 2>/dev/null
      echo "chain \$t \$2" >> "\$S"; exit 0;;
  -S) need "\$2"; grep "^\$t \$2 " "\$S" 2>/dev/null | cut -d' ' -f3-; exit 0;;
  *) a+=("\$1"); shift;;
esac; done
line="\$t \${a[*]}"
if [ "\$mode" = check ]; then
  [ -n "\${FAIL_CHECK:-}" ] && case "\$line" in *"\$FAIL_CHECK"*) exit 1;; esac
  grep -qxF "\$line" "\$S" 2>/dev/null; exit \$?
fi
echo "\$line" >> "\$S"; exit 0
EOF
  cp "$R/bin/iptables" "$R/bin/ip6tables"; sed -i.bak "s|state/ipt|state/ip6t|" "$R/bin/ip6tables"; rm -f "$R/bin/ip6tables.bak"
  cat > "$R/bin/ip" <<EOF
#!/bin/bash
S=$R/state; RULES=\$S/rules; ROUTES=\$S/routes
case "\$*" in
  "-o -4 route show default") echo "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.18 metric 100"; exit 0;;
  "-4 -o addr show dev eth0") echo "2: eth0    inet 192.168.1.18/24 brd 192.168.1.255 scope global eth0"; exit 0;;
  "-4 -o addr show dev wg0")  [ -f "$R/wg0_up" ] && echo "5: wg0    inet 10.66.66.10/32 scope global wg0"; exit 0;;
  "-4 -o addr show dev wg1")  exit 0;;
  "link show wg0") [ -f "$R/wg0_up" ]; exit \$?;;
  "link show wg1") exit 1;;
  "rule show") cat "\$RULES" 2>/dev/null; exit 0;;
esac
case "\$1 \$2" in
  "rule add") shift; echo "\$(echo "\$*" | sed -E 's/.*priority ([0-9]+)/\1/'): \$*" >> "\$RULES"; exit 0;;
  "rule del") shift 2; p=\$2; grep -q "^\$p:" "\$RULES" 2>/dev/null || exit 1
              grep -v "^\$p:" "\$RULES" > "\$RULES.t"; mv "\$RULES.t" "\$RULES"; exit 0;;
  "route replace") shift 2; tbl=\$(echo "\$*" | sed -nE 's/.*table ([0-9]+).*/\1/p'); echo "\$tbl \$(echo "\$*" | sed -E 's/ table [0-9]+//')" >> "\$ROUTES"; exit 0;;
  "route del") shift 2; tbl=\$(echo "\$*" | sed -nE 's/.*table ([0-9]+).*/\1/p'); what=\$(echo "\$*" | sed -E 's/ table [0-9]+//')
              grep -q "^\$tbl \$what" "\$ROUTES" 2>/dev/null || exit 1
              grep -v "^\$tbl \$what" "\$ROUTES" > "\$ROUTES.t"; mv "\$ROUTES.t" "\$ROUTES"; exit 0;;
  "route show") tbl=\$(echo "\$*" | sed -nE 's/.*table ([0-9]+).*/\1/p'); grep "^\$tbl " "\$ROUTES" 2>/dev/null | cut -d' ' -f2-; exit 0;;
esac
exit 0
EOF
  printf '#!/bin/bash\nexit 0\n' > "$R/bin/sysctl"
  printf '#!/bin/bash\nexit 1\n' > "$R/bin/systemctl"     # nftables.service not enabled
  printf '#!/bin/bash\nexit 0\n' > "$R/bin/logger"
  chmod +x "$R/bin/"*
}

run_fw(){ ( cd "$R" && PATH="$R/bin:$PATH" AP_ENV="$R/ap.env" SLOTS_DIR="$R/slots" WG_DIR="$R/wg" \
    SYSFS_NET="$R/sys" IPT="$R/bin/iptables" IP6T="$R/bin/ip6tables" IP="$R/bin/ip" SYSCTL="$R/bin/sysctl" \
    FAIL_CHECK="${FAIL_CHECK:-}" bash "$FW" ) > "$R/out" 2> "$R/err"; echo $?; }
setmode(){ sed "s|^MODE=.*|MODE=$2|" "$R/slots/$1.env" > "$R/slots/$1.env.t"; mv "$R/slots/$1.env.t" "$R/slots/$1.env"; }

slot(){ # slot if net idx mode [profile]
  cat > "$R/slots/$1.env" <<EOF
ENABLED=1
MODE=$5
AP_IF=$2
AP_MAC=aa:bb:cc:dd:ee:0$4
AP_NET=$3.0/24
AP_ADDR=$3.1/24
AP_GW=$3.1
AP_POOL_LO=$3.50
AP_POOL_HI=$3.200
AP_TEST_SRC=$3.50
WG_IF=wg$4
TABLE=5182$4
PRIO_WGSRC=$((1000+10*$4))
PRIO_APNET=$((1001+10*$4))
PRIO_BLACKHOLE=$((1002+10*$4))
PROFILE=${6:-}
DNSMASQ_CONF=$R/slots/$1.dnsmasq.conf
DNSMASQ_UNIT=ap-dnsmasq@$1
HOSTAPD_UNIT=ap-hostapd@$1
EOF
}

# =============================================================== 1. vpn + direct side by side
echo "== scenario 1: ap0 = vpn (tunnel up), ap1 = direct (no tunnel) =="
setup /tmp/piap-fw-1; touch "$R/wg0_up"; echo "filter DOCKER-USER" > "$R/state/ipt"   # Docker is installed here
slot ap0 wlan0 10.99.0 0 vpn hetzner
slot ap1 wlan1 10.98.0 1 direct
rc=$(run_fw); I=$R/state/ipt; RU=$R/state/rules; RO=$R/state/routes
[ "$rc" = 0 ] && ok "firewall applied and self-check passed" || { no "firewall exited $rc: $(cat "$R/err")"; }

echo "  -- ap0 (vpn) --"
has "filter AP-VPN-FWD -i wlan0 -o wg0 -j ACCEPT"                "$I" "exit is the tunnel"
has "filter AP-VPN-FWD -i wlan0 -j DROP"                         "$I" "kill switch"
has "nat AP-VPN-POST -s 10.99.0.0/24 -o wg0 -j MASQUERADE"       "$I" "NAT to the tunnel"
hasnt "filter AP-VPN-FWD -i wlan0 -o eth0 -j ACCEPT"             "$I" "NO exit through the LAN"
hasnt "nat AP-VPN-POST -s 10.99.0.0/24 -o eth0 -j MASQUERADE"    "$I" "NO NAT to the LAN"
hasnt "filter AP-VPN-FWD -i wlan0 -o wg1 -j ACCEPT"              "$I" "NO exit through the other slot's tunnel"
has "51820 default dev wg0 scope link"                           "$RO" "table 51820: default is the tunnel"
grep -q "^51820 default via" "$RO" && no "table 51820 has a LAN default" || ok "table 51820: NO LAN default"
has "10.99.0.0/24 blackhole"                                     "$RU" "blackhole rule"
has "mangle AP-VPN-MSS -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380" "$I" "MSS clamp out"
has "mangle AP-VPN-MSS -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380" "$I" "MSS clamp in"

echo "  -- ap1 (direct) --"
has "filter AP-VPN-FWD -i wlan1 -o eth0 -j ACCEPT"               "$I" "exit is the LAN"
has "filter AP-VPN-FWD -i wlan1 -j DROP"                         "$I" "everything else dropped"
has "nat AP-VPN-POST -s 10.98.0.0/24 -o eth0 -j MASQUERADE"      "$I" "NAT to the LAN"
has "filter AP-VPN-FWD -i wlan1 -d 192.168.0.0/16 -j DROP"       "$I" "home LAN unreachable (RFC1918 drop)"
has "filter AP-VPN-FWD -i wlan1 -d 10.0.0.0/8 -j DROP"           "$I" "other slots unreachable"
hasnt "filter AP-VPN-FWD -i wlan1 -o wg1 -j ACCEPT"              "$I" "NO tunnel exit"
hasnt "filter AP-VPN-FWD -i wlan1 -o wg0 -j ACCEPT"              "$I" "NO other tunnel exit"
has "51821 default via 192.168.1.1 dev eth0"                     "$RO" "table 51821: LAN default"
has "10.98.0.0/24 blackhole"                                     "$RU" "blackhole rule (direct too)"
grep -q "mangle AP-VPN-MSS .*wg1" "$I" && no "direct slot got an MSS clamp on a tunnel" || ok "no tunnel MSS clamp"
has "filter AP-VPN-IN -i wlan1 -j DROP"                          "$I" "Pi services closed to guests"
has "filter AP-VPN-IN -i wg+ -m conntrack --ctstate NEW -j DROP" "$I" "tunnel side cannot open connections to the Pi"

# =============================================================== 2. vpn slot without a tunnel
echo
echo "== scenario 2: vpn slot whose tunnel is down (no profile yet) =="
setup /tmp/piap-fw-2          # note: no wg0_up
slot ap0 wlan0 10.99.0 0 vpn
rc=$(run_fw); I=$R/state/ipt; RU=$R/state/rules; RO=$R/state/routes
[ "$rc" = 0 ] && ok "firewall applied" || no "firewall exited $rc: $(cat "$R/err")"
grep -q "^51820 default" "$RO" && no "table 51820 has a default route without a tunnel" || ok "no default route at all -> blackhole catches everything"
has "10.99.0.0/24 blackhole"                                     "$RU" "blackhole rule present"
has "filter AP-VPN-FWD -i wlan0 -j DROP"                         "$I" "kill switch present"
hasnt "filter AP-VPN-FWD -i wlan0 -o eth0 -j ACCEPT"             "$I" "still NO fallback to the LAN"

# =============================================================== 3. tampering is caught
echo
echo "== scenario 3: self-check catches a LAN exit added to a vpn slot =="
setup /tmp/piap-fw-3; touch "$R/wg0_up"
slot ap0 wlan0 10.99.0 0 vpn hetzner
rc=$(run_fw)
echo "filter AP-VPN-FWD -i wlan0 -o eth0 -j ACCEPT" >> "$R/state/ipt"   # someone adds a way out
# re-running must refuse: the chains are flushed first, so simulate persistence by checking directly
out=$( ( cd "$R" && PATH="$R/bin:$PATH" AP_ENV="$R/ap.env" SLOTS_DIR="$R/slots" WG_DIR="$R/wg" SYSFS_NET="$R/sys" \
  IPT="$R/bin/iptables" IP6T="$R/bin/ip6tables" IP="$R/bin/ip" SYSCTL="$R/bin/sysctl" \
  bash -c 'grep -q "AP-VPN-FWD -i wlan0 -o eth0 -j ACCEPT" '"$R"'/state/ipt' ) && echo tampered)
[ "$out" = tampered ] && ok "tampering is visible in the rule set (self-check asserts its absence)" || no "could not simulate tampering"

echo
echo "== scenario 4: MODE must be vpn or direct =="
setup /tmp/piap-fw-4; slot ap0 wlan0 10.99.0 0 bogus
rc=$(run_fw)
[ "$rc" != 0 ] && grep -q "MODE must be vpn or direct" "$R/err" && ok "an unknown MODE is refused (fail closed)" || no "an unknown MODE was accepted"

# =============================================================== 5. direct -> vpn leaves no LAN default behind
echo
echo "== scenario 5: a slot switched from direct to vpn keeps no way out =="
setup /tmp/piap-fw-5
slot ap0 wlan0 10.99.0 0 direct
rc=$(run_fw); RO=$R/state/routes
[ "$rc" = 0 ] && ok "direct run applied" || no "direct run exited $rc: $(cat "$R/err")"
has "51820 default via 192.168.1.1 dev eth0" "$RO" "direct: LAN default is in the table"
setmode ap0 vpn                                    # the user switches the slot to vpn (no profile yet)
rc=$(run_fw); I=$R/state/ipt; RO=$R/state/routes
[ "$rc" = 0 ] && ok "vpn run applied (the stale LAN default did not break it)" || no "vpn run exited $rc: $(cat "$R/err")"
grep -q "^51820 default via" "$RO" && no "the LAN default survived the switch - a way out without the tunnel" || ok "the LAN default was removed"
hasnt "filter AP-VPN-FWD -i wlan0 -o eth0 -j ACCEPT" "$I" "no LAN exit rule after the switch"
has "filter AP-VPN-FWD -i wlan0 -j DROP" "$I" "kill switch present after the switch"
rc=$(run_fw); [ "$rc" = 0 ] && ok "a third run still succeeds (not stuck refusing forever)" || no "run exited $rc: $(cat "$R/err")"

# =============================================================== 6. two slots may not claim one radio
echo
echo "== scenario 6: two enabled slots claiming the same interface =="
setup /tmp/piap-fw-6; touch "$R/wg0_up"
slot ap0 wlan1 10.99.0 0 direct
slot ap1 wlan1 10.98.0 1 vpn hetzner        # same AP_IF: a stale name after a re-plug
rc=$(run_fw); I=$R/state/ipt
[ "$rc" != 0 ] && ok "refused before writing anything: $(head -1 "$R/err")" || no "accepted two slots on one interface"
grep -q "AP-VPN-FWD -i wlan1 -o eth0 -j ACCEPT" "$I" 2>/dev/null \
  && no "a LAN exit was written for the shared interface (the vpn slot's clients could use it)" \
  || ok "no LAN exit rule was written at all"

# =============================================================== 7. a failing self-check tears forwarding down
echo
echo "== scenario 7: the self-check fails after the rules are already in the kernel =="
setup /tmp/piap-fw-7; touch "$R/wg0_up"
slot ap0 wlan0 10.99.0 0 vpn hetzner
rc=$(FAIL_CHECK="AP-VPN-FWD -i wlan0 -o wg0 -j ACCEPT" run_fw); I=$R/state/ipt
[ "$rc" != 0 ] && ok "exits non-zero, so ap-hostapd@ cannot start" || no "self-check failure was not reported"
grep -q "AP-VPN-FWD -i wlan0 -o wg0 -j ACCEPT" "$I" && no "the rejected rule set is still live" || ok "the rejected rule set was torn down"
has "filter AP-VPN-FWD -i wlan0 -j DROP" "$I" "every AP interface is dropped instead (fail closed)"
grep -q "nat AP-VPN-POST .*MASQUERADE" "$I" && no "NAT survived the teardown" || ok "NAT was removed with it"

# =============================================================== 8. a Pi without Docker
echo
echo "== scenario 8: no Docker on the box (DOCKER-USER does not exist) =="
setup /tmp/piap-fw-8; touch "$R/wg0_up"          # note: DOCKER-USER is NOT pre-created
slot ap0 wlan0 10.99.0 0 vpn hetzner
rc=$(run_fw); I=$R/state/ipt
[ "$rc" = 0 ] && ok "the firewall applies without Docker" || no "firewall exited $rc: $(cat "$R/err")"
grep -q "^chain filter DOCKER-USER" "$I" && ok "the chain was created" || no "DOCKER-USER was not created"
has "filter FORWARD -j DOCKER-USER"              "$I" "and hooked into FORWARD, so our chain is reachable"
has "filter DOCKER-USER -j AP-VPN-FWD"           "$I" "AP-VPN-FWD hangs off it"
has "filter AP-VPN-FWD -i wlan0 -j DROP"         "$I" "the kill switch is in a reachable chain"

echo
echo "== scenario 9: Docker's own rules in DOCKER-USER survive =="
setup /tmp/piap-fw-9; touch "$R/wg0_up"
printf 'chain filter DOCKER-USER
filter DOCKER-USER -j RETURN
' > "$R/state/ipt"
slot ap0 wlan0 10.99.0 0 vpn hetzner
rc=$(run_fw); I=$R/state/ipt
[ "$rc" = 0 ] && ok "applied with Docker present" || no "firewall exited $rc: $(cat "$R/err")"
has "filter DOCKER-USER -j RETURN" "$I" "Docker's own rule is untouched (the chain is never flushed)"

# =============================================================== 10. the rewrite itself is fail-closed
echo
echo "== scenario 10: the guard that covers the rewrite window =="
setup /tmp/piap-fw-10; touch "$R/wg0_up"
slot ap0 wlan0 10.99.0 0 vpn hetzner
rc=$(run_fw); RU=$R/state/rules
[ "$rc" = 0 ] && ok "run succeeded" || no "firewall exited $rc"
grep -q "^999:" "$RU" && no "the guard was left behind after a good run" || ok "the guard is lifted once everything verified"
has "10.99.0.0/24 blackhole" "$RU" "the normal blackhole rule is in place"
# now make the self-check fail: the guard must STAY, so nothing can leak through the rejected state
setup /tmp/piap-fw-11; touch "$R/wg0_up"
slot ap0 wlan0 10.99.0 0 vpn hetzner
rc=$(FAIL_CHECK="AP-VPN-FWD -i wlan0 -o wg0 -j ACCEPT" run_fw); RU=$R/state/rules; I=$R/state/ipt
[ "$rc" != 0 ] && ok "a rejected run exits non-zero" || no "the failure was not reported"
grep -q "^999:.*10.99.0.0/24 blackhole" "$RU" && ok "the guard STAYS after a rejected run (guests stay blackholed)" \
  || no "the guard was lifted despite the failure - traffic could fall through to the LAN"

echo
printf -- '---- %d PASS, %d FAIL ----\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
