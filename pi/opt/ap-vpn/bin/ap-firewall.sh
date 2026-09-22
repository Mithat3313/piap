#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-firewall.sh   (v4 — COKLU SLOT)
#  Her slot = {AP_IF, AP_NET, WG_IF, TABLE, PRIO_*}. Slot dosyalari:
#      /etc/ap-vpn/slots/<slot>.env   (ENABLED=1 olanlar islenir)
#  Garanti: slot X'in istemcileri SADECE slot X'in tunelinden cikar.
#    - wlanX -> wgX ACCEPT, wlanX -> (baska her sey) DROP  => capraz slot sizintisi imkansiz
#    - her slotun kendi routing tablosu + blackhole kurali (tunel dusunce main'e DUSMEZ)
#  Zincirler ortak, kurallar slot basina. Idempotent: zincirler flush + yeniden.
#  Sonda slot basina self-check; biri bile eksikse exit 1 -> hostapd@* baslamaz.
# =============================================================================
set -u
. /etc/ap-vpn/ap.env
IPT=/usr/sbin/iptables; IP6T=/usr/sbin/ip6tables; IP=/usr/sbin/ip; SYSCTL=/usr/sbin/sysctl
SLOTS_DIR=/etc/ap-vpn/slots

die(){ logger -t ap-firewall -p daemon.err "HATA: $*"; echo "ap-firewall: HATA: $*" >&2; exit 1; }
mkchain(){ $IPT -t "$1" -N "$2" 2>/dev/null || $IPT -t "$1" -F "$2"; }
hook(){    $IPT -t "$1" -C "$2" -j "$3" 2>/dev/null || $IPT -t "$1" -I "$2" 1 -j "$3"; }

# ------------------------------------------------------------- 0. global on-ucus
DEF_IF=$($IP -o -4 route show default | awk '{print $5; exit}')
[ -n "$DEF_IF" ] || die "default route yok - hicbir seye dokunmuyorum"
if systemctl is-enabled --quiet nftables.service 2>/dev/null; then
  die "nftables.service ENABLED - /etc/nftables.conf flush ruleset ile Docker tablolarini ve kill-switch'i siler"
fi
SLOT_FILES=$(ls "$SLOTS_DIR"/*.env 2>/dev/null) || true
[ -n "$SLOT_FILES" ] || die "hic slot yok ($SLOTS_DIR)"

# slot env'ini alt kabukta degil, degiskenleri temizleyerek yukle
load_slot(){
  unset AP_IF AP_NET AP_GW AP_ADDR WG_IF TABLE PRIO_WGSRC PRIO_APNET PRIO_BLACKHOLE ENABLED PROFILE AP_TEST_SRC
  . "$1"
  SLOT=$(basename "$1" .env)
  : "${ENABLED:=1}"
  [ "$AP_IF" != "$LAN_IF" ] || die "$SLOT: AP_IF ile LAN_IF ayni"
  [ "$AP_IF" != "$DEF_IF" ]  || die "$SLOT: default route $AP_IF uzerinde - SSH'i keserdi"
  LAN_PFX=$($IP -4 -o addr show dev "$LAN_IF" 2>/dev/null | awk '{print $4}' | cut -d. -f1-3 | head -1)
  [ -z "$LAN_PFX" ] || case "$AP_NET" in "$LAN_PFX".*) die "$SLOT: AP_NET LAN agiyla cakisiyor";; esac
  WGCONF=/etc/wireguard/${WG_IF}.conf
  if [ -r "$WGCONF" ]; then
    grep -qiE '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off' "$WGCONF" || die "$WGCONF icinde 'Table = off' yok"
    grep -qiE '^[[:space:]]*DNS[[:space:]]*=' "$WGCONF" && die "$WGCONF icinde DNS= var (resolv.conf'u ezer)"
  fi
  WG_SRC=$($IP -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  if [ -z "${WG_SRC:-}" ] && [ -r "$WGCONF" ]; then
    WG_SRC=$(sed -n 's/^[[:space:]]*[Aa]ddress[[:space:]]*=[[:space:]]*//p' "$WGCONF" | tr ',' '\n' | tr -d ' \r' | grep -v ':' | cut -d/ -f1 | head -1)
  fi
  WG_MTU=$(cat "/sys/class/net/$WG_IF/mtu" 2>/dev/null)
  [ -n "${WG_MTU:-}" ] || WG_MTU=$(sed -n 's/^[[:space:]]*MTU[[:space:]]*=[[:space:]]*//p' "$WGCONF" 2>/dev/null | tr -d ' \r' | head -1)
  [ -n "${WG_MTU:-}" ] || WG_MTU=1420
  MSS=$((WG_MTU - 40))
}

# ------------------------------------------------------------- 1. zincirler (bir kez)
mkchain filter AP-VPN-FWD; mkchain filter AP-VPN-IN
mkchain nat AP-VPN-POST;   mkchain nat AP-VPN-PRE
mkchain mangle AP-VPN-MSS
$SYSCTL -qw net.ipv4.ip_forward=1

# eski tek-slot kurallarini (tum "from ... lookup/blackhole" kurallarimizi) temizle
$IP rule show | awk -F: '$1>=1000 && $1<2000 {print $1}' | sort -u | while read -r pref; do
  while $IP rule del pref "$pref" 2>/dev/null; do :; done
done

# ------------------------------------------------------------- 2. slot basina kurallar
ACTIVE=""
for f in $SLOT_FILES; do
  load_slot "$f"
  [ "$ENABLED" = 1 ] || { logger -t ap-firewall "$SLOT devre disi, atlandi"; continue; }
  ACTIVE="$ACTIVE $SLOT"

  # sysctl (sadece bu slotun arayuzleri)
  $SYSCTL -qw "net.ipv4.conf.$AP_IF.rp_filter=2" 2>/dev/null || true
  $SYSCTL -qw "net.ipv4.conf.$WG_IF.rp_filter=2" 2>/dev/null || true
  $SYSCTL -qw "net.ipv6.conf.$AP_IF.disable_ipv6=1" 2>/dev/null || true
  $SYSCTL -qw "net.ipv6.conf.$AP_IF.accept_ra=0" 2>/dev/null || true

  # routing: once AP'nin yerel rotasi (dnsmasq cevaplari tunele gitmesin), sonra default
  $IP route replace "$AP_NET" dev "$AP_IF" scope link src "$AP_GW" table "$TABLE" 2>/dev/null || true
  if $IP link show "$WG_IF" >/dev/null 2>&1; then
    $IP route replace default dev "$WG_IF" scope link table "$TABLE" 2>/dev/null || true
  fi
  [ -n "${WG_SRC:-}" ] && $IP rule add from "$WG_SRC" lookup "$TABLE" priority "$PRIO_WGSRC"
  $IP rule add from "$AP_NET" lookup "$TABLE" priority "$PRIO_APNET"   || die "$SLOT: rule $PRIO_APNET"
  $IP rule add from "$AP_NET" blackhole priority "$PRIO_BLACKHOLE"      || die "$SLOT: blackhole"
  [ -n "${WG_SRC:-}" ] && $IP rule add from "$WG_SRC" blackhole priority "$PRIO_BLACKHOLE"

  # NAT + DNS zorlama
  $IPT -t nat -A AP-VPN-POST -s "$AP_NET" -o "$WG_IF" -j MASQUERADE
  $IPT -t nat -A AP-VPN-PRE -i "$AP_IF" -p udp --dport 53 -j REDIRECT --to-ports 53
  $IPT -t nat -A AP-VPN-PRE -i "$AP_IF" -p tcp --dport 53 -j REDIRECT --to-ports 53

  # MSS (iki yonde sabit, bu tunelin MTU'sundan)
  $IPT -t mangle -A AP-VPN-MSS -o "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"
  $IPT -t mangle -A AP-VPN-MSS -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS"

  # FORWARD: ozel aglar DROP -> kendi tuneline ACCEPT -> geri donus ACCEPT -> HER SEY DROP
  for N in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 169.254.0.0/16 100.64.0.0/10; do
    $IPT -A AP-VPN-FWD -i "$AP_IF" -d "$N" -j DROP
  done
  $IPT -A AP-VPN-FWD -i "$AP_IF" -o "$WG_IF" -j ACCEPT
  $IPT -A AP-VPN-FWD -i "$WG_IF" -o "$AP_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  $IPT -A AP-VPN-FWD -i "$AP_IF" -j DROP                 # KILLSWITCH + capraz-slot + LAN izolasyonu
  $IPT -A AP-VPN-FWD -i "$WG_IF" -o "$AP_IF" -j DROP     # tunelden ice yeni baglanti yok
  $IPT -A AP-VPN-FWD -i "$LAN_IF" -o "$AP_IF" -j DROP

  # INPUT: sadece DHCP + DNS + ping
  $IPT -A AP-VPN-IN -i "$AP_IF" -p udp --dport 67 -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -p udp --dport 53 -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -p tcp --dport 53 -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -p icmp --icmp-type echo-request -j ACCEPT
  $IPT -A AP-VPN-IN -i "$AP_IF" -j DROP
done
[ -n "$ACTIVE" ] || die "etkin slot yok"

# tunel tarafi (VPN sunucusu) Pi'ye YENI baglanti acamaz (web paneli 8443, SSH vb. tunelden gorunmez).
# ESTABLISHED/RELATED (dnsmasq upstream DNS cevaplari, exit-ip curl) etkilenmez. ICMP echo serbest.
$IPT -A AP-VPN-IN -i wg+ -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A AP-VPN-IN -i wg+ -m conntrack --ctstate NEW -j DROP

# ------------------------------------------------------------- 3. bagla
hook filter DOCKER-USER AP-VPN-FWD
hook filter INPUT       AP-VPN-IN
hook nat    POSTROUTING AP-VPN-POST
hook nat    PREROUTING  AP-VPN-PRE
hook mangle FORWARD     AP-VPN-MSS

# ------------------------------------------------------------- 4. IPv6 (tum AP arayuzleri)
$IP6T -N AP-VPN-6 2>/dev/null || $IP6T -F AP-VPN-6
for f in $SLOT_FILES; do
  load_slot "$f"; [ "$ENABLED" = 1 ] || continue
  $IP6T -A AP-VPN-6 -i "$AP_IF" -j DROP; $IP6T -A AP-VPN-6 -o "$AP_IF" -j DROP
done
$IP6T -C INPUT   -j AP-VPN-6 2>/dev/null || $IP6T -I INPUT   1 -j AP-VPN-6
$IP6T -C FORWARD -j AP-VPN-6 2>/dev/null || $IP6T -I FORWARD 1 -j AP-VPN-6

# ------------------------------------------------------------- 5. self-check (slot basina)
fail=""
$IPT -C DOCKER-USER -j AP-VPN-FWD 2>/dev/null || fail="$fail DOCKER-USER-hook"
$IPT -C INPUT -j AP-VPN-IN        2>/dev/null || fail="$fail INPUT-hook"
$IPT -C AP-VPN-IN -i wg+ -m conntrack --ctstate NEW -j DROP 2>/dev/null || fail="$fail tunel-input-drop"
for f in $SLOT_FILES; do
  load_slot "$f"; [ "$ENABLED" = 1 ] || continue
  $IPT -C AP-VPN-FWD -i "$AP_IF" -j DROP                       2>/dev/null || fail="$fail $SLOT:killswitch"
  $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$WG_IF" -j ACCEPT          2>/dev/null || fail="$fail $SLOT:fwd"
  $IPT -C AP-VPN-IN  -i "$AP_IF" -j DROP                       2>/dev/null || fail="$fail $SLOT:input-drop"
  $IPT -t nat -C AP-VPN-POST -s "$AP_NET" -o "$WG_IF" -j MASQUERADE 2>/dev/null || fail="$fail $SLOT:masq"
  $IP rule show | grep -q "from ${AP_NET} lookup ${TABLE}"       || fail="$fail $SLOT:rule"
  $IP rule show | grep -q "from ${AP_NET} blackhole"             || fail="$fail $SLOT:blackhole"
  $IP route show table "$TABLE" | grep -q "^${AP_NET} dev ${AP_IF}" || fail="$fail $SLOT:ap-route"
  [ "$($IPT -t mangle -S AP-VPN-MSS | grep -c "$WG_IF .*set-mss $MSS")" = 2 ] || fail="$fail $SLOT:mss"
  # CAPRAZ SLOT: bu slotun AP'sinden BASKA bir tunele ACCEPT olmamali
  for g in $SLOT_FILES; do
    OTHER_WG=$(sed -n 's/^WG_IF=//p' "$g"); [ "$OTHER_WG" = "$WG_IF" ] && continue
    $IPT -C AP-VPN-FWD -i "$AP_IF" -o "$OTHER_WG" -j ACCEPT 2>/dev/null && fail="$fail $SLOT:CAPRAZ($OTHER_WG)"
  done
done
[ -z "$fail" ] || die "self-check basarisiz:$fail"
logger -t ap-firewall "v4 uygulandi, slotlar:$ACTIVE"
echo "ap-firewall: OK slotlar:$ACTIVE"
exit 0
