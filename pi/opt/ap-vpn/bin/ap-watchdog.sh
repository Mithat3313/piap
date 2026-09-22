#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-watchdog.sh  (v2)
#  Tunel "sessizce olu" olabilir: wg0 ayakta, kurallar esliyor, paketler
#  bosluga gidiyor. Bunu firewall YAKALAYAMAZ - ama SIZINTI DA YOK:
#  paket wg0'a girip kaybolur, ISP'ye gitmez. Bu script KURTARMA yapar,
#  KORUMA yapmaz. Korumanin tamami yapisaldir (blackhole + AP-VPN-FWD).
#  v2: esik 180 -> 300 (yanlis alarm), flap koruma (cooldown), rota
#      dogrulamasi (wg-quick restart tablodaki default'u siler!).
# =============================================================================
set -u
. /etc/ap-vpn/ap.env
# AP_WATCHDOG_SLOT_LOOP: --slot verilmediyse her etkin slot icin kendini cagir
if ! printf "%s\n" "$@" | grep -q "^--slot="; then /opt/ap-vpn/bin/ap-pin.sh enforce >/dev/null 2>&1; rc=0; for f in /etc/ap-vpn/slots/*.env; do grep -q "^ENABLED=1" "$f" && { "$0" --slot=$(basename "$f" .env) || rc=1; }; done; exit $rc; fi
SLOT=ap0; for _a in "$@"; do case "$_a" in --slot=*) SLOT="${_a#--slot=}";; esac; done; [ -r "/etc/ap-vpn/slots/$SLOT.env" ] && . "/etc/ap-vpn/slots/$SLOT.env"; export SLOT
IP=/usr/sbin/ip
WG=/usr/bin/wg
STATE=/run/ap-vpn/$SLOT
mkdir -p "$STATE"
LASTR="$STATE/last_restart"
[ -f "$LASTR" ] || echo 0 > "$LASTR"

# --- 1. wg0 hic yok mu? ---
if [ ! -d "/sys/class/net/$WG_IF" ]; then
  logger -t ap-watchdog "$WG_IF yok - wg-quick@$WG_IF baslatiliyor"
  systemctl start "wg-quick@${WG_IF}.service"
  sleep 3
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1
  exit 0
fi

# --- 2. Kill-switch butunlugu (routing katmani) ---
# wg-quick restart wg0'i silip yeniden yaratir; cihaza bagli rotalar kernel
# tarafindan silinir ve Table=off yuzunden GERI GELMEZ. Bu sessizce
# "tunel saglikli ama tum misafirler blackhole'da" durumunu uretir.
if ! $IP route show table "$TABLE" | grep -q "^default dev $WG_IF"; then
  logger -t ap-watchdog -p daemon.warning "table $TABLE icinde $WG_IF default rotasi yok - firewall yeniden uygulaniyor"
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1
fi
if ! $IP rule show | grep -q "from ${AP_NET} blackhole"; then
  logger -t ap-watchdog -p daemon.err "KILL-SWITCH BOZUK: blackhole kurali yok - firewall yeniden uygulaniyor"
  /opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1
fi

# --- 3. Handshake yasi ---
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

# --- 4. Bayat: cooldown ile restart ---
LAST=$(cat "$LASTR" 2>/dev/null || echo 0)
if [ $((NOW-LAST)) -lt "$RESTART_COOLDOWN" ]; then
  logger -t ap-watchdog -p daemon.warning "handshake bayat (${BEST}s) ama cooldown aktif ($((RESTART_COOLDOWN-(NOW-LAST)))s kaldi) - restart yok"
  exit 0
fi
echo "$NOW" > "$LASTR"
logger -t ap-watchdog -p daemon.err "handshake ${BEST}s (> ${HS_MAX_AGE}s) - wg-quick@${WG_IF} yeniden kuruluyor"
systemctl restart "wg-quick@${WG_IF}.service" \
  || logger -t ap-watchdog -p daemon.err "wg-quick restart BASARISIZ - misafirler fail-closed kaliyor"
sleep 3
# ZORUNLU: restart tablodaki default rotayi ve WG_SRC'yi degistirmis olabilir.
/opt/ap-vpn/bin/ap-firewall.sh >/dev/null 2>&1 \
  || logger -t ap-watchdog -p daemon.err "ap-firewall.sh restart sonrasi BASARISIZ"
command -v conntrack >/dev/null && conntrack -D -s "$AP_NET" >/dev/null 2>&1
logger -t ap-watchdog "yeniden kurulum tamam"
exit 0
