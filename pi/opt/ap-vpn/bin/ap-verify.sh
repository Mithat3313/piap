#!/bin/bash
# /opt/ap-vpn/bin/ap-verify.sh - her iddiayi ciktisi kanit olan bir komuta cevirir.
# SALT OKUNUR. Hicbir FAIL yoksa exit 0.
set -u
. /etc/ap-vpn/ap.env
SLOT=ap0; for _a in "$@"; do case "$_a" in --slot=*) SLOT="${_a#--slot=}";; esac; done; [ -r "/etc/ap-vpn/slots/$SLOT.env" ] && . "/etc/ap-vpn/slots/$SLOT.env"; export SLOT
LAN_IP=$(/usr/sbin/ip -4 -o addr show dev "$LAN_IF" 2>/dev/null | awk "{print \$4}" | cut -d/ -f1 | head -1); LAN_IP=${LAN_IP:-127.0.0.1}
LAN_GW=${LAN_GW:-$(/usr/sbin/ip -o -4 route show default 2>/dev/null | awk '{print $3; exit}')}
IP=/usr/sbin/ip; IPT=/usr/sbin/iptables; IP6T=/usr/sbin/ip6tables; WG=/usr/bin/wg
p=0; f=0
P(){ printf '  PASS  %s\n' "$1"; p=$((p+1)); }
F(){ printf '  FAIL  %s\n' "$1"; f=$((f+1)); }
H(){ printf '\n== %s ==\n' "$1"; }

H "1. HOST YOLU DOKUNULMADI (en sert kisit)"
ip route get 1.1.1.1 2>&1 | grep -q "dev $LAN_IF" \
  && P "Pi'nin kendi default rotasi hala $LAN_IF" \
  || F "HOST ELE GECIRILDI: $(ip route get 1.1.1.1 2>&1) - Pi'nin kendi servisleri etkilenir"
ip -4 route show table main | grep -qw "$WG_IF" \
  && F "table main icinde $WG_IF rotasi var (Table=off tutmamis)" \
  || P "table main'de $WG_IF yok"
$WG show "$WG_IF" fwmark 2>/dev/null | grep -qv off \
  && F "wg-quick fwmark kurmus" || P "fwmark yok (Table=off dogru)"
[ "$(/usr/sbin/sysctl -n net.ipv4.conf.all.src_valid_mark 2>/dev/null)" = 0 ] \
  && P "src_valid_mark hala 0" || F "src_valid_mark degismis"
grep -q "$LAN_GW" /etc/resolv.conf \
  && P "host resolv.conf hala $LAN_GW" || F "host resolv.conf degismis (wg-quick DNS= ezmis olabilir)"
# Pi'nin kendi servisleri: ap.env icinde HOST_CHECKS="http:8123 tcp:1883" gibi (bos = atla)
for hc in ${HOST_CHECKS:-}; do
  hp=${hc##*:}
  case "$hc" in
    http:*) curl -s -o /dev/null -m 8 "http://${LAN_IP}:${hp}/" && P "host http:$hp LAN'dan cevap veriyor" || F "host http:$hp cevap vermiyor";;
    tcp:*)  /usr/bin/ss -lntH "sport = :$hp" | grep -q ":$hp" && P "host tcp:$hp dinliyor" || F "host tcp:$hp dinlemiyor";;
  esac
done
if command -v docker >/dev/null 2>&1; then
  [ "$($IPT -t nat -S POSTROUTING | grep -c '172.17.0.0/16')" = 1 ] \
    && P "Docker masquerade bozulmamis" || F "Docker masquerade sayisi beklenmedik"
fi

H "2. MISAFIR YOLU SADECE TUNELDEN"
$IP rule show | grep -q "^${PRIO_APNET}:.*from ${AP_NET} lookup ${TABLE}" \
  && P "rule ${PRIO_APNET} ($AP_NET -> $TABLE)" || F "rule ${PRIO_APNET} YOK"
$IP rule show | grep -q "from ${AP_NET} blackhole" \
  && P "blackhole kurali VAR (bos tablo main'e DUSMEZ)" \
  || F "BLACKHOLE YOK = SIZINTI. Bos tablo kural degerlendirmesini durdurmaz, paket main'e ve ISP'ye duser."
$IP route show table "$TABLE" | grep -q "^${AP_NET} dev ${AP_IF}" \
  && P "AP link rotasi tabloda (dnsmasq cevaplari tunele gitmiyor)" \
  || F "AP link rotasi YOK - istemciler isim cozemez"
if $IP link show "$WG_IF" >/dev/null 2>&1; then
  ip route get 1.1.1.1 from "$AP_TEST_SRC" iif "$AP_IF" 2>&1 | grep -q "dev $WG_IF" \
    && P "misafir kaynakli paket $WG_IF'e gidiyor" \
    || F "misafir paketi $WG_IF'e GITMIYOR: $(ip route get 1.1.1.1 from $AP_TEST_SRC iif $AP_IF 2>&1)"
else
  echo "  INFO  $WG_IF yok - misafir trafigi blackhole'da (kill-switch calisiyor)"
fi
ip route get "$AP_TEST_SRC" from "$AP_GW" 2>&1 | grep -q "dev $AP_IF" \
  && P "AP->AP cevaplari $AP_IF'te kaliyor" || F "AP->AP cevaplari yanlis yolda"
$IPT -C DOCKER-USER -j AP-VPN-FWD 2>/dev/null && P "DOCKER-USER -> AP-VPN-FWD bagli" || F "DOCKER-USER hook YOK"
$IPT -C AP-VPN-FWD -i "$AP_IF" -j DROP 2>/dev/null && P "kill-switch filtre kurali var" || F "kill-switch filtre kurali YOK"
$IPT -t nat -C AP-VPN-POST -s "$AP_NET" -o "$WG_IF" -j MASQUERADE 2>/dev/null \
  && P "masquerade var" || F "masquerade YOK - dugum 10.99.0.x paketlerini atar"
NAT_PKT=$($IPT -t nat -vxnL AP-VPN-POST | awk '/MASQUERADE/{print $1; exit}')
[ "${NAT_PKT:-0}" -gt 0 ] 2>/dev/null && P "masquerade sayaci ${NAT_PKT} paket (gercekten calisiyor)" \
  || echo "  INFO  masquerade sayaci 0 - misafir trafigi uret ve tekrar calistir"

H "3. RP_FILTER (1 OLMAMALI)"
bad=0
for k in all default "$AP_IF" "$WG_IF" "$LAN_IF"; do
  v=$(/usr/sbin/sysctl -n "net.ipv4.conf.$k.rp_filter" 2>/dev/null)
  printf '       %-8s = %s\n' "$k" "${v:-yok}"
  [ "${v:-0}" = 1 ] && bad=1
done
[ $bad = 0 ] && P "rp_filter hicbir yerde 1 degil" \
  || F "rp_filter=1 (STRICT): $WG_IF'ten donen trafik sessizce dusar; semptom 'handshake taze, hicbir sey calismiyor'"

H "4. MSS / MTU"
M=$(cat /sys/class/net/$WG_IF/mtu 2>/dev/null); EXP=$((${M:-1420}-40))
printf '       %s mtu=%s beklenen mss=%s\n' "$WG_IF" "${M:-yok}" "$EXP"
[ "$($IPT -t mangle -S AP-VPN-MSS | grep -c "$WG_IF .*set-mss $EXP")" = 2 ] \
  && P "MSS iki yonde de $EXP (canli MTU'dan turetildi)" \
  || F "MSS clamp yanlis/eksik: buyuk HTTPS indirmeleri sessizce takilir"

H "5. IPv6 KAPALI"
[ "$(/usr/sbin/sysctl -n net.ipv6.conf.$AP_IF.disable_ipv6 2>/dev/null)" = 1 ] \
  && P "$AP_IF uzerinde IPv6 kapali" || F "$AP_IF uzerinde IPv6 ACIK - v4 kill-switch'in kapsamadigi yol"
[ -z "$($IP -6 addr show dev $AP_IF 2>/dev/null | grep inet6)" ] \
  && P "$AP_IF'te IPv6 adresi yok" || F "$AP_IF'te IPv6 adresi var"
[ "$($IP6T -S INPUT   | grep -c 'AP-VPN v6-in')"  = 0 ] && P "ip6 INPUT'ta artik kayit yok"  || F "ip6 INPUT'ta v1 artigi kaldi"
[ "$($IP6T -S FORWARD | grep -c 'AP-VPN v6-fwd')" = 0 ] && P "ip6 FORWARD'da artik kayit yok" || F "ip6 FORWARD'da v1 artigi kaldi"
$IP6T -C INPUT -j AP-VPN-6 2>/dev/null && P "AP-VPN-6 zinciri bagli" || F "AP-VPN-6 bagli degil"

H "6. MISAFIR IZOLASYONU (Pi servisleri)"
$IPT -C AP-VPN-IN -i "$AP_IF" -j DROP 2>/dev/null \
  && P "AP-VPN-IN sonunda DROP (SSH, web, MQTT, mDNS vb. kapali)" || F "INPUT DROP YOK"
for pr in 67:udp 53:udp 53:tcp; do
  pt=${pr%%:*}; pp=${pr##*:}
  $IPT -C AP-VPN-IN -i "$AP_IF" -p "$pp" --dport "$pt" -j ACCEPT 2>/dev/null \
    && P "DROP oncesi $pp/$pt ACCEPT var" || F "$pp/$pt ACCEPT eksik - istemci lease/DNS alamaz"
done
grep -qE '^\s*ap_isolate=1' /etc/hostapd/$SLOT.conf \
  && P "hostapd ap_isolate=1 (istemci-istemci radyoda engelli)" \
  || F "ap_isolate!=1 - misafirler birbirine ulasir, firewall bunu goremez (L2, IP yiginina hic girmez)"
grep -qE '^\s*deny-interfaces=wlan0' /etc/avahi/avahi-daemon.conf \
  && P "avahi wlan0'a duyuru yapmiyor" || F "avahi wlan0'da - misafire tum LAN envanterini verir"

H "7. NFTABLES SERVISI (KAPALI KALMALI)"
[ "$(systemctl is-enabled nftables 2>/dev/null)" = disabled ] \
  && P "nftables.service disabled" \
  || F "nftables.service enabled: /etc/nftables.conf 'flush ruleset' ile basliyor, Docker'in TUM tablolarini ve kill-switch'i siler"

H "8. TUNEL SAGLIGI"
if $WG show "$WG_IF" >/dev/null 2>&1; then
  now=$(date +%s); best=999999
  while read -r _k t; do [ -n "${t:-}" ] || continue; [ "$t" = 0 ] && continue
    a=$((now-t)); [ $a -lt $best ] && best=$a; done < <($WG show "$WG_IF" latest-handshakes)
  [ $best -lt 999999 ] && [ $best -le "$HS_MAX_AGE" ] \
    && P "handshake ${best}s once (<= ${HS_MAX_AGE}s)" \
    || F "handshake ${best}s - BAYAT (veya hic olmamis)"
  $WG show "$WG_IF" transfer | sed 's/^/       /'
else
  echo "  INFO  $WG_IF yok"
fi

H "9. KALICILIK"
bad=0
for u in ap-wlan@$SLOT ap-firewall $HOSTAPD_UNIT $DNSMASQ_UNIT wg-quick@$WG_IF ap-watchdog.timer ap-bootcheck.timer; do
  e=$(systemctl is-enabled "$u" 2>&1); a=$(systemctl is-active "$u" 2>&1)
  printf '       %-22s enabled=%-10s active=%s\n' "$u" "$e" "$a"
  case "$e" in enabled|enabled-runtime|static) :;; *) bad=1;; esac
  case "$u" in *timer) :;; *) [ "$a" = active ] || bad=1;; esac
done
[ $bad = 0 ] && P "her unit enabled ve calisiyor" || F "en az bir unit enabled/active degil - reboot'ta geri gelmez"
systemctl --failed --no-legend | sed 's/^/       /'

H "10. ATAMA SABITLEME (SSID <-> profil <-> sunucu anahtari <-> radyo)"
msg=$(/opt/ap-vpn/bin/ap-pin.sh check "$SLOT") && P "sabit tutuyor: $msg" || F "SABIT IHLALI: $msg"
grep -q '^PIN_PROFILE=.\+' "/etc/ap-vpn/slots/$SLOT.env" && P "slot sabitlenmis (PIN_PROFILE)" || F "slot sabitlenmemis: ap-ctl --slot $SLOT slot pin --confirm '<SSID>'"
grep -q '^AP_MAC=.\+' "/etc/ap-vpn/slots/$SLOT.env" && P "radyo MAC sabit (AP_MAC)" || F "AP_MAC yok"
grep -q 'ap-pin.sh check' /etc/systemd/system/ap-hostapd@.service && P "hostapd baslarken sabit denetimi (ExecStartPre)" || F "ap-hostapd@ sabit denetimi YOK"
grep -q 'ap-pin.sh enforce' /opt/ap-vpn/bin/ap-watchdog.sh && P "watchdog 30 sn'de bir sabit uyguluyor" || F "watchdog enforce YOK"
[ -f "/run/ap-vpn/$SLOT/pin-violation" ] && F "ihlal bayragi duruyor: $(cat /run/ap-vpn/$SLOT/pin-violation)" || P "ihlal bayragi yok"

printf '\n---- %d PASS, %d FAIL ----\n' "$p" "$f"
[ "$f" -eq 0 ]
