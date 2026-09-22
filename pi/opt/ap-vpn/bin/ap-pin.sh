#!/bin/bash
# =============================================================================
#  /opt/ap-vpn/bin/ap-pin.sh — ATAMA SABITLEME (SSID <-> profil <-> sunucu anahtari <-> radyo MAC)
#  Amac: yayin/VPN eslesmesi kullanici ELLE degistirmedikce degisemez. Sabit, slot
#  env'inde durur (PIN_SSID_HEX, PIN_PROFILE, PIN_PEER, AP_MAC) ve onu yalnizca apctl
#  (yazili onaydan sonra) gunceller. Bu script SALT OKUNUR denetim + fail-closed uygulama:
#    check <slot>   canli durum sabitle esleşiyor mu (exit 0/1; sebep stdout)  [ap-hostapd@ ExecStartPre]
#    iface <slot>   radyo MAC'i AP_MAC ile esleşiyor mu (exit 0/1)             [ap-wlan@ ExecStartPre]
#    enforce        etkin slotlar; ihlalde hostapd DURDURULUR (SSID kapanir)    [ap-watchdog, 30 sn'de bir]
#  Sabitsiz slot (PIN_PROFILE bos = profil koparilmis): tunel de KAPALI olmali.
#  Uzun islem kilidi (/run/ap-vpn/long.lock) tutuluyorsa enforce denetim yapmaz (gecici ara durumlar).
# =============================================================================
set -u
WG=/usr/bin/wg; SLOTS=/etc/ap-vpn/slots; PROFILES=/etc/ap-vpn/profiles; LOCK=/run/ap-vpn/long.lock
load(){ unset ENABLED AP_IF WG_IF PROFILE PIN_SSID_HEX PIN_PROFILE PIN_PEER AP_MAC HOSTAPD_UNIT
        . "$SLOTS/$1.env" || return 1; HOSTAPD_UNIT=${HOSTAPD_UNIT:-ap-hostapd@$1}; }
pubkey_of(){ sed -nE 's/^[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*([^[:space:]#]+).*/\1/p' "$1" 2>/dev/null | head -1; }
ssid_hex(){ sed -n 's/^ssid=//p' "/etc/hostapd/$1.conf" 2>/dev/null | head -1 | tr -d '\n' | od -An -v -tx1 | tr -d ' \n'; }
hex2s(){ printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
live_peer(){ $WG show "$1" peers 2>/dev/null | head -1; }

iface_check(){ load "$1" || { echo "slot env okunamadi"; return 1; }
  [ -z "${AP_MAC:-}" ] && { echo "radyo sabitlenmemis (AP_MAC bos)"; return 0; }
  local mac; mac=$(cat "/sys/class/net/$AP_IF/address" 2>/dev/null)
  [ "$mac" = "$AP_MAC" ] && { echo "radyo $AP_IF=$mac sabit"; return 0; }
  echo "RADYO FARKLI: $AP_IF=${mac:-yok} sabit=$AP_MAC (adaptor/ad degismis)"; return 1; }

check(){ load "$1" || { echo "slot env okunamadi"; return 1; }
  local m; m=$(iface_check "$1") || { echo "$m"; return 1; }
  local lp; lp=$(live_peer "$WG_IF")
  if [ -z "${PIN_PROFILE:-}" ]; then
    [ -z "${PROFILE:-}" ] || { echo "sabit yok ama PROFILE=$PROFILE (sabitleyin: ap-ctl --slot $1 slot pin)"; return 1; }
    [ -z "$lp" ] || { echo "sabit yok ama $WG_IF ayakta (peer ${lp:0:8}...) - tunel kapatilmali"; return 1; }
    echo "profil atanmamis, tunel kapali"; return 0
  fi
  [ "${PROFILE:-}" = "$PIN_PROFILE" ] || { echo "PROFILE='${PROFILE:-}' sabit='$PIN_PROFILE'"; return 1; }
  local sh; sh=$(ssid_hex "$1")
  [ "$sh" = "${PIN_SSID_HEX:-}" ] || { echo "SSID '$(hex2s "$sh")' sabit '$(hex2s "${PIN_SSID_HEX:-}")'"; return 1; }
  local pp; pp=$(pubkey_of "$PROFILES/$PIN_PROFILE.conf")
  [ -n "$pp" ] || { echo "profil dosyasi yok/anahtarsiz: $PIN_PROFILE"; return 1; }
  [ "$pp" = "$PIN_PEER" ] || { echo "profil '$PIN_PROFILE' icindeki sunucu anahtari sabitten farkli"; return 1; }
  local cp; cp=$(pubkey_of "/etc/wireguard/$WG_IF.conf")
  [ "$cp" = "$PIN_PEER" ] || { echo "$WG_IF.conf sunucu anahtari sabitten farkli"; return 1; }
  [ -z "$lp" ] || [ "$lp" = "$PIN_PEER" ] || { echo "$WG_IF CANLI peer sabitten farkli"; return 1; }
  echo "$(hex2s "$sh") -> $PIN_PROFILE (${PIN_PEER:0:8}...) [$AP_IF $AP_MAC]"; return 0; }

enforce(){ mkdir -p /run/ap-vpn
  exec 9>>"$LOCK"; if ! flock -n 9; then echo "uzun islem suruyor, denetim atlandi"; return 0; fi
  local rc=0 s msg r st f
  for f in "$SLOTS"/*.env; do s=$(basename "$f" .env); grep -q '^ENABLED=1' "$f" || continue
    st=/run/ap-vpn/$s; mkdir -p "$st"
    msg=$(check "$s"); r=$?; load "$s"
    if [ $r -ne 0 ]; then rc=1; echo "$msg" > "$st/pin-violation"
      if systemctl is-active --quiet "$HOSTAPD_UNIT"; then
        logger -t ap-pin -p daemon.err "$s ATAMA IHLALI: $msg -> $HOSTAPD_UNIT durduruluyor (fail-closed)"
        systemctl stop "$HOSTAPD_UNIT"; fi
      if [ -z "${PIN_PROFILE:-}" ] && [ -d "/sys/class/net/$WG_IF" ]; then
        logger -t ap-pin -p daemon.err "$s sabitsiz slotta $WG_IF ayakta -> kapatiliyor"; systemctl stop "wg-quick@$WG_IF"; fi
      echo "$s IHLAL: $msg"
    else rm -f "$st/pin-violation"; echo "$s ok: $msg"; fi
  done
  flock -u 9; return $rc; }

case "${1:-}" in
  check)   [ -n "${2:-}" ] || { echo "slot?"; exit 2; }; check "$2";;
  iface)   [ -n "${2:-}" ] || { echo "slot?"; exit 2; }; iface_check "$2";;
  enforce) enforce;;
  *) echo "kullanim: $0 check <slot> | iface <slot> | enforce"; exit 2;;
esac
