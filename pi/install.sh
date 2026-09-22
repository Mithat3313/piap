#!/bin/bash
# =============================================================================
#  PiAP installer — runs as root on Raspberry Pi OS / Debian 12+. Idempotent.
#    sudo ./install.sh [--lan-if eth0] [--disable-nftables]
#  Installs packages, /opt/ap-vpn (bin/lib/web/templates), /etc/ap-vpn/ap.env, the systemd
#  units, the web certificate + password and the BLE access key. It does NOT create a
#  radio/slot: after installing, run  sudo ap-slot-new.sh ap0 wlan0 5  for the first SSID.
# =============================================================================
set -euo pipefail
SRC=$(cd "$(dirname "$0")" && pwd)
LAN_IF=""; DISABLE_NFT=0
while [ $# -gt 0 ]; do case "$1" in
  --lan-if) LAN_IF=$2; shift 2;; --disable-nftables) DISABLE_NFT=1; shift;;
  *) echo "unknown option: $1" >&2; exit 2;; esac; done
die(){ echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "root required: sudo ./install.sh"
command -v apt-get >/dev/null || die "a Debian-based system is required"
[ -d "$SRC/opt/ap-vpn/bin" ] || die "source not found: $SRC/opt/ap-vpn"

echo "########## 0) pre-flight ##########"
LAN_IF=${LAN_IF:-$(ip -o -4 route show default | awk '{print $5; exit}')}
[ -n "$LAN_IF" ] || die "no default route; pass the LAN interface with --lan-if"
echo "  LAN interface: $LAN_IF ($(ip -4 -o addr show dev "$LAN_IF" | awk '{print $4}' | head -1))"
if systemctl is-enabled --quiet nftables.service 2>/dev/null; then
  if [ "$DISABLE_NFT" = 1 ]; then systemctl disable --now nftables.service; echo "  nftables.service disabled"
  else die "nftables.service is ENABLED. /etc/nftables.conf runs 'flush ruleset', which wipes Docker's tables and the kill switch. Re-run with --disable-nftables to turn it off."; fi
fi

echo "########## 1) packages ##########"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq hostapd dnsmasq wireguard-tools iptables bluez iw rfkill curl openssl conntrack \
  python3 python3-flask python3-dbus python3-gi python3-cryptography >/dev/null
# The system-wide hostapd/dnsmasq units are not used; every slot has its own units.
systemctl disable --now hostapd.service dnsmasq.service >/dev/null 2>&1 || true
echo "  done"

echo "########## 2) files ##########"
install -d -m 0755 /opt/ap-vpn/bin /opt/ap-vpn/lib /opt/ap-vpn/web /opt/ap-vpn/templates
install -d -m 0700 /opt/ap-vpn/backup /etc/ap-vpn/profiles
install -d -m 0755 /etc/ap-vpn/slots /run/ap-vpn
install -m 0755 "$SRC"/opt/ap-vpn/bin/* /opt/ap-vpn/bin/
install -m 0644 "$SRC"/opt/ap-vpn/lib/apctl.py /opt/ap-vpn/lib/
install -m 0644 "$SRC"/opt/ap-vpn/web/index.html /opt/ap-vpn/web/
install -m 0644 "$SRC"/opt/ap-vpn/templates/* /opt/ap-vpn/templates/
ln -sf /opt/ap-vpn/bin/ap-ctl /usr/local/sbin/ap-ctl
ln -sf /opt/ap-vpn/bin/ap-slot-new.sh /usr/local/sbin/ap-slot-new.sh
if [ ! -f /etc/ap-vpn/ap.env ]; then
  sed "s|__LAN_IF__|$LAN_IF|" /opt/ap-vpn/templates/ap.env > /etc/ap-vpn/ap.env; echo "  /etc/ap-vpn/ap.env created"
else echo "  /etc/ap-vpn/ap.env already exists (left untouched)"; fi
echo "  /opt/ap-vpn ready"

echo "########## 3) systemd ##########"
install -m 0644 "$SRC"/systemd/ap-*.service "$SRC"/systemd/ap-*.timer /etc/systemd/system/
if command -v docker >/dev/null 2>&1; then
  install -d /etc/systemd/system/docker.service.d
  install -m 0644 "$SRC"/systemd/docker-10-ap-firewall.conf /etc/systemd/system/docker.service.d/10-ap-firewall.conf
  echo "  Docker found: drop-in for the DOCKER-USER hook installed"
fi
systemctl daemon-reload
systemctl enable ap-firewall.service ap-watchdog.timer ap-bootcheck.timer ap-web.service ap-ble-agent.service >/dev/null 2>&1
echo "  units installed and enabled"

echo "########## 4) web panel: certificate + password ##########"
if [ ! -f /etc/ap-vpn/web-cert.pem ]; then
  LAN_IP=$(ip -4 -o addr show dev "$LAN_IF" | awk '{print $4}' | cut -d/ -f1 | head -1)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -keyout /etc/ap-vpn/web-key.pem -out /etc/ap-vpn/web-cert.pem -subj "/CN=PiAP" \
    -addext "subjectAltName=DNS:$(hostname),DNS:$(hostname).local${LAN_IP:+,IP:$LAN_IP}" >/dev/null 2>&1
  chmod 600 /etc/ap-vpn/web-key.pem; chmod 644 /etc/ap-vpn/web-cert.pem
  echo "  certificate generated (self-signed, 10 years)"
else echo "  certificate already exists"; fi
if [ ! -f /etc/ap-vpn/web-password ]; then
  WEBPW=$(/opt/ap-vpn/bin/ap-ctl web password | python3 -c "import json,sys; print(json.load(sys.stdin)['password'])")
else WEBPW="(unchanged; to set a new one: sudo ap-ctl web password)"; fi
systemctl restart ap-web.service

echo "########## 5) Bluetooth agent: access key ##########"
BLETOK=$(/opt/ap-vpn/bin/ap-ctl ble token | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
systemctl restart ap-ble-agent.service || true
systemctl start ap-watchdog.timer ap-bootcheck.timer >/dev/null 2>&1 || true

echo
echo "########## INSTALLATION COMPLETE ##########"
echo "  Web panel:        https://$(ip -4 -o addr show dev "$LAN_IF" | awk '{print $4}' | cut -d/ -f1 | head -1):$(. /etc/ap-vpn/ap.env; echo "${WEB_PORT:-8443}")"
echo "  Web password:     $WEBPW"
echo "  BLE access key:   $BLETOK   (shown again by: ap-ctl ble token)"
echo
echo "  First SSID:   sudo ap-slot-new.sh ap0 wlan0 5"
echo "  VPN profile:  sudo ap-ctl vpn add <name> /path/client.conf"
echo "                sudo ap-ctl --slot ap0 vpn activate <name> --confirm '<SSID>'"
echo "  Verify:       sudo ap-ctl --slot ap0 verify"
