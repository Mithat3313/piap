#!/bin/bash
# =============================================================================
#  tests/confirm-dryrun.sh — the typed confirmation that guards every change of a slot's exit.
#  Runs apctl's own _require_confirm against temporary hostapd configs; no root, no hardware.
#
#    ./tests/confirm-dryrun.sh
#
#  What it protects: this gate is the only thing standing between a mis-click and an SSID changing
#  which tunnel (or no tunnel) it exits through. It has to refuse anything that is not the SSID, and
#  it must never refuse EVERYTHING either - an SSID nobody can type would freeze the slot's settings.
# =============================================================================
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
exec python3 - "$HERE/../pi/opt/ap-vpn/lib" <<'PY'
import sys, os, tempfile
sys.path.insert(0, sys.argv[1])
import apctl

d = tempfile.mkdtemp(); os.makedirs(d + '/hostapd', exist_ok=True)
apctl._hostapd_path = lambda s: f"{d}/hostapd/{s['SLOT']}.conf"
slot = {'SLOT': 'ap0'}; other = {'SLOT': 'ap1'}
def write(name, ssid): open(f"{d}/hostapd/{name}.conf", 'w').write(f"interface=wlan0\nssid={ssid}\n")

ok = fail = 0
def check(name, fn, want_ok):
    global ok, fail
    err = ''
    try: fn(); got = True
    except apctl.ApError as e: got, err = False, str(e)
    if got == want_ok: print('  PASS ', name); ok += 1
    else: print('  FAIL ', name, err); fail += 1

write('ap0', ' guest ')          # hostapd keeps leading/trailing spaces verbatim
check('a padded SSID is confirmable with the text a person sees', lambda: apctl._require_confirm('guest', slot), True)
check('the padded form is accepted as well', lambda: apctl._require_confirm('  guest  ', slot), True)
check('a different SSID is refused', lambda: apctl._require_confirm('other', slot), False)

write('ap0', 'office_nomap')
check('the exact SSID is accepted', lambda: apctl._require_confirm('office_nomap', slot), True)
check('an empty confirmation is refused', lambda: apctl._require_confirm('', slot), False)
check('None is refused', lambda: apctl._require_confirm(None, slot), False)
check('a prefix is refused', lambda: apctl._require_confirm('office', slot), False)

write('ap1', 'guest_nomap')
check('two affected SSIDs must both be typed, in order',
      lambda: apctl._require_confirm('office_nomap / guest_nomap', slot, other), True)
check('the wrong order is refused',
      lambda: apctl._require_confirm('guest_nomap / office_nomap', slot, other), False)
check('only one of the two is refused',
      lambda: apctl._require_confirm('office_nomap', slot, other), False)

os.unlink(f"{d}/hostapd/ap0.conf")   # the SSID cannot be read at all
check('an unreadable SSID refuses everything, including the empty string',
      lambda: apctl._require_confirm('', slot), False)
check('...and refuses a plausible guess too', lambda: apctl._require_confirm('office_nomap', slot), False)

print(f'\n---- {ok} PASS, {fail} FAIL ----')
sys.exit(1 if fail else 0)
PY
