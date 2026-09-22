#!/usr/bin/env python3
"""
apctl v2 — Pi5 VPN-AP kontrol katmani (COKLU SLOT).
Slot = bir radyo + bir alt ag + bir WireGuard tuneli. /etc/ap-vpn/slots/<slot>.env
Kutuphane (ap-ble-agent import eder) + CLI (/opt/ap-vpn/bin/ap-ctl). Root gerektirir.
"""
import json, os, re, subprocess, sys, time, secrets, tempfile, shutil, fcntl, contextlib, hashlib, hmac

ENV       = '/etc/ap-vpn/ap.env'
SLOTS_DIR = '/etc/ap-vpn/slots'
PROFILES  = '/etc/ap-vpn/profiles'
TOKEN     = '/etc/ap-vpn/ble-token'
PAIR_FILE = '/run/ap-vpn/ble-pair-until'
SWAP      = '/opt/ap-vpn/bin/ap-swap-peer.sh'
VERIFY    = '/opt/ap-vpn/bin/ap-verify.sh'
FIREWALL  = '/opt/ap-vpn/bin/ap-firewall.sh'
PIN       = '/opt/ap-vpn/bin/ap-pin.sh'
IW, WG, IP, SYSCTL = '/usr/sbin/iw', '/usr/bin/wg', '/usr/sbin/ip', '/usr/bin/systemctl'
SYSTEMD_RUN = '/usr/bin/systemd-run'
_NAME = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z')


class ApError(Exception):
    pass


LONG_LOCK_FILE = '/run/ap-vpn/long.lock'


@contextlib.contextmanager
def long_op(label='islem'):
    """Surecler arasi (BLE ajani + web) uzun islem kilidi. Mesgulse hemen hata."""
    os.makedirs(os.path.dirname(LONG_LOCK_FILE), exist_ok=True)
    fd = os.open(LONG_LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        for _i in range(15):   # ap-pin enforce kilidi <1 sn tutar: kisa bekle, sonra hata
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                if _i == 14:
                    who = os.read(fd, 200).decode(errors='ignore').strip()
                    raise ApError(f'baska bir uzun islem suruyor ({who or "?"}), bekleyin')
                time.sleep(0.2)
        os.ftruncate(fd, 0); os.lseek(fd, 0, 0); os.write(fd, f'{label} pid={os.getpid()} t={int(time.time())}'.encode())
        yield
    finally:
        try: fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception: pass
        os.close(fd)


# ----------------------------------------------------------------- yardimcilar
def _parse_env(path):
    d = {}
    try:
        for line in open(path):
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line: continue
            k, v = line.split('=', 1); d[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return d


def _env():
    d = _parse_env(ENV); d.setdefault('LAN_IF', 'eth0'); return d


def _set_env_key(path, key, value):
    src = open(path).read() if os.path.exists(path) else ''
    line = f'{key}={value}'
    if re.search(rf'^{re.escape(key)}=.*$', src, re.M):
        new = re.sub(rf'^{re.escape(key)}=.*$', lambda m: line, src, count=1, flags=re.M)
    else:
        new = src.rstrip('\n') + '\n' + line + '\n'
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path)); os.write(fd, new.encode()); os.close(fd)
    os.chmod(tmp, 0o644); os.replace(tmp, path)


def slots():
    """Slot adi -> env dict (dosya sirasina gore)."""
    out = {}
    if not os.path.isdir(SLOTS_DIR): return out
    for fn in sorted(os.listdir(SLOTS_DIR)):
        if fn.endswith('.env'):
            name = fn[:-4]; e = _parse_env(os.path.join(SLOTS_DIR, fn)); e['SLOT'] = name
            e.setdefault('ENABLED', '1'); e.setdefault('HOSTAPD_UNIT', f'ap-hostapd@{name}')
            e.setdefault('DNSMASQ_UNIT', f'ap-dnsmasq@{name}'); e.setdefault('DNSMASQ_CONF', f'{SLOTS_DIR}/{name}.dnsmasq.conf')
            out[name] = e
    return out


def _slot(name):
    if not name:
        s = slots()
        if not s: raise ApError('hic slot yok')
        return next(iter(s.values()))
    if not _NAME.match(name): raise ApError('gecersiz slot adi')
    s = slots().get(name)
    if not s: raise ApError(f'slot yok: {name}')
    return s


def _run(cmd, timeout=30, input_text=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, '', f'timeout ({timeout}s): {" ".join(cmd)}'
    except FileNotFoundError as e:
        return 127, '', str(e)


def _run_detached(cmd, timeout):
    """Uzun ayricalikli isi ajanin cgroup'undan AYIR: ajan yeniden baslasa da is tamamlanir."""
    unit = 'ap-job-' + secrets.token_hex(4)
    return _run([SYSTEMD_RUN, '--wait', '--pipe', '--collect', '--quiet', '--unit=' + unit,
                 '-p', 'KillMode=none', *cmd], timeout)


def _active(unit):
    return _run([SYSCTL, 'is-active', unit], 5)[1].strip() == 'active'


def _default_route():
    m = re.search(r'default via (\S+) dev (\S+)', _run([IP, '-4', '-o', 'route', 'show', 'default'], 5)[1])
    return (m.group(1), m.group(2)) if m else (None, None)


def _iface_ip(dev):
    m = re.search(r'inet (\S+)', _run([IP, '-4', '-o', 'addr', 'show', 'dev', dev], 5)[1])
    return m.group(1) if m else None


def _read_kv(path):
    conf = {}
    try:
        for line in open(path):
            line = line.rstrip('\n')
            if not line or line.startswith('#') or '=' not in line: continue
            k, v = line.split('=', 1); conf[k.strip()] = v
    except FileNotFoundError:
        pass
    return conf


def _hostapd_path(slot): return f'/etc/hostapd/{slot["SLOT"]}.conf'


# ----------------------------------------------------------------- durum
def _ap_info(slot):
    h = _read_kv(_hostapd_path(slot)); ap_if = slot['AP_IF']
    out = _run([IW, 'dev', ap_if, 'info'], 5)[1]
    t = re.search(r'\btype (\S+)', out); ch = re.search(r'channel (\d+) \((\d+) MHz\), width: (\d+) MHz', out)
    return {'if': ap_if, 'ssid': h.get('ssid'), 'up': bool(t and t.group(1) == 'AP'),
            'channel': int(ch.group(1)) if ch else None, 'freq_mhz': int(ch.group(2)) if ch else None,
            'width_mhz': int(ch.group(3)) if ch else None, 'band': '5GHz' if h.get('hw_mode') == 'a' else '2.4GHz',
            'isolate': h.get('ap_isolate') == '1'}


def _vpn_info(slot):
    wg_if = slot['WG_IF']; v = {'if': wg_if, 'up': False, 'profile': slot.get('PROFILE') or None}
    rc, out, _ = _run([WG, 'show', wg_if, 'dump'], 5)
    if rc == 0 and out.strip():
        lines = out.strip().split('\n')
        if len(lines) >= 2:
            p = lines[1].split('\t'); hs = int(p[4]) if len(p) > 4 and p[4].isdigit() else 0
            v.update({'up': True, 'endpoint': p[2] if len(p) > 2 else None,
                      'handshake_age_s': (int(time.time()) - hs) if hs else None,
                      'rx_bytes': int(p[5]) if len(p) > 5 else 0, 'tx_bytes': int(p[6]) if len(p) > 6 else 0,
                      'address': _iface_ip(wg_if)})
            try: v['mtu'] = int(open(f'/sys/class/net/{wg_if}/mtu').read())
            except Exception: v['mtu'] = None
    v['healthy'] = bool(v.get('handshake_age_s') is not None and v['handshake_age_s'] <= 300)
    return v


def _killswitch(slot):
    ipt = '/usr/sbin/iptables'; ap_if, wg_if, ap_net = slot['AP_IF'], slot['WG_IF'], slot['AP_NET']
    ok_drop = _run([ipt, '-C', 'AP-VPN-FWD', '-i', ap_if, '-j', 'DROP'], 5)[0] == 0
    ok_fwd = _run([ipt, '-C', 'AP-VPN-FWD', '-i', ap_if, '-o', wg_if, '-j', 'ACCEPT'], 5)[0] == 0
    ok_hook = _run([ipt, '-C', 'DOCKER-USER', '-j', 'AP-VPN-FWD'], 5)[0] == 0
    ok_bh = f'from {ap_net} blackhole' in _run([IP, 'rule', 'show'], 5)[1]
    return {'filter': ok_drop and ok_fwd and ok_hook, 'blackhole': ok_bh, 'ok': ok_drop and ok_fwd and ok_hook and ok_bh}


def slot_status(name=None):
    s = _slot(name)
    return {'name': s['SLOT'], 'enabled': s.get('ENABLED', '1') == '1', 'ap': _ap_info(s), 'vpn': _vpn_info(s),
            'net': s['AP_NET'], 'clients': len(clients(s['SLOT'])), 'killswitch': _killswitch(s), 'pin': _pin_info(s),
            'services': {u: _active(u) for u in (s['HOSTAPD_UNIT'], s['DNSMASQ_UNIT'], f"wg-quick@{s['WG_IF']}", f"ap-wlan@{s['SLOT']}")}}


def status():
    gw, dev = _default_route()
    sl = [slot_status(n) for n in slots()]
    temp = None
    m = re.search(r'temp=([\d.]+)', _run(['/usr/bin/vcgencmd', 'measure_temp'], 5)[1])
    if m: temp = float(m.group(1))
    up = int(float(open('/proc/uptime').read().split()[0])); load = float(open('/proc/loadavg').read().split()[0])
    return {'slots': sl, 'lan': {'if': dev, 'gw': gw, 'ip': _iface_ip(dev) if dev else None},
            'services': {u: _active(u) for u in ('ap-firewall', 'ap-ble-agent', 'ap-watchdog.timer', 'bluetooth')},
            'clients': sum(x['clients'] for x in sl), 'uptime_s': up, 'load1': load, 'temp_c': temp,
            'killswitch': {'ok': all(x['killswitch']['ok'] for x in sl if x['enabled'])},
            'pin': {'ok': all(x['pin']['ok'] for x in sl if x['enabled'])}, 'ts': int(time.time()),
            'ap': sl[0]['ap'] if sl else {}, 'vpn': sl[0]['vpn'] if sl else {}}   # geriye uyumluluk


# ----------------------------------------------------------------- istemciler
def _leases(path):
    d = {}
    try:
        for line in open(path):
            p = line.split()
            if len(p) >= 4: d[p[1].lower()] = {'ip': p[2], 'hostname': None if p[3] == '*' else p[3]}
    except FileNotFoundError:
        pass
    return d


def clients(slot=None):
    targets = [_slot(slot)] if slot else list(slots().values())
    res = []
    for s in targets:
        conf = open(s['DNSMASQ_CONF']).read() if os.path.exists(s['DNSMASQ_CONF']) else ''
        lp = re.search(r'^dhcp-leasefile=(.+)$', conf, re.M)
        leases = _leases(lp.group(1).strip()) if lp else {}
        out = _run([IW, 'dev', s['AP_IF'], 'station', 'dump'], 5)[1]
        cur = None; mine = []
        for line in out.split('\n'):
            m = re.match(r'Station ([0-9a-f:]{17})', line)
            if m:
                cur = {'mac': m.group(1).lower(), 'slot': s['SLOT']}; mine.append(cur); continue
            if cur is None: continue
            line = line.strip()
            for key, pat, conv in (('signal_dbm', r'^signal:\s+(-?\d+)', int), ('connected_s', r'^connected time:\s+(\d+)', int),
                                   ('rx_bytes', r'^rx bytes:\s+(\d+)', int), ('tx_bytes', r'^tx bytes:\s+(\d+)', int),
                                   ('tx_rate_mbps', r'^tx bitrate:\s+([\d.]+)', float), ('rx_rate_mbps', r'^rx bitrate:\s+([\d.]+)', float)):
                mm = re.match(pat, line)
                if mm: cur[key] = conv(mm.group(1))
        for c in mine:
            l = leases.get(c['mac'], {}); c['ip'] = l.get('ip'); c['hostname'] = l.get('hostname')
        res += mine
    return res


def kick(mac, slot=None):
    if not re.match(r'\A[0-9a-fA-F:]{17}\Z', mac or ''): raise ApError('gecersiz MAC')
    targets = [_slot(slot)] if slot else list(slots().values())
    for s in targets:
        rc, out, err = _run(['/usr/sbin/hostapd_cli', '-i', s['AP_IF'], 'deauthenticate', mac], 5)
        if rc == 0 and 'OK' in out: return {'kicked': mac.lower(), 'slot': s['SLOT']}
    raise ApError('istemci bulunamadi')


# ----------------------------------------------------------------- wifi
def wifi_get(slot=None):
    s = _slot(slot); h = _read_kv(_hostapd_path(s)); psk = h.get('wpa_passphrase', '')
    return {'slot': s['SLOT'], 'if': s['AP_IF'], 'ssid': h.get('ssid'), 'band': '5GHz' if h.get('hw_mode') == 'a' else '2.4GHz',
            'channel': int(h.get('channel', 0) or 0), 'psk': psk, 'psk_len': len(psk)}


def _validate_ssid(ssid):
    if not isinstance(ssid, str) or not (1 <= len(ssid.encode('utf-8')) <= 32): raise ApError('SSID 1-32 bayt olmali')
    if any(ch in ssid for ch in '\r\n\0'): raise ApError('SSID gecersiz karakter iceriyor')


def _validate_psk(psk):
    if not isinstance(psk, str) or not (8 <= len(psk) <= 63): raise ApError('parola 8-63 karakter olmali')
    if not all(32 <= ord(c) <= 126 for c in psk): raise ApError('parola sadece yazdirilabilir ASCII olabilir')


def _wifi_set_impl(slot=None, ssid=None, psk=None):
    s = _slot(slot); path = _hostapd_path(s)
    if ssid is None and psk is None: raise ApError('ssid veya psk gerekli')
    if ssid is not None: _validate_ssid(ssid)
    if psk is not None: _validate_psk(psk)
    src = open(path).read(); new = src
    # re.sub'da DEGISTIRME SABLONU degil lambda: PSK icindeki '\\' veya '\\1' yorumlanmasin
    if ssid is not None: new = re.sub(r'^ssid=.*$', lambda m: 'ssid=' + ssid, new, count=1, flags=re.M)
    if psk is not None: new = re.sub(r'^wpa_passphrase=.*$', lambda m: 'wpa_passphrase=' + psk, new, count=1, flags=re.M)
    if new == src: return wifi_get(s['SLOT'])
    bak = path + '.bak'; shutil.copy2(path, bak)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path)); os.write(fd, new.encode()); os.close(fd)
    os.chmod(tmp, 0o600); os.replace(tmp, path)
    rc, _, err = _run([SYSCTL, 'restart', s['HOSTAPD_UNIT']], 30); time.sleep(3)
    if rc != 0 or not _active(s['HOSTAPD_UNIT']):
        shutil.copy2(bak, path); _run([SYSCTL, 'restart', s['HOSTAPD_UNIT']], 30)
        raise ApError(f'hostapd yeni ayarla baslamadi, geri alindi: {err.strip()[:200]}')
    if ssid is not None and s.get('PIN_PROFILE'):   # SSID degisti: sabitteki SSID'yi de guncelle (onayli islem)
        _set_env_key(os.path.join(SLOTS_DIR, s['SLOT'] + '.env'), 'PIN_SSID_HEX', _ssid_of(s).encode().hex())
    return wifi_get(s['SLOT'])


# ----------------------------------------------------------------- vpn profilleri
def _parse_conf(text):
    def g(section, key):
        m = re.search(rf'^\[{section}\](.*?)(?=^\[|\Z)', text, re.S | re.M)
        if not m: return None
        mm = re.search(rf'^\s*{key}\s*=\s*(.+?)\s*$', m.group(1), re.M | re.I)
        return mm.group(1).strip() if mm else None
    return {'endpoint': g('Peer', 'Endpoint'), 'address': g('Interface', 'Address'), 'peer_pubkey': g('Peer', 'PublicKey'), 'mtu': g('Interface', 'MTU')}


def _profile_users():
    return {s.get('PROFILE'): n for n, s in slots().items() if s.get('PROFILE')}


def vpn_list():
    os.makedirs(PROFILES, mode=0o700, exist_ok=True); users = _profile_users(); res = []
    for fn in sorted(os.listdir(PROFILES)):
        if not fn.endswith('.conf'): continue
        name = fn[:-5]; p = os.path.join(PROFILES, fn); info = _parse_conf(open(p).read())
        res.append({'name': name, 'type': 'wireguard', 'slot': users.get(name), 'active': name in users,
                    'endpoint': info['endpoint'], 'address': info['address'], 'mtu': info['mtu'], 'added': int(os.stat(p).st_mtime)})
    return res


def _vpn_add_impl(name, conf_text, overwrite=False):
    if not _NAME.match(name or ''): raise ApError('profil adi: harf/rakam/-/_ , 1-32 karakter')
    if not isinstance(conf_text, str) or len(conf_text) > 8192: raise ApError('config metni gecersiz veya cok buyuk')
    os.makedirs(PROFILES, mode=0o700, exist_ok=True); dst = os.path.join(PROFILES, name + '.conf')
    if os.path.exists(dst) and not overwrite: raise ApError(f'"{name}" zaten var (overwrite=true ile ez)')
    if name in _profile_users() and overwrite: raise ApError('kullanimdaki profil ezilemez; once slotu baska profile gecir')
    fd, tmp = tempfile.mkstemp(suffix='.conf', dir='/etc/wireguard', prefix='.upload-'); os.write(fd, conf_text.encode()); os.close(fd)
    os.chmod(tmp, 0o600)
    try:
        rc, out, err = _run([SWAP, tmp], 60)   # kuru calisma = dogrulama
        if rc != 0: raise ApError('config dogrulanamadi: ' + (err.strip() or out.strip())[-300:])
        shutil.copy2(tmp, dst); os.chmod(dst, 0o600)
    finally:
        os.unlink(tmp)
    return {'name': name, **_parse_conf(conf_text), 'warnings': [l.strip() for l in err.split('\n') if 'cikarildi' in l]}


def vpn_remove(name):
    if not _NAME.match(name or ''): raise ApError('gecersiz ad')
    u = _profile_users()
    if name in u: raise ApError(f'profil {u[name]} slotunda aktif, once degistir')
    p = os.path.join(PROFILES, name + '.conf')
    if not os.path.exists(p): raise ApError('profil yok')
    os.unlink(p); return {'removed': name}


# ----------------------------------------------------------------- ATAMA SABITLEME (pin)
# Yayin (SSID) <-> profil <-> VPN sunucu anahtari <-> radyo MAC dortlusu slot env'inde sabitlenir.
# Sabiti yalnizca YAZILI ONAY gecmis islemler gunceller; ap-pin.sh sapmada yayini durdurur (fail-closed).
def _ssid_of(s): return _read_kv(_hostapd_path(s)).get('ssid') or ''


def _pin_info(s):
    rc, out, _ = _run([PIN, 'check', s['SLOT']], 10)
    viol = None
    try: viol = open(f"/run/ap-vpn/{s['SLOT']}/pin-violation").read().strip() or None
    except FileNotFoundError: pass
    hx = s.get('PIN_SSID_HEX') or ''
    return {'pinned': bool(s.get('PIN_PROFILE')), 'profile': s.get('PIN_PROFILE') or None,
            'ssid': bytes.fromhex(hx).decode('utf-8', 'replace') if hx else None,
            'peer': (s.get('PIN_PEER') or '')[:12] or None, 'mac': s.get('AP_MAC') or None,
            'ok': rc == 0, 'msg': out.strip(), 'violation': viol}


def _pin_write(s):
    """Slotun MEVCUT durumunu sabitle. SADECE yazili onay gecmis islemlerden cagrilir."""
    s = _slot(s['SLOT']); env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    prof = s.get('PROFILE') or ''; peer = ''
    if prof:
        peer = _parse_conf(open(os.path.join(PROFILES, prof + '.conf')).read()).get('peer_pubkey') or ''
        if not peer: raise ApError(f'profil {prof}: PublicKey yok, sabitlenemez')
    try: mac = open(f"/sys/class/net/{s['AP_IF']}/address").read().strip()
    except FileNotFoundError: mac = s.get('AP_MAC') or ''
    for k, v in (('PIN_SSID_HEX', _ssid_of(s).encode().hex()), ('PIN_PROFILE', prof), ('PIN_PEER', peer), ('AP_MAC', mac)):
        _set_env_key(env_path, k, v)
    try: os.unlink(f"/run/ap-vpn/{s['SLOT']}/pin-violation")
    except FileNotFoundError: pass
    return _pin_info(_slot(s['SLOT']))


def _pin_clear(s):
    env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    for k in ('PIN_SSID_HEX', 'PIN_PROFILE', 'PIN_PEER'): _set_env_key(env_path, k, '')


def _require_confirm(confirm, *affected):
    """Yayin-VPN eslesmesini degistiren islemler: etkilenen yayinlarin SSID'leri ' / ' ile birlestirilmis
    halde AYNEN yazilmis olmali. Yanlis tiklamaya karsi; sistem bu degisikligi kendiliginden ASLA yapmaz."""
    expected = ' / '.join(_ssid_of(x) for x in affected)
    if str(confirm or '').strip() != expected:
        raise ApError(f'ONAY GEREKLI: bu islem yayin-VPN eslesmesini degistirir. Onaylamak icin aynen yazin: {expected}')


def _slot_pin_impl(slot, confirm=None):
    s = _slot(slot); _require_confirm(confirm, s)
    info = _pin_write(s)
    if s.get('ENABLED', '1') == '1' and not _active(s['HOSTAPD_UNIT']):
        _run([SYSCTL, 'reset-failed', s['HOSTAPD_UNIT']], 10); _run([SYSCTL, 'start', s['HOSTAPD_UNIT']], 30)
        info['hostapd_started'] = _active(s['HOSTAPD_UNIT'])
    return info


def _detach_profile(slot_env):
    """Slotun tunelini kapat ve profil bagini kaldir (profil baska slota gecebilsin). Sabit de kalkar."""
    _run([SYSCTL, 'stop', f"wg-quick@{slot_env['WG_IF']}"], 60)
    _set_env_key(os.path.join(SLOTS_DIR, slot_env['SLOT'] + '.env'), 'PROFILE', ''); _pin_clear(slot_env)
    _run([FIREWALL], 60)   # blackhole + killswitch bu slot icin devrede kalir (fail-closed)


def _vpn_activate_impl(name, slot=None, force=False, confirm=None, _internal=False):
    """Profili slota ata. force=True: profil baska slottaysa oradan ALIR (o slot tunelsiz kalir, killswitch tutar).
    ATAMA SABITLEME: _internal degilse etkilenen HER yayinin SSID'si 'confirm' ile aynen yazilmis olmali;
    basarida sabit (PIN_*) guncellenir. Cagiran long_op kilidini tutar (ap-pin enforce bu sirada denetlemez)."""
    s = _slot(slot)
    if not _NAME.match(name or ''): raise ApError('gecersiz ad')
    p = os.path.join(PROFILES, name + '.conf')
    if not os.path.exists(p): raise ApError('profil yok')
    u = _profile_users()
    victim = _slot(u[name]) if u.get(name) and u[name] != s['SLOT'] else None
    if victim and not force: raise ApError(f'"{name}" zaten {victim["SLOT"]} slotunda aktif (ayni anahtar iki tunelde kullanilamaz; force ile alinabilir)')
    if not _internal: _require_confirm(confirm, s, *([victim] if victim else []))
    if victim: _detach_profile(victim)
    was_detached = not s.get('PROFILE')
    rc, out, err = _run_detached([SWAP, p, '--apply', f"--slot={s['SLOT']}"], 200)
    ok = rc == 0
    if ok:
        _set_env_key(os.path.join(SLOTS_DIR, s['SLOT'] + '.env'), 'PROFILE', name); _pin_write(s)
    elif was_detached:
        # Koparilmis slotta swap script'in geri getirdigi 'eski' conf artik BASKA slota ait olabilir (takas yarida kaldi):
        # ayni anahtar iki tunelde calismasin diye tunel kapatilir; slot profilsiz/sabitsiz kalir (killswitch tutar).
        _run([SYSCTL, 'stop', f"wg-quick@{s['WG_IF']}"], 60); _run([FIREWALL], 60)
    tail = (out + '\n' + err).strip().split('\n')
    summary = [l for l in tail if any(k in l for k in ('yeni cikis IP', 'PASS,', 'FAIL', 'geri', 'RED', 'handshake'))]
    if not ok: raise ApError(('aktivasyon basarisiz (slot tunelsiz birakildi): ' if was_detached else 'aktivasyon basarisiz (eski profile geri donuldu): ') + '\n'.join(summary[-5:] or tail[-5:]))
    return {'activated': True, 'name': name, 'slot': s['SLOT'], 'log': tail[-25:], 'summary': summary, 'pin': _pin_info(_slot(s['SLOT']))}


def _vpn_swap_impl(slot_a, slot_b, confirm=None):
    """Iki slotun profillerini takas et. Sira: B'yi kopar -> A'ya B'nin profilini ver -> B'ye A'nin eski profilini ver.
    Onay: iki yayinin SSID'si de yazilmis olmali (' / ' ile, A B sirasiyla)."""
    a, b = _slot(slot_a), _slot(slot_b)
    if a['SLOT'] == b['SLOT']: raise ApError('ayni slot')
    pa, pb = a.get('PROFILE') or None, b.get('PROFILE') or None
    if not pa and not pb: raise ApError('iki slotta da profil yok')
    _require_confirm(confirm, a, b)
    log = []
    if pb: _detach_profile(b); log.append(f"{b['SLOT']}: {pb} koparildi")
    if pb:
        r = _vpn_activate_impl(pb, a['SLOT'], _internal=True); log += r['summary']; log.append(f"{a['SLOT']} -> {pb}")
    else:
        _detach_profile(a); log.append(f"{a['SLOT']}: {pa} koparildi")
    if pa:
        r = _vpn_activate_impl(pa, b['SLOT'], _internal=True); log += r['summary']; log.append(f"{b['SLOT']} -> {pa}")
    return {'swapped': True, a['SLOT']: pb, b['SLOT']: pa, 'summary': log}


def _slot_enable_impl(slot, enabled):
    s = _slot(slot); env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    units = [s['HOSTAPD_UNIT'], s['DNSMASQ_UNIT'], f"wg-quick@{s['WG_IF']}"]
    if enabled:
        _set_env_key(env_path, 'ENABLED', '1'); _run([SYSCTL, 'start', f"ap-wlan@{s['SLOT']}"], 20)
        _run([FIREWALL], 60); _run([SYSCTL, 'start', *units], 60); _run([SYSCTL, 'enable', *units], 20)
    else:
        _run([SYSCTL, 'disable', *units], 20); _run([SYSCTL, 'stop', s['HOSTAPD_UNIT'], s['DNSMASQ_UNIT']], 60)
        _set_env_key(env_path, 'ENABLED', '0'); _run([FIREWALL], 60)
        _run([SYSCTL, 'stop', f"wg-quick@{s['WG_IF']}"], 60)
    time.sleep(2)
    return slot_status(s['SLOT'])


def exit_ip(slot=None):
    s = _slot(slot); addr = _iface_ip(s['WG_IF'])
    if not addr: raise ApError(f"{s['WG_IF']} arayuzunde adres yok")
    src = addr.split('/')[0]
    rc, out, err = _run(['/usr/bin/curl', '-4', '-s', '-m', '8', '--interface', src, 'https://api.ipify.org'], 12)
    if rc != 0 or not out.strip(): raise ApError('cikis IP alinamadi (tunel calismiyor olabilir)')
    return {'slot': s['SLOT'], 'exit_ip': out.strip(), 'via': src}


# ----------------------------------------------------------------- sistem
def _verify_impl(slot=None):
    targets = [_slot(slot)] if slot else list(slots().values())
    total_p = total_f = 0; fails = []; ok = True
    for s in targets:
        if s.get('ENABLED', '1') != '1': continue
        rc, out, err = _run([VERIFY, f"--slot={s['SLOT']}"], 120)
        m = re.search(r'(\d+) PASS, (\d+) FAIL', out)
        if m: total_p += int(m.group(1)); total_f += int(m.group(2))
        fails += [f"[{s['SLOT']}] " + l.strip() for l in out.split('\n') if l.strip().startswith('FAIL')]
        ok = ok and rc == 0
    return {'pass': total_p, 'fail': total_f, 'failures': fails, 'ok': ok}


def firewall_reapply():
    rc, out, err = _run([FIREWALL], 60)
    if rc != 0: raise ApError('firewall: ' + (err or out).strip()[-300:])
    return {'ok': True, 'msg': out.strip()}


def system_logs(lines=60, unit=None):
    lines = max(1, min(int(lines or 60), 400))
    cmd = ['/usr/bin/journalctl', '--no-pager', '-n', str(lines), '-o', 'short']
    if unit and re.match(r'\A[A-Za-z0-9@._-]+\Z', unit): cmd += ['-u', unit]
    else:
        cmd += ['-t', 'ap-firewall', '-t', 'ap-watchdog', '-t', 'ap-bootcheck', '-t', 'ap-ble']
        for s in slots().values(): cmd += ['-u', s['HOSTAPD_UNIT'], '-u', f"wg-quick@{s['WG_IF']}"]
    return {'lines': _run(cmd, 15)[1].rstrip('\n').split('\n')}


def system_reboot(delay=3):
    _run([SYSTEMD_RUN, '--on-active=%ds' % int(delay), '--unit=ble-reboot', SYSCTL, 'reboot'], 5)
    return {'rebooting_in_s': int(delay)}


# ----------------------------------------------------------------- BLE
_UPDATABLE = {'apctl.py': '/opt/ap-vpn/lib/apctl.py', 'ap-ble-agent.py': '/opt/ap-vpn/bin/ap-ble-agent.py'}


def agent_update(name, content, restart=True):
    if name not in _UPDATABLE: raise ApError('sadece ' + ', '.join(_UPDATABLE) + ' guncellenebilir')
    if not isinstance(content, str) or not (200 < len(content) < 400_000): raise ApError('icerik boyutu gecersiz')
    dst = _UPDATABLE[name]
    fd, tmp = tempfile.mkstemp(suffix='.py', dir=os.path.dirname(dst), prefix='.upd-'); os.write(fd, content.encode()); os.close(fd)
    try:
        rc, out, err = _run([sys.executable, '-m', 'py_compile', tmp], 30)
        if rc != 0: raise ApError('sozdizimi hatasi: ' + (err or out).strip()[-300:])
        bak = dst + '.bak'
        if os.path.exists(dst): shutil.copy2(dst, bak)
        os.chmod(tmp, 0o755 if name.endswith('agent.py') else 0o644); os.replace(tmp, dst)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    if restart: _run([SYSTEMD_RUN, '--on-active=3s', '--unit=ble-agent-restart', SYSCTL, 'restart', 'ap-ble-agent'], 5)
    return {'updated': name, 'bytes': len(content), 'backup': bak, 'restart_in_s': 3 if restart else 0}


def ble_setname(name):
    if not isinstance(name, str) or not (1 <= len(name.encode()) <= 20) or not re.match(r'\A[A-Za-z0-9 _.-]+\Z', name):
        raise ApError('ad 1-20 bayt, harf/rakam/bosluk/-/_/. olabilir')
    _set_env_key(ENV, 'BLE_NAME', name)
    _run([SYSTEMD_RUN, '--on-active=3s', '--unit=ble-agent-restart', SYSCTL, 'restart', 'ap-ble-agent'], 5)
    return {'name': name, 'restart_in_s': 3}


def ble_token(regen=False):
    if regen or not os.path.exists(TOKEN):
        os.makedirs(os.path.dirname(TOKEN), exist_ok=True)
        fd = os.open(TOKEN, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, (secrets.token_hex(32) + '\n').encode()); os.close(fd)
    return {'token': open(TOKEN).read().strip(), 'path': TOKEN}


def ble_pair(seconds=120):
    """Eslestirme penceresi ac: ajan bu dosyayi izler, Pairable'i gecici acar."""
    seconds = max(10, min(int(seconds), 900)); os.makedirs(os.path.dirname(PAIR_FILE), exist_ok=True)
    with open(PAIR_FILE, 'w') as f: f.write(str(int(time.time()) + seconds))
    return {'pairable_for_s': seconds, 'hint': 'Bu sure icinde yeni bir Mac baglanip eslesebilir; sonra kapi kapanir.'}


# ----------------------------------------------------------------- uzun islem sarmalayicilari (kilitli)
def wifi_set(slot=None, ssid=None, psk=None):
    with long_op('wifi.set'):
        return _wifi_set_impl(slot, ssid, psk)


def vpn_activate(name, slot=None, force=False, confirm=None):
    with long_op('vpn.activate'):
        return _vpn_activate_impl(name, slot, force, confirm)


def vpn_swap(slot_a, slot_b, confirm=None):
    with long_op('vpn.swap'):
        return _vpn_swap_impl(slot_a, slot_b, confirm)


def slot_pin(slot, confirm=None):
    with long_op('slot.pin'):
        return _slot_pin_impl(slot, confirm)


def slot_enable(slot, enabled):
    with long_op('slot.enable'):
        return _slot_enable_impl(slot, enabled)


def verify(slot=None):
    with long_op('verify'):
        return _verify_impl(slot)


def vpn_add(name, conf_text, overwrite=False):
    with long_op('vpn.add'):
        return _vpn_add_impl(name, conf_text, overwrite)


# ----------------------------------------------------------------- WEB
WEB_PW = '/etc/ap-vpn/web-password'   # icerik: salt_hex$sha256(salt||pw)_hex


def _pw_hash(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000).hex()


def web_set_password(pw=None):
    """Parola belirle (verilmezse rastgele uret ve dondur). Dosyada sadece hash tutulur."""
    shown = None
    if not pw: pw = secrets.token_urlsafe(12); shown = pw
    if not (8 <= len(pw) <= 128): raise ApError('parola 8-128 karakter olmali')
    salt = secrets.token_bytes(16)
    fd = os.open(WEB_PW, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, f'{salt.hex()}${_pw_hash(pw, salt)}\n'.encode()); os.close(fd)
    return {'set': True, 'password': shown, 'hint': 'Parola sadece simdi gosterildi; kaybedersen: sudo ap-ctl web password'}


def web_check_password(pw):
    try: salt_hex, h = open(WEB_PW).read().strip().split('$')
    except Exception: return False
    return hmac.compare_digest(_pw_hash(pw or '', bytes.fromhex(salt_hex)), h)


# ----------------------------------------------------------------- CLI
def _cli(argv):
    import argparse
    ap = argparse.ArgumentParser(prog='ap-ctl', description='Pi5 VPN-AP kontrol (coklu slot)')
    ap.add_argument('--slot', help='slot adi (ap0, ap1 ...)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for c in ('status', 'clients', 'verify', 'exitip', 'slots'): sub.add_parser(c)
    k = sub.add_parser('kick'); k.add_argument('mac')
    w = sub.add_parser('wifi'); ws = w.add_subparsers(dest='sub', required=True); ws.add_parser('get')
    wset = ws.add_parser('set'); wset.add_argument('--ssid'); wset.add_argument('--psk')
    v = sub.add_parser('vpn'); vs = v.add_subparsers(dest='sub', required=True); vs.add_parser('list')
    va = vs.add_parser('add'); va.add_argument('name'); va.add_argument('file', nargs='?'); va.add_argument('--overwrite', action='store_true')
    vr = vs.add_parser('remove'); vr.add_argument('name'); vx = vs.add_parser('activate'); vx.add_argument('name'); vx.add_argument('--force', action='store_true'); vx.add_argument('--confirm', help="etkilenen yayinlarin SSID'leri (' / ' ile)")
    vsw = vs.add_parser('swap'); vsw.add_argument('slot_a'); vsw.add_argument('slot_b'); vsw.add_argument('--confirm', help="'SSID_A / SSID_B'")
    sl = sub.add_parser('slot'); sls = sl.add_subparsers(dest='sub', required=True); sls.add_parser('enable'); sls.add_parser('disable'); sls.add_parser('pin').add_argument('--confirm', help='yayinin SSID\'si')
    s = sub.add_parser('system'); ss = s.add_subparsers(dest='sub', required=True)
    slg = ss.add_parser('logs'); slg.add_argument('-n', type=int, default=60); slg.add_argument('-u'); ss.add_parser('reboot'); ss.add_parser('firewall')
    wb = sub.add_parser('web'); wbs = wb.add_subparsers(dest='sub', required=True); wp = wbs.add_parser('password'); wp.add_argument('value', nargs='?')
    b = sub.add_parser('ble'); bs = b.add_subparsers(dest='sub', required=True)
    bt = bs.add_parser('token'); bt.add_argument('--regen', action='store_true')
    bn = bs.add_parser('setname'); bn.add_argument('name'); bp = bs.add_parser('pair'); bp.add_argument('seconds', nargs='?', type=int, default=120)
    a = ap.parse_args(argv)
    try:
        if a.cmd == 'status': r = status()
        elif a.cmd == 'slots': r = [slot_status(n) for n in slots()]
        elif a.cmd == 'clients': r = clients(a.slot)
        elif a.cmd == 'verify': r = verify(a.slot)
        elif a.cmd == 'exitip': r = exit_ip(a.slot)
        elif a.cmd == 'kick': r = kick(a.mac, a.slot)
        elif a.cmd == 'wifi': r = wifi_get(a.slot) if a.sub == 'get' else wifi_set(a.slot, a.ssid, a.psk)
        elif a.cmd == 'vpn':
            if a.sub == 'list': r = vpn_list()
            elif a.sub == 'add': r = vpn_add(a.name, open(a.file).read() if a.file else sys.stdin.read(), a.overwrite)
            elif a.sub == 'remove': r = vpn_remove(a.name)
            elif a.sub == 'activate': r = vpn_activate(a.name, a.slot, a.force, a.confirm)
            elif a.sub == 'swap': r = vpn_swap(a.slot_a, a.slot_b, a.confirm)
        elif a.cmd == 'slot': r = slot_pin(a.slot, a.confirm) if a.sub == 'pin' else slot_enable(a.slot, a.sub == 'enable')
        elif a.cmd == 'system':
            if a.sub == 'logs': r = system_logs(a.n, a.u)
            elif a.sub == 'reboot': r = system_reboot()
            elif a.sub == 'firewall': r = firewall_reapply()
        elif a.cmd == 'web': r = web_set_password(a.value)
        elif a.cmd == 'ble':
            r = ble_setname(a.name) if a.sub == 'setname' else ble_pair(a.seconds) if a.sub == 'pair' else ble_token(a.regen)
        print(json.dumps(r, ensure_ascii=False, indent=2)); return 0
    except ApError as e:
        print(json.dumps({'error': str(e)}, ensure_ascii=False), file=sys.stderr); return 2


if __name__ == '__main__':
    if os.geteuid() != 0:
        print(json.dumps({'error': 'root gerekli (sudo ap-ctl ...)'}), file=sys.stderr); sys.exit(1)
    sys.exit(_cli(sys.argv[1:]))
