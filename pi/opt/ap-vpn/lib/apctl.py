#!/usr/bin/env python3
"""
apctl — control layer for the Pi VPN-AP (multi-slot).
A slot = one radio + one subnet + one WireGuard tunnel, defined in /etc/ap-vpn/slots/<slot>.env
Library (imported by ap-ble-agent and ap-web) + CLI (/opt/ap-vpn/bin/ap-ctl). Requires root.
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
IFSYNC    = '/opt/ap-vpn/bin/ap-ifsync.sh'
IW, WG, IP, SYSCTL = '/usr/sbin/iw', '/usr/bin/wg', '/usr/sbin/ip', '/usr/bin/systemctl'
SYSTEMD_RUN = '/usr/bin/systemd-run'
_NAME = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z')


class ApError(Exception):
    pass


LONG_LOCK_FILE = '/run/ap-vpn/long.lock'


@contextlib.contextmanager
def long_op(label='operation'):
    """Cross-process lock for long operations (BLE agent + web panel). Fails fast when busy."""
    os.makedirs(os.path.dirname(LONG_LOCK_FILE), exist_ok=True)
    fd = os.open(LONG_LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        for _i in range(15):   # ap-pin enforce holds the lock for <1 s: wait briefly, then fail
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                if _i == 14:
                    who = os.read(fd, 200).decode(errors='ignore').strip()
                    raise ApError(f'another long operation is running ({who or "?"}), please wait')
                time.sleep(0.2)
        os.ftruncate(fd, 0); os.lseek(fd, 0, 0); os.write(fd, f'{label} pid={os.getpid()} t={int(time.time())}'.encode())
        yield
    finally:
        try: fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception: pass
        os.close(fd)


# ----------------------------------------------------------------- helpers
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
    """Slot name -> env dict (in file order)."""
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
        if not s: raise ApError('no slots configured')
        return next(iter(s.values()))
    if not _NAME.match(name): raise ApError('invalid slot name')
    s = slots().get(name)
    if not s: raise ApError(f'no such slot: {name}')
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
    """Run a long privileged job OUTSIDE the agent's cgroup, so it completes even if the agent restarts."""
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


# ----------------------------------------------------------------- status
def _ap_info(slot):
    h = _read_kv(_hostapd_path(slot)); ap_if = slot['AP_IF']
    out = _run([IW, 'dev', ap_if, 'info'], 5)[1]
    t = re.search(r'\btype (\S+)', out); ch = re.search(r'channel (\d+) \((\d+) MHz\), width: (\d+) MHz', out)
    return {'if': ap_if, 'ssid': h.get('ssid'), 'up': bool(t and t.group(1) == 'AP'),
            'channel': int(ch.group(1)) if ch else None, 'freq_mhz': int(ch.group(2)) if ch else None,
            'width_mhz': int(ch.group(3)) if ch else None, 'band': '5GHz' if h.get('hw_mode') == 'a' else '2.4GHz',
            'isolate': h.get('ap_isolate') == '1'}


def _radio(slot):
    """The physical radio behind a slot. The MAC is the identity; the name can change."""
    ap_if = slot['AP_IF']; mac = slot.get('AP_MAC') or None
    try: live = open(f'/sys/class/net/{ap_if}/address').read().strip()
    except OSError: live = None
    drv = None
    p = f'/sys/class/net/{ap_if}/device/driver'
    if os.path.islink(p): drv = os.path.basename(os.path.realpath(p))
    return {'if': ap_if, 'mac': mac, 'live_mac': live, 'driver': drv,
            'present': live is not None and (mac is None or live == mac)}


def _vpn_info(slot):
    mode = slot.get('MODE', 'vpn')
    wg_if = slot['WG_IF']; v = {'if': wg_if, 'mode': mode, 'up': False, 'profile': slot.get('PROFILE') or None}
    if mode == 'direct':
        # No tunnel by design: report the LAN as the exit so every surface can show it plainly.
        v.update({'healthy': True, 'exit': 'lan', 'endpoint': _env().get('LAN_IF', 'eth0')})
        return v
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
    v['exit'] = 'tunnel'
    return v


def _killswitch(slot):
    ipt = '/usr/sbin/iptables'; ap_if, ap_net = slot['AP_IF'], slot['AP_NET']
    exit_if = _env().get('LAN_IF', 'eth0') if slot.get('MODE', 'vpn') == 'direct' else slot['WG_IF']
    ok_drop = _run([ipt, '-C', 'AP-VPN-FWD', '-i', ap_if, '-j', 'DROP'], 5)[0] == 0
    ok_fwd = _run([ipt, '-C', 'AP-VPN-FWD', '-i', ap_if, '-o', exit_if, '-j', 'ACCEPT'], 5)[0] == 0
    ok_hook = _run([ipt, '-C', 'DOCKER-USER', '-j', 'AP-VPN-FWD'], 5)[0] == 0
    ok_bh = f'from {ap_net} blackhole' in _run([IP, 'rule', 'show'], 5)[1]
    return {'filter': ok_drop and ok_fwd and ok_hook, 'blackhole': ok_bh, 'ok': ok_drop and ok_fwd and ok_hook and ok_bh}


def slot_status(name=None):
    s = _slot(name)
    return {'name': s['SLOT'], 'enabled': s.get('ENABLED', '1') == '1', 'mode': s.get('MODE', 'vpn'),
            'ap': _ap_info(s), 'vpn': _vpn_info(s), 'radio': _radio(s),
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
            'ap': sl[0]['ap'] if sl else {}, 'vpn': sl[0]['vpn'] if sl else {}}   # backwards compatibility


# ----------------------------------------------------------------- clients
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
    if not re.match(r'\A[0-9a-fA-F:]{17}\Z', mac or ''): raise ApError('invalid MAC address')
    targets = [_slot(slot)] if slot else list(slots().values())
    for s in targets:
        rc, out, err = _run(['/usr/sbin/hostapd_cli', '-i', s['AP_IF'], 'deauthenticate', mac], 5)
        if rc == 0 and 'OK' in out: return {'kicked': mac.lower(), 'slot': s['SLOT']}
    raise ApError('client not found')


# ----------------------------------------------------------------- wifi
def wifi_get(slot=None):
    s = _slot(slot); h = _read_kv(_hostapd_path(s)); psk = h.get('wpa_passphrase', '')
    return {'slot': s['SLOT'], 'if': s['AP_IF'], 'ssid': h.get('ssid'), 'band': '5GHz' if h.get('hw_mode') == 'a' else '2.4GHz',
            'channel': int(h.get('channel', 0) or 0), 'psk': psk, 'psk_len': len(psk)}


def _validate_ssid(ssid):
    if not isinstance(ssid, str) or not (1 <= len(ssid.encode('utf-8')) <= 32): raise ApError('the SSID must be 1-32 bytes')
    if any(ch in ssid for ch in '\r\n\0'): raise ApError('the SSID contains an invalid character')


def _validate_psk(psk):
    if not isinstance(psk, str) or not (8 <= len(psk) <= 63): raise ApError('the password must be 8-63 characters')
    if not all(32 <= ord(c) <= 126 for c in psk): raise ApError('the password must be printable ASCII')


def _restart_hostapd(slot_env, timeout=30):
    """stop + reset-failed + start instead of a plain restart: when ExecStartPre fails, the unit
    enters an unthrottled auto-restart loop and a queued 'restart' job can block until it times out."""
    unit = slot_env['HOSTAPD_UNIT']
    _run([SYSCTL, 'stop', unit], timeout); _run([SYSCTL, 'reset-failed', unit], 5)
    return _run([SYSCTL, 'start', unit], timeout)


def _wifi_set_impl(slot=None, ssid=None, psk=None):
    s = _slot(slot); path = _hostapd_path(s)
    if ssid is None and psk is None: raise ApError('ssid or psk is required')
    if ssid is not None: _validate_ssid(ssid)
    if psk is not None: _validate_psk(psk)
    src = open(path).read(); new = src
    # A lambda, not a replacement template: a '\\' or '\\1' inside the PSK must not be interpreted.
    if ssid is not None: new = re.sub(r'^ssid=.*$', lambda m: 'ssid=' + ssid, new, count=1, flags=re.M)
    if psk is not None: new = re.sub(r'^wpa_passphrase=.*$', lambda m: 'wpa_passphrase=' + psk, new, count=1, flags=re.M)
    if new == src: return wifi_get(s['SLOT'])
    env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env'); old_pin = s.get('PIN_SSID_HEX') or ''
    bak = path + '.bak'; shutil.copy2(path, bak)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path)); os.write(fd, new.encode()); os.close(fd)
    os.chmod(tmp, 0o600); os.replace(tmp, path)
    # The pin has to be updated BEFORE the restart: ap-hostapd@ runs 'ap-pin.sh check' as ExecStartPre,
    # and a pin still holding the old SSID would refuse the new one (the SSID would never come up).
    if ssid is not None and old_pin: _set_env_key(env_path, 'PIN_SSID_HEX', ssid.encode().hex())
    rc, _, err = _restart_hostapd(s); time.sleep(3)
    if rc != 0 or not _active(s['HOSTAPD_UNIT']):
        shutil.copy2(bak, path)
        if ssid is not None and old_pin: _set_env_key(env_path, 'PIN_SSID_HEX', old_pin)
        _restart_hostapd(s); _run([FIREWALL], 60)
        raise ApError(f'hostapd did not start with the new settings, rolled back: {err.strip()[:200]}')
    # Stopping hostapd takes the radio down, and the kernel drops (or marks linkdown) the AP's link route in the
    # slot's routing table. Without it dnsmasq's replies are routed into the tunnel and clients resolve nothing,
    # so the firewall has to be re-applied after every restart. Idempotent.
    _run([FIREWALL], 60)
    return wifi_get(s['SLOT'])


# ----------------------------------------------------------------- vpn profiles
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
    if not _NAME.match(name or ''): raise ApError('profile name: letters/digits/-/_ , 1-32 characters')
    if not isinstance(conf_text, str) or len(conf_text) > 8192: raise ApError('the config text is invalid or too large')
    os.makedirs(PROFILES, mode=0o700, exist_ok=True); dst = os.path.join(PROFILES, name + '.conf')
    if os.path.exists(dst) and not overwrite: raise ApError(f'"{name}" already exists (pass overwrite=true to replace it)')
    if name in _profile_users() and overwrite: raise ApError('a profile in use cannot be replaced; move that slot to another profile first')
    fd, tmp = tempfile.mkstemp(suffix='.conf', dir='/etc/wireguard', prefix='.upload-'); os.write(fd, conf_text.encode()); os.close(fd)
    os.chmod(tmp, 0o600)
    try:
        rc, out, err = _run([SWAP, tmp], 60)   # dry run = validation
        if rc != 0: raise ApError('the config could not be validated: ' + (err.strip() or out.strip())[-300:])
        shutil.copy2(tmp, dst); os.chmod(dst, 0o600)
    finally:
        os.unlink(tmp)
    return {'name': name, **_parse_conf(conf_text), 'warnings': [l.strip() for l in err.split('\n') if 'stripped' in l]}


def vpn_remove(name):
    if not _NAME.match(name or ''): raise ApError('invalid name')
    u = _profile_users()
    if name in u: raise ApError(f'the profile is active on slot {u[name]}, change that slot first')
    p = os.path.join(PROFILES, name + '.conf')
    if not os.path.exists(p): raise ApError('no such profile')
    os.unlink(p); return {'removed': name}


# ----------------------------------------------------------------- ASSIGNMENT PINNING
# The quadruple SSID <-> profile <-> VPN server key <-> radio MAC is pinned in the slot env.
# Only operations that passed a typed confirmation update the pin; ap-pin.sh stops the SSID on drift (fail-closed).
def _ssid_of(s): return _read_kv(_hostapd_path(s)).get('ssid') or ''


def _pin_info(s):
    rc, out, _ = _run([PIN, 'check', s['SLOT']], 15)
    viol = None
    try: viol = open(f"/run/ap-vpn/{s['SLOT']}/pin-violation").read().strip() or None
    except FileNotFoundError: pass
    hx = s.get('PIN_SSID_HEX') or ''
    mode = s.get('MODE', 'vpn')
    return {'pinned': bool(s.get('PIN_PROFILE')) or (mode == 'direct' and bool(s.get('PIN_MODE'))),
            'mode': s.get('PIN_MODE') or None, 'profile': s.get('PIN_PROFILE') or None,
            'ssid': bytes.fromhex(hx).decode('utf-8', 'replace') if hx else None,
            'peer': (s.get('PIN_PEER') or '')[:12] or None, 'mac': s.get('AP_MAC') or None,
            'ok': rc == 0, 'msg': out.strip(), 'violation': viol}


def _pin_write(s):
    """Pin the slot's CURRENT state. Called ONLY from operations that passed a typed confirmation."""
    s = _slot(s['SLOT']); env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    prof = s.get('PROFILE') or ''; peer = ''
    if prof:
        peer = _parse_conf(open(os.path.join(PROFILES, prof + '.conf')).read()).get('peer_pubkey') or ''
        if not peer: raise ApError(f'profile {prof}: no PublicKey, cannot be pinned')
    # The MAC is the slot's identity, so it is written ONCE (when the slot is first pinned) and after an
    # explicit 'slot bind'. Adopting whatever adapter happens to sit on AP_IF would let a foreign radio
    # inherit this slot's subnet and tunnel through an ordinary activate/pin.
    mac = s.get('AP_MAC') or ''
    if not mac:
        try: mac = open(f"/sys/class/net/{s['AP_IF']}/address").read().strip()
        except OSError: mac = ''
    for k, v in (('PIN_MODE', s.get('MODE', 'vpn')), ('PIN_SSID_HEX', _ssid_of(s).encode().hex()),
                 ('PIN_PROFILE', prof), ('PIN_PEER', peer), ('AP_MAC', mac)):
        _set_env_key(env_path, k, v)
    try: os.unlink(f"/run/ap-vpn/{s['SLOT']}/pin-violation")
    except FileNotFoundError: pass
    return _pin_info(_slot(s['SLOT']))


def _pin_clear(s):
    env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    for k in ('PIN_SSID_HEX', 'PIN_PROFILE', 'PIN_PEER'): _set_env_key(env_path, k, '')


def _require_confirm(confirm, *affected):
    """For operations that change the SSID-VPN mapping: the affected SSIDs, joined with ' / ',
    must be typed VERBATIM. Guards against a mis-click; the system NEVER makes this change on its own."""
    # Compare what a person can actually type: an SSID may carry leading or trailing spaces (hostapd
    # keeps them verbatim), and demanding those back would make the slot impossible to confirm at all.
    parts = [_ssid_of(x).strip() for x in affected]
    expected = ' / '.join(parts)
    if not all(parts):
        raise ApError('cannot read the SSID of ' + ', '.join(x['SLOT'] for x in affected) + ' - refusing to change anything')
    if str(confirm or '').strip() != expected:
        raise ApError(f'CONFIRMATION REQUIRED: this operation changes the SSID-VPN mapping. To confirm, type exactly: {expected}')


def _slot_pin_impl(slot, confirm=None):
    s = _slot(slot); _require_confirm(confirm, s)
    info = _pin_write(s)
    if s.get('ENABLED', '1') == '1' and not _active(s['HOSTAPD_UNIT']):
        _run([SYSCTL, 'reset-failed', s['HOSTAPD_UNIT']], 10); _run([SYSCTL, 'start', s['HOSTAPD_UNIT']], 30)
        info['hostapd_started'] = _active(s['HOSTAPD_UNIT'])
    return info


def _detach_profile(slot_env):
    """Stop the slot's tunnel and unbind its profile (so it can move to another slot). The pin is cleared too."""
    _run([SYSCTL, 'stop', f"wg-quick@{slot_env['WG_IF']}"], 60)
    _set_env_key(os.path.join(SLOTS_DIR, slot_env['SLOT'] + '.env'), 'PROFILE', ''); _pin_clear(slot_env)
    _run([FIREWALL], 60)   # the blackhole + kill switch stay in place for this slot (fail-closed)


def _vpn_activate_impl(name, slot=None, force=False, confirm=None, _internal=False):
    """Assign a profile to a slot. force=True TAKES it from another slot (that slot is left without a
    tunnel; the kill switch holds). PINNING: unless _internal, every affected SSID must be typed verbatim
    in 'confirm'; on success the pin (PIN_*) is updated. The caller holds the long_op lock, so ap-pin
    enforce skips its audit meanwhile."""
    s = _slot(slot)
    if s.get('MODE', 'vpn') != 'vpn':
        raise ApError(f"{s['SLOT']} is in direct mode (no VPN). Switch it first: "
                      f"ap-ctl --slot {s['SLOT']} slot mode vpn --confirm '{_ssid_of(s)}'")
    if not _NAME.match(name or ''): raise ApError('invalid name')
    p = os.path.join(PROFILES, name + '.conf')
    if not os.path.exists(p): raise ApError('no such profile')
    u = _profile_users()
    victim = _slot(u[name]) if u.get(name) and u[name] != s['SLOT'] else None
    if victim and not force: raise ApError(f'"{name}" is already active on slot {victim["SLOT"]} (the same key cannot run in two tunnels; use force to take it)')
    if not _internal: _require_confirm(confirm, s, *([victim] if victim else []))
    if victim: _detach_profile(victim)
    was_detached = not s.get('PROFILE')
    rc, out, err = _run_detached([SWAP, p, '--apply', f"--slot={s['SLOT']}"], 200)
    ok = rc == 0
    if ok:
        _set_env_key(os.path.join(SLOTS_DIR, s['SLOT'] + '.env'), 'PROFILE', name); _pin_write(s)
    elif was_detached:
        # On a detached slot the 'previous' conf restored by the swap script may now belong to ANOTHER slot
        # (a half-finished swap): stop the tunnel so the same key never runs twice; the slot stays without a
        # profile and without a pin (the kill switch holds).
        _run([SYSCTL, 'stop', f"wg-quick@{s['WG_IF']}"], 60); _run([FIREWALL], 60)
    tail = (out + '\n' + err).strip().split('\n')
    summary = [l for l in tail if any(k in l for k in ('new exit IP', 'PASS,', 'FAIL', 'rolled back', 'REJECTED', 'handshake'))]
    if not ok: raise ApError(('activation failed (the slot was left without a tunnel): ' if was_detached else 'activation failed (rolled back to the previous profile): ') + '\n'.join(summary[-5:] or tail[-5:]))
    return {'activated': True, 'name': name, 'slot': s['SLOT'], 'log': tail[-25:], 'summary': summary, 'pin': _pin_info(_slot(s['SLOT']))}


def _vpn_swap_impl(slot_a, slot_b, confirm=None):
    """Swap the profiles of two slots. Order: detach B -> give A the profile of B -> give B the old profile of A.
    Confirmation: both SSIDs must be typed (joined with ' / ', in A B order)."""
    a, b = _slot(slot_a), _slot(slot_b)
    if a['SLOT'] == b['SLOT']: raise ApError('same slot')
    # Refuse BEFORE touching anything: a direct slot has no tunnel to swap, and finding that out
    # halfway would leave the other slot stripped of its profile.
    for x in (a, b):
        if x.get('MODE', 'vpn') != 'vpn':
            raise ApError(f"{x['SLOT']} is in direct mode (no VPN) - nothing to swap; switch it to vpn mode first")
    pa, pb = a.get('PROFILE') or None, b.get('PROFILE') or None
    if not pa and not pb: raise ApError('neither slot has a profile')
    _require_confirm(confirm, a, b)
    log = []
    if pb: _detach_profile(b); log.append(f"{b['SLOT']}: {pb} detached")
    if pb:
        r = _vpn_activate_impl(pb, a['SLOT'], _internal=True); log += r['summary']; log.append(f"{a['SLOT']} -> {pb}")
    else:
        _detach_profile(a); log.append(f"{a['SLOT']}: {pa} detached")
    if pa:
        r = _vpn_activate_impl(pa, b['SLOT'], _internal=True); log += r['summary']; log.append(f"{b['SLOT']} -> {pa}")
    return {'swapped': True, a['SLOT']: pb, b['SLOT']: pa, 'summary': log}


def devices():
    """Every wireless radio on the Pi: interface, MAC (its identity), driver, AP capability, owning slot."""
    rc, out, err = _run([IFSYNC, 'list'], 15)
    if rc != 0: raise ApError('could not list the radios: ' + (err or out).strip()[-200:])
    rows = []
    for line in out.strip().split('\n')[1:]:
        p = line.split()
        if len(p) >= 5:
            rows.append({'if': p[0], 'mac': p[1], 'driver': None if p[2] == '-' else p[2],
                         'ap_capable': p[3] == 'yes', 'slot': None if p[4] == '-' else p[4]})
    return rows


def _dnsmasq_upstream(s, wg_src=None):
    """Point the slot's resolver at the right place: through the tunnel in vpn mode (server=IP@src),
    straight out in direct mode. Without the @src binding a vpn slot could resolve outside the tunnel,
    so the two must always follow the mode."""
    path = s['DNSMASQ_CONF']
    if not os.path.exists(path): return
    src = open(path).read()
    if s.get('MODE', 'vpn') == 'direct':
        new = re.sub(r'^(server=[0-9.]+)@.*$', lambda m: m.group(1), src, flags=re.M)
    else:
        # 127.0.0.1 is the fail-closed placeholder: no tunnel address yet means no upstream query leaves.
        tgt = wg_src or _iface_ip(s['WG_IF']) or '127.0.0.1'
        tgt = tgt.split('/')[0]
        new = re.sub(r'^(server=[0-9.]+)(@.*)?$', lambda m: m.group(1) + '@' + tgt, src, flags=re.M)
    if new != src:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path)); os.write(fd, new.encode()); os.close(fd)
        os.chmod(tmp, 0o644); os.replace(tmp, path)
        _run([SYSCTL, 'restart', s['DNSMASQ_UNIT']], 30)


def _slot_mode_impl(slot, mode, confirm=None):
    """Switch a slot between 'vpn' (exit only through its tunnel) and 'direct' (no VPN at all).
    This is exactly the change that could let someone out through the local network by accident, so it
    needs the SSID typed back, it is written into the pin, and going direct detaches the profile and
    stops the tunnel first - a slot is never both."""
    if mode not in ('vpn', 'direct'): raise ApError("mode must be 'vpn' or 'direct'")
    s = _slot(slot); _require_confirm(confirm, s)
    env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    was = s.get('MODE', 'vpn')
    # Repeating the command must be able to REPAIR a half-applied switch, so 'already in that mode' only
    # short-circuits when the pin agrees too; otherwise every step below runs again (all are idempotent).
    if mode == was and _pin_info(s)['ok'] and (s.get('PIN_MODE') or '') == mode:
        return {'slot': s['SLOT'], 'mode': mode, 'unchanged': True, 'pin': _pin_info(_slot(s['SLOT']))}
    if mode == 'direct':
        if s.get('PROFILE'): _detach_profile(s)      # stops the tunnel and clears the pin
        # Disable it too: a unit that is merely stopped comes back at the next boot and violates the pin.
        _run([SYSCTL, 'disable', f"wg-quick@{s['WG_IF']}"], 20)
        _set_env_key(env_path, 'MODE', 'direct')
    else:
        _set_env_key(env_path, 'MODE', 'vpn')        # no profile yet: fail closed until one is assigned
    s = _slot(s['SLOT'])
    _dnsmasq_upstream(s)
    rc, out, err = _run([FIREWALL], 60)
    if rc != 0:
        # Leave nothing half-switched: put MODE back, re-apply, and report. The firewall itself has
        # already dropped all AP forwarding, so the slot is fail-closed either way.
        _set_env_key(env_path, 'MODE', was); _dnsmasq_upstream(_slot(s['SLOT'])); _run([FIREWALL], 60)
        raise ApError('firewall refused the new mode (rolled back to ' + was + '): ' + (err or out).strip()[-300:])
    _pin_write(s)
    _restart_hostapd(s); time.sleep(2)
    return {'slot': s['SLOT'], 'mode': mode, 'ssid': _ssid_of(s), 'hostapd': _active(s['HOSTAPD_UNIT']),
            'pin': _pin_info(_slot(s['SLOT']))}


def _claim_interface(ifname):
    """Take a radio away from NetworkManager and avahi, the way ap-slot-new.sh does for a new slot."""
    nm = '/etc/NetworkManager/conf.d/99-ap-unmanaged.conf'
    if os.path.isdir('/etc/NetworkManager'):
        try:
            txt = open(nm).read() if os.path.exists(nm) else '[keyfile]\nunmanaged-devices=\n'
            if f'interface-name:{ifname};' not in txt + ';':
                txt = re.sub(r'^(unmanaged-devices=)(.*)$',
                             lambda m: m.group(1) + (m.group(2) + ';' if m.group(2) else '') +
                                       f'interface-name:{ifname};interface-name:p2p-dev-{ifname}',
                             txt, count=1, flags=re.M)
                lan = _env().get('LAN_IF', 'eth0')
                if f'interface-name:{lan}' in txt: raise ApError('refusing: the LAN interface would become unmanaged')
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(nm)); os.write(fd, txt.encode()); os.close(fd)
                os.chmod(tmp, 0o644); os.replace(tmp, nm)
            _run(['/usr/bin/nmcli', 'device', 'set', ifname, 'managed', 'no'], 15)
            _run([SYSCTL, 'reload', 'NetworkManager'], 20)
        except ApError: raise
        except Exception: pass
    av = '/etc/avahi/avahi-daemon.conf'
    if os.path.exists(av):
        try:
            txt = open(av).read(); m = re.search(r'^deny-interfaces=(.*)$', txt, re.M)
            cur = [x for x in (m.group(1).split(',') if m else []) if x]
            if ifname not in cur:
                new = ','.join(sorted(set(cur + [ifname])))
                txt = (re.sub(r'^deny-interfaces=.*$', lambda _m: 'deny-interfaces=' + new, txt, count=1, flags=re.M)
                       if m else txt.replace('[server]', '[server]\ndeny-interfaces=' + new, 1))
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(av)); os.write(fd, txt.encode()); os.close(fd)
                os.chmod(tmp, 0o644); os.replace(tmp, av)
                _run([SYSCTL, 'restart', 'avahi-daemon'], 20)
        except Exception: pass


def _slot_bind_impl(slot, target, confirm=None):
    """Bind a slot to a different physical radio (by interface name or MAC). The default is that a new
    adapter gets its OWN slot - this is the explicit exception, for when you really mean 'this slot now
    lives on that device'. Refused when the device already belongs to another slot."""
    s = _slot(slot); _require_confirm(confirm, s)
    target = (target or '').strip().lower()
    devs = devices()
    d = next((x for x in devs if x['mac'] == target or x['if'] == target), None)
    if not d: raise ApError(f'no such radio: {target} (see: ap-ctl devices)')
    if d['slot'] and d['slot'] != s['SLOT']: raise ApError(f"that radio already belongs to slot {d['slot']}")
    if not d['ap_capable']: raise ApError(f"{d['if']} does not support AP mode")
    env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    _run([SYSCTL, 'stop', s['HOSTAPD_UNIT'], s['DNSMASQ_UNIT']], 60)
    _run([SYSCTL, 'stop', f"ap-wlan@{s['SLOT']}"], 30)
    _set_env_key(env_path, 'AP_MAC', d['mac']); _set_env_key(env_path, 'AP_IF', d['if'])
    for path, key in ((_hostapd_path(s), 'interface'), (s['DNSMASQ_CONF'], 'interface')):
        if os.path.exists(path):
            txt = re.sub(rf'^{key}=.*$', lambda m: f"{key}={d['if']}", open(path).read(), count=1, flags=re.M)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path)); os.write(fd, txt.encode()); os.close(fd)
            os.chmod(tmp, 0o600 if 'hostapd' in path else 0o644); os.replace(tmp, path)
    s = _slot(s['SLOT'])
    # A new radio is unknown to NetworkManager and avahi; without these it would be managed away or
    # announce the guest network, exactly as ap-slot-new.sh prevents for a freshly created slot.
    _claim_interface(d['if'])
    _run([SYSCTL, 'start', f"ap-wlan@{s['SLOT']}"], 30)
    rc, fo, fe = _run([FIREWALL], 60)
    if rc != 0: raise ApError('firewall refused the new radio: ' + (fe or fo).strip()[-300:])
    _run([SYSCTL, 'start', s['DNSMASQ_UNIT']], 30)
    _pin_write(s); _restart_hostapd(s); time.sleep(2)
    return {'slot': s['SLOT'], 'radio': _radio(_slot(s['SLOT'])), 'hostapd': _active(s['HOSTAPD_UNIT']),
            'pin': _pin_info(_slot(s['SLOT']))}


def _slot_sync_impl(slot=None):
    """Follow the pinned radio to whatever name it has now (ap-ifsync), then make the running services
    match: rewriting the config files alone would leave hostapd and dnsmasq bound to the old interface."""
    s = _slot(slot)
    rc, out, err = _run([IFSYNC, 'sync', s['SLOT']], 40)
    if rc != 0: raise ApError((err or out).strip()[-300:])
    moved = '->' in out
    s = _slot(s['SLOT'])
    if moved:
        _run([SYSCTL, 'stop', s['HOSTAPD_UNIT']], 60)
        _run([SYSCTL, 'restart', f"ap-wlan@{s['SLOT']}"], 30)
    rc, fo, fe = _run([FIREWALL], 60)
    if rc != 0: raise ApError('firewall refused the new interface: ' + (fe or fo).strip()[-300:])
    if moved:
        _run([SYSCTL, 'restart', s['DNSMASQ_UNIT']], 30)
        _restart_hostapd(s); time.sleep(2)
    return {'slot': s['SLOT'], 'msg': out.strip(), 'moved': moved, 'radio': _radio(_slot(s['SLOT'])),
            'hostapd': _active(s['HOSTAPD_UNIT']), 'pin': _pin_info(_slot(s['SLOT']))}


def _slot_enable_impl(slot, enabled):
    s = _slot(slot); env_path = os.path.join(SLOTS_DIR, s['SLOT'] + '.env')
    # A direct slot has no tunnel: starting or enabling one would contradict its pin and the watchdog
    # would stop the SSID a minute later.
    units = [s['HOSTAPD_UNIT'], s['DNSMASQ_UNIT']]
    if s.get('MODE', 'vpn') == 'vpn': units.append(f"wg-quick@{s['WG_IF']}")
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
    """What the outside world sees for this slot: the tunnel's exit in vpn mode, the LAN's own public
    address in direct mode (there the clients are simply NATed out like any other device on the LAN)."""
    s = _slot(slot)
    if s.get('MODE', 'vpn') == 'direct':
        lan = _env().get('LAN_IF', 'eth0')
        rc, out, err = _run(['/usr/bin/curl', '-4', '-s', '-m', '8', '--interface', lan, 'https://api.ipify.org'], 12)
        if rc != 0 or not out.strip(): raise ApError('could not read the exit IP (no internet on the LAN?)')
        return {'slot': s['SLOT'], 'exit_ip': out.strip(), 'via': lan, 'mode': 'direct'}
    addr = _iface_ip(s['WG_IF'])
    if not addr: raise ApError(f"no address on interface {s['WG_IF']}")
    src = addr.split('/')[0]
    rc, out, err = _run(['/usr/bin/curl', '-4', '-s', '-m', '8', '--interface', src, 'https://api.ipify.org'], 12)
    if rc != 0 or not out.strip(): raise ApError('could not read the exit IP (the tunnel may be down)')
    return {'slot': s['SLOT'], 'exit_ip': out.strip(), 'via': src, 'mode': 'vpn'}


# ----------------------------------------------------------------- system
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
    # Takes the same lock as the other long operations: two ap-firewall runs at once would flush the
    # chains under each other and one of them would finish against a half-built rule set.
    with long_op('firewall'):
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
    if name not in _UPDATABLE: raise ApError('only ' + ', '.join(_UPDATABLE) + ' can be updated')
    if not isinstance(content, str) or not (200 < len(content) < 400_000): raise ApError('invalid content size')
    dst = _UPDATABLE[name]
    fd, tmp = tempfile.mkstemp(suffix='.py', dir=os.path.dirname(dst), prefix='.upd-'); os.write(fd, content.encode()); os.close(fd)
    try:
        rc, out, err = _run([sys.executable, '-m', 'py_compile', tmp], 30)
        if rc != 0: raise ApError('syntax error: ' + (err or out).strip()[-300:])
        bak = dst + '.bak'
        if os.path.exists(dst): shutil.copy2(dst, bak)
        os.chmod(tmp, 0o755 if name.endswith('agent.py') else 0o644); os.replace(tmp, dst)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    if restart: _run([SYSTEMD_RUN, '--on-active=3s', '--unit=ble-agent-restart', SYSCTL, 'restart', 'ap-ble-agent'], 5)
    return {'updated': name, 'bytes': len(content), 'backup': bak, 'restart_in_s': 3 if restart else 0}


def ble_setname(name):
    if not isinstance(name, str) or not (1 <= len(name.encode()) <= 20) or not re.match(r'\A[A-Za-z0-9 _.-]+\Z', name):
        raise ApError('the name must be 1-20 bytes of letters/digits/space/-/_/.')
    _set_env_key(ENV, 'BLE_NAME', name)
    _run([SYSTEMD_RUN, '--on-active=3s', '--unit=ble-agent-restart', SYSCTL, 'restart', 'ap-ble-agent'], 5)
    return {'name': name, 'restart_in_s': 3}


def ble_token(regen=False):
    if regen or not os.path.exists(TOKEN):
        os.makedirs(os.path.dirname(TOKEN), exist_ok=True)
        fd = os.open(TOKEN, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, (secrets.token_hex(32) + '\n').encode()); os.close(fd)
    return {'token': open(TOKEN).read().strip(), 'path': TOKEN}


def ble_pair(seconds=120):
    """Open a pairing window: the agent watches this file and turns Pairable on temporarily."""
    seconds = max(10, min(int(seconds), 900)); os.makedirs(os.path.dirname(PAIR_FILE), exist_ok=True)
    with open(PAIR_FILE, 'w') as f: f.write(str(int(time.time()) + seconds))
    return {'pairable_for_s': seconds, 'hint': 'A new Mac can connect and pair during this window; afterwards the gate closes.'}


# ----------------------------------------------------------------- long-operation wrappers (locked)
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


def slot_mode(slot, mode, confirm=None):
    with long_op('slot.mode'):
        return _slot_mode_impl(slot, mode, confirm)


def slot_bind(slot, target, confirm=None):
    with long_op('slot.bind'):
        return _slot_bind_impl(slot, target, confirm)


def slot_sync(slot=None):
    with long_op('slot.sync'):
        return _slot_sync_impl(slot)


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
WEB_PW = '/etc/ap-vpn/web-password'   # content: salt_hex$pbkdf2(salt, pw)_hex


def _pw_hash(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000).hex()


def web_set_password(pw=None):
    """Set the password (generate and return a random one when none is given). Only the hash is stored."""
    shown = None
    if not pw: pw = secrets.token_urlsafe(12); shown = pw
    if not (8 <= len(pw) <= 128): raise ApError('the password must be 8-128 characters')
    salt = secrets.token_bytes(16)
    fd = os.open(WEB_PW, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, f'{salt.hex()}${_pw_hash(pw, salt)}\n'.encode()); os.close(fd)
    return {'set': True, 'password': shown, 'hint': 'Shown only once; if you lose it: sudo ap-ctl web password'}


def web_check_password(pw):
    try: salt_hex, h = open(WEB_PW).read().strip().split('$')
    except Exception: return False
    return hmac.compare_digest(_pw_hash(pw or '', bytes.fromhex(salt_hex)), h)


# ----------------------------------------------------------------- CLI
def _cli(argv):
    import argparse
    ap = argparse.ArgumentParser(prog='ap-ctl', description='Raspberry Pi VPN-AP control (multi-slot)')
    ap.add_argument('--slot', help='slot name (ap0, ap1 ...)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for c in ('status', 'clients', 'verify', 'exitip', 'slots', 'devices'): sub.add_parser(c)
    k = sub.add_parser('kick'); k.add_argument('mac')
    w = sub.add_parser('wifi'); ws = w.add_subparsers(dest='sub', required=True); ws.add_parser('get')
    wset = ws.add_parser('set'); wset.add_argument('--ssid'); wset.add_argument('--psk')
    v = sub.add_parser('vpn'); vs = v.add_subparsers(dest='sub', required=True); vs.add_parser('list')
    va = vs.add_parser('add'); va.add_argument('name'); va.add_argument('file', nargs='?'); va.add_argument('--overwrite', action='store_true')
    vr = vs.add_parser('remove'); vr.add_argument('name'); vx = vs.add_parser('activate'); vx.add_argument('name'); vx.add_argument('--force', action='store_true'); vx.add_argument('--confirm', help="the affected SSIDs, joined with ' / '")
    vsw = vs.add_parser('swap'); vsw.add_argument('slot_a'); vsw.add_argument('slot_b'); vsw.add_argument('--confirm', help="'SSID_A / SSID_B'")
    sl = sub.add_parser('slot'); sls = sl.add_subparsers(dest='sub', required=True); sls.add_parser('enable'); sls.add_parser('disable'); sls.add_parser('pin').add_argument('--confirm', help="the SSID of this slot")
    smode = sls.add_parser('mode'); smode.add_argument('value', choices=('vpn', 'direct')); smode.add_argument('--confirm', help="the SSID of this slot")
    sbind = sls.add_parser('bind'); sbind.add_argument('target', help='interface name or MAC of the radio'); sbind.add_argument('--confirm', help="the SSID of this slot")
    sls.add_parser('sync')
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
        elif a.cmd == 'devices': r = devices()
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
        elif a.cmd == 'slot':
            if a.sub == 'pin': r = slot_pin(a.slot, a.confirm)
            elif a.sub == 'mode': r = slot_mode(a.slot, a.value, a.confirm)
            elif a.sub == 'bind': r = slot_bind(a.slot, a.target, a.confirm)
            elif a.sub == 'sync': r = slot_sync(a.slot)
            else: r = slot_enable(a.slot, a.sub == 'enable')
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
        print(json.dumps({'error': 'root required (sudo ap-ctl ...)'}), file=sys.stderr); sys.exit(1)
    sys.exit(_cli(sys.argv[1:]))
