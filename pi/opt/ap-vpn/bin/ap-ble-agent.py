#!/usr/bin/env python3
"""
ap-ble-agent v2 — Pi5 VPN-AP icin BLE GATT yonetim arayuzu (PROTOKOL v2: uctan uca sifreli).

  Servis  7f2a0001-9c1e-4b7a-8d3e-5a6b7c8d9e0f
  RX      7f2a0002-...  (istemci -> Pi, write)
  TX      7f2a0003-...  (Pi -> istemci, notify)

Cerceve (her BLE yazimi/bildirimi): 1 bayt baslik (bit7=FIN, bit0-6=sira) + yuk.
Parcalar FIN'e kadar birlestirilir.

El sikisma (duz metin, sadece bu 4 mesaj):
  M->P {"op":"hello","v":2,"nonce":nc}
  P->M {"op":"challenge","v":2,"nonce":ns,"proof":HMAC(token,"srv|"+nc+"|"+ns),"name":BLE_NAME}
  M->P {"op":"auth","proof":HMAC(token,"cli|"+nc+"|"+ns)}
  P->M {"ok":true,"authed":true,"v":2}
  K = HKDF-SHA256(ikm=token, salt=nc||ns, info="piap-ble-v2", 32 bayt)

Sonrasi (her mesaj): counter(8B BE) || ChaCha20-Poly1305(K, nonce=dir(4B)||counter, JSON)
  dir: b"c2p\\0" istemci->Pi, b"p2c\\0" Pi->istemci. Counter her yonde kesin artan (replay korumasi).
  => TX bildirimlerini dinleyen ikinci bir abone SADECE sifreli metin gorur; sahte cerceveler tag'de duser;
     relay bir peripheral anahtari bilemez (inceleme bulgulari 1, 2, 4).

Ek sertlestirme: Pairable VARSAYILAN KAPALI (ap-ctl ble pair N ile pencere; bonded cihaz yoksa ilk 10 dk acik),
tek kimlik-dogrulanmis oturum (ikinci central dusurulur), global auth kilidi, uzun islemler icin kilit.
Pi -> istemci yonunde token ve WireGuard private key ASLA gonderilmez.
"""
import sys, os, json, hmac, hashlib, secrets, threading, time, struct, traceback, subprocess
import dbus, dbus.service, dbus.mainloop.glib, dbus.exceptions
from gi.repository import GLib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, '/opt/ap-vpn/lib')
import apctl

BLUEZ = 'org.bluez'
IFACE_GATT_MGR, IFACE_ADV_MGR = 'org.bluez.GattManager1', 'org.bluez.LEAdvertisingManager1'
IFACE_SERVICE, IFACE_CHAR, IFACE_ADV = 'org.bluez.GattService1', 'org.bluez.GattCharacteristic1', 'org.bluez.LEAdvertisement1'
IFACE_AGENT, IFACE_AGENT_MGR = 'org.bluez.Agent1', 'org.bluez.AgentManager1'
IFACE_ADAPTER, IFACE_DEVICE = 'org.bluez.Adapter1', 'org.bluez.Device1'
DBUS_OM, DBUS_PROP = 'org.freedesktop.DBus.ObjectManager', 'org.freedesktop.DBus.Properties'

SVC_UUID = '7f2a0001-9c1e-4b7a-8d3e-5a6b7c8d9e0f'
RX_UUID = '7f2a0002-9c1e-4b7a-8d3e-5a6b7c8d9e0f'
TX_UUID = '7f2a0003-9c1e-4b7a-8d3e-5a6b7c8d9e0f'
PROTO_VER = 2
MAX_MSG = 512 * 1024
SESSION_IDLE_S = 600
LOCK_DEV_FAILS, LOCK_DEV_S = 3, 60
LOCK_GLOBAL_FAILS, LOCK_GLOBAL_WINDOW_S, LOCK_GLOBAL_S = 6, 600, 120
FIRST_PAIR_WINDOW_S = 600

ENV = apctl._env()
ENCRYPT_LINK = ENV.get('BLE_ENCRYPT', '1') == '1'
LOCAL_NAME = ENV.get('BLE_NAME', 'PiAP')
DIR_C2P, DIR_P2C = b'c2p\x00', b'p2c\x00'


def log(*a): print('[ap-ble]', *a, flush=True)


class InvalidArgs(dbus.exceptions.DBusException): _dbus_error_name = 'org.freedesktop.DBus.Error.InvalidArgs'
class NotSupported(dbus.exceptions.DBusException): _dbus_error_name = 'org.bluez.Error.NotSupported'
class Failed(dbus.exceptions.DBusException): _dbus_error_name = 'org.bluez.Error.Failed'


def token_bytes(): return apctl.ble_token()['token'].encode()


def derive_key(nc, ns):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(nc) + bytes.fromhex(ns), info=b'piap-ble-v2').derive(token_bytes())


# ============================================================ oturum
class Session:
    __slots__ = ('dev', 'authed', 'nc', 'ns', 'key', 'c2p_last', 'p2c_next', 'fails', 'buf', 'seq', 'mtu', 'last')

    def __init__(self, dev):
        self.dev = dev; self.authed = False; self.nc = self.ns = None; self.key = None
        self.c2p_last = -1; self.p2c_next = 0; self.fails = 0
        self.buf = bytearray(); self.seq = 0; self.mtu = 23; self.last = time.time()

    def seal(self, obj):
        data = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()
        ctr = self.p2c_next; self.p2c_next += 1
        nonce = DIR_P2C + struct.pack('>Q', ctr)
        return struct.pack('>Q', ctr) + ChaCha20Poly1305(self.key).encrypt(nonce, data, None)

    def open(self, blob):
        if len(blob) < 8 + 16: raise ValueError('kisa')
        ctr = struct.unpack('>Q', blob[:8])[0]
        if ctr <= self.c2p_last: raise ValueError('replay/sira')
        pt = ChaCha20Poly1305(self.key).decrypt(DIR_C2P + blob[:8], blob[8:], None)
        self.c2p_last = ctr
        return json.loads(pt.decode('utf-8'))


class Sessions:
    def __init__(self):
        self.s = {}; self.lock = {}; self.gfails = []; self.glock_until = 0

    def get(self, dev, mtu=None):
        now = time.time(); s = self.s.get(dev)
        if s is None or now - s.last > SESSION_IDLE_S: s = Session(dev); self.s[dev] = s
        if mtu: s.mtu = int(mtu)
        s.last = now; return s

    def locked(self, dev):
        return self.lock.get(dev, 0) > time.time() or self.glock_until > time.time()

    def punish(self, dev, s):
        now = time.time(); s.fails += 1; s.authed = False; s.key = None
        self.gfails = [t for t in self.gfails if now - t < LOCK_GLOBAL_WINDOW_S] + [now]
        if s.fails >= LOCK_DEV_FAILS: self.lock[dev] = now + LOCK_DEV_S; s.fails = 0; log(f'{dev}: cihaz kilidi {LOCK_DEV_S}s')
        if len(self.gfails) >= LOCK_GLOBAL_FAILS: self.glock_until = now + LOCK_GLOBAL_S; log(f'GLOBAL auth kilidi {LOCK_GLOBAL_S}s')

    def drop(self, dev): self.s.pop(dev, None)

    def authed_other(self, dev):
        return any(x.authed and time.time() - x.last < SESSION_IDLE_S for d, x in self.s.items() if d != dev)


SESS = Sessions()
LONG_LOCK = threading.Lock()
LONG_OPS = {'vpn.activate', 'vpn.swap', 'vpn.add', 'verify', 'wifi.set', 'exitip', 'firewall', 'agent.update', 'slot.enable', 'slot.disable', 'slot.pin'}


# ============================================================ komutlar
def dispatch(msg):
    op = msg.get('op'); a = msg.get('args') or {}; slot = a.get('slot')
    if op == 'status':        return apctl.status()
    if op == 'slots':         return [apctl.slot_status(n) for n in apctl.slots()]
    if op == 'clients':       return apctl.clients(slot)
    if op == 'kick':          return apctl.kick(a.get('mac', ''), slot)
    if op == 'wifi.get':      return apctl.wifi_get(slot)
    if op == 'wifi.set':      return apctl.wifi_set(slot, a.get('ssid'), a.get('psk'))
    if op == 'vpn.list':      return apctl.vpn_list()
    if op == 'vpn.add':       return apctl.vpn_add(a.get('name'), a.get('conf'), bool(a.get('overwrite')))
    if op == 'vpn.remove':    return apctl.vpn_remove(a.get('name'))
    if op == 'vpn.activate':  return apctl.vpn_activate(a.get('name'), slot, bool(a.get('force')), a.get('confirm'))
    if op == 'vpn.swap':      return apctl.vpn_swap(a.get('slot_a'), a.get('slot_b'), a.get('confirm'))
    if op == 'slot.enable':   return apctl.slot_enable(slot, True)
    if op == 'slot.disable':  return apctl.slot_enable(slot, False)
    if op == 'slot.pin':      return apctl.slot_pin(slot, a.get('confirm'))
    if op == 'exitip':        return apctl.exit_ip(slot)
    if op == 'verify':        return apctl.verify(slot)
    if op == 'firewall':      return apctl.firewall_reapply()
    if op == 'logs':          return apctl.system_logs(a.get('lines', 60), a.get('unit'))
    if op == 'reboot':        return apctl.system_reboot()
    if op == 'ping':          return {'pong': int(time.time())}
    if op == 'agent.update':  return apctl.agent_update(a.get('name'), a.get('content'), bool(a.get('restart', True)))
    if op == 'ble.setname':   return apctl.ble_setname(a.get('name'))
    if op == 'ble.info':      return {'name': LOCAL_NAME, 'encrypt': ENCRYPT_LINK, 'ver': PROTO_VER}
    raise apctl.ApError(f'bilinmeyen op: {op}')


# ============================================================ GATT
class Application(dbus.service.Object):
    PATH = '/org/apvpn/app'
    def __init__(self, bus): super().__init__(bus, self.PATH); self.services = []
    def add(self, s): self.services.append(s)
    @dbus.service.method(DBUS_OM, out_signature='a{oa{sa{sv}}}')
    def GetManagedObjects(self):
        r = {}
        for s in self.services:
            r[s.get_path()] = s.get_properties()
            for c in s.characteristics: r[c.get_path()] = c.get_properties()
        return r


class Service(dbus.service.Object):
    def __init__(self, bus, index, uuid):
        self.path = f'{Application.PATH}/service{index}'; self.uuid = uuid; self.characteristics = []
        super().__init__(bus, self.path)
    def get_path(self): return dbus.ObjectPath(self.path)
    def add(self, c): self.characteristics.append(c)
    def get_properties(self):
        return {IFACE_SERVICE: {'UUID': self.uuid, 'Primary': True,
                                'Characteristics': dbus.Array([c.get_path() for c in self.characteristics], signature='o')}}
    @dbus.service.method(DBUS_PROP, in_signature='s', out_signature='a{sv}')
    def GetAll(self, iface):
        if iface != IFACE_SERVICE: raise InvalidArgs()
        return self.get_properties()[IFACE_SERVICE]


class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = f'{service.path}/char{index}'; self.uuid = uuid; self.service = service; self.flags = flags; self.notifying = False
        super().__init__(bus, self.path)
    def get_path(self): return dbus.ObjectPath(self.path)
    def get_properties(self):
        return {IFACE_CHAR: {'Service': self.service.get_path(), 'UUID': self.uuid,
                             'Flags': dbus.Array(self.flags, signature='s'), 'Notifying': dbus.Boolean(self.notifying)}}
    @dbus.service.method(DBUS_PROP, in_signature='s', out_signature='a{sv}')
    def GetAll(self, iface):
        if iface != IFACE_CHAR: raise InvalidArgs()
        return self.get_properties()[IFACE_CHAR]
    @dbus.service.method(IFACE_CHAR, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options): raise NotSupported()
    @dbus.service.method(IFACE_CHAR, in_signature='aya{sv}')
    def WriteValue(self, value, options): raise NotSupported()
    @dbus.service.method(IFACE_CHAR)
    def StartNotify(self): raise NotSupported()
    @dbus.service.method(IFACE_CHAR)
    def StopNotify(self): raise NotSupported()
    @dbus.service.signal(DBUS_PROP, signature='sa{sv}as')
    def PropertiesChanged(self, interface, changed, invalidated): pass


class TxCharacteristic(Characteristic):
    def __init__(self, bus, index, service):
        super().__init__(bus, index, TX_UUID, ['encrypt-read', 'notify'] if ENCRYPT_LINK else ['read', 'notify'], service)
        self.seq = 0
    @dbus.service.method(IFACE_CHAR, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        return dbus.Array([dbus.Byte(b) for b in json.dumps({'v': PROTO_VER, 'name': LOCAL_NAME}).encode()], signature='y')
    @dbus.service.method(IFACE_CHAR)
    def StartNotify(self): self.notifying = True; log('TX: notify acildi')
    @dbus.service.method(IFACE_CHAR)
    def StopNotify(self): self.notifying = False; log('TX: notify kapandi')
    def send_raw(self, data, mtu):
        if not self.notifying: log('TX: abone yok, mesaj dusuruldu'); return
        chunk = max(16, min(int(mtu), 512) - 3 - 1)
        parts = [data[i:i + chunk] for i in range(0, len(data), chunk)] or [b'']
        for i, p in enumerate(parts):
            hdr = (0x80 if i == len(parts) - 1 else 0) | (self.seq & 0x7f); self.seq = (self.seq + 1) & 0x7f
            self.PropertiesChanged(IFACE_CHAR, {'Value': dbus.Array([dbus.Byte(b) for b in bytes([hdr]) + p], signature='y')}, [])


class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, tx):
        super().__init__(bus, index, RX_UUID, ['encrypt-write'] if ENCRYPT_LINK else ['write', 'write-without-response'], service)
        self.tx = tx

    @dbus.service.method(IFACE_CHAR, in_signature='aya{sv}')
    def WriteValue(self, value, options):
        dev = str(options.get('device', 'unknown')); raw = bytes(value)
        if not raw: raise InvalidArgs()
        if SESS.locked(dev): raise Failed('locked')
        s = SESS.get(dev, options.get('mtu'))
        hdr, payload = raw[0], raw[1:]; fin, seq = bool(hdr & 0x80), hdr & 0x7f
        if seq != s.seq: s.buf = bytearray(); s.seq = seq
        s.buf += payload; s.seq = (seq + 1) & 0x7f
        if len(s.buf) > MAX_MSG: s.buf = bytearray(); raise InvalidArgs()
        if not fin: return
        data = bytes(s.buf); s.buf = bytearray()
        if s.authed and s.key:
            try: msg = s.open(data)
            except Exception as e:
                log(f'{dev}: sifreli mesaj acilamadi ({e}) - oturum dusuruldu'); s.authed = False; s.key = None
                self._plain(s, {'ok': False, 'error': 'oturum gecersiz, yeniden hello'}); return
            self._command(s, msg); return
        try:
            msg = json.loads(data.decode('utf-8'))
            if not isinstance(msg, dict): raise ValueError('dict degil')
        except Exception as e:
            self._plain(s, {'ok': False, 'error': f'gecersiz JSON: {e}'}); return
        self._handshake(s, msg)

    def _plain(self, s, obj):
        data = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()
        GLib.idle_add(lambda: (self.tx.send_raw(data, s.mtu), False)[1])

    def _sealed(self, s, obj):
        try: data = s.seal(obj)
        except Exception as e: log('seal hatasi', e); return
        GLib.idle_add(lambda: (self.tx.send_raw(data, s.mtu), False)[1])

    def _handshake(self, s, msg):
        op = msg.get('op'); mid = msg.get('id')
        if op == 'hello':
            nc = str(msg.get('nonce', ''))
            if msg.get('v') != PROTO_VER or len(nc) != 32 or any(c not in '0123456789abcdef' for c in nc):
                self._plain(s, {'id': mid, 'ok': False, 'error': f'protokol v{PROTO_VER} gerekli (uygulamayi guncelleyin)'}); return
            if SESS.authed_other(s.dev):
                self._plain(s, {'id': mid, 'ok': False, 'error': 'baska bir oturum aktif'}); log(f'{s.dev}: ikinci oturum reddedildi'); return
            s.authed = False; s.key = None; s.nc = nc; s.ns = secrets.token_hex(16)
            proof = hmac.new(token_bytes(), f'srv|{s.nc}|{s.ns}'.encode(), hashlib.sha256).hexdigest()
            self._plain(s, {'id': mid, 'op': 'challenge', 'v': PROTO_VER, 'nonce': s.ns, 'proof': proof, 'name': LOCAL_NAME}); return
        if op == 'auth':
            if not s.nc or not s.ns: self._plain(s, {'id': mid, 'ok': False, 'error': 'once hello'}); return
            expect = hmac.new(token_bytes(), f'cli|{s.nc}|{s.ns}'.encode(), hashlib.sha256).hexdigest()
            given = str(msg.get('proof', '')); nc, ns = s.nc, s.ns; s.nc = s.ns = None
            if hmac.compare_digest(expect, given):
                s.key = derive_key(nc, ns); s.c2p_last = -1; s.p2c_next = 0; s.authed = True; s.fails = 0
                log(f'{s.dev}: kimlik dogrulandi (v2, sifreli oturum)')
                self._plain(s, {'id': mid, 'ok': True, 'authed': True, 'v': PROTO_VER}); return
            SESS.punish(s.dev, s); log(f'{s.dev}: auth BASARISIZ')
            self._plain(s, {'id': mid, 'ok': False, 'error': 'kimlik dogrulama basarisiz'}); return
        self._plain(s, {'id': mid, 'ok': False, 'error': 'yetkisiz (once hello+auth)'})

    def _command(self, s, msg):
        op = msg.get('op'); mid = msg.get('id')
        def work():
            try: out = {'id': mid, 'ok': True, 'result': dispatch(msg)}
            except apctl.ApError as e: out = {'id': mid, 'ok': False, 'error': str(e)}
            except Exception as e: log('HATA', op, traceback.format_exc()); out = {'id': mid, 'ok': False, 'error': f'ic hata: {e}'}
            finally:
                if op in LONG_OPS: LONG_LOCK.release()
            self._sealed(s, out)
        if op in LONG_OPS:
            if not LONG_LOCK.acquire(blocking=False):
                self._sealed(s, {'id': mid, 'ok': False, 'error': 'baska bir uzun islem suruyor, bekleyin'}); return
            self._sealed(s, {'id': mid, 'ack': True, 'op': op})
            threading.Thread(target=work, daemon=True).start()
        else:
            work()


# ============================================================ reklam / agent
class Advertisement(dbus.service.Object):
    PATH = '/org/apvpn/adv0'
    def __init__(self, bus): super().__init__(bus, self.PATH)
    def props(self):
        return {'Type': 'peripheral', 'ServiceUUIDs': dbus.Array([SVC_UUID], signature='s'), 'LocalName': dbus.String(LOCAL_NAME),
                'Includes': dbus.Array(['tx-power'], signature='s'), 'Discoverable': dbus.Boolean(True)}
    @dbus.service.method(DBUS_PROP, in_signature='s', out_signature='a{sv}')
    def GetAll(self, iface):
        if iface != IFACE_ADV: raise InvalidArgs()
        return self.props()
    @dbus.service.method(IFACE_ADV)
    def Release(self): log('reklam serbest birakildi')


class Agent(dbus.service.Object):
    """Just-Works. Gercek kimlik = HMAC/AEAD; eslestirme kapisi Pairable ile kontrol edilir."""
    PATH = '/org/apvpn/agent'
    def __init__(self, bus): super().__init__(bus, self.PATH)
    @dbus.service.method(IFACE_AGENT)
    def Release(self): pass
    @dbus.service.method(IFACE_AGENT, in_signature='os')
    def AuthorizeService(self, device, uuid): pass
    @dbus.service.method(IFACE_AGENT, in_signature='o', out_signature='s')
    def RequestPinCode(self, device): return '0000'
    @dbus.service.method(IFACE_AGENT, in_signature='o', out_signature='u')
    def RequestPasskey(self, device): return dbus.UInt32(0)
    @dbus.service.method(IFACE_AGENT, in_signature='ouq')
    def DisplayPasskey(self, device, passkey, entered): pass
    @dbus.service.method(IFACE_AGENT, in_signature='os')
    def DisplayPinCode(self, device, pincode): pass
    @dbus.service.method(IFACE_AGENT, in_signature='ou')
    def RequestConfirmation(self, device, passkey): log(f'eslestirme kabul: {device}')
    @dbus.service.method(IFACE_AGENT, in_signature='o')
    def RequestAuthorization(self, device): log(f'yetkilendirme kabul: {device}')
    @dbus.service.method(IFACE_AGENT)
    def Cancel(self): pass


def mgmt_adv_start():
    name = LOCAL_NAME.encode()[:20]; scan_rsp = bytes([len(name) + 1, 0x09]) + name
    inner = f"btmgmt add-adv -c -g -u {SVC_UUID} -s {scan_rsp.hex()} 1"
    r = subprocess.run(['/usr/bin/timeout', '5', '/usr/bin/script', '-qc', inner, '/dev/null'], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    ok = 'Instance added' in (r.stdout + r.stderr)
    if not ok: log('btmgmt add-adv basarisiz:', (r.stdout + r.stderr).strip()[-200:])
    return ok


def mgmt_adv_stop():
    subprocess.run(['/usr/bin/timeout', '5', '/usr/bin/script', '-qc', 'btmgmt rm-adv 1', '/dev/null'], capture_output=True, stdin=subprocess.DEVNULL)


def find_adapter(bus):
    om = dbus.Interface(bus.get_object(BLUEZ, '/'), DBUS_OM)
    for path, ifaces in om.GetManagedObjects().items():
        if IFACE_GATT_MGR in ifaces and IFACE_ADV_MGR in ifaces: return path
    return None


def bonded_count(bus):
    om = dbus.Interface(bus.get_object(BLUEZ, '/'), DBUS_OM); n = 0
    for path, ifaces in om.GetManagedObjects().items():
        d = ifaces.get(IFACE_DEVICE)
        if d and d.get('Paired'): n += 1
    return n


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True); dbus.mainloop.glib.threads_init()
    bus = dbus.SystemBus(); adapter = find_adapter(bus)
    if not adapter: log('GATT/LEAdvertising destekli adaptor yok'); sys.exit(1)
    log(f'adaptor: {adapter} proto=v{PROTO_VER} link-encrypt={ENCRYPT_LINK} name={LOCAL_NAME}')
    props = dbus.Interface(bus.get_object(BLUEZ, adapter), DBUS_PROP)
    props.Set(IFACE_ADAPTER, 'Powered', dbus.Boolean(True)); props.Set(IFACE_ADAPTER, 'Alias', dbus.String(LOCAL_NAME))
    props.Set(IFACE_ADAPTER, 'Discoverable', dbus.Boolean(False))
    apctl.ble_token()

    # ---- eslestirme kapisi: varsayilan KAPALI; pencere = /run/ap-vpn/ble-pair-until; bonded cihaz yoksa ilk 10 dk acik
    pair_state = {'open': None}
    if bonded_count(bus) == 0:
        apctl.ble_pair(FIRST_PAIR_WINDOW_S); log(f'bonded cihaz yok -> {FIRST_PAIR_WINDOW_S}s eslestirme penceresi')
    def pair_tick():
        try: until = int(open(apctl.PAIR_FILE).read().strip())
        except Exception: until = 0
        want = time.time() < until
        if want != pair_state['open']:
            props.Set(IFACE_ADAPTER, 'Pairable', dbus.Boolean(want))
            if want: props.Set(IFACE_ADAPTER, 'PairableTimeout', dbus.UInt32(max(10, int(until - time.time()))))
            pair_state['open'] = want; log('eslestirme penceresi ' + ('ACIK' if want else 'kapali'))
        return True
    pair_tick(); GLib.timeout_add_seconds(5, pair_tick)

    app = Application(bus); svc = Service(bus, 0, SVC_UUID); tx = TxCharacteristic(bus, 0, svc); rx = RxCharacteristic(bus, 1, svc, tx)
    svc.add(tx); svc.add(rx); app.add(svc)
    agent = Agent(bus); am = dbus.Interface(bus.get_object(BLUEZ, '/org/bluez'), IFACE_AGENT_MGR)
    am.RegisterAgent(Agent.PATH, 'NoInputNoOutput'); am.RequestDefaultAgent(Agent.PATH)
    gm = dbus.Interface(bus.get_object(BLUEZ, adapter), IFACE_GATT_MGR)
    gm.RegisterApplication(Application.PATH, {}, reply_handler=lambda: log('GATT uygulamasi kayitli'),
                           error_handler=lambda e: (log('GATT kayit HATASI', e), sys.exit(1)))
    adv = Advertisement(bus); lm = dbus.Interface(bus.get_object(BLUEZ, adapter), IFACE_ADV_MGR); state = {'mode': None}
    def adv_ok(): state['mode'] = 'dbus'; log(f'LE reklami yayinda (D-Bus): "{LOCAL_NAME}"')
    def adv_fail(e):
        log('D-Bus reklam reddedildi -> legacy btmgmt')
        if mgmt_adv_start(): state['mode'] = 'mgmt'; log(f'LE reklami yayinda (legacy mgmt): "{LOCAL_NAME}"')
        else: log('HICBIR reklam yolu calismadi'); sys.exit(1)
    lm.RegisterAdvertisement(Advertisement.PATH, {}, reply_handler=adv_ok, error_handler=adv_fail)
    def adv_refresh():
        if state['mode'] == 'mgmt': mgmt_adv_start()
        return True
    GLib.timeout_add_seconds(60, adv_refresh)

    # ---- tek oturum: kimligi dogrulanmis oturum varken baglanan ikinci cihazi dusur; kopanin oturumunu sil
    def on_props(iface, changed, invalidated, path=None):
        if iface != IFACE_DEVICE or 'Connected' not in changed: return
        p = str(path)
        if changed['Connected']:
            if SESS.authed_other(p):
                try: dbus.Interface(bus.get_object(BLUEZ, p), IFACE_DEVICE).Disconnect(); log(f'{p}: ikinci central dusuruldu')
                except Exception as e: log('disconnect hatasi', e)
        else:
            SESS.drop(p); log(f'{p}: baglanti koptu, oturum silindi')
    bus.add_signal_receiver(on_props, dbus_interface=DBUS_PROP, signal_name='PropertiesChanged', path_keyword='path')

    loop = GLib.MainLoop()
    try: loop.run()
    except KeyboardInterrupt: pass
    finally:
        mgmt_adv_stop()
        try: lm.UnregisterAdvertisement(Advertisement.PATH)
        except Exception: pass
        try: gm.UnregisterApplication(Application.PATH)
        except Exception: pass


if __name__ == '__main__':
    if os.geteuid() != 0: log('root gerekli'); sys.exit(1)
    main()
