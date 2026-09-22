#!/usr/bin/env python3
"""
ap-web — web management panel for the Pi VPN-AP (Flask, HTTPS :8443).
Same core (apctl) as the BLE agent: same operations, same lock.
Security: password (PBKDF2, /etc/ap-vpn/web-password), session cookie (HttpOnly+Secure+SameSite=Strict),
X-Requested-With: piap required on state-changing requests (CSRF), login rate limit (per IP and global).
Access from the AP and tunnel interfaces is blocked in the firewall (LAN only).
"""
import os, sys, time, json, secrets, functools, threading, logging
from flask import Flask, request, jsonify, make_response, send_file, abort

sys.path.insert(0, '/opt/ap-vpn/lib')
import apctl

APP_DIR = '/opt/ap-vpn/web'
CERT, KEY = '/etc/ap-vpn/web-cert.pem', '/etc/ap-vpn/web-key.pem'
PORT = int(apctl._env().get('WEB_PORT', '8443'))
SESSION_TTL = 12 * 3600

app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024
log = logging.getLogger('ap-web'); logging.basicConfig(level=logging.INFO, format='[ap-web] %(message)s')

SESSIONS = {}            # sid -> {'exp': ts, 'ip': str}
FAILS = {}               # ip -> [ts...]
GFAILS = []
LOCK = threading.Lock()


def _client_ip(): return request.remote_addr or '?'


def _rate_ok(ip):
    now = time.time()
    with LOCK:
        FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 600]
        GFAILS[:] = [t for t in GFAILS if now - t < 600]
        return len(FAILS[ip]) < 5 and len(GFAILS) < 20


def _fail(ip):
    with LOCK: FAILS.setdefault(ip, []).append(time.time()); GFAILS.append(time.time())


def _session():
    sid = request.cookies.get('piap_session')
    s = SESSIONS.get(sid) if sid else None
    if not s or s['exp'] < time.time(): return None
    s['exp'] = time.time() + SESSION_TTL
    return s


def auth(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not _session(): return jsonify(ok=False, error='login required'), 401
        if request.method != 'GET' and request.headers.get('X-Requested-With') != 'piap':
            return jsonify(ok=False, error='CSRF: X-Requested-With missing'), 403
        return f(*a, **k)
    return w


def ok(result): return jsonify(ok=True, result=result)


def api(fn, *a, **k):
    try: return ok(fn(*a, **k))
    except apctl.ApError as e: return jsonify(ok=False, error=str(e)), 400
    except Exception as e:
        log.exception('internal error'); return jsonify(ok=False, error=f'internal error: {e}'), 500


def body(): return request.get_json(silent=True) or {}


# ---------------------------------------------------------------- page
@app.get('/')
def index():
    r = make_response(send_file(os.path.join(APP_DIR, 'index.html')))
    r.headers['Cache-Control'] = 'no-store'
    r.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    r.headers['X-Frame-Options'] = 'DENY'; r.headers['X-Content-Type-Options'] = 'nosniff'; r.headers['Referrer-Policy'] = 'no-referrer'
    return r


# ---------------------------------------------------------------- session
@app.post('/api/login')
def login():
    ip = _client_ip()
    if not _rate_ok(ip): return jsonify(ok=False, error='too many failed attempts, wait 10 minutes'), 429
    pw = str(body().get('password', ''))
    if not apctl.web_check_password(pw):
        _fail(ip); log.warning(f'{ip}: failed login'); time.sleep(0.5)
        return jsonify(ok=False, error='wrong password'), 401
    sid = secrets.token_urlsafe(32); SESSIONS[sid] = {'exp': time.time() + SESSION_TTL, 'ip': ip}
    log.info(f'{ip}: logged in')
    r = ok({'authed': True}); r.set_cookie('piap_session', sid, max_age=SESSION_TTL, httponly=True, secure=True, samesite='Strict', path='/')
    return r


@app.post('/api/logout')
def logout():
    sid = request.cookies.get('piap_session'); SESSIONS.pop(sid, None)
    r = ok({'authed': False}); r.delete_cookie('piap_session'); return r


@app.get('/api/me')
def me(): return ok({'authed': bool(_session()), 'name': apctl._env().get('BLE_NAME', 'PiAP')})


# ---------------------------------------------------------------- read
@app.get('/api/status')
@auth
def status(): return api(apctl.status)

@app.get('/api/clients')
@auth
def clients(): return api(apctl.clients, request.args.get('slot'))

@app.get('/api/profiles')
@auth
def profiles(): return api(apctl.vpn_list)

@app.get('/api/wifi/<slot>')
@auth
def wifi_get(slot): return api(apctl.wifi_get, slot)

@app.get('/api/logs')
@auth
def logs(): return api(apctl.system_logs, request.args.get('lines', 80), request.args.get('unit'))


# ---------------------------------------------------------------- write
@app.post('/api/slot/<slot>/enable')
@auth
def slot_enable(slot): return api(apctl.slot_enable, slot, True)

@app.post('/api/slot/<slot>/disable')
@auth
def slot_disable(slot): return api(apctl.slot_enable, slot, False)

@app.post('/api/slot/<slot>/profile')
@auth
def slot_profile(slot):
    b = body(); return api(apctl.vpn_activate, b.get('name'), slot, bool(b.get('force')), b.get('confirm'))

@app.post('/api/swap')
@auth
def swap():
    b = body(); return api(apctl.vpn_swap, b.get('a'), b.get('b'), b.get('confirm'))

@app.post('/api/slot/<slot>/pin')
@auth
def slot_pin(slot):
    b = body(); return api(apctl.slot_pin, slot, b.get('confirm'))

@app.post('/api/wifi/<slot>')
@auth
def wifi_set(slot):
    b = body(); return api(apctl.wifi_set, slot, b.get('ssid'), b.get('psk'))

@app.post('/api/profiles')
@auth
def profile_add():
    b = body(); return api(apctl.vpn_add, b.get('name'), b.get('conf'), bool(b.get('overwrite')))

@app.delete('/api/profiles/<name>')
@auth
def profile_del(name): return api(apctl.vpn_remove, name)

@app.post('/api/exitip/<slot>')
@auth
def exitip(slot): return api(apctl.exit_ip, slot)

@app.post('/api/kick')
@auth
def kick():
    b = body(); return api(apctl.kick, b.get('mac', ''), b.get('slot'))

@app.post('/api/verify')
@auth
def verify(): return api(apctl.verify, request.args.get('slot'))

@app.post('/api/firewall')
@auth
def firewall(): return api(apctl.firewall_reapply)

@app.post('/api/reboot')
@auth
def reboot(): return api(apctl.system_reboot)

@app.post('/api/password')
@auth
def password():
    b = body(); return api(apctl.web_set_password, b.get('password'))


@app.errorhandler(404)
def nf(e): return jsonify(ok=False, error='not found'), 404


if __name__ == '__main__':
    if os.geteuid() != 0: print('root required'); sys.exit(1)
    if not (os.path.exists(CERT) and os.path.exists(KEY)): print('no certificate:', CERT); sys.exit(1)
    log.info(f'https://0.0.0.0:{PORT} (LAN only; the AP and tunnel interfaces are blocked in the firewall)')
    from werkzeug.serving import make_server
    srv = make_server('0.0.0.0', PORT, app, threaded=True, ssl_context=(CERT, KEY))
    srv.serve_forever()
