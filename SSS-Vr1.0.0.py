# ============================================================
# SSS is Start now
# ============================================================
print("SSS Vr1.0.0")
# 1. install
!apt-get update -qq && apt-get install -y -qq tor
!pip install flask requests requests[socks] cryptography -q
!wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O /content/cloudflared
!chmod +x /content/cloudflared
print("Installation complete")

# 2. Tor
import os, subprocess, time, socket, requests, base64, re, json, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib.parse import urlparse
import ipaddress
import hashlib
from functools import wraps

os.system('pkill -9 -f tor')
time.sleep(1)

os.system('rm -rf /content/tor_data')
os.makedirs('/content/tor_data', exist_ok=True)

torrc = """SocksPort 127.0.0.1:9050
DataDirectory /content/tor_data
ExitPolicy reject *:*
Log notice file /content/tor_log.txt"""
with open('/content/torrc', 'w') as f:
    f.write(torrc)

subprocess.Popen(
    ['tor', '-f', '/content/torrc'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
)
print("Waiting for service to start...")
for i in range(20):
    time.sleep(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sock.connect_ex(('127.0.0.1', 9050)) == 0:
        print("✓ Internal service startup completed")
        sock.close()
        break
    sock.close()
    print(f" 待機... ({i+1}/20)")
else:
    raise RuntimeError("☓ oops, Internal service startup failed.")

# 3. app.py
app_code = r'''import json, base64, re, os, secrets, time
from flask import Flask, request, Response, jsonify
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib.parse import urlparse
import ipaddress
import hashlib
from functools import wraps

app = Flask(__name__)

EXPECTED_HASH = "============your hash here==============="

_tokens = {}
_TOKEN_EXPIRE = 3600

def _gen_token():
    t = secrets.token_urlsafe(32)
    _tokens[t] = { 'exp': time.time() + _TOKEN_EXPIRE, 'u': 'auth' }
    return t

def _verify_token(tk):
    if not tk: return False
    d = _tokens.get(tk)
    if not d: return False
    if time.time() > d['exp']:
        del _tokens[tk]
        return False
    return True

def _auth(f):
    @wraps(f)
    def dec(*args, **kwargs):
        tk = request.headers.get('Authorization')
        if not tk:
            return Response('Unauthorized', status=401)
        if tk.startswith('Bearer '):
            tk = tk[7:]
        if not _verify_token(tk):
            return Response('Unauthorized', status=401)
        return f(*args, **kwargs)
    return dec

_ALLOWED_SCHEMES = ('http', 'https')
_BLOCKED_HOSTS = {
    'localhost', '127.0.0.1', '0.0.0.0',
    '169.254.169.254', 'metadata.google.internal', 'instance-metadata'
}

def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def _validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return f'Fraudulent scheme: {parsed.scheme}'
    host = parsed.hostname or ''
    if not host:
        return 'Invalid URL'
    if host in _BLOCKED_HOSTS:
        return 'Access-denied host'
    if _is_private_ip(host):
        return 'Access to private IPs is prohibited.'
    return None

_KEY_FILE = '/content/session_key.bin'
if os.path.exists(_KEY_FILE):
    with open(_KEY_FILE, 'rb') as f:
        SESSION_KEY = f.read()
else:
    SESSION_KEY = AESGCM.generate_key(bit_length=256)
    with open(_KEY_FILE, 'wb') as f:
        f.write(SESSION_KEY)

_PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'password' not in data:
        return 'No password', 400
    pwd = data['password']
    hashed = hashlib.sha3_256(pwd.encode('utf-8')).hexdigest()
    if hashed == EXPECTED_HASH:
        token = _gen_token()
        return jsonify({'status': 'success', 'token': token}), 200
    else:
        return 'wrong pass word', 401

@app.route('/ping', methods=['GET'])
def ping():
    return 'pong'

@app.route('/get_key', methods=['GET'])
@_auth
def get_key():
    return jsonify({'key': base64.b64encode(SESSION_KEY).decode()})

@app.route('/')
def index():
    return """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>DeepSearch Browser</title></head>
<body style="margin:0;font-family:sans-serif;background:#1a1a2e;color:#fff;">
    <div id="L1" style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#1a1a2e;">
        <div style="background:#16213e;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.3);text-align:center;">
            <h2 style="margin:0 0 20px;color:#e94560;">Authentication Required</h2>
            <input id="I1" type="password" placeholder="Password" style="padding:12px 16px;font-size:16px;border:none;border-radius:8px;background:#0f3460;color:#fff;width:250px;outline:none;margin-bottom:16px;display:block;">
            <button id="B1" style="padding:12px 32px;background:#e94560;border:none;border-radius:8px;color:#fff;font-size:16px;font-weight:bold;cursor:pointer;">Login</button>
            <div id="M1" style="margin-top:12px;color:#e94560;font-size:14px;min-height:20px;"></div>
        </div>
    </div>
    <div id="L2" style="display:none;">
        <div style="padding:16px 20px;background:#16213e;border-bottom:2px solid #0f3460;display:flex;gap:12px;flex-wrap:wrap;">
            <input id="I2" type="text" placeholder="Enter URL (例: duckduckgo.com)" style="flex:1;min-width:200px;padding:10px 16px;font-size:15px;border:none;border-radius:8px;background:#0f3460;color:#fff;outline:none;">
            <button id="B2" style="padding:10px 28px;background:#e94560;border:none;border-radius:8px;color:#fff;font-size:15px;font-weight:bold;cursor:pointer;">Go</button>
            <button id="B3" style="padding:10px 20px;background:#0f3460;border:none;border-radius:8px;color:#fff;font-size:15px;cursor:pointer;">Logout</button>
            <span id="S1" style="font-size:13px;color:#4ecdc4;">&bull; Ready</span>
        </div>
        <iframe id="F1" style="width:100%;height:calc(100vh - 80px);border:none;background:#fff;"></iframe>
    </div>
    <script>
    const _B = window.location.origin;
    const _T = localStorage.getItem('_t');
    const _L1 = document.getElementById('L1');
    const _L2 = document.getElementById('L2');
    const _M = document.getElementById('M1');

    if (!_T) { _L1.style.display = 'flex'; _L2.style.display = 'none'; }
    else { _L1.style.display = 'none'; _L2.style.display = 'block'; }

    async function _login() {
        const p = document.getElementById('I1').value;
        const r = await fetch(_B + '/login', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({password: p})
        });
        if (r.ok) {
            const d = await r.json();
            localStorage.setItem('_t', d.token);
            location.reload();
        } else {
            _M.textContent = 'Invalid password';
        }
    }
    document.getElementById('B1').addEventListener('click', _login);
    document.getElementById('I1').addEventListener('keydown', e => { if(e.key==='Enter') _login(); });
    document.getElementById('B3').addEventListener('click', () => {
        localStorage.removeItem('_t');
        location.reload();
    });

    const _I = document.getElementById('I2');
    const _F = document.getElementById('F1');
    const _S = document.getElementById('S1');
    let _K = null;

    function _headers(e) {
        const h = {'Content-Type':'application/json'};
        if (_T) h['Authorization'] = 'Bearer ' + _T;
        return Object.assign(h, e || {});
    }

    async function _getKey() {
        const r = await fetch(_B + '/get_key', { headers: _headers() });
        if (!r.ok) {
            if (r.status === 401) {
                localStorage.removeItem('_t');
                location.reload();
                return;
            }
            throw new Error(await r.text());
        }
        const d = await r.json();
        _K = Uint8Array.from(atob(d.key), c => c.charCodeAt(0));
    }

    async function _enc(p) {
        if (!_K) await _getKey();
        const e = new TextEncoder().encode(p);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await crypto.subtle.importKey('raw', _K, {name:'AES-GCM'}, false, ['encrypt']);
        const enc = await crypto.subtle.encrypt({name:'AES-GCM', iv:iv}, key, e);
        const c = new Uint8Array(iv.length + enc.byteLength);
        c.set(iv);
        c.set(new Uint8Array(enc), iv.length);
        return btoa(String.fromCharCode(...c));
    }

    async function _load() {
        let u = _I.value.trim();
        if (!u) return;
        if (!/^https?:\\/\\//i.test(u)) u = 'https://' + u;
        _S.textContent = '⏳ Encrypting...';
        _S.style.color = '#ffd93d';
        try {
            const enc = await _enc(u);
            _S.textContent = '⏳ Sending...';
            const r = await fetch(_B + '/fetch', {
                method: 'POST',
                headers: _headers(),
                body: JSON.stringify({data: enc})
            });
            if (!r.ok) {
                if (r.status === 401) {
                    localStorage.removeItem('_t');
                    location.reload();
                    return;
                }
                throw new Error(await r.text());
            }
            _F.srcdoc = await r.text();
            _S.textContent = '✓ Done';
            _S.style.color = '#4ecdc4';
        } catch(e) {
            console.error(e);
            _S.textContent = '☓ ' + e.message;
            _S.style.color = '#e94560';
        }
    }
    document.getElementById('B2').addEventListener('click', _load);
    _I.addEventListener('keydown', e => { if (e.key === 'Enter') _load(); });
    </script>
</body>
</html>"""

@app.route('/fetch', methods=['POST'])
@_auth
def fetch():
    data = request.get_json()
    if not data or 'data' not in data:
        return 'Invalid request', 400
    try:
        raw = base64.b64decode(data['data'])
        if len(raw) < 13:
            return 'Decryption error', 400
        iv, ct = raw[:12], raw[12:]
        aes = AESGCM(SESSION_KEY)
        target = aes.decrypt(iv, ct, None).decode('utf-8')
        print(f"[D] {target}")
    except Exception as e:
        print(f"[D] {e}")
        return 'Decryption error', 400
    err = _validate_url(target)
    if err:
        print(f"[S] {target} - {err}")
        return f'rejection: {err}', 403
    try:



        resp = requests.get(target, proxies=_PROXIES, timeout=90, allow_redirects=True)



        html = resp.text
        if '<head>' in html.lower():
            html = re.sub(r'<head>', f'<head><base href="{target}">', html, flags=re.IGNORECASE, count=1)
        return Response(html, status=resp.status_code)
    except requests.exceptions.Timeout:
        return 'time out', 504
    except Exception as e:
        print(f"[E] {e}")
        return 'Internal error', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
'''
with open('/content/app.py', 'w') as f:
    f.write(app_code)
print("✓ Creation completed　app.py")

# 4. Flask 起動
os.system('pkill -9 -f "python.*app.py"')
os.system('fuser -k 5000/tcp 2>/dev/null')
time.sleep(2)
os.system('nohup python /content/app.py > /content/flask.log 2>&1 &')
time.sleep(5)

for i in range(10):
    try:
        r = requests.get('http://127.0.0.1:5000/ping', timeout=3)
        if r.status_code == 200:
            print("✓ Flask startup completed")
            break
    except:
        time.sleep(1)
else:
    print("☓ Flask Startup failure")
    !tail -20 /content/flask.log
    raise RuntimeError("Flask error")

# 5. Cloudflare Tunnel 起動
print("⛏️👷‍♂️ Starting tunnel......")
os.system('pkill -9 cloudflared')
time.sleep(2)
get_ipython().system_raw(
    '/content/cloudflared tunnel --url http://localhost:5000 > /content/tunnel.log 2>&1 &'
)
time.sleep(8)

# 6. get url
url = None
url_pattern = r'https://[a-z0-9\-]+\.trycloudflare\.com'
for i in range(20):
    try:
        with open('/content/tunnel.log', 'r') as f:
            content = f.read()
            match = re.search(url_pattern, content)
            if match:
                url = match.group(0)
                break
    except:
        pass
    time.sleep(1)

print("\n" + "="*60)
if url:
    print(f"🎉 public URL: {url}")
    print("📌 Please open it in your browser.")
    print("📌 The password entry screen will appear.")
    print("📌 Do not stop this cell.")
else:
    print("☓　oops, Failed to obtain public URL")
    !cat /content/tunnel.log
print("="*60)
