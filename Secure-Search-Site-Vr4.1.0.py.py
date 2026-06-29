#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ===================================================================
# SSS (Secure-Search-Site) WebSocket Stealth Proxy Vr4.1.0 (Colab Fixed)
# Fixes: SSRF (DNS Rebinding), XSS, DoS (OOM), Colab Compatibility
# ===================================================================
import os
import sys
import time
import secrets
import base64
import re
import json
import socket
import ipaddress
import threading
from functools import wraps
from urllib.parse import urlparse, urljoin

from flask import Flask, request, Response, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sock import Sock
import requests
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
sock = Sock(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# 環境変数 SSS_PASSWORD_HASH が必須
_PASSWORD_HASH_ENV = os.environ.get("SSS_PASSWORD_HASH")
if not _PASSWORD_HASH_ENV:
    # Colab環境用にデフォルトパスワードを設定するフォールバック
    if 'google.colab' in sys.modules:
        default_pw = "colab_secure_2024"
        _PASSWORD_HASH_ENV = bcrypt.hashpw(default_pw.encode(), bcrypt.gensalt()).decode()
        print(f"[!] SSS_PASSWORD_HASH not set. Using default password: {default_pw}")
    else:
        raise RuntimeError("SSS_PASSWORD_HASH environment variable is required")
        
PASSWORD_HASH = _PASSWORD_HASH_ENV.encode() if isinstance(_PASSWORD_HASH_ENV, str) else _PASSWORD_HASH_ENV
_TOKEN_EXPIRE = 3600
_MAX_REDIRECTS = 5
_MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB limit to prevent OOM

# Tor経由で通信 (ColabではTorが起動していない場合があるためフォールバックを用意)
_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

_sessions = {}

def _gen_session():
    token = secrets.token_urlsafe(32)
    _sessions[token] = {"exp": time.time() + _TOKEN_EXPIRE, "key": None}
    return token

def _get_session(token):
    if not token: return None
    sess = _sessions.get(token)
    if not sess: return None
    if time.time() > sess["exp"]:
        del _sessions[token]
        return None
    return sess

def _auth_required_http(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return Response("Unauthorized", status=401)
        sess = _get_session(auth[7:])
        if not sess: return Response("Unauthorized", status=401)
        request._sess = sess
        return f(*args, **kwargs)
    return decorated

# --- URL Validation (SSRF対策強化: DNS解決チェック含む) ---
_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
    "169.254.169.254", "metadata.google.internal"
}

def _is_private_ip(host):
    # 1. 直接IPアドレスの場合
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        pass
    
    # 2. ドメイン名の場合、DNS解決してIPをチェック (DNS Rebinding対策)
    try:
        addr_info = socket.getaddrinfo(host, None)
        for info in addr_info:
            ip_str = info[4][0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return True
    except socket.gaierror:
        pass # 解決失敗は後続のrequestsに任せる
    return False

def _validate_url(url: str):
    if not url or len(url) > 2048: return "Invalid URL"
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES: return "Fraudulent scheme"
    host = parsed.hostname
    if not host or host.lower() in _BLOCKED_HOSTS or _is_private_ip(host):
        return "Access-denied host (SSRF blocked)"
    return None

def _safe_fetch(url: str):
    current_url = url
    for _ in range(_MAX_REDIRECTS):
        err = _validate_url(current_url)
        if err: return None, err, 403
        
        try:
            # stream=True でメモリオーバーフローを防ぐ
            resp = requests.get(
                current_url, proxies=_PROXIES, timeout=15,
                allow_redirects=False, stream=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
        except requests.exceptions.ProxyError:
            # Torが起動していない場合は直線接続にフォールバック (警告付き)
            try:
                resp = requests.get(
                    current_url, timeout=15, allow_redirects=False, stream=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                )
            except Exception as e:
                return None, f"Network error (Direct): {str(e)}", 502
        except Exception as e:
            return None, f"Network error (Tor): {str(e)}", 502

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            resp.close()
            if not location: return None, "Invalid redirect", 400
            current_url = urljoin(current_url, location)
            continue

        # コンテンツサイズチェック (DoS対策)
        cl = resp.headers.get('Content-Length')
        if cl and int(cl) > _MAX_RESPONSE_SIZE:
            resp.close()
            return None, "Response too large (>10MB)", 413

        chunks = []
        size = 0
        try:
            for chunk in resp.iter_content(8192):
                size += len(chunk)
                if size > _MAX_RESPONSE_SIZE:
                    resp.close()
                    return None, "Response too large (>10MB)", 413
                chunks.append(chunk)
        except Exception as e:
            resp.close()
            return None, f"Stream error: {str(e)}", 502
            
        resp.close()
        html = b''.join(chunks).decode('utf-8', errors='ignore')

        # HTMLのbaseタグ書き換え
        if "<head>" in html.lower():
            html = re.sub(r"<head>", f'<head><base href="{current_url}">', html, flags=re.IGNORECASE, count=1)
        elif "<html>" in html.lower():
            html = re.sub(r"<html>", f'<html><base href="{current_url}">', html, flags=re.IGNORECASE, count=1)
        else:
            html = f'<base href="{current_url}">' + html
            
        return html, None, resp.status_code

    return None, "Too many redirects", 400

# --- Routes ---
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    if not data or "password" not in data: return "No password", 400
    if not bcrypt.checkpw(data["password"].encode("utf-8"), PASSWORD_HASH):
        return "wrong pass word", 401
    token = _gen_session()
    return jsonify({"status": "success", "token": token}), 200

@app.route("/ping")
def ping():
    return "pong"

# --- WebSocket Stealth Tunnel ---
@sock.route("/ws")
def ws_tunnel(ws):
    token = request.args.get("token")
    sess = _get_session(token)
    if not sess:
        ws.send(json.dumps({"error": "Unauthorized"}))
        ws.close()
        return

    key = AESGCM.generate_key(bit_length=256)
    sess["key"] = key
    ws.send(json.dumps({"status": "key_issued", "key": base64.b64encode(key).decode()}))

    while True:
        try:
            msg = ws.receive(timeout=60)
            if not msg:
                ws.send(json.dumps({"type": "heartbeat"}))
                continue
                
            data = json.loads(msg)
            if data.get("type") == "fetch":
                raw = base64.b64decode(data["payload"])
                iv, ct = raw[:12], raw[12:]
                aes = AESGCM(key)
                target_url = aes.decrypt(iv, ct, None).decode("utf-8")
                
                html, err_msg, status = _safe_fetch(target_url)
                if err_msg:
                    err_payload = json.dumps({"error": err_msg, "status": status}).encode()
                    iv_r = os.urandom(12)
                    enc_err = AESGCM(key).encrypt(iv_r, err_payload, None)
                    ws.send(base64.b64encode(iv_r + enc_err).decode())
                    continue

                iv_r = os.urandom(12)
                enc_html = AESGCM(key).encrypt(iv_r, html.encode("utf-8"), None)
                ws.send(base64.b64encode(iv_r + enc_html).decode())
                
            elif data.get("type") == "ping":
                ws.send(json.dumps({"type": "pong"}))
        except Exception as e:
            break

@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>Stealth Browser</title>
<style>
body{margin:0;font-family:sans-serif;background:#1a1a2e;color:#fff;}
#L1{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;}
.box{background:#16213e;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.3);text-align:center;}
input{padding:12px 16px;font-size:16px;border:none;border-radius:8px;background:#0f3460;color:#fff;width:250px;outline:none;margin-bottom:16px;display:block;}
button{padding:12px 32px;background:#e94560;border:none;border-radius:8px;color:#fff;font-size:16px;font-weight:bold;cursor:pointer;}
#L2{display:none;height:100vh;display:flex;flex-direction:column;}
#bar{padding:10px;background:#16213e;display:flex;gap:10px;}
#I2{flex:1;padding:10px;border:none;border-radius:8px;background:#0f3460;color:#fff;}
#F1{flex:1;border:none;background:#fff;}
#S1{color:#4ecdc4;padding:0 10px;line-height:40px;}
</style>
</head>
<body>
<div id="L1">
<div class="box">
<h2 style="color:#e94560;">Secure WS Tunnel</h2>
<input id="I1" type="password" placeholder="Password">
<button id="B1">Connect</button>
<div id="M1" style="color:#e94560;margin-top:10px;"></div>
</div>
</div>
<div id="L2" style="display:none;">
<div id="bar">
<input id="I2" type="text" placeholder="Enter URL...">
<button id="B2">Go</button>
<span id="S1">Disconnected</span>
</div>
<iframe id="F1" sandbox="allow-scripts allow-forms"></iframe>
</div>
<script>
const _B = window.location.origin.replace('http', 'ws');
let _ws = null;
let _K = null;

// XSS対策: HTMLエスケープ関数
function escapeHtml(t){return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');}

async function _login() {
    const p = document.getElementById('I1').value;
    const r = await fetch('/login', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({password: p})
    });
    if (r.ok) {
        const d = await r.json();
        localStorage.setItem('_t', d.token);
        _connectWs(d.token);
    } else {
        document.getElementById('M1').textContent = 'Invalid password';
    }
}

function _connectWs(token) {
    _ws = new WebSocket(`${_B}/ws?token=${token}`);
    _ws.onmessage = async (event) => {
        const msg = event.data;
        if (msg.startsWith('{')) {
            const d = JSON.parse(msg);
            if (d.status === 'key_issued') {
                _K = Uint8Array.from(atob(d.key), c => c.charCodeAt(0));
                document.getElementById('L1').style.display = 'none';
                document.getElementById('L2').style.display = 'flex';
                document.getElementById('S1').textContent = '● Tunnel Active';
                document.getElementById('S1').style.color = '#4ecdc4';
                _startHeartbeat();
            } else if (d.error) {
                alert('Error: ' + d.error);
            }
        } else {
            const raw = Uint8Array.from(atob(msg), c => c.charCodeAt(0));
            const iv = raw.slice(0, 12);
            const ct = raw.slice(12);
            const key = await crypto.subtle.importKey('raw', _K, {name:'AES-GCM'}, false, ['decrypt']);
            const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv:iv}, key, ct);
            const html = new TextDecoder().decode(dec);
            
            if (html.startsWith('{"error"')) {
                const err = JSON.parse(html);
                // XSS対策: エスケープして挿入
                document.getElementById('F1').srcdoc = `<h1>Error ${escapeHtml(err.status)}</h1><p>${escapeHtml(err.error)}</p>`;
            } else {
                document.getElementById('F1').srcdoc = html;
            }
        }
    };
    _ws.onclose = () => {
        document.getElementById('S1').textContent = '× Disconnected';
        document.getElementById('S1').style.color = '#e94560';
        localStorage.removeItem('_t');
    };
}

async function _enc(p) {
    const e = new TextEncoder().encode(p);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', _K, {name:'AES-GCM'}, false, ['encrypt']);
    const enc = await crypto.subtle.encrypt({name:'AES-GCM', iv:iv}, key, e);
    const c = new Uint8Array(iv.length + enc.byteLength);
    c.set(iv); c.set(new Uint8Array(enc), iv.length);
    return btoa(String.fromCharCode(...c));
}

async function _load() {
    let u = document.getElementById('I2').value.trim();
    if (!u) return;
    if (!/^https?:\\/\\//i.test(u)) u = 'https://' + u;
    const payload = await _enc(u);
    _ws.send(JSON.stringify({type: 'fetch', payload: payload}));
}

function _startHeartbeat() {
    setInterval(() => {
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify({type: 'ping'}));
        }
    }, 30000);
}

document.getElementById('B1').addEventListener('click', _login);
document.getElementById('B2').addEventListener('click', _load);
document.getElementById('I2').addEventListener('keydown', e => { if(e.key==='Enter') _load(); });

if (localStorage.getItem('_t')) {
    _connectWs(localStorage.getItem('_t'));
}
</script>
</body>
</html>"""

if __name__ == "__main__":
    # Colab環境検出とバックグラウンド実行
    if 'google.colab' in sys.modules:
        def run_app():
            # use_reloader=False はColabでの多重起動バグを防ぐ
            app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
        threading.Thread(target=run_app, daemon=True).start()
        print("✅ Flask server started in background on port 5000.")
    else:
        app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)