#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ===================================================================
# SSS(Secure-Search-Site) Secure Proxy System Vr3.0.0 released!!!!
# ===================================================================
import os
import time
import secrets
import base64
import re
import json
from functools import wraps
from urllib.parse import urlparse, urljoin
import ipaddress

from flask import Flask, request, Response, jsonify, after_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# 環境変数 SSS_PASSWORD_HASH が必須（未設定の場合は起動を拒否）
_PASSWORD_HASH_ENV = os.environ.get("SSS_PASSWORD_HASH")
if not _PASSWORD_HASH_ENV:
    raise RuntimeError("SSS_PASSWORD_HASH environment variable is required")
PASSWORD_HASH = _PASSWORD_HASH_ENV.encode()

_TOKEN_EXPIRE = 3600
_MAX_REDIRECTS = 5
_MAX_BODY_SIZE = 1024 * 1024

_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

_sessions = {}

def _gen_session():
    token = secrets.token_urlsafe(32)
    key = AESGCM.generate_key(bit_length=256)
    _sessions[token] = {"exp": time.time() + _TOKEN_EXPIRE, "key": key}
    return token, key

def _get_session(token):
    if not token:
        return None
    sess = _sessions.get(token)
    if not sess:
        return None
    if time.time() > sess["exp"]:
        del _sessions[token]
        return None
    return sess

def _auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth:
            return Response("Unauthorized", status=401)
        if auth.startswith("Bearer "):
            auth = auth[7:]
        sess = _get_session(auth)
        if not sess:
            return Response("Unauthorized", status=401)
        request._sess = sess
        return f(*args, **kwargs)
    return decorated

_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
    "169.254.169.254", "metadata.google.internal",
    "instance-metadata", "metadata", "metadata.google.internal."
}

def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False

def _validate_url(url: str) -> str | None:
    if not url or len(url) > 2048:
        return "Invalid URL"
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return f"Fraudulent scheme: {parsed.scheme}"
    host = parsed.hostname
    if not host:
        return "Invalid URL"
    host = host.lower().strip()
    if host in _BLOCKED_HOSTS:
        return "Access-denied host"
    if _is_private_ip(host):
        return "Access to private IPs is prohibited."
    port = parsed.port
    if port and port in {22, 23, 25, 53, 110, 143, 3389, 5432, 6379, 3306, 27017, 9200}:
        return "Access to restricted port is prohibited."
    return None

def _safe_fetch(url: str):
    current_url = url
    for redirect_count in range(_MAX_REDIRECTS):
        err = _validate_url(current_url)
        if err:
            return None, err, 403

        try:
            resp = requests.get(
                current_url,
                proxies=_PROXIES,
                timeout=90,
                allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
                stream=False
            )
        except requests.exceptions.Timeout:
            return None, "time out", 504
        except requests.exceptions.ProxyError as e:
            return None, "Proxy error", 502
        except Exception as e:
            app.logger.error(f"[E] {e}")
            return None, "Internal error", 500

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return None, "Invalid redirect", 400
            current_url = urljoin(current_url, location)
            continue

        return resp, None, resp.status_code

    return None, "Too many redirects", 400

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    if not data or "password" not in data:
        return "No password", 400

    pwd = data["password"].encode("utf-8")
    if not bcrypt.checkpw(pwd, PASSWORD_HASH):
        return "wrong pass word", 401

    token, key = _gen_session()
    return jsonify({"status": "success", "token": token}), 200

@app.route("/ping", methods=["GET"])
def ping():
    return "pong"

@app.route("/get_key", methods=["GET"])
@_auth_required
def get_key():
    key = request._sess["key"]
    return jsonify({"key": base64.b64encode(key).decode()})

@app.route("/fetch", methods=["POST"])
@_auth_required
@limiter.limit("30 per minute")
def fetch():
    data = request.get_json()
    if not data or "data" not in data:
        return "Invalid request", 400

    key = request._sess["key"]

    try:
        raw = base64.b64decode(data["data"])
        if len(raw) < 13:
            return "Decryption error", 400
        iv, ct = raw[:12], raw[12:]
        aes = AESGCM(key)
        target = aes.decrypt(iv, ct, None).decode("utf-8")
        app.logger.info(f"[D] {target}")
    except Exception as e:
        app.logger.warning(f"[D] Decrypt error: {e}")
        return "Decryption error", 400

    resp, err_msg, status = _safe_fetch(target)
    if err_msg:
        return err_msg, status

    html = resp.text
    if "<head>" in html.lower():
        html = re.sub(
            r"<head>",
            f'<head><base href="{target}">',
            html,
            flags=re.IGNORECASE,
            count=1
        )
    elif "<html>" in html.lower():
        html = re.sub(
            r"<html>",
            f'<html><base href="{target}">',
            html,
            flags=re.IGNORECASE,
            count=1
        )
    else:
        html = f'<base href="{target}">' + html

    try:
        iv_r = os.urandom(12)
        aes_r = AESGCM(key)
        enc_html = aes_r.encrypt(iv_r, html.encode("utf-8"), None)
        payload = iv_r + enc_html
        b64_payload = base64.b64encode(payload).decode()
        return jsonify({"encrypted": True, "data": b64_payload})
    except Exception as e:
        app.logger.error(f"[E] Encrypt error: {e}")
        return "Encryption error", 500

@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DeepSearch Browser</title>
<style>
body{margin:0;font-family:sans-serif;background:#1a1a2e;color:#fff;}
#L1{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#1a1a2e;}
.box{background:#16213e;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.3);text-align:center;}
input{padding:12px 16px;font-size:16px;border:none;border-radius:8px;background:#0f3460;color:#fff;width:250px;outline:none;margin-bottom:16px;display:block;}
button{padding:12px 32px;background:#e94560;border:none;border-radius:8px;color:#fff;font-size:16px;font-weight:bold;cursor:pointer;}
button:hover{background:#d63a54;}
#M1{margin-top:12px;color:#e94560;font-size:14px;min-height:20px;}
#L2{display:none;}
#bar{padding:16px 20px;background:#16213e;border-bottom:2px solid #0f3460;display:flex;gap:12px;flex-wrap:wrap;align-items:center;}
#I2{flex:1;min-width:200px;padding:10px 16px;font-size:15px;border:none;border-radius:8px;background:#0f3460;color:#fff;outline:none;}
#B2{padding:10px 28px;background:#e94560;border:none;border-radius:8px;color:#fff;font-size:15px;font-weight:bold;cursor:pointer;}
#B3{padding:10px 20px;background:#0f3460;border:none;border-radius:8px;color:#fff;font-size:15px;cursor:pointer;}
#S1{font-size:13px;color:#4ecdc4;}
#F1{width:100%;height:calc(100vh - 80px);border:none;background:#fff;}
</style>
</head>
<body>
<div id="L1">
  <div class="box">
    <h2 style="margin:0 0 20px;color:#e94560;">Authentication Required</h2>
    <input id="I1" type="password" placeholder="Password" autocomplete="off">
    <button id="B1">Login</button>
    <div id="M1"></div>
  </div>
</div>
<div id="L2">
  <div id="bar">
    <input id="I2" type="text" placeholder="Enter URL (e.g. duckduckgo.com)" autocomplete="off">
    <button id="B2">Go</button>
    <button id="B3">Logout</button>
    <span id="S1">&bull; Ready</span>
  </div>
  <!-- FIX: allow-same-origin removed to prevent DOM XSS / session hijacking -->
  <iframe id="F1" sandbox="allow-scripts allow-forms"></iframe>
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

async function _dec(b64) {
    if (!_K) await _getKey();
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = raw.slice(0, 12);
    const ct = raw.slice(12);
    const key = await crypto.subtle.importKey('raw', _K, {name:'AES-GCM'}, false, ['decrypt']);
    const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv:iv}, key, ct);
    return new TextDecoder().decode(dec);
}

async function _load() {
    let u = _I.value.trim();
    if (!u) return;
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
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
        const d = await r.json();
        if (d.encrypted) {
            const html = await _dec(d.data);
            _F.srcdoc = html;
        } else {
            _F.srcdoc = d.data || await r.text();
        }
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

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "frame-src 'self'; "
        "object-src 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Rate limit exceeded", 429

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"Server Error: {e}")
    return "Internal Server Error", 500

if __name__ == "__main__":
    # For production, use Gunicorn + Nginx.
    # This is for standalone testing only.
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
