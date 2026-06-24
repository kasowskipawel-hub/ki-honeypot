"""KI Honeypot License Server.

Endpoints:
  POST /api/license/activate   {key, machine_id} → {ok, token, days_left, email}
  POST /api/license/validate   {token, machine_id} → {ok, days_left, email}
  POST /api/license/revoke     {key, admin_secret} → {ok}
  POST /api/license/request    {name, email} → {ok, message}  ← trial signup
  GET  /api/license/status     X-Admin-Secret header → list of all keys
  GET  /trial                  → signup form (HTML)
  GET  /health                 → {"ok": true}

Token format: base64url( JSON({machine_id, key, expires_unix}) ) + "." + HMAC-SHA256
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN_SECRET  = os.environ.get("LICENSE_ADMIN_SECRET", "changeme-set-in-env").strip()
HMAC_SECRET   = os.environ.get("LICENSE_HMAC_SECRET",  "changeme-hmac-secret").strip()
DB_PATH       = os.environ.get("LICENSE_DB",   "/data/license.db")
PORT          = int(os.environ.get("LICENSE_PORT", "7443"))
TOKEN_TTL     = 30 * 86400
MAX_MACHINES  = int(os.environ.get("LICENSE_MAX_MACHINES", "1"))
TRIAL_DAYS    = int(os.environ.get("TRIAL_DAYS", "30"))

# SMTP — set these in environment for email delivery
SMTP_HOST     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASS     = os.environ.get("SMTP_PASS", "")
SMTP_FROM     = os.environ.get("SMTP_FROM", "noreply@ki-honeypot.de")
NOTIFY_EMAIL  = os.environ.get("NOTIFY_EMAIL", "info@ki-honeypot.de")

_db_lock = threading.Lock()

# ── DB ────────────────────────────────────────────────────────────────────────

def _db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with _db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS keys (
            key         TEXT PRIMARY KEY,
            email       TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0,
            notes       TEXT DEFAULT ''
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS activations (
            key         TEXT NOT NULL,
            machine_id  TEXT NOT NULL,
            activated_at INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL,
            PRIMARY KEY (key, machine_id)
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS trial_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            email       TEXT NOT NULL UNIQUE,
            key         TEXT NOT NULL,
            requested_at INTEGER NOT NULL,
            sent        INTEGER NOT NULL DEFAULT 0
        )""")


# ── Key generation ────────────────────────────────────────────────────────────

def _gen_key() -> str:
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return "HPOT-" + "-".join(parts)


def _create_key(email: str, days: int, notes: str = "") -> str:
    key = _gen_key()
    now = int(time.time())
    with _db_lock, _db() as con:
        con.execute(
            "INSERT INTO keys (key, email, created_at, expires_at, notes) VALUES (?,?,?,?,?)",
            (key, email, now, now + days * 86400, notes)
        )
    return key


# ── Token sign / verify ───────────────────────────────────────────────────────

def _sign(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    sig  = hmac.new(HMAC_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def _verify(token: str) -> dict | None:
    try:
        body, sig = token.rsplit(".", 1)
        expected = hmac.new(HMAC_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return json.loads(base64.urlsafe_b64decode(body + "=="))
    except Exception:
        return None


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_email(to: str, subject: str, body: str):
    if not SMTP_USER or not SMTP_PASS:
        print(f"[mail] SMTP not configured — would send to {to}: {subject}", flush=True)
        return
    try:
        msg = MIMEText(body, "html", "utf-8")
        msg["Subject"] = subject
        msg["From"]    = SMTP_FROM
        msg["To"]      = to
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[mail] sent '{subject}' → {to}", flush=True)
    except Exception as e:
        print(f"[mail] ERROR sending to {to}: {e}", flush=True)


def _send_trial_key(name: str, email: str, key: str):
    body = f"""
<div style="font-family:sans-serif;max-width:600px;margin:0 auto">
  <h2 style="color:#1a1a2e">🛡️ Your KI Honeypot Trial Key</h2>
  <p>Hi {name},</p>
  <p>Thanks for signing up! Here is your 30-day trial license key:</p>
  <div style="background:#0d1117;border-radius:8px;padding:20px;margin:20px 0;text-align:center">
    <code style="color:#58a6ff;font-size:20px;letter-spacing:2px;font-weight:bold">{key}</code>
  </div>
  <p><strong>Install in 60 seconds:</strong></p>
  <pre style="background:#0d1117;color:#e6edf3;padding:16px;border-radius:6px;overflow:auto">curl -sSL https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/install.sh \\
  | sudo bash -s -- --key {key}</pre>
  <p>Your key is valid for <strong>30 days</strong> on one server.</p>
  <p>For extended or multi-server licensing, just reply to this email.</p>
  <hr style="border-color:#30363d">
  <p style="color:#8b949e;font-size:13px">
    KI Honeypot · <a href="mailto:info@ki-honeypot.de" style="color:#58a6ff">info@ki-honeypot.de</a>
  </p>
</div>
"""
    _send_email(email, "Your KI Honeypot 30-Day Trial Key", body)


def _notify_admin(name: str, email: str, key: str):
    body = f"New trial signup:\n\nName:  {name}\nEmail: {email}\nKey:   {key}\n"
    _send_email(NOTIFY_EMAIL, f"[KI Honeypot] New trial: {email}", body)


# ── Business logic ────────────────────────────────────────────────────────────

def _activate(key: str, machine_id: str) -> dict:
    with _db_lock, _db() as con:
        row = con.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
        if not row:
            return {"ok": False, "error": "Invalid license key"}
        if row["revoked"]:
            return {"ok": False, "error": "License key revoked"}
        if time.time() > row["expires_at"]:
            return {"ok": False, "error": "License key expired"}

        machines = con.execute(
            "SELECT machine_id FROM activations WHERE key=?", (key,)
        ).fetchall()
        machine_ids = [m["machine_id"] for m in machines]
        if machine_id not in machine_ids:
            if len(machine_ids) >= MAX_MACHINES:
                return {"ok": False, "error": "License already used on another machine"}
            con.execute(
                "INSERT INTO activations VALUES (?,?,?,?)",
                (key, machine_id, int(time.time()), int(time.time()))
            )
        else:
            con.execute(
                "UPDATE activations SET last_seen=? WHERE key=? AND machine_id=?",
                (int(time.time()), key, machine_id)
            )

        token_expires = min(int(time.time()) + TOKEN_TTL, row["expires_at"])
        payload = {"key": key, "machine_id": machine_id,
                   "expires": token_expires, "email": row["email"]}
        token = _sign(payload)
        days_left = max(0, int((row["expires_at"] - time.time()) / 86400))
        return {"ok": True, "token": token, "days_left": days_left, "email": row["email"]}


def _validate(token: str, machine_id: str) -> dict:
    payload = _verify(token)
    if not payload:
        return {"ok": False, "error": "Invalid token signature"}
    if payload.get("machine_id") != machine_id:
        return {"ok": False, "error": "Machine ID mismatch"}
    if time.time() > payload.get("expires", 0):
        return {"ok": False, "error": "Token expired"}

    key = payload.get("key", "")
    with _db_lock, _db() as con:
        row = con.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()
        if not row or row["revoked"]:
            return {"ok": False, "error": "Key revoked"}
        if time.time() > row["expires_at"]:
            return {"ok": False, "error": "License expired"}
        con.execute(
            "UPDATE activations SET last_seen=? WHERE key=? AND machine_id=?",
            (int(time.time()), key, machine_id)
        )
        days_left = max(0, int((row["expires_at"] - time.time()) / 86400))
        return {"ok": True, "days_left": days_left, "email": row["email"]}


def _request_trial(name: str, email: str) -> dict:
    name  = name.strip()[:100]
    email = email.strip().lower()[:200]

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"ok": False, "error": "Invalid email address"}
    if len(name) < 2:
        return {"ok": False, "error": "Please enter your name"}

    # Check duplicate first (separate lock scope)
    with _db_lock, _db() as con:
        existing = con.execute(
            "SELECT key FROM trial_requests WHERE email=?", (email,)
        ).fetchone()
        if existing:
            return {"ok": False, "error": "A trial key was already sent to this email address"}

    # Create key (acquires its own lock internally)
    key = _create_key(email, TRIAL_DAYS, notes=f"trial:{name}")

    with _db_lock, _db() as con:
        con.execute(
            "INSERT INTO trial_requests (name, email, key, requested_at) VALUES (?,?,?,?)",
            (name, email, key, int(time.time()))
        )

    # Send emails in background so HTTP response is instant
    def _deliver():
        _send_trial_key(name, email, key)
        _notify_admin(name, email, key)
        with _db_lock, _db() as con:
            con.execute("UPDATE trial_requests SET sent=1 WHERE email=?", (email,))

    threading.Thread(target=_deliver, daemon=True).start()
    print(f"[trial] new request: {name} <{email}> → {key}", flush=True)
    return {"ok": True, "message": "Your license key has been sent to your email address."}


# ── HTML form ─────────────────────────────────────────────────────────────────

_TRIAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KI Honeypot — Free 30-Day Trial</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --blue: #58a6ff; --green: #3fb950;
    --red: #f85149;
  }
  body { background: var(--bg); color: var(--text); font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 48px 40px; max-width: 480px; width: 100%; }
  .logo { font-size: 36px; margin-bottom: 8px; text-align: center; }
  h1 { font-size: 24px; font-weight: 700; text-align: center; margin-bottom: 4px; }
  .sub { color: var(--muted); text-align: center; margin-bottom: 32px; font-size: 15px; }
  .features { list-style: none; margin-bottom: 32px; display: flex; flex-direction: column; gap: 8px; }
  .features li { color: var(--muted); font-size: 14px; padding-left: 20px; position: relative; }
  .features li::before { content: "✓"; color: var(--green); position: absolute; left: 0; font-weight: 700; }
  label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; color: var(--text); }
  input { width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; color: var(--text); font-size: 15px; outline: none; transition: border-color .15s; margin-bottom: 16px; }
  input:focus { border-color: var(--blue); }
  button { width: 100%; background: var(--blue); color: #0d1117; border: none; border-radius: 6px; padding: 12px; font-size: 16px; font-weight: 700; cursor: pointer; transition: opacity .15s; }
  button:hover { opacity: .85; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .msg { border-radius: 6px; padding: 12px 16px; font-size: 14px; margin-top: 16px; display: none; }
  .msg.ok  { background: #1a3a22; border: 1px solid var(--green); color: var(--green); }
  .msg.err { background: #3a1a1a; border: 1px solid var(--red);   color: var(--red); }
  .footer { text-align: center; margin-top: 24px; font-size: 13px; color: var(--muted); }
  .footer a { color: var(--blue); text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">🛡️</div>
  <h1>KI Honeypot</h1>
  <p class="sub">Free 30-day trial — no credit card required</p>

  <ul class="features">
    <li>15+ emulated protocols (SSH, HTTP, Redis, SMB, RDP, Telnet, ...)</li>
    <li>AI-powered threat analysis with MITRE ATT&amp;CK mapping</li>
    <li>Live dashboard with session replay</li>
    <li>Malware capture &amp; static analysis</li>
    <li>SIEM-ready JSON event feed via REST API</li>
    <li>One-line installer — running in 60 seconds</li>
  </ul>

  <form id="form">
    <label for="name">Your name</label>
    <input id="name" type="text" name="name" placeholder="John Doe" required autocomplete="name">

    <label for="email">Email address</label>
    <input id="email" type="email" name="email" placeholder="you@example.com" required autocomplete="email">

    <button type="submit" id="btn">Get my free trial key →</button>
  </form>

  <div class="msg" id="msg"></div>

  <p class="footer">
    Need a longer license or multiple sensors?<br>
    <a href="mailto:info@ki-honeypot.de">info@ki-honeypot.de</a>
  </p>
</div>

<script>
document.getElementById("form").addEventListener("submit", async function(e) {
  e.preventDefault();
  const btn = document.getElementById("btn");
  const msg = document.getElementById("msg");
  btn.disabled = true;
  btn.textContent = "Sending...";
  msg.style.display = "none";
  msg.className = "msg";

  try {
    const res = await fetch("/api/license/request", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        name:  document.getElementById("name").value.trim(),
        email: document.getElementById("email").value.trim()
      })
    });
    const data = await res.json();
    if (data.ok) {
      msg.className = "msg ok";
      msg.textContent = "✓ " + data.message;
      document.getElementById("form").style.display = "none";
    } else {
      msg.className = "msg err";
      msg.textContent = "✗ " + data.error;
      btn.disabled = false;
      btn.textContent = "Get my free trial key →";
    }
    msg.style.display = "block";
  } catch(err) {
    msg.className = "msg err";
    msg.textContent = "✗ Network error. Please try again.";
    msg.style.display = "block";
    btn.disabled = false;
    btn.textContent = "Get my free trial key →";
  }
});
</script>
</body>
</html>
""".encode("utf-8")


# ── HTTP handler ──────────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[license-srv] {self.address_string()} {fmt % args}", flush=True)

    def _send(self, status: int, body: dict):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        if n <= 0:
            return {}
        return json.loads(self.rfile.read(min(n, 65536)))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Secret")
        self.end_headers()

    def do_POST(self):
        try:
            body = self._read_body()
        except Exception:
            self._send(400, {"ok": False, "error": "Bad JSON"})
            return

        p = self.path.rstrip("/")

        if p == "/api/license/activate":
            key = str(body.get("key", "")).strip()
            mid = str(body.get("machine_id", "")).strip()
            if not key or not mid:
                self._send(400, {"ok": False, "error": "key and machine_id required"})
                return
            res = _activate(key, mid)
            self._send(200 if res["ok"] else 403, res)

        elif p == "/api/license/validate":
            token = str(body.get("token", "")).strip()
            mid   = str(body.get("machine_id", "")).strip()
            if not token or not mid:
                self._send(400, {"ok": False, "error": "token and machine_id required"})
                return
            res = _validate(token, mid)
            self._send(200 if res["ok"] else 403, res)

        elif p == "/api/license/revoke":
            if body.get("admin_secret") != ADMIN_SECRET:
                self._send(403, {"ok": False, "error": "Forbidden"})
                return
            key = str(body.get("key", "")).strip()
            with _db_lock, _db() as con:
                con.execute("UPDATE keys SET revoked=1 WHERE key=?", (key,))
            self._send(200, {"ok": True})

        elif p == "/api/license/request":
            name  = str(body.get("name",  "")).strip()
            email = str(body.get("email", "")).strip()
            res = _request_trial(name, email)
            self._send(200 if res["ok"] else 400, res)

        else:
            self._send(404, {"ok": False, "error": "Not found"})

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/")

        if p in ("/trial", "/signup", ""):
            self._send_html(200, _TRIAL_HTML)

        elif p == "/api/license/status":
            secret = self.headers.get("X-Admin-Secret", "")
            if secret != ADMIN_SECRET:
                self._send(403, {"ok": False, "error": "Forbidden"})
                return
            with _db_lock, _db() as con:
                keys    = [dict(r) for r in con.execute("SELECT * FROM keys").fetchall()]
                acts    = [dict(r) for r in con.execute("SELECT * FROM activations").fetchall()]
                trials  = [dict(r) for r in con.execute("SELECT * FROM trial_requests ORDER BY requested_at DESC").fetchall()]
            self._send(200, {"ok": True, "keys": keys, "activations": acts, "trials": trials})

        elif p == "/health":
            self._send(200, {"ok": True})

        else:
            self._send(404, {"ok": False, "error": "Not found"})


if __name__ == "__main__":
    _init_db()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), _Handler)
    print(f"[license-srv] listening on 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()
