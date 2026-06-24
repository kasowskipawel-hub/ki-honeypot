"""License client for win443-honeypot.

Checks a HMAC-signed token against the license server at startup and every 6 h.
Stores the token locally in /data/license.json for offline grace (72 h).
Shuts down gracefully when the license expires or is revoked.
"""
import hashlib
import hmac
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

LICENSE_SERVER = os.environ.get(
    "LICENSE_SERVER", "https://license.ki-honeypot.de/api/license"
)
LICENSE_KEY    = os.environ.get("LICENSE_KEY", "").strip()
LICENSE_FILE   = os.environ.get("LICENSE_FILE", "/data/license.json")
GRACE_SECONDS  = int(os.environ.get("LICENSE_GRACE_H", "72")) * 3600
CHECK_INTERVAL = int(os.environ.get("LICENSE_CHECK_H", "6")) * 3600

_state: dict = {"valid": False, "days_left": 0, "email": "", "error": ""}
_lock = threading.Lock()


# ── Machine fingerprint ───────────────────────────────────────────────────────

def _machine_id() -> str:
    """Stable ID: SHA256 of hostname + first non-loopback MAC address."""
    parts = [socket.gethostname()]
    try:
        # Works on Linux; graceful fallback on other platforms
        with open("/sys/class/net/eth0/address") as f:
            parts.append(f.read().strip())
    except Exception:
        parts.append(str(uuid.getnode()))
    raw = "|".join(parts).encode()
    return hashlib.sha256(raw).hexdigest()[:32]


# ── Token helpers ─────────────────────────────────────────────────────────────

def _load_token() -> dict:
    try:
        with open(LICENSE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_token(data: dict):
    try:
        os.makedirs(os.path.dirname(LICENSE_FILE) or ".", exist_ok=True)
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


# ── Server communication ──────────────────────────────────────────────────────

def _post(endpoint: str, payload: dict, timeout: int = 15) -> dict:
    url = f"{LICENSE_SERVER.rstrip('/')}/{endpoint}"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "win443hp/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _activate() -> dict:
    """Call /activate with key + machine_id → get signed token."""
    if not LICENSE_KEY:
        return {"ok": False, "error": "LICENSE_KEY not set"}
    try:
        return _post("activate", {"key": LICENSE_KEY, "machine_id": _machine_id()})
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            return {"ok": False, "error": body.get("detail", str(e))}
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _validate(token: str) -> dict:
    """Call /validate with stored token → get {ok, days_left, email}."""
    try:
        return _post("validate", {"token": token, "machine_id": _machine_id()})
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            return {"ok": False, "error": body.get("detail", str(e))}
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Core check logic ──────────────────────────────────────────────────────────

def _check_once() -> bool:
    """Single license check cycle. Returns True if valid."""
    stored = _load_token()
    token  = stored.get("token", "")

    # Try to validate existing token first
    if token:
        res = _validate(token)
        if res.get("ok"):
            new_stored = {**stored, "token": token,
                          "last_ok": time.time(),
                          "days_left": res.get("days_left", 0),
                          "email": res.get("email", "")}
            _save_token(new_stored)
            with _lock:
                _state.update({"valid": True,
                                "days_left": res.get("days_left", 0),
                                "email": res.get("email", ""),
                                "error": ""})
            return True

    # No valid token → try to activate with key
    res = _activate()
    if res.get("ok") and res.get("token"):
        new_stored = {"token": res["token"],
                      "last_ok": time.time(),
                      "days_left": res.get("days_left", 30),
                      "email": res.get("email", "")}
        _save_token(new_stored)
        with _lock:
            _state.update({"valid": True,
                            "days_left": res.get("days_left", 30),
                            "email": res.get("email", ""),
                            "error": ""})
        print(f"[license] activated — {res.get('days_left', 30)} days left "
              f"({res.get('email', '')})", flush=True)
        return True

    # Server unreachable → check grace period
    last_ok = stored.get("last_ok", 0)
    if last_ok and (time.time() - last_ok) < GRACE_SECONDS:
        remaining_grace = int((GRACE_SECONDS - (time.time() - last_ok)) / 3600)
        err = res.get("error", "server unreachable")
        print(f"[license] offline grace — {remaining_grace}h left ({err})", flush=True)
        with _lock:
            _state.update({"valid": True,
                            "days_left": stored.get("days_left", 0),
                            "email": stored.get("email", ""),
                            "error": f"offline ({remaining_grace}h grace)"})
        return True

    # No valid token, no activation, grace expired
    err = res.get("error", "license invalid or expired")
    with _lock:
        _state.update({"valid": False, "days_left": 0, "error": err})
    return False


def _loop():
    """Background thread: re-check every CHECK_INTERVAL seconds."""
    while True:
        time.sleep(CHECK_INTERVAL)
        ok = _check_once()
        if not ok:
            print("[license] EXPIRED or REVOKED — shutting down in 60s", flush=True)
            time.sleep(60)
            os.kill(os.getpid(), 15)   # SIGTERM → clean Docker shutdown


# ── Public API ────────────────────────────────────────────────────────────────

def check_and_start() -> bool:
    """Call once at startup. Returns True if license is valid.
    Starts background re-check thread on success.
    Exits the process on hard failure (no key, no grace).
    """
    print("[license] checking…", flush=True)
    ok = _check_once()
    if not ok:
        with _lock:
            err = _state.get("error", "unknown")
        print(f"[license] INVALID — {err}", flush=True)
        print("[license] Set LICENSE_KEY env var or contact support.", flush=True)
        sys.exit(1)

    with _lock:
        days = _state.get("days_left", 0)
        email = _state.get("email", "")
    print(f"[license] OK — {days} days left ({email})", flush=True)

    t = threading.Thread(target=_loop, daemon=True, name="license-checker")
    t.start()
    return True


def status() -> dict:
    """Return current license state dict (thread-safe)."""
    with _lock:
        return dict(_state)
