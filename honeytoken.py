"""Honeytoken beacons.

Every fake secret we hand out (in /.env, terraform state, git config, …) is
stamped with a unique token `htk_<hex>` embedded in beacon URLs that point back
at this honeypot. When an attacker's tooling later *uses* the leaked secrets —
e.g. a credential-validation bot curls the API/webhook/Sentry URL — the request
carries the token and we record a BEACON HIT, correlating:

    issued_ip  (who scraped the secret)  ⟷  trigger_ip (who operationalised it)

This turns dead bait into a live trip-wire. Pure observation: the beacon URLs
resolve to us, we never call out anywhere. No external services, no own domains.
"""
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone

_DATA = os.environ.get("DATA_DIR", "/data")
_TOK_FILE = os.path.join(_DATA, "honeytokens.json")
_EVENTS = os.environ.get("EVENTS", os.path.join(_DATA, "events.jsonl"))
_BEACON_HOST = os.environ.get("BEACON_HOST", "164.68.121.252")

_TOKEN_RE = re.compile(r"htk_[0-9a-f]{16}")
_lock = threading.Lock()


def _ts():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load() -> dict:
    try:
        with open(_TOK_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(d: dict):
    try:
        with open(_TOK_FILE, "w") as f:
            json.dump(d, f)
    except OSError:
        pass


_tokens = _load()


def mint(src_ip: str, kind: str = "env") -> str:
    """Issue a fresh honeytoken, remembering who we gave it to."""
    tok = "htk_" + secrets.token_hex(8)
    with _lock:
        # Cap growth: keep the most recent 5000.
        if len(_tokens) > 5000:
            for k in list(_tokens)[:1000]:
                _tokens.pop(k, None)
        _tokens[tok] = {"issued_ip": src_ip, "kind": kind, "ts": _ts()}
        _save(_tokens)
    return tok


def beacon_host() -> str:
    return _BEACON_HOST


def scan(text: str, trigger_ip: str) -> list:
    """Scan an incoming request for previously-issued tokens. Each match is a
    beacon hit → logged as a high-value event. Returns list of hit tokens."""
    if not text or "htk_" not in text:
        return []
    hits = []
    for tok in set(_TOKEN_RE.findall(text)):
        with _lock:
            meta = _tokens.get(tok)
        if not meta:
            continue
        hits.append(tok)
        ev = {
            "ts": _ts(), "service": "honeytoken", "src_ip": trigger_ip,
            "lure": "honeytoken-triggered", "token": tok,
            "issued_ip": meta.get("issued_ip"), "issued_ts": meta.get("ts"),
            "kind": meta.get("kind"),
            "lateral": meta.get("issued_ip") not in ("", trigger_ip),
        }
        try:
            with open(_EVENTS, "a") as f:
                f.write(json.dumps(ev) + "\n")
        except OSError:
            pass
        print(f"[honeytoken] BEACON HIT {tok} issued_to={meta.get('issued_ip')} "
              f"triggered_by={trigger_ip} kind={meta.get('kind')}", flush=True)
    return hits
