"""Threat-intel lookups: geo/ASN, GreyNoise (free), Feodo, URLhaus, VirusTotal."""
import json
import os
import socket
import time
import threading
import urllib.request
import urllib.error
from functools import lru_cache

VT_KEY        = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")   # free 1000/day
ABUSECH_KEY   = os.environ.get("ABUSECH_KEY", "")     # one key: MalwareBazaar+URLhaus+ThreatFox
GREYNOISE_KEY = os.environ.get("GREYNOISE_KEY", "")   # free account lifts rate limit
TIMEOUT = 4  # was 8 — halves worst-case stall per new IP

# ── VirusTotal daily quota guard (free tier: 500/day hard cap) ────────────────
# VT is reserved for HASH lookups only — not IPs (ip-api+Shodan+GreyNoise cover those).
# Counter resets at UTC midnight; cutoff at 450 to keep buffer for manual queries.
_VT_DAILY_MAX  = 450
_vt_lock       = threading.Lock()
_vt_count      = 0
_vt_day        = ""   # YYYY-MM-DD UTC

def _vt_allowed() -> bool:
    """Return True and increment counter if VT quota is still available today."""
    global _vt_count, _vt_day
    today = time.strftime("%Y-%m-%d", time.gmtime())
    with _vt_lock:
        if _vt_day != today:
            _vt_day, _vt_count = today, 0
        if _vt_count >= _VT_DAILY_MAX:
            return False
        _vt_count += 1
        return True


_UA = "Mozilla/5.0 (X11; Linux x86_64) intel-enricher/1.0"

def _get(url, headers=None):
    h = {"User-Agent": _UA}          # some APIs (Shodan) 403 the default python-urllib UA
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def _get_txt(url):
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
            return r.read().decode()
    except Exception:
        return ""


# ── Feodo blocklist: cached for 30 min instead of downloaded per IP ──────────
_feodo_cache: dict = {"ips": set(), "ts": 0.0}
_FEODO_TTL = 1800  # 30 minutes


def _feodo_ips() -> set:
    now = time.time()
    if now - _feodo_cache["ts"] < _FEODO_TTL and _feodo_cache["ips"]:
        return _feodo_cache["ips"]
    raw = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    lst = raw if isinstance(raw, list) else (raw.get("results", []) if isinstance(raw, dict) else [])
    ips = {e.get("ip_address") for e in lst if isinstance(e, dict) and e.get("ip_address")}
    if ips:
        _feodo_cache["ips"] = ips
        _feodo_cache["ts"] = now
    return _feodo_cache["ips"]


@lru_cache(maxsize=4096)
def lookup_ip(ip: str) -> dict:
    if not ip or ip.startswith(("127.", "10.", "172.16.", "192.168.", "::1")):
        return {"ip": ip, "private": True}

    result = {"ip": ip}

    # Geo/ASN via ip-api (free)
    geo = _get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,org,as,isp,query")
    if geo.get("status") == "success":
        result.update({
            "country": geo.get("countryCode", ""),
            "country_name": geo.get("country", ""),
            "city": geo.get("city", ""),
            "org": geo.get("org", ""),
            "asn": geo.get("as", ""),
            "isp": geo.get("isp", ""),
        })

    # Reverse DNS — capped at 3s via concurrent future
    try:
        import concurrent.futures as _cf
        with _cf.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            result["rdns"] = fut.result(timeout=3)[0]
    except Exception:
        result["rdns"] = ""

    # Shodan InternetDB (KEYLESS, free) — open ports, known CVEs, tags
    sh = _get(f"https://internetdb.shodan.io/{ip}")
    if sh and sh.get("ip"):
        result["shodan"] = {
            "ports": sh.get("ports", [])[:25],
            "vulns": sh.get("vulns", [])[:25],
            "tags": sh.get("tags", []),
            "cpes": sh.get("cpes", [])[:10],
        }

    # GreyNoise community — free; an account key lifts the 25/week rate limit
    gn = _get(f"https://api.greynoise.io/v3/community/{ip}",
              headers={"key": GREYNOISE_KEY} if GREYNOISE_KEY else None)
    if gn and "rate limit" not in str(gn.get("message", "")).lower():
        result["greynoise"] = {
            "noise": gn.get("noise", False),
            "riot": gn.get("riot", False),
            "classification": gn.get("classification", ""),
            "name": gn.get("name", ""),
        }

    # AbuseIPDB — abuse-confidence score (free 1000/day, needs key)
    if ABUSEIPDB_KEY:
        ai = _get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                  headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
        d = ai.get("data", {})
        if d:
            result["abuseipdb"] = {
                "score": d.get("abuseConfidenceScore", 0),
                "reports": d.get("totalReports", 0),
                "usage": d.get("usageType", ""),
            }

    # Feodo tracker (C2 botnet list) — uses module-level 30-min cache
    result["feodo_c2"] = ip in _feodo_ips()

    # URLhaus (submission-based)
    try:
        import urllib.parse
        payload = urllib.parse.urlencode({"host": ip}).encode()
        _uh_hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        if ABUSECH_KEY:
            _uh_hdr["Auth-Key"] = ABUSECH_KEY      # abuse.ch made this mandatory (2024)
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data=payload,
            headers=_uh_hdr,
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            uh = json.loads(r.read().decode())
        result["urlhaus"] = {
            "query_status": uh.get("query_status", ""),
            "urls_count": len(uh.get("urls", [])),
        }
    except Exception:
        pass

    # VirusTotal intentionally skipped for IPs — daily quota (500/day) is reserved
    # exclusively for hash lookups where VT adds unique value (detection verdicts).
    # ip-api + Shodan + GreyNoise + AbuseIPDB already cover IP reputation sufficiently.

    return result


@lru_cache(maxsize=512)
def lookup_hash(sha256: str) -> dict:
    result = {"sha256": sha256}

    # CIRCL hashlookup (KEYLESS) — known-good/known-bad reputation
    cr = _get(f"https://hashlookup.circl.lu/lookup/sha256/{sha256}")
    if cr and "message" not in cr:
        result["circl"] = {
            "known": True,
            "filename": cr.get("FileName", ""),
            "source": cr.get("source", ""),
            "trust": cr.get("hashlookup:trust", ""),
        }

    # MalwareBazaar
    try:
        import urllib.parse
        payload = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        _mb_hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        if ABUSECH_KEY:
            _mb_hdr["Auth-Key"] = ABUSECH_KEY      # mandatory since 2024
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=payload,
            headers=_mb_hdr,
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            mb = json.loads(r.read().decode())
        if mb.get("query_status") == "ok":
            info = mb.get("data", [{}])[0]
            result["malwarebazaar"] = {
                "file_name": info.get("file_name", ""),
                "file_type": info.get("file_type", ""),
                "tags": info.get("tags", []),
                "vendor_intel": info.get("vendor_intel", {}),
                "signature": info.get("signature", ""),
            }
    except Exception:
        pass

    if VT_KEY and _vt_allowed():
        vt = _get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_KEY},
        )
        attrs = vt.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["virustotal"] = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "tags": attrs.get("tags", []),
            "name": attrs.get("meaningful_name", ""),
        }

    return result


if __name__ == "__main__":
    import sys
    for target in sys.argv[1:]:
        print(json.dumps(lookup_ip(target), indent=2))
