"""IOC extraction, payload decoding and malware-sample capture.

This is the analysis core: it pulls everything interesting out of a decrypted
attacker request, auto-decodes the obfuscation layers Windows loaders love
(PowerShell -EncodedCommand, base64, JNDI), and optionally fetches second-stage
binaries for offline reversing. Samples are only ever STORED, never executed.
"""
import base64
import hashlib
import os
import re
import threading
import time
import urllib.request
from urllib.parse import urlparse

SAMPLE_DIR = os.environ.get("SAMPLE_DIR", "/data/samples")
CAPTURE_SAMPLES = os.environ.get("CAPTURE_SAMPLES", "1") == "1"
SAMPLE_MAX = int(os.environ.get("SAMPLE_MAX_BYTES", str(15 * 1024 * 1024)))

# Cross-call fetch cache: the SAME C2 URL shows up in hundreds of events; without
# this we re-download it once per event (observed: one benign URL fetched 844×).
# Remember every URL we've fetched and skip it for SAMPLE_URL_TTL seconds.
SAMPLE_URL_TTL = int(os.environ.get("SAMPLE_URL_TTL", str(6 * 3600)))
_URL_CACHE: dict[str, dict] = {}   # url -> {"t": fetched_ts, "result": <list-entry or None>}
_URL_CACHE_LOCK = threading.Lock()

URL_RE = re.compile(rb"(?:https?|ftp|tftp)://[^\s'\"()<>{}\\^`|]+", re.I)
# PowerShell:  -enc / -EncodedCommand / -e  <base64>
PS_ENC_RE = re.compile(rb"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})", re.I)
# Generic long base64 blobs
B64_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
JNDI_RE = re.compile(rb"\$\{jndi:[^}]+\}", re.I)
IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SAMPLE_RECURSE_DEPTH = int(os.environ.get("SAMPLE_RECURSE_DEPTH", "2"))

# Windows-loader / living-off-the-land indicators worth tagging
LOLBAS = [b"powershell", b"pwsh", b"certutil", b"bitsadmin", b"mshta",
          b"regsvr32", b"rundll32", b"wmic", b"cscript", b"wscript",
          b"msiexec", b"FromBase64String", b"DownloadString", b"DownloadFile",
          b"IEX", b"Invoke-Expression", b"Invoke-WebRequest", b"New-Object",
          b"cmd.exe", b"/c ", b"net user", b"schtasks", b"vssadmin",
          b"WScript.Shell", b"ScriptControl", b"frombase64"]


def _try_b64(blob: bytes):
    """Decode a base64 blob, picking the encoding that yields the cleanest text.

    PowerShell -enc is UTF-16LE; PHP/shell payloads are UTF-8. We score every
    candidate and keep the most ASCII-sensible one (avoids UTF-16 mojibake on
    ASCII payloads, which previously masked C2 URLs).
    """
    best, best_score = None, 0.0
    for dec in (blob, blob + b"=" * (-len(blob) % 4)):
        try:
            raw = base64.b64decode(dec, validate=False)
        except Exception:
            continue
        if not raw:
            continue
        for enc in ("utf-8", "utf-16-le", "latin-1"):
            try:
                txt = raw.decode(enc)
            except Exception:
                continue
            if not txt:
                continue
            ascii_ok = sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in txt) / len(txt)
            score = ascii_ok
            low = txt.lower()
            if any(k in low for k in ("http", "wget", "curl", "powershell", "/bin/",
                                      "cmd", "exec", "iex", "function", "shell")):
                score += 0.5
            if score > best_score and ascii_ok > 0.6:
                best, best_score = txt.strip(), score
    return best


def _clean_url(u: str) -> str:
    """Strip trailing shell/markup punctuation the URL regex greedily grabbed,
    e.g. 'http://x/y.sh;' from `wget http://x/y.sh; sh` → 'http://x/y.sh'."""
    return u.rstrip(";,'\")(<>{}|`\\ \t\r\n")


def extract_iocs(request_bytes: bytes) -> dict:
    iocs = {"urls": [], "powershell_decoded": [], "base64_decoded": [],
            "jndi": [], "tags": []}

    for m in set(URL_RE.findall(request_bytes)):
        iocs["urls"].append(m.decode("latin-1", "replace"))

    for m in JNDI_RE.findall(request_bytes):
        iocs["jndi"].append(m.decode("latin-1", "replace"))
        iocs["tags"].append("log4shell")

    for m in PS_ENC_RE.findall(request_bytes):
        txt = _try_b64(m)
        if txt:
            iocs["powershell_decoded"].append(txt)
            iocs["tags"].append("powershell-encodedcommand")
            for u in URL_RE.findall(txt.encode("utf-8", "replace")):
                iocs["urls"].append(u.decode("latin-1", "replace"))

    # generic base64 blobs (skip ones already handled as PS-enc)
    seen = set()
    for m in B64_RE.findall(request_bytes):
        if len(m) > 4000 or m in seen:
            continue
        seen.add(m)
        txt = _try_b64(m)
        if txt and txt not in iocs["powershell_decoded"]:
            iocs["base64_decoded"].append(txt[:2000])
            for u in URL_RE.findall(txt.encode("utf-8", "replace")):
                iocs["urls"].append(u.decode("latin-1", "replace"))

    low = request_bytes.lower()
    for ind in LOLBAS:
        if ind.lower() in low:
            iocs["tags"].append(ind.decode().strip().lower())

    iocs["urls"] = sorted({_clean_url(u) for u in iocs["urls"]} - {""})
    iocs["tags"] = sorted(set(iocs["tags"]))
    return iocs


def filetype(data: bytes) -> str:
    """Cheap magic-byte file-type ID to classify the captured code."""
    if data[:2] == b"MZ":
        return "PE (Windows EXE/DLL)"
    if data[:4] == b"\x7fELF":
        return "ELF (Linux binary)"
    if data[:4] == b"\xca\xfe\xba\xbe":
        return "Java class"
    if data[:2] == b"PK":
        return "ZIP/JAR/Office"
    if data[:4] == b"%PDF":
        return "PDF"
    low = data[:64].lstrip().lower()
    if low.startswith(b"<?php"):
        return "PHP script"
    if low.startswith((b"#!", b"function", b"$", b"iex", b"powershell", b"import ")):
        return "script (PowerShell/shell/py)"
    printable = sum(9 <= c < 127 for c in data[:512]) / max(min(len(data), 512), 1)
    return "text/script" if printable > 0.85 else "binary/unknown"


def triage(data: bytes) -> dict:
    """Identify the sample and pull embedded C2 indicators (the sources)."""
    return {
        "filetype": filetype(data),
        "embedded_urls": sorted({_clean_url(m.decode("latin-1", "replace")) for m in URL_RE.findall(data)} - {""})[:50],
        "embedded_ips": sorted({m.decode() for m in IPV4_RE.findall(data)
                                if not m.startswith((b"0.", b"127.", b"255."))})[:50],
    }


# Benign infrastructure we must never crawl (kills recursion noise).
BENIGN_HOSTS = ("w3.org", "google.com", "googleapis.com", "gstatic", "google.dev",
                "android.com", "chrome.com", "appspot.com", "microsoft.com",
                "mozilla.org", "schema.org", "creativecommons.org", "gofundme.com",
                "fourthwall.com", "bsky.app", "cloudflare.com", "jquery", "wikipedia.org",
                "youtube.com", "ai.studio", "bootstrapcdn", "fontawesome", "github.io",
                "digicert.com", "letsencrypt.org", "sectigo", "linkedin.com",
                "paloaltonetworks.com", "driftnet.io", "framerusercontent.com",
                "censys.io", "infrawat.ch",
                # research scanners / CDNs / SaaS whose URLs appear in scanner UAs
                # (caused benign false-captures: modat.io homepage, masscan github page)
                "github.com", "githubusercontent.com", "modat.io", "shodan.io",
                "parastorage.com", "wixapps.net", "wix.com", "filesusr.com",
                "internet-measurement.com", "leakix.net", "shadowserver.org",
                "bing.com", "apple.com", "openai.com", "amazonaws.com",
                "sentry.io", "sentry-cdn.com", "ipip.net", "cyberconvoy.co",
                "nokia.com", "go-mpulse.net")


def _benign(url):
    try:
        h = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return any(b in h for b in BENIGN_HOSTS)


def _is_webpage(data):
    head = data[:600].lstrip().lower()
    return (head.startswith((b"<!doctype html", b"<html", b"<?xml"))
            or b"<head" in head or b"<body" in head)


def _fetch(url, tries=3):
    """Fetch a URL with a few retries (attacker C2 is often intermittently up)."""
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read(SAMPLE_MAX + 1)
        except Exception:
            if i + 1 < tries:
                time.sleep(3)
    return None


def capture_samples(urls, _depth=0, _seen=None) -> list:
    """Download referenced payloads, triage them, and follow the *loader chain*
    (the "reverse loop"). Recursion is restricted to real loaders: benign
    infrastructure is never fetched, and we do NOT crawl into web pages (their
    links are navigation, not next stages). Samples are stored raw and never run.
    """
    out = []
    if not CAPTURE_SAMPLES:
        return out
    if _seen is None:
        _seen = set()
        # Prune expired cache entries occasionally (top-level calls only).
        if len(_URL_CACHE) > 5000:
            cutoff = time.time() - SAMPLE_URL_TTL
            with _URL_CACHE_LOCK:
                for u in [k for k, v in _URL_CACHE.items() if v["t"] < cutoff]:
                    _URL_CACHE.pop(u, None)
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    now = time.time()
    for url in urls:
        if url in _seen or not url.lower().startswith(("http://", "https://")):
            continue
        _seen.add(url)
        if _benign(url):
            continue
        # Cross-call cache: skip URLs fetched recently (don't re-hammer the same C2).
        with _URL_CACHE_LOCK:
            hit = _URL_CACHE.get(url)
            if hit and now - hit["t"] < SAMPLE_URL_TTL:
                if hit["result"] is not None:
                    out.append({**hit["result"], "cached": True})
                continue
        data = _fetch(url)
        if data is None:
            with _URL_CACHE_LOCK:
                _URL_CACHE[url] = {"t": now, "result": None}
            out.append({"url": url, "error": "fetch failed/unreachable", "depth": _depth})
            continue
        if len(data) > SAMPLE_MAX:
            with _URL_CACHE_LOCK:
                _URL_CACHE[url] = {"t": now, "result": None}
            continue
        sha = hashlib.sha256(data).hexdigest()
        path = os.path.join(SAMPLE_DIR, sha)
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(data)
        tri = triage(data)
        entry = {"url": url, "sha256": sha, "size": len(data), "path": path,
                 "filetype": tri["filetype"], "depth": _depth,
                 "embedded_ips": tri["embedded_ips"],
                 "embedded_urls": tri["embedded_urls"]}
        with _URL_CACHE_LOCK:
            _URL_CACHE[url] = {"t": now, "result": entry}
        out.append(entry)
        # reverse loop: only chase next stages from real loaders, not web pages
        if _depth < SAMPLE_RECURSE_DEPTH and not _is_webpage(data):
            nxt = [u for u in tri["embedded_urls"] if not _benign(u)]
            if nxt:
                out.extend(capture_samples(nxt, _depth + 1, _seen))
    return out
