"""Enricher — tails events.jsonl, does threat-intel lookups, writes enriched.jsonl."""
import json
import os
import time
import re
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

from intel import lookup_ip, lookup_hash
try:
    import ttp_analyzer as _ttp
except Exception:
    _ttp = None
try:
    import ai_analyst as _ai
except Exception:
    _ai = None
try:
    import c2_puller as _c2pull
except Exception:
    _c2pull = None

_XMR_RE  = re.compile(r'\b(4[0-9A-Za-z]{94})\b')
_BTC_RE  = re.compile(r'\b(bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_POOL_RE = re.compile(r'(?:stratum\+tcp|pool)[_. :]*://([a-z0-9.-]+:[0-9]+)', re.I)
_WVAR_RE = re.compile(r'(?:WALLET|XMR_WALLET|BTC_ADDR|POOL_USER|USER)\s*[=:]\s*["\']?([0-9A-Za-z]{40,})', re.I)


def fetch_c2_wallet(url: str, timeout: int = 6) -> dict:
    """Fetch C2 dropper URL, extract embedded wallet addresses and pool configs."""
    result: dict = {"url": url, "wallets": [], "pools": [], "error": None}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw  = r.read(65536)
            text = raw.decode("utf-8", "replace")
        seen: set = set()
        for m in _XMR_RE.findall(text):
            if m not in seen:
                seen.add(m); result["wallets"].append({"type": "XMR", "addr": m})
        for m in _BTC_RE.findall(text):
            if m not in seen:
                seen.add(m); result["wallets"].append({"type": "BTC", "addr": m})
        for m in _WVAR_RE.findall(text):
            if m not in seen and len(m) >= 40:
                seen.add(m); result["wallets"].append({"type": "var", "addr": m})
        result["pools"] = list(dict.fromkeys(_POOL_RE.findall(text)))
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except Exception as e:
        result["error"] = str(e)
    return result


EVENTS   = os.environ.get("EVENTS",   "/data/events.jsonl")
ENRICHED = os.environ.get("ENRICHED", "/data/enriched.jsonl")
CURSOR   = os.environ.get("ENRICH_CURSOR", "/data/enricher_cursor")
INTERVAL = float(os.environ.get("ENRICH_INTERVAL", "2"))
RE_IP    = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

_write_lock = threading.Lock()
# Outer pool: one task per event line.
_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="enrich")
# Separate pool for the nested IP/hash lookups. MUST be distinct from _POOL —
# submitting inner tasks back into _POOL and waiting on them starves/deadlocks
# the pool (all workers block on tasks queued behind themselves).
_IP_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="enrich-ip")


def extract_public_ips(ev: dict) -> list[str]:
    """Pull all IP-like strings from the event and return non-private ones."""
    seen = set()
    for v in [ev.get("src_ip", ""), ev.get("dst_ip", ""), str(ev.get("iocs", []))]:
        for m in RE_IP.finditer(str(v)):
            ip = m.group(1)
            parts = ip.split(".")
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
            if ip.startswith(("127.", "10.", "192.168.", "0.", "255.")):
                continue
            if ip.startswith("172.") and 16 <= int(parts[1]) <= 31:
                continue
            seen.add(ip)
    return list(seen)


def enrich(ev: dict) -> dict:
    enriched = dict(ev)

    # ── Split ssh_creds into top-level ssh_user/ssh_pass for live-feed display ──
    if ev.get("service") in ("ssh", "telnet") and not enriched.get("ssh_user"):
        creds = ev.get("ssh_creds") or []
        if creds:
            first = str(creds[0])
            u, _, p = first.partition(":")
            enriched["ssh_user"] = u or "?"
            enriched["ssh_pass"] = p or ""

    # ── Active C2 pull: fetch the 2nd-stage payload the RCE chain installs ──
    # Redis/worm loaders deliver over raw /dev/tcp + rogue-master replication
    # (non-HTTP), which passive capture never grabbed. Pull it now, then fold the
    # samples into captured_samples so hash-intel + AI dropper analysis run too.
    if _c2pull and (ev.get("redis_commands") or ev.get("redis_c2_urls")
                    or ev.get("redis_cron") or ev.get("c2_urls")):
        try:
            pulled = _c2pull.pull_all(ev)
        except Exception as e:
            pulled = []
            print(f"[enricher] c2-pull error: {e}", flush=True)
        if pulled:
            enriched["c2_pulled_samples"] = pulled
            merged = list(ev.get("captured_samples") or [])
            merged.extend(pulled)
            ev = {**ev, "captured_samples": merged}

    ips = extract_public_ips(ev)

    if ips:
        # Parallel IP lookups — each IP submitted to thread pool independently
        from concurrent.futures import as_completed
        ip_futures = {_IP_POOL.submit(lookup_ip, ip): ip for ip in ips}
        ip_intel = {}
        for fut in as_completed(ip_futures, timeout=20):
            ip = ip_futures[fut]
            try:
                ip_intel[ip] = fut.result()
            except Exception as e:
                ip_intel[ip] = {"error": str(e)}
        enriched["intel"] = ip_intel

    hash_intel = {}
    # Collect hashes from sha256_list AND captured_samples (the real source).
    _hashes = list(ev.get("sha256_list", []))
    for s in (ev.get("captured_samples") or []):
        if isinstance(s, dict) and s.get("sha256"):
            _hashes.append(s["sha256"])
    for h in dict.fromkeys(_hashes):
        if isinstance(h, str) and len(h) == 64:
            try:
                hash_intel[h] = lookup_hash(h)
            except Exception as e:
                hash_intel[h] = {"error": str(e)}
    if hash_intel:
        enriched["hash_intel"] = hash_intel

    # Fetch C2 dropper URLs and extract embedded wallet addresses
    c2_urls = list(dict.fromkeys(
        u for u in (ev.get("redis_c2_urls") or []) + (ev.get("c2_urls") or [])
        if isinstance(u, str) and u.startswith("http")
    ))
    if c2_urls:
        c2_intel = []
        for url in c2_urls[:3]:
            res = fetch_c2_wallet(url)
            c2_intel.append(res)
            if res.get("wallets") or res.get("pools"):
                print(f"[enricher] C2 wallet hit: {res}", flush=True)
        enriched["c2_wallet_intel"] = c2_intel

    # ── AI dropper analysis: explain captured script samples ──────────────
    if _ai and _ai.available():
        analyses = []
        for s in (ev.get("captured_samples") or []):
            if not isinstance(s, dict):
                continue
            ft = s.get("filetype", "")
            path = s.get("path", "")
            sha = s.get("sha256", "")
            # only text/script samples; binaries give the LLM nothing
            if path and ("script" in ft.lower() or "text" in ft.lower()
                         or "php" in ft.lower()):
                try:
                    with open(path, "rb") as fh:
                        body = fh.read(8192).decode("utf-8", "replace")
                    a = _ai.analyze_dropper(body, ft, sha)
                    if a:
                        analyses.append({"sha256": sha, **a})
                        print(f"[enricher] AI dropper {sha[:12]}: "
                              f"{a.get('family','?')} / {a.get('summary','')[:60]}", flush=True)
                except Exception:
                    pass
        if analyses:
            enriched["ai_sample_analysis"] = analyses

        # ── AI payload decode: crack obfuscation regex missed ─────────────
        iocs = ev.get("iocs") or {}
        blobs = (iocs.get("powershell_decoded") or []) + (iocs.get("base64_decoded") or [])
        for blob in blobs[:2]:
            if isinstance(blob, str) and len(blob) > 40:
                try:
                    d = _ai.decode_payload(blob)
                    if d:
                        enriched.setdefault("ai_payload_decode", []).append(d)
                except Exception:
                    pass

        # ── AI exploit description (EXPLOITS tab) ─────────────────────────
        lure = ev.get("lure", "")
        _benign_lures = ("iis-default", "favicon", "robots", "ssh-login",
                         "redis-recon", "root-redirect", "")
        if lure not in _benign_lures and str(ev.get("service", "")) not in ("ssh", "telnet"):
            try:
                d = _ai.describe_exploit(lure, ev.get("path", ""), ev.get("method", ""))
                if d:
                    enriched["ai_exploit_desc"] = d
            except Exception:
                pass

        # ── AI 0-day classification (only GENUINELY novel lands in 0-DAY tab) ─
        if ev.get("zero_day_score") or ev.get("technique") or ev.get("anomaly_reasons"):
            try:
                c = _ai.classify_threat(
                    ev.get("technique", ""), ev.get("path", ""),
                    ev.get("anomaly_reasons"), ev.get("zero_day_score", 0),
                    (ev.get("body_preview") or "")[:200])
                if c:
                    enriched["ai_threat_desc"]  = c.get("desc", "")
                    enriched["ai_threat_novel"] = c.get("novel", False)
                    enriched["ai_threat_cve"]   = c.get("cve", "")
                    enriched["ai_threat_family"] = c.get("family", "")
            except Exception:
                pass

        # ── AI SSH/Telnet session intent (CREDENTIALS / COMMANDS tab) ──────
        if ev.get("service") in ("ssh", "telnet") and ev.get("ssh_commands"):
            try:
                si = _ai.ssh_intent(ev.get("ssh_commands", []))
                if si:
                    enriched["ai_ssh_intent"] = si
            except Exception:
                pass

        # ── AI Redis replication-stream analysis ──────────────────────────
        # Cached by normalised command fingerprint → 0 tokens on repeat C2.
        for _s in (enriched.get("c2_pulled_samples") or []):
            if not isinstance(_s, dict):
                continue
            repl_cmds = _s.get("repl_commands", [])
            if repl_cmds:
                try:
                    ra = _ai.analyze_repl_stream(repl_cmds, _s.get("source", ""))
                    if ra:
                        enriched.setdefault("ai_repl_analysis", []).append(
                            {"source": _s.get("source", ""), **ra})
                except Exception:
                    pass

        # ── AI binary strings analysis ────────────────────────────────────
        # ELF/PE samples: extract strings → classify via LLM. Cached by sha256.
        import re as _re
        for _s in (enriched.get("captured_samples") or []) + (enriched.get("c2_pulled_samples") or []):
            if not isinstance(_s, dict):
                continue
            ft   = _s.get("filetype", "")
            path = _s.get("path", "")
            sha  = _s.get("sha256", "")
            if not path or not sha:
                continue
            if any(t in ft.lower() for t in ("script", "text", "php", "shell")):
                continue  # text samples handled by analyze_dropper
            if not any(t in ft.lower() for t in ("elf", "pe32", "executable", "unknown")):
                continue
            # Known malware (VT hit) → skip LLM strings analysis, save tokens
            vt_score = (enriched.get("hash_intel") or {}).get(sha, {}).get("vt_detections", 0)
            if vt_score and vt_score > 0:
                continue
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(1024 * 1024)
                found = _re.findall(rb"[\x20-\x7e]{6,}", raw)
                interesting = [b.decode("latin-1", "replace") for b in found
                               if any(c in b.decode("latin-1", "replace")
                                      for c in ("://", "/", ".", "-", "_"))
                               or len(b) > 12]
                strings_blob = "\n".join(interesting[:200])
                if strings_blob:
                    ba = _ai.analyze_binary_strings(strings_blob, ft, sha)
                    if ba:
                        enriched.setdefault("ai_binary_analysis", []).append(
                            {"sha256": sha, **ba})
            except Exception:
                pass

    return enriched


def _process_line(raw_line: str):
    """Enrich one raw JSON line and append to ENRICHED. Runs in thread pool."""
    raw_line = raw_line.strip()
    if not raw_line:
        return
    try:
        ev = json.loads(raw_line)
    except json.JSONDecodeError:
        return
    try:
        enriched = enrich(ev)
    except Exception as e:
        enriched = {"_enrich_error": str(e), **ev}
    try:
        line = json.dumps(enriched, ensure_ascii=False) + "\n"
        with _write_lock:
            with open(ENRICHED, "a", encoding="utf-8") as out:
                out.write(line)
        # Async TTP analysis — non-blocking, runs in background thread
        if _ttp:
            try: _ttp.enrich_event(enriched)
            except Exception: pass
    except Exception as e:
        print(f"[enricher] write error: {e}", flush=True)


def _cursor_read() -> int:
    try:
        with open(CURSOR) as f:
            return max(0, int(f.read().strip()))
    except Exception:
        return -1  # -1 = no cursor → seek to EOF (first-run behaviour)


def _cursor_write(pos: int):
    try:
        with open(CURSOR, "w") as f:
            f.write(str(pos))
    except Exception:
        pass


def tail(path: str):
    """Yield new lines appended to path. Resumes from last cursor on restart."""
    while not os.path.exists(path):
        time.sleep(1)
    saved = _cursor_read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if saved >= 0:
            # Resume from last known position — catches events missed during downtime
            try:
                fh.seek(saved)
            except OSError:
                fh.seek(0, 2)
        else:
            fh.seek(0, 2)  # first run: start from current end
        while True:
            line = fh.readline()
            if line:
                # Yield the line AND its end-position; the cursor is now advanced
                # by main() only AFTER the line is successfully enriched (no longer
                # on read) — so a crash mid-processing never loses events.
                yield line, fh.tell()
            else:
                time.sleep(INTERVAL)


def main():
    print(f"[enricher] watching {EVENTS} → {ENRICHED}", flush=True)
    os.makedirs(os.path.dirname(ENRICHED) or ".", exist_ok=True)
    from collections import deque
    pending = deque()           # (future, end_pos) in read order
    MAXQ = 64                   # backpressure: cap in-flight tasks

    def _drain_done():
        # Advance cursor over the contiguous run of completed tasks (low-water
        # mark): only persist a position once that line AND all earlier ones are
        # done. Out-of-order completions wait for their predecessors.
        while pending and pending[0][0].done():
            _, p = pending.popleft()
            _cursor_write(p)

    for raw_line, pos in tail(EVENTS):
        fut = _POOL.submit(_process_line, raw_line)
        pending.append((fut, pos))
        _drain_done()
        # If the queue is full, block on the oldest task before reading more.
        while len(pending) >= MAXQ:
            fut0, p0 = pending.popleft()
            try:
                fut0.result(timeout=60)
            except Exception:
                pass
            _cursor_write(p0)
            _drain_done()


if __name__ == "__main__":
    main()
