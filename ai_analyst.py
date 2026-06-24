"""AI analyst — Mistral-backed deep analysis for the honeypot.

Central module that turns raw captured artefacts into readable threat
intelligence. Every function:
  * degrades gracefully (returns {} / "" when the LLM is unavailable),
  * caches aggressively (the same dropper/IP/campaign recurs thousands of
    times — we must NOT spend a quota call per event),
  * never executes anything; it only reasons over text.

Backed by groq_client (currently Mistral La Plateforme). All callers are
additive: they attach extra fields, nothing breaks if this module is absent.
"""
import json
import os
import re
import threading
import time

try:
    import groq_client as _llm
except Exception:
    _llm = None

# ── caches (bounded, PERSISTENT) ─────────────────────────────────────────────
# Everything that recurs is stored on disk so repeats cost ZERO Mistral tokens —
# even across container restarts. One JSON file holds all caches.
_LOCK = threading.Lock()
_dropper_cache: dict = {}    # sha256 -> analysis dict
_ip_cache: dict = {}         # ip -> verdict str
_camp_cache: dict = {}       # fingerprint -> {name, summary}
_payload_cache: dict = {}    # hash(text) -> decode dict
_exploit_cache: dict = {}    # lure|path -> {desc,cve,severity}
_threat_cache: dict = {}     # technique|path -> str
_sshintent_cache: dict = {}  # cmd-fingerprint -> str
_misc_cache: dict = {}       # small one-off generated artefacts (e.g. fake git log)
_CACHE_MAX = 4000

_CACHE_FILE = os.environ.get("AI_ANALYST_CACHE", "/data/ai_analyst_cache.json")
_CACHES = {
    "dropper": _dropper_cache, "ip": _ip_cache, "camp": _camp_cache,
    "payload": _payload_cache, "exploit": _exploit_cache,
    "threat": _threat_cache, "sshintent": _sshintent_cache, "misc": _misc_cache,
}
_last_save = 0.0
_save_min_interval = 20.0   # throttle disk writes


def _load_persisted():
    try:
        with open(_CACHE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        for name, cache in _CACHES.items():
            saved = d.get(name)
            if isinstance(saved, dict):
                cache.update(saved)
    except Exception:
        pass


def _save_persisted(force: bool = False):
    """Atomic, throttled write of all caches to disk. MERGES with the on-disk
    file first so the 3 containers (honeypot/enricher/dashboard) that all write
    this shared file never clobber each other's entries (last-writer-wins bug)."""
    global _last_save
    now = time.time()
    if not force and (now - _last_save) < _save_min_interval:
        return
    _last_save = now
    try:
        # 1) load what's currently on disk (other processes' entries)
        disk = {}
        try:
            with open(_CACHE_FILE, encoding="utf-8") as f:
                disk = json.load(f)
        except Exception:
            disk = {}
        # 2) merge disk → our in-memory caches (disk fills gaps; ours wins on conflict)
        with _LOCK:
            for name, cache in _CACHES.items():
                for k, v in (disk.get(name) or {}).items():
                    if k not in cache:
                        cache[k] = v
            snapshot = {name: dict(cache) for name, cache in _CACHES.items()}
        # 3) write the merged result
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False)
        os.replace(tmp, _CACHE_FILE)
    except Exception:
        pass


_load_persisted()


def _flush_loop():
    while True:
        time.sleep(30)
        _save_persisted(force=True)


threading.Thread(target=_flush_loop, daemon=True).start()


def _norm_path(p: str) -> str:
    """Collapse near-identical paths so the cache hits across IPs/IDs."""
    p = str(p or "")[:120]
    p = re.sub(r"[0-9a-f]{8,}", "X", p)      # hashes/ids
    p = re.sub(r"\d+", "N", p)               # numbers
    return p.lower()


def _norm_path(p: str) -> str:
    """Collapse near-identical paths so the cache hits across IPs/IDs."""
    import re
    p = str(p or "")[:120]
    p = re.sub(r"[0-9a-f]{8,}", "X", p)      # hashes/ids
    p = re.sub(r"\d+", "N", p)               # numbers
    return p.lower()


def available() -> bool:
    return bool(_llm and _llm.available())


def cached_ip_verdict(ip: str) -> str:
    """Non-blocking read of a previously computed IP verdict (no LLM call).
    Used in latency-sensitive request paths like the public feed."""
    with _LOCK:
        return _ip_cache.get(ip, "")


def _trim(cache: dict):
    if len(cache) > _CACHE_MAX:
        for k in list(cache)[:len(cache) - _CACHE_MAX]:
            cache.pop(k, None)


def _json_from(text: str) -> dict:
    """Extract the first JSON object from an LLM reply, tolerating prose/fences."""
    if not text:
        return {}
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except Exception:
        return {}


# ── 1. Dropper / malware-sample analysis ─────────────────────────────────────
def analyze_dropper(text: str, filetype: str = "", sha256: str = "") -> dict:
    """Explain a captured script/dropper. Cached by sha256.

    Returns: {summary, capabilities[], c2[], persistence[], family, confidence}
    Empty dict when unavailable or sample is binary/uninteresting.
    """
    if not available() or not text:
        return {}
    if sha256:
        with _LOCK:
            if sha256 in _dropper_cache:
                return _dropper_cache[sha256]
    # Only analyse text-like payloads; binaries give the LLM nothing useful.
    sample = text[:6000]
    printable = sum(c.isprintable() or c in "\r\n\t" for c in sample) / max(len(sample), 1)
    if printable < 0.7:
        return {}

    system = (
        "Du bist ein Malware-Analyst. Du bekommst ein in einem Honeypot erfasstes "
        "Dropper-/Loader-Script (NICHT ausführen, nur analysieren). Antworte AUSSCHLIESSLICH "
        "mit einem JSON-Objekt, kein Fließtext, keine Markdown-Fences. Schema:\n"
        '{"summary": "1-2 Sätze was das Script tut (deutsch)", '
        '"capabilities": ["kurze Stichworte"], '
        '"c2": ["URLs/IPs/Domains die als C2/Download dienen"], '
        '"persistence": ["cron/systemd/ssh-key/etc"], '
        '"family": "vermutete Malware-Familie oder leer", '
        '"confidence": "high|medium|low"}\n'
        "Erfinde keine IOCs — nur was wörtlich im Script steht."
    )
    out = _llm.chat(
        [{"role": "system", "content": system},
         {"role": "user", "content": f"Filetype: {filetype}\n\nScript:\n{sample}"}],
        max_tokens=500, temperature=0.1, timeout=25,
    )
    res = _json_from(out)
    if res and sha256:
        with _LOCK:
            _dropper_cache[sha256] = res
            _trim(_dropper_cache)
    return res


# ── 2. Obfuscated payload / C2 script decoder ────────────────────────────────
def decode_payload(text: str) -> dict:
    """Interpret an obfuscated payload the regex IOC layer couldn't crack.

    Returns: {explanation, iocs[], deobfuscated} — empty when unavailable.
    """
    if not available() or not text:
        return {}
    key = str(hash(text[:2000]))
    with _LOCK:
        if key in _payload_cache:
            return _payload_cache[key]
    system = (
        "Du bist ein Reverse-Engineer. Dekodiere/erkläre das obfuskierte Payload "
        "(base64/XOR/hex/string-concat). NICHT ausführen. Antworte NUR als JSON:\n"
        '{"explanation": "was es tut (deutsch, 1-2 Sätze)", '
        '"iocs": ["URLs/IPs/Domains/Dateipfade"], '
        '"deobfuscated": "der entschachtelte Kernbefehl, gekürzt"}\n'
        "Nur was tatsächlich im Payload steht."
    )
    out = _llm.chat(
        [{"role": "system", "content": system},
         {"role": "user", "content": text[:5000]}],
        max_tokens=400, temperature=0.1, timeout=25,
    )
    res = _json_from(out)
    if res:
        with _LOCK:
            _payload_cache[key] = res
            _trim(_payload_cache)
    return res


# ── 3. SSH campaign naming ───────────────────────────────────────────────────
def name_campaign(fingerprint: str, cmds: list, ip_count: int = 0) -> dict:
    """Give an SSH command-cluster a human name + one-line summary. Cached by fp.

    Returns: {name, summary} — empty when unavailable.
    """
    if not available() or not cmds:
        return {}
    with _LOCK:
        if fingerprint in _camp_cache:
            return _camp_cache[fingerprint]
    blob = "\n".join(str(c)[:200] for c in cmds[:15])
    system = (
        "Du bist ein Threat-Intel-Analyst. Du bekommst die Befehlssequenz eines "
        "automatisierten Angreifer-Clusters (SSH-Botnet) aus einem Honeypot. "
        "Antworte NUR als JSON:\n"
        '{"name": "kurzer prägnanter Kampagnen-Name (2-4 Wörter, z.B. \'XMRig Cron-Dropper\')", '
        '"summary": "1 Satz was die Kampagne tut (deutsch)"}\n'
        "Erfinde keine bekannten Botnet-Eigennamen außer sie sind eindeutig erkennbar."
    )
    out = _llm.chat(
        [{"role": "system", "content": system},
         {"role": "user", "content": f"Befehle ({ip_count} IPs):\n{blob}"}],
        max_tokens=120, temperature=0.2, timeout=20,
    )
    res = _json_from(out)
    if res:
        with _LOCK:
            _camp_cache[fingerprint] = res
            _trim(_camp_cache)
    return res


# ── 4. Per-IP feed verdict (RapidAPI value-add) ──────────────────────────────
def ip_verdict(ip: str, services: list = None, hits: int = 0,
               top_paths: list = None) -> str:
    """One-line analyst verdict for an attacker IP. Cached by IP.

    Used to enrich the sold RapidAPI feed. Returns "" when unavailable.
    """
    if not available() or not ip:
        return ""
    with _LOCK:
        if ip in _ip_cache:
            return _ip_cache[ip]
    ctx = (f"IP {ip}; services={services or []}; hits={hits}; "
           f"paths={[str(p)[:40] for p in (top_paths or [])][:8]}")
    system = (
        "Du bist ein Threat-Intel-Analyst. Gib EIN prägnantes englisches Verdict "
        "(max 15 Wörter) zu dieser Honeypot-Angreifer-IP: wahrscheinlicher Typ "
        "(scanner/bruteforce-bot/exploit-bot/APT-recon), Ziel, Konfidenz. "
        "Nur der Satz, kein JSON, keine Anführungszeichen."
    )
    out = _llm.chat(
        [{"role": "system", "content": system},
         {"role": "user", "content": ctx}],
        max_tokens=60, temperature=0.2, timeout=15,
    )
    out = (out or "").strip().strip('"').replace("\n", " ")[:160]
    if out:
        with _LOCK:
            _ip_cache[ip] = out
            _trim(_ip_cache)
    return out


# ── exploit description (EXPLOITS tab) ───────────────────────────────────────
def describe_exploit(lure: str, path: str = "", method: str = "") -> dict:
    """Explain what an exploit attempt is. Cached by lure+normalised-path.

    Returns: {desc, cve, severity} — empty when unavailable.
    """
    if not available() or not (lure or path):
        return {}
    key = f"{lure}|{_norm_path(path)}"
    with _LOCK:
        if key in _exploit_cache:
            return _exploit_cache[key]
    system = (
        "Du bist ein Exploit-Analyst. Erkläre KNAPP einen in einem Honeypot "
        "beobachteten Exploit-Versuch. Antworte NUR als JSON:\n"
        '{"desc": "1-2 Sätze: was wird ausgenutzt, was will der Angreifer (deutsch)", '
        '"cve": "CVE-ID falls eindeutig, sonst leer", '
        '"severity": "critical|high|medium|low"}'
    )
    out = _llm.chat(
        [{"role": "system", "content": system},
         {"role": "user", "content": f"lure={lure!r} method={method} path={path[:160]!r}"}],
        max_tokens=180, temperature=0.1, timeout=20,
    )
    res = _json_from(out)
    if res:
        with _LOCK:
            _exploit_cache[key] = res
            _trim(_exploit_cache)
    return res


# ── 0-day / behavioral threat description (0-DAY INTEL tab) ───────────────────
def describe_threat(technique: str, path: str = "", reasons=None, score: int = 0) -> str:
    """Plain-language explanation of a behavioral/0-day detector hit.
    Cached by technique+normalised-path. Returns "" when unavailable."""
    if not available():
        return ""
    key = f"{technique}|{_norm_path(path)}"
    with _LOCK:
        if key in _threat_cache:
            return _threat_cache[key]
    rs = ", ".join(reasons or [])
    system = (
        "Du bist ein Threat-Analyst eines Honeypots. Erkläre in 1-2 Sätzen (deutsch) "
        "was dieser Verhaltens-/Anomalie-Treffer bedeutet, wie neuartig er wirkt und "
        "warum er erfasst wurde. Kein JSON, nur der Satz. Erfinde keine CVE."
    )
    out = _llm.quick(
        f"technique={technique!r} score={score} path={path[:140]!r} anomalie_gründe=[{rs}]",
        max_tokens=160, system=system)
    out = (out or "").strip().replace("\n", " ")[:400]
    if out:
        with _LOCK:
            _threat_cache[key] = out
            _trim(_threat_cache)
    return out


# ── 0-day classification: is this GENUINELY novel or a known N-day? ──────────
def classify_threat(technique: str, path: str = "", reasons=None, score: int = 0,
                    body: str = "") -> dict:
    """Decide whether a detector hit is a KNOWN exploit (→ keep out of the 0-day
    tab) or something genuinely new/unknown. Cached by technique+path.
    Returns {desc, novel(bool), cve(str), family(str)}."""
    if not available():
        return {}
    key = f"cls\x00{technique}|{_norm_path(path)}"
    with _LOCK:
        if key in _threat_cache and isinstance(_threat_cache[key], dict):
            return _threat_cache[key]
    rs = ", ".join(reasons or [])
    system = (
        "Du bist ein Exploit-Analyst. Entscheide, ob dieser in einem Honeypot "
        "beobachtete Treffer ein BEKANNTER Exploit / eine bekannte CVE / ein "
        "bekanntes Tool ist, oder etwas WIRKLICH NEUES/UNBEKANNTES (echter 0-day-"
        "Kandidat). Bekannte N-days (z.B. CVE-2017-9841 PHPUnit, Log4Shell, "
        "ProxyShell, Hikvision CVE-2021-36260, Shellshock, alte RCEs) sind NICHT "
        "novel. Antworte NUR als JSON:\n"
        '{"known_cve":"CVE-ID oder Tool-Name falls bekannt, sonst leer",'
        '"is_novel":true|false,'
        '"family":"Exploit-/Tool-Familie oder leer",'
        '"desc":"1 Satz Einordnung (deutsch)"}'
    )
    out = _llm.quick(
        f"technique={technique!r} path={path[:140]!r} score={score} "
        f"anomalie=[{rs}] body={body[:200]!r}",
        max_tokens=200, system=system)
    d = _json_from(out)
    if not d:
        return {}
    res = {
        "desc": str(d.get("desc", ""))[:300],
        "cve": str(d.get("known_cve", ""))[:40],
        "family": str(d.get("family", ""))[:60],
        # genuinely novel ONLY if the model says so AND it named no known CVE/tool
        "novel": bool(d.get("is_novel")) and not str(d.get("known_cve", "")).strip(),
    }
    with _LOCK:
        _threat_cache[key] = res
        _trim(_threat_cache)
    return res


# ── SSH session intent (CREDENTIALS / COMMANDS tab) ──────────────────────────
def ssh_intent(commands: list) -> str:
    """Summarise what an SSH command sequence is trying to achieve.
    Cached by a fingerprint of the normalised commands. "" when unavailable."""
    if not available() or not commands:
        return ""
    import hashlib
    norm = "\n".join(_norm_path(str(c)) for c in commands[:20])
    fp = hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:16]
    with _LOCK:
        if fp in _sshintent_cache:
            return _sshintent_cache[fp]
    blob = "\n".join(str(c)[:200] for c in commands[:20])
    system = (
        "Du bist ein Analyst. Fasse in 1-2 Sätzen (deutsch) zusammen, was diese in "
        "einem SSH-Honeypot erfassten Angreifer-Befehle bezwecken (z.B. Recon, "
        "Miner-Install, Persistenz, Wurm-Verbreitung). Kein JSON, nur der Satz."
    )
    out = _llm.quick(blob, max_tokens=160, system=system)
    out = (out or "").strip().replace("\n", " ")[:400]
    if out:
        with _LOCK:
            _sshintent_cache[fp] = out
            _trim(_sshintent_cache)
    return out


# ── Believable command output for injected commands (e.g. Hikvision RCE) ──────
_CMD_TIME_SENSITIVE = re.compile(r"^\s*(date|uptime|w|who|last|top|free|cal|timedatectl)\b", re.I)


def fake_cmd_output(cmd: str, device: str = "linux") -> str:
    """Plausible terminal output for an attacker-injected command, in the given
    device context. Cached per (device, cmd) → 0 tokens on repeat. The current
    date/time is always supplied so date/uptime/log output is real. Time-sensitive
    commands bypass the cache so they stay fresh."""
    if not available() or not cmd:
        return ""
    cmd = cmd.strip()[:200]
    ts_sensitive = bool(_CMD_TIME_SENSITIVE.match(cmd))
    key = f"{device}\x00{_norm_path(cmd)}"
    if not ts_sensitive:
        with _LOCK:
            if key in _misc_cache:
                return _misc_cache[key]
    now = time.strftime("%a %b %d %H:%M:%S UTC %Y", time.gmtime())
    briefs = {
        "hikvision": ("BusyBox v1.19 embedded Linux on a Hikvision IP camera "
                      "(ARMv7, user root, /home/root). Minimal toolset (busybox)."),
        "linux": "Ubuntu 22.04 Linux server, user root.",
        "windows": ("Windows Server 2019 (IIS web server EXCH01, user "
                    "'nt authority\\system', domain contoso.local, cwd "
                    "C:\\inetpub\\wwwroot). cmd.exe / PowerShell syntax."),
        "openwrt": ("OpenWrt SNAPSHOT on a TP-Link TL-WR841N router "
                    "(MIPS 1004Kc, BusyBox v1.26.2, kernel 4.14.195, user root, "
                    "cwd /root). Only busybox applets available — no apt/yum. "
                    "LAN IP 192.168.1.1, WAN via DHCP. ash shell."),
    }
    system = (
        f"Du simulierst eine ECHTE Shell auf: {briefs.get(device, briefs['linux'])}\n"
        f"Aktuelles Datum/Uhrzeit: {now} (UTC) — nutze es für date/uptime/Logs.\n"
        "Gib NUR die rohe Terminal-Ausgabe des Befehls aus — korrektes Format, "
        "plausible Werte, kein Markdown, keine Erklärung, kein Prompt. Bei Fehlern "
        "die echte Fehlermeldung."
    )
    out = _llm.quick(f"Command: {cmd}\nOutput:", max_tokens=200, system=system)
    out = (out or "").strip("`\n ")
    if out and not ts_sensitive:
        with _LOCK:
            _misc_cache[key] = out
            _trim(_misc_cache)
    return out


# ── Believable Redis value for GET on an unknown key (looks like prod data) ───
def fake_redis_value(key: str) -> str:
    """Plausible value for a Redis key an attacker GETs, so the instance looks
    like a full production cache → they explore/exfiltrate more. Cached per key."""
    if not available() or not key:
        return ""
    k = key[:120]
    ck = "redisval\x00" + _norm_path(k)
    with _LOCK:
        if ck in _misc_cache:
            return _misc_cache[ck]
    system = (
        "Du bist ein echter Produktions-Redis-Cache. Gib NUR den plausiblen Wert "
        "für den abgefragten Key zurück (z.B. JSON-Session, gecachtes User-Objekt, "
        "Token, Config-Wert) — kein Markdown, keine Erklärung, nur der rohe Wert. "
        "Realistisch, aber KEINE echten Secrets (Platzhalter/Fake-Werte)."
    )
    out = _llm.quick(f"GET {k}", max_tokens=200, system=system)
    out = (out or "").strip("`\n ")[:1500]
    if out:
        with _LOCK:
            _misc_cache[ck] = out
            _trim(_misc_cache)
    return out


# ── Believable OWA/EWS post-auth response (attacker 'has' a mailbox) ──────────
def fake_owa(operation: str) -> str:
    """Plausible OWA/EWS response body for a post-auth mailbox operation, so an
    attacker who 'got in' keeps exploring/exfiltrating → we capture intent.
    Cached per operation fingerprint."""
    if not available() or not operation:
        return ""
    ck = "owa\x00" + _norm_path(operation[:160])
    with _LOCK:
        if ck in _misc_cache:
            return _misc_cache[ck]
    system = (
        "Du simulierst einen Microsoft Exchange/OWA-Server, auf den ein Angreifer "
        "nach erfolgreichem Login zugreift. Antworte mit einem KURZEN, plausiblen "
        "Body (JSON oder XML passend zur Anfrage) — z.B. eine Mailbox-Ordnerliste, "
        "Suchergebnisse mit ein paar Fake-Mail-Betreffs/Absendern, oder ein "
        "Mail-Item. Realistisch, aber nur Fake-Daten, keine echten Secrets. "
        "Nur der Body, kein Markdown."
    )
    out = _llm.quick(operation[:400], max_tokens=320, system=system)
    out = (out or "").strip("`\n ")[:2500]
    if out:
        with _LOCK:
            _misc_cache[ck] = out
            _trim(_misc_cache)
    return out


# ── Fake git commit history for git-dumpers (/.git/logs/HEAD) ─────────────────
def fake_git_log() -> str:
    """Mistral-generated, believable git commit history. Cached ONCE (persistent)
    — every git-dumper gets the same plausible repo for free after the first.
    Contains the literal placeholders {HOST} and {TOKEN}; the caller substitutes
    live honeytoken/beacon values per request so each leak is uniquely tracked."""
    with _LOCK:
        if _misc_cache.get("git_commits"):
            return _misc_cache["git_commits"]
    if not available():
        return ""
    system = (
        "Du generierst eine glaubwürdige Git-Commit-Historie für ein internes "
        "Firmen-Web-App-Repo (Node/Python), die ein Angreifer beim Dumpen von "
        "/.git findet. Antworte NUR als JSON-Liste von 7-10 Commits, neueste zuerst:\n"
        '[{"author":"Vorname Nachname","email":"user@firma.tld",'
        '"msg":"commit message"}]\n'
        "Mische realistische Messages; MINDESTENS zwei müssen verräterisch klingen "
        "(z.B. 'fix: move db creds to .env', 'hotfix: temp aws key', "
        "'add backup script for \\\\\\\\fileserver share'). Keine echten Secrets, nur Messages."
    )
    out = _llm.quick("Generiere die Commit-Historie.", max_tokens=600, system=system)
    commits = []
    try:
        m = re.search(r"\[.*\]", out, re.S)
        commits = json.loads(m.group(0)) if m else []
    except Exception:
        commits = []
    if not commits:
        return ""
    # Format as a real .git/logs/HEAD reflog. SHAs are random-but-valid hex.
    import hashlib as _h
    lines = []
    prev = "0" * 40
    base_ts = 1739000000
    for i, c in enumerate(reversed(commits)):
        sha = _h.sha1(f"{i}{c.get('msg','')}".encode()).hexdigest()
        ts = base_ts + i * 86400
        kind = "commit (initial)" if i == 0 else "commit"
        author = str(c.get("author", "Dev"))[:40]
        email = str(c.get("email", "dev@corp.local"))[:60]
        msg = str(c.get("msg", "update"))[:100]
        lines.append(f"{prev} {sha} {author} <{email}> {ts} +0000\t{kind}: {msg}")
        prev = sha
    text = "\n".join(lines) + "\n"
    # plant one extra reflog line that leaks a UNC + honeytoken beacon
    text += (f"{prev} {prev} Backup Bot <ci@corp.local> {base_ts + 999999} +0000"
             f"\tcommit: chore: nightly backup to \\\\{{HOST}}\\backups (token {{TOKEN}})\n")
    with _LOCK:
        _misc_cache["git_commits"] = text
        _trim(_misc_cache)
    return text


# ── Redis replication-stream analysis ────────────────────────────────────────
_repl_cache: dict = {}
_CACHES["repl"] = _repl_cache


def analyze_repl_stream(commands: list, src_host: str = "") -> dict:
    """Explain what a Redis rogue-master replication stream is doing.

    The repl stream is the actual RCE payload (MODULE LOAD, CONFIG SET,
    cron/ssh-key SET). Cached by a fingerprint of the normalised commands so
    the same C2 chain only costs one Mistral call regardless of how many bots
    connect. Returns {summary, technique, mitre, persistence[], iocs[]} or {}.
    """
    if not available() or not commands:
        return {}
    import hashlib
    norm = "\n".join(_norm_path(str(c)) for c in commands[:30])
    fp = hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:20]
    with _LOCK:
        if fp in _repl_cache:
            return _repl_cache[fp]
    blob = "\n".join(str(c)[:200] for c in commands[:30])
    system = (
        "Du bist ein Redis-Exploit-Analyst. Dir wird der Befehlsstrom gezeigt, "
        "den ein Rogue-Redis-Master nach dem RDB-Dump an sein Opfer schickt "
        "(die eigentliche RCE-Chain). Antworte NUR als JSON:\n"
        '{"summary": "1-2 Sätze: was macht die RCE-Chain (deutsch)", '
        '"technique": "z.B. redis-module-rce / cron-persistence / ssh-key-injection", '
        '"mitre": "MITRE ATT&CK Tactic/Technique-ID z.B. T1505.003", '
        '"persistence": ["wie wird Persistenz hergestellt"], '
        '"iocs": ["URLs/IPs/Domains/Wallet-Adressen die im Stream vorkommen"]}\n'
        "Nur was wörtlich in den Kommandos steht — nichts erfinden."
    )
    out = _llm.chat(
        [{"role": "system", "content": system},
         {"role": "user", "content": f"Quelle: {src_host}\n\nREPL-Stream:\n{blob}"}],
        max_tokens=350, temperature=0.1, timeout=25,
    )
    res = _json_from(out)
    if res:
        with _LOCK:
            _repl_cache[fp] = res
            _trim(_repl_cache)
        print(f"[ai] repl-stream {fp}: {res.get('technique','?')} / {res.get('mitre','?')}", flush=True)
    return res


# ── Binary sample strings analysis ───────────────────────────────────────────
_binary_cache: dict = {}
_CACHES["binary"] = _binary_cache


def analyze_binary_strings(strings_blob: str, filetype: str = "",
                            sha256: str = "") -> dict:
    """Classify a captured binary from its printable strings.

    Called when the filetype is ELF/PE/unknown (non-text), where the full
    source can't be sent. We send the top ~150 most interesting strings
    (filtered for length and printability). Cached by sha256.
    Returns {summary, family, arch, capabilities[], c2[], confidence} or {}.
    """
    if not available() or not strings_blob:
        return {}
    if sha256:
        with _LOCK:
            if sha256 in _binary_cache:
                return _binary_cache[sha256]
    sample = strings_blob[:5000]
    system = (
        "Du bist ein Malware-Reverse-Engineer. Dir werden die interessantesten "
        "lesbaren Strings aus einem in einem Honeypot gefangenen Binary gezeigt "
        "(kein ausführbarer Code, nur extrahierte Strings). "
        "Antworte NUR als JSON:\n"
        '{"summary": "1-2 Sätze was das Binary vermutlich tut (deutsch)", '
        '"family": "vermutete Malware-Familie (z.B. Mirai, XMRig-loader, Omicron)", '
        '"arch": "vermutete Architektur (x86_64/ARM/MIPS/...)", '
        '"capabilities": ["kurze Stichworte z.B. ssh-bruteforce/crypto-miner/..."], '
        '"c2": ["C2-URLs/IPs/Domains die in den Strings stehen"], '
        '"confidence": "high|medium|low"}\n'
        "Nur was wörtlich in den Strings steht — nichts erfinden."
    )
    out = _llm.chat(
        [{"role": "system", "content": system},
         {"role": "user", "content": f"Filetype: {filetype}\nSHA256: {sha256[:16]}…\n\nStrings:\n{sample}"}],
        max_tokens=400, temperature=0.1, timeout=25,
    )
    res = _json_from(out)
    if res and sha256:
        with _LOCK:
            _binary_cache[sha256] = res
            _trim(_binary_cache)
        print(f"[ai] binary {sha256[:12]}: {res.get('family','?')} / {res.get('arch','?')}", flush=True)
    return res
