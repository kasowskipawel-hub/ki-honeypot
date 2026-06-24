"""Behavioral zero-day exploit detector.

Classifies attack techniques purely from observable HTTP signals — no CVE
signatures needed. Works on every request before the lure layer, so it catches
novel payloads that don't match known paths.

Returns a threat dict that honeypot.py merges into the event record, and that
dashboard.py renders in the THREAT INTEL tab.
"""
import re
import hashlib
import json
import os
import time
import base64
import gzip
import math
import queue
import threading
import urllib.parse
from collections import defaultdict, Counter

try:
    import persona as _persona            # local LLM for grey-zone triage
except Exception:
    _persona = None

_EVENTS = os.environ.get("EVENTS", os.path.join(os.environ.get("DATA_DIR", "/data"), "events.jsonl"))


# ── (A) Recursive decode — reveal nested encodings before the regex scan ──────
def _shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s); c = Counter(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _deep_decode(path: str, body_str: str) -> str:
    """Return path+body PLUS recursively URL/base64/gzip-decoded layers, so an
    obfuscated payload (the classic 0-day evasion) is exposed to the classifier."""
    parts = [path, body_str]
    # multi-pass URL-decode of path+body
    for src in (path, body_str):
        cur = src
        for _ in range(3):
            try:
                u = urllib.parse.unquote_plus(cur)
            except Exception:
                break
            if u == cur:
                break
            parts.append(u); cur = u
    # base64 blobs anywhere → decode (and gunzip if needed)
    for m in set(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", path + " " + body_str)):
        try:
            dec = base64.b64decode(m + "=" * (-len(m) % 4), validate=False)
            if dec[:2] == b"\x1f\x8b":
                try: dec = gzip.decompress(dec)
                except Exception: pass
            s = dec.decode("utf-8", "replace")
            if sum(ch.isprintable() for ch in s) > len(s) * 0.7:
                parts.append(s)
        except Exception:
            pass
    return " ".join(parts)


# ── (B) Anomaly heuristics — structural novelty, no signature needed ─────────
_seen_paths: dict = defaultdict(int)   # base path → times seen (this run)
_ANOMALY_SCORES = {
    "unknown-path": 20, "high-entropy-payload": 25, "oversized-payload": 15,
    "shell-metachars": 20, "header-flood": 10, "oversized-header": 15,
    "deep-encoding": 20, "binary-in-text": 20,
}


def _anomaly(path: str, headers: dict, body_str: str, decoded: str):
    reasons = []
    base = path.split("?", 1)[0]
    seen = _seen_paths[base]; _seen_paths[base] += 1
    qs = path.split("?", 1)[1] if "?" in path else ""
    payload = " ".join(x for x in (qs, body_str) if x)
    longest = max((len(x) for x in (qs, body_str, path)), default=0)
    ent = max((_shannon(x) for x in (qs, body_str) if len(x) > 32), default=0.0)
    specials = sum(payload.count(c) for c in ";|&$`<>(){}\\")

    if seen == 0:
        reasons.append("unknown-path")
    if ent > 5.3 and longest > 48:
        reasons.append("high-entropy-payload")
    if longest > 2000:
        reasons.append("oversized-payload")
    if specials >= 4:
        reasons.append("shell-metachars")
    if decoded != (path + " " + body_str) and len(decoded) > len(path + body_str) + 16:
        reasons.append("deep-encoding")
    if body_str and sum(not ch.isprintable() and ch not in "\r\n\t" for ch in body_str[:512]) > 40:
        reasons.append("binary-in-text")
    if len(headers) > 30:
        reasons.append("header-flood")
    if any(len(str(v)) > 1500 for v in headers.values()):
        reasons.append("oversized-header")

    score = min(sum(_ANOMALY_SCORES.get(r, 0) for r in reasons), 100)
    return score, reasons, (seen == 0)


# ── (C) LLM grey-zone triage — async, never blocks the request path ──────────
_triage_q: "queue.Queue" = queue.Queue(maxsize=300)
_triage_seen: set = set()   # hash of (path,body) already triaged → dedupe


def _triage_enqueue(method, path, headers, body_str, src_ip, anomaly_reasons):
    h = hashlib.md5((path + body_str[:400]).encode()).hexdigest()
    if h in _triage_seen:
        return
    _triage_seen.add(h)
    if len(_triage_seen) > 5000:
        _triage_seen.clear()
    try:
        _triage_q.put_nowait((method, path, headers, body_str, src_ip, anomaly_reasons))
    except queue.Full:
        pass


def _triage_worker():
    while True:
        method, path, headers, body_str, src_ip, reasons = _triage_q.get()
        try:
            _llm_triage(method, path, headers, body_str, src_ip, reasons)
        except Exception:
            pass


def _llm_triage(method, path, headers, body_str, src_ip, reasons):
    if _persona is None:
        return
    ua = headers.get("User-Agent", "") or headers.get("user-agent", "")
    prompt = (
        "You are a web-exploitation analyst. Decide if this HTTP request is an "
        "exploitation attempt. Reply with ONE compact JSON object only: "
        '{"exploit":true|false,"technique":"<short>","cve":"<id or unknown>",'
        '"novel":true|false,"confidence":0-100,"why":"<6 words>"}.\n'
        f"Anomaly hints: {reasons}\n"
        f"{method} {path}\nUser-Agent: {ua}\nBody: {body_str[:800]}\n\nJSON:"
    )
    out = _persona.llm_generate(prompt, num_predict=140)
    if not out:
        return
    m = re.search(r"\{.*\}", out, re.S)
    if not m:
        return
    try:
        verdict = json.loads(m.group(0))
    except Exception:
        return
    if not verdict.get("exploit"):
        return
    ev = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service": "zero-day-llm", "src_ip": src_ip,
        "lure": "llm-0day-verdict", "method": method, "path": path[:200],
        "technique": ("LLM:" + str(verdict.get("technique", ""))[:50]),
        "attack_phase": "exploit",
        "llm_technique": str(verdict.get("technique", ""))[:60],
        "llm_cve": str(verdict.get("cve", ""))[:40],
        "llm_novel": bool(verdict.get("novel")),
        "llm_confidence": verdict.get("confidence", 0),
        "llm_why": str(verdict.get("why", ""))[:120],
        "anomaly_reasons": reasons,
        "threat_score": max(60, int(verdict.get("confidence", 0) or 0)),
        "indicators": ["llm-flagged"] + reasons,
        "novel": bool(verdict.get("novel")),
    }
    try:
        with open(_EVENTS, "a") as f:
            f.write(json.dumps(ev) + "\n")
    except OSError:
        pass
    print(f"[zero-day-llm] {src_ip} EXPLOIT={verdict.get('technique')} "
          f"novel={verdict.get('novel')} conf={verdict.get('confidence')} "
          f"cve={verdict.get('cve')} :: {path[:60]}", flush=True)


if _persona is not None:
    threading.Thread(target=_triage_worker, daemon=True).start()

# ------------------------------------------------------------------
# Canary tokens injected into high-value bait responses.
# Real attackers exfil these → external alerting (future use).
# ------------------------------------------------------------------
CANARY_AWS_KEY   = "AKIAIOSFODNN7EXAMPLE"  # known safe example key
CANARY_AWS_SEC   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
CANARY_DB_URL    = "postgresql://app:Pr0d_DB_2024!@10.0.0.20:5432/prod"
CANARY_JWT       = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJTVVBFUkFETUlOIn0"
                    ".CANARY_SIG_0000000000000")

# ------------------------------------------------------------------
# Per-IP attack phase tracker (in-memory, resets on restart).
# Phases: recon → probe → exploit → post-exploit
# ------------------------------------------------------------------
_PHASE_ORDER = ["recon", "probe", "exploit", "post-exploit"]
_ip_state: dict = defaultdict(lambda: {
    "phase": "recon",
    "score": 0,
    "techniques": [],
    "first_seen": time.time(),
    "last_seen": time.time(),
    "hits": 0,
})

# ------------------------------------------------------------------
# Regexes — compiled once
# ------------------------------------------------------------------

# Path traversal
_TRAV_DOT  = re.compile(r"(\.\.[\\/]){2,}")
_TRAV_ENC  = re.compile(r"(%2e%2e|%252e|%%32%65|\.\.%2f|%2e%2e%2f)", re.I)
_NULL_BYTE  = re.compile(r"%00|\\x00|\x00")

# Template injection
_TMPL_JINJA    = re.compile(r"\{\{.*?\}\}|\{%.*?%\}")
_TMPL_FTL      = re.compile(r"<#|<@|freemarker|velocity|#set\s*\(", re.I)
_TMPL_OGNL     = re.compile(r"\$\{ognl:|%\{.*?\}|\$\{.*?\.class", re.I)
_TMPL_EL       = re.compile(r"\$\{.*?\}|#\{.*?\}")
_TMPL_TWIG     = re.compile(r"\{\{.*?\}\}|\{%.*?%\}")
_TMPL_MVEL     = re.compile(r"import\s+java\.|new\s+java\.", re.I)

# Command injection — Unix + Windows + PHP
_CMD_UNIX  = re.compile(r"(;|\||`|\$\()\s*(bash|sh|nc|curl|wget|python|perl|ruby|php)\b", re.I)
_CMD_WIN   = re.compile(r"(cmd\.exe|powershell|wscript|cscript|mshta|certutil|bitsadmin)", re.I)
_CMD_PHP   = re.compile(r"(system|passthru|shell_exec|exec|popen|proc_open)\s*\(", re.I)
_CMD_JAVA  = re.compile(r"(Runtime\.getRuntime|ProcessBuilder|Runtime\.exec)\s*[\.(]", re.I)

# Deserialization
_DESER_JAVA   = re.compile(r"rO0AB[XY]")                          # Java serialized
_DESER_PHP    = re.compile(r"O:\d+:\"[A-Za-z]")                   # PHP serialize
_DESER_NET    = re.compile(r"AAEAAAD|BinaryFormatter")            # .NET
_DESER_GADGET = re.compile(r"ysoserial|CommonsCollections|URLDNS", re.I)

# SSRF
_SSRF_META = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|"
    r"metadata\.aws|instance-data|imds\.amazonaws\.com|"
    r"100\.100\.100\.200", re.I)
_SSRF_PRIV = re.compile(r"@10\.|@192\.168\.|@172\.(1[6-9]|2\d|3[01])\.|@127\.", re.I)

# XXE
_XXE = re.compile(r"<!ENTITY\s+\S+\s+SYSTEM|SYSTEM\s+['\"]file://|"
                  r"<!DOCTYPE\s+\w+\s*\[", re.I)

# RCE verification (attacker checks if RCE succeeded)
_RCE_VERIFY_MD5   = re.compile(r"md5\s*\(\s*['\"][^'\"]{4,40}['\"]", re.I)
_RCE_VERIFY_ECHO  = re.compile(r"echo\s+['\"]?[A-Za-z0-9]{8,40}['\"]?")
_RCE_VERIFY_NONCE = re.compile(r"\b[0-9a-f]{32}\b")               # pre-computed md5

# SQL injection
_SQLI = re.compile(
    r"(\bUNION\b.*\bSELECT\b|\bOR\b\s+[\'\"]?\d+=[\'\"]?\d+|"
    r"--\s*$|;\s*DROP\s+TABLE|\bXP_CMDSHELL\b|1=1--)", re.I)

# JNDI / Log4Shell (in any field)
_LOG4J = re.compile(r"\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|nis)s?://", re.I)

# XSS (light — mainly to detect script injection probes)
_XSS = re.compile(r"<script|javascript:|on(load|error|click|mouse)\s*=", re.I)

# Known malware tools
_TOOLS = {
    "androxgh0st":  ("androxgh0st", "credential-scraper", 70),
    "masscan":      ("masscan",     "port-scanner",        30),
    "zgrab":        ("zgrab",       "port-scanner",        30),
    "nuclei":       ("nuclei",      "vuln-scanner",        40),
    "sqlmap":       ("sqlmap",      "sqli-tool",           60),
    "acunetix":     ("acunetix",    "web-scanner",         35),
    "nikto":        ("nikto",       "web-scanner",         35),
    "dirsearch":    ("dirsearch",   "dir-bruteforce",      30),
    "gobuster":     ("gobuster",    "dir-bruteforce",      30),
    "hydra":        ("hydra",       "brute-force",         50),
    "metasploit":   ("metasploit",  "exploit-framework",   80),
    "cobalt strike":("cobalt",      "c2-framework",        90),
    "sliver":       ("sliver",      "c2-framework",        90),
    "havoc":        ("havoc",       "c2-framework",        90),
    "beef":         ("beef",        "browser-exploit",     75),
}

# Webshell one-liners
_WEBSHELL = re.compile(
    r"(eval\s*\(\s*base64_decode|eval\s*\(\s*gzinflate|"
    r"assert\s*\(\s*\$_|preg_replace.*\/e\s*[\',\"]|"
    r"create_function\s*\(|move_uploaded_file|"
    r"\$_REQUEST\s*\[|@shell_exec)", re.I)

# Double URL encoding
_DOUBLE_ENC = re.compile(r"%25[0-9a-fA-F]{2}|%%[0-9a-fA-F]{2}")

# Byte-range magic for known file types in upload bodies
_MAGIC = {
    b"\x4d\x5a":       "pe-exe",
    b"\x7fELF":        "elf-binary",
    b"PK\x03\x04":     "zip-archive",
    b"\xca\xfe\xba\xbe": "java-class",
    b"<?php":          "php-webshell",
    b"#!/":            "shell-script",
    b"\xac\xed\x00\x05": "java-serialized",
}


def _score_indicators(indicators: list) -> int:
    scores = {
        "path-traversal": 45, "double-encoding": 50, "null-byte": 55,
        "template-injection": 75, "cmd-injection": 80, "cmd-windows": 70,
        "cmd-php": 75, "cmd-java": 70,
        "deser-java": 85, "deser-php": 75, "deser-dotnet": 70, "deser-gadget": 90,
        "ssrf-metadata": 80, "ssrf-private-ip": 65,
        "xxe": 80,
        "rce-verify": 95,
        "sqli": 65,
        "log4shell": 95,
        "xss": 35,
        "webshell-code": 80,
        "credential-scraper": 70,
        "vuln-scanner": 35,
        "port-scanner": 30,
        "dir-bruteforce": 30,
        "sqli-tool": 60,
        "brute-force": 50,
        "exploit-framework": 80,
        "c2-framework": 90,
        "browser-exploit": 75,
        "malicious-upload": 85,
    }
    return max((scores.get(i, 0) for i in indicators), default=0)


def _phase_from_score(score: int) -> str:
    if score >= 80:
        return "post-exploit"
    if score >= 55:
        return "exploit"
    if score >= 35:
        return "probe"
    return "recon"


def analyze(method: str, path: str, headers: dict, body: bytes,
            src_ip: str) -> dict:
    """
    Returns a dict with threat intelligence fields.

    Fields:
      threat_score   int 0-100
      indicators     list[str]   — technique labels
      technique      str         — primary technique or ""
      attack_phase   str         — recon|probe|exploit|post-exploit
      is_rce_verify  bool        — attacker checking if RCE succeeded
      novel          bool        — not a known CVE lure path
      canary         str|None    — canary token to embed in response
      tool           str|None    — detected tool name
      upload_magic   str|None    — magic bytes type of body
    """
    indicators: list[str] = []
    is_rce_verify = False
    tool_name = None
    upload_magic = None

    # concatenate everything into one blob for regex scanning
    path_str  = path or ""
    body_str  = (body or b"").decode("utf-8", "replace") if body else ""
    ua        = headers.get("User-Agent", "") or headers.get("user-agent", "") or ""
    all_hdrs  = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    # (A) recursively decode nested encodings so the regexes see the real payload
    decoded   = _deep_decode(path_str, body_str)
    blob      = f"{decoded} {all_hdrs}"

    # --- Path traversal ---
    if _TRAV_DOT.search(path_str) or _TRAV_DOT.search(body_str):
        indicators.append("path-traversal")
    if _TRAV_ENC.search(path_str) or _TRAV_ENC.search(body_str):
        indicators.append("path-traversal")
        indicators.append("double-encoding")
    if _DOUBLE_ENC.search(path_str):
        indicators.append("double-encoding")
    if _NULL_BYTE.search(path_str):
        indicators.append("null-byte")

    # --- Template injection ---
    if _TMPL_JINJA.search(blob) or _TMPL_EL.search(blob):
        indicators.append("template-injection")
    if _TMPL_FTL.search(blob) or _TMPL_OGNL.search(blob):
        indicators.append("template-injection")
    if _TMPL_MVEL.search(blob):
        indicators.append("template-injection")

    # --- Command injection ---
    if _CMD_UNIX.search(blob):
        indicators.append("cmd-injection")
    if _CMD_WIN.search(blob):
        indicators.append("cmd-windows")
    if _CMD_PHP.search(blob):
        indicators.append("cmd-php")
    if _CMD_JAVA.search(blob):
        indicators.append("cmd-java")

    # --- Deserialization ---
    if body and _DESER_JAVA.search(body_str):
        indicators.append("deser-java")
    if _DESER_PHP.search(body_str):
        indicators.append("deser-php")
    if _DESER_NET.search(blob):
        indicators.append("deser-dotnet")
    if _DESER_GADGET.search(blob):
        indicators.append("deser-gadget")

    # --- SSRF ---
    if _SSRF_META.search(blob):
        indicators.append("ssrf-metadata")
    if _SSRF_PRIV.search(blob):
        indicators.append("ssrf-private-ip")

    # --- XXE ---
    if _XXE.search(blob):
        indicators.append("xxe")

    # --- Log4Shell (anywhere including headers) ---
    if _LOG4J.search(blob):
        indicators.append("log4shell")

    # --- SQL injection ---
    if _SQLI.search(blob):
        indicators.append("sqli")

    # --- XSS ---
    if _XSS.search(blob):
        indicators.append("xss")

    # --- Webshell code in body ---
    if _WEBSHELL.search(body_str):
        indicators.append("webshell-code")

    # --- RCE verify (highest priority) ---
    if _RCE_VERIFY_MD5.search(blob) or _RCE_VERIFY_ECHO.search(body_str):
        is_rce_verify = True
        indicators.append("rce-verify")

    # --- Known tools (UA + body) ---
    combined_lower = (ua + " " + body_str).lower()
    for keyword, (short, cat, _) in _TOOLS.items():
        if keyword in combined_lower:
            indicators.append(cat)
            tool_name = short
            break

    # --- Upload magic bytes ---
    if body and len(body) >= 4:
        for magic, label in _MAGIC.items():
            if body.startswith(magic):
                upload_magic = label
                if label in ("php-webshell", "java-serialized", "java-class"):
                    indicators.append("malicious-upload")
                elif label in ("pe-exe", "elf-binary"):
                    indicators.append("malicious-upload")
                break

    # Deduplicate
    seen = set()
    unique_indicators = [x for x in indicators if not (x in seen or seen.add(x))]

    sig_score = _score_indicators(unique_indicators)
    if is_rce_verify:
        sig_score = max(sig_score, 95)

    # (B) structural anomaly — novelty without a signature
    anomaly_score, anomaly_reasons, unknown_path = _anomaly(
        path_str, headers or {}, body_str, decoded)
    # Anomaly contributes to the threat score (so a never-seen weird payload
    # still surfaces even if no regex matched).
    score = max(sig_score, anomaly_score)
    for r in anomaly_reasons:
        if r not in unique_indicators:
            unique_indicators.append(r)

    # (C) grey zone: looks anomalous but signatures are weak → ask the LLM.
    if _persona is not None and anomaly_score >= 40 and sig_score < 55 and method:
        _triage_enqueue(method, path_str, headers or {}, body_str, src_ip, anomaly_reasons)

    phase = _phase_from_score(score)

    # --- Update IP state ---
    state = _ip_state[src_ip]
    state["last_seen"] = time.time()
    state["hits"] += 1
    state["score"] = max(state["score"], score)
    for ind in unique_indicators:
        if ind not in state["techniques"]:
            state["techniques"].append(ind)
    # Only advance phase, never retreat
    cur_idx = _PHASE_ORDER.index(state["phase"])
    new_idx = _PHASE_ORDER.index(phase)
    if new_idx > cur_idx:
        state["phase"] = phase

    # Primary technique label
    priority = [
        "log4shell", "rce-verify", "deser-gadget", "deser-java", "c2-framework",
        "exploit-framework", "webshell-code", "malicious-upload", "cmd-injection",
        "ssrf-metadata", "xxe", "template-injection", "deser-php", "deser-dotnet",
        "credential-scraper", "brute-force", "sqli-tool",
        "double-encoding", "path-traversal", "sqli", "xss",
    ]
    technique = next((t for t in priority if t in unique_indicators), "")

    # Canary: inject into high-score responses (score >= 70)
    canary = None
    if score >= 70:
        canary = CANARY_AWS_KEY

    return {
        "threat_score":  score,
        "indicators":    unique_indicators,
        "technique":     technique,
        "attack_phase":  state["phase"],
        "is_rce_verify": is_rce_verify,
        # (D) real novelty: a never-before-seen path carrying either an exploit
        # primitive or anomalous structure, from no known scanner tool.
        "novel":         unknown_path and tool_name is None and
                         (technique != "" or anomaly_score >= 40),
        "anomaly_score": anomaly_score,
        "anomaly_reasons": anomaly_reasons,
        "canary":        canary,
        "tool":          tool_name,
        "upload_magic":  upload_magic,
    }


def get_ip_state(ip: str) -> dict:
    """Return the accumulated state for an IP (for dashboard queries)."""
    s = _ip_state.get(ip)
    if s is None:
        return {}
    return {
        "ip": ip,
        "phase": s["phase"],
        "score": s["score"],
        "techniques": s["techniques"],
        "hits": s["hits"],
        "first_seen": s["first_seen"],
        "last_seen": s["last_seen"],
    }


def all_threat_ips() -> list:
    """Return all IPs with score > 40, sorted by score desc."""
    result = []
    for ip, s in _ip_state.items():
        if s["score"] > 40:
            result.append({
                "ip": ip,
                "phase": s["phase"],
                "score": s["score"],
                "techniques": s["techniques"],
                "hits": s["hits"],
            })
    result.sort(key=lambda x: x["score"], reverse=True)
    return result
