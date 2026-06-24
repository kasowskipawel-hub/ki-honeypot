"""AI Strategist — Mistral-driven per-session deception strategy.

Watches each attacker session, forms a hypothesis about what the bot is and
what it wants, and picks a TACTIC that maximises intelligence extraction
(reveal the C2, draw the next loader stage, keep it talking). It steers OUR
responses — it never touches, mutates or executes attacker code. Pure deception.

Design constraints that shape everything here:
  * LATENCY — live sockets (Redis/SSH/HTTP) must answer fast. So modules call
    note() synchronously (cheap, returns instantly); the LLM runs in a
    background worker; modules read the cached tactic via stance() on the NEXT
    interaction. First touch is always deterministic; steering kicks in once a
    tactic is ready. Deterministic fallback is ALWAYS available.
  * QUOTA — thousands of commodity scans would burn the free tier. Only
    "interesting" sessions (RCE vectors, unhandled commands, exploit attempts,
    uploads) ever trigger an LLM call, and at most once per session unless the
    behaviour materially changes.
  * SAFETY — a tactic is a STANCE + optional suggested fake response text. It is
    sanity-checked (valid enum, length-capped) before use. Garbage is dropped
    and the module falls back to its built-in lure.

Everything the strategist decides is written to the strategy journal
(/data/ai_strategy.jsonl) so the operator can see WHAT it did and WHY.
"""
import hashlib
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

try:
    import groq_client as _llm
except Exception:
    _llm = None

JOURNAL   = os.environ.get("AI_STRATEGY_LOG", "/data/ai_strategy.jsonl")
ENABLE    = os.environ.get("AI_STRATEGIST", "1") == "1"
ACTIVE    = os.environ.get("AI_STRATEGIST_ACTIVE", "1") == "1"   # 0 = shadow (log only)
TTL       = int(os.environ.get("AI_STRATEGIST_TTL", "1800"))    # session state lifetime
MAX_SESS  = 3000

# Valid stances the modules know how to apply. Anything else is rejected.
STANCES = {
    "engage",      # play along maximally, ack "successes" to draw the next stage
    "mimic_vuln",  # look freshly exploitable to elicit the exploit/payload
    "probe",       # return leading errors/prompts that make the bot reveal more
    "tarpit",      # slow/stall to keep a noisy bot busy and harvest more
    "default",     # no steering — use the module's built-in lure
}

_lock     = threading.Lock()
_sessions: dict = {}          # sid -> session record
_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="strategist")
_jlock = threading.Lock()

# ── Playbook: the LEARNED memory ─────────────────────────────────────────────
# fingerprint(attack-pattern) -> {tactic, hits, first, last}. Persisted to disk.
# A cache hit means an identical / near-identical case was already solved by the
# LLM once → we reuse that tactic instantly and spend ZERO tokens.
PLAYBOOK_FILE = os.environ.get("AI_PLAYBOOK", "/data/ai_playbook.json")
_PLAYBOOK_MAX = 5000
_pb_lock = threading.Lock()
try:
    with open(PLAYBOOK_FILE, "r", encoding="utf-8") as _f:
        _PLAYBOOK = json.load(_f)
except Exception:
    _PLAYBOOK = {}


def _pb_save():
    try:
        with _pb_lock:
            tmp = PLAYBOOK_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(_PLAYBOOK, f)
            os.replace(tmp, PLAYBOOK_FILE)
    except Exception:
        pass


def _norm(text: str) -> str:
    """Normalise one observation so that near-identical cases collapse to the
    same token: strip IPs, hashes, ports and numbers — keep the structure."""
    t = str(text).lower()
    t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP", t)   # ipv4
    t = re.sub(r"[0-9a-f]{6,}", "HEX", t)                 # hashes/tokens
    t = re.sub(r"\d+", "N", t)                            # any number/port
    t = re.sub(r"[\"'`]", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:80]


def _fingerprint(rec: dict) -> str:
    """Stable fingerprint of an attack pattern (module + normalised behaviour).
    Identical or near-identical sessions produce the same fingerprint."""
    toks = sorted({_norm(o.get("text", "")) for o in rec["obs"] if o.get("text")})
    raw = rec.get("module", "?") + "|" + "|".join(toks)
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


def available() -> bool:
    return bool(ENABLE and _llm and _llm.available())


def playbook_stats() -> dict:
    with _pb_lock:
        total_hits = sum(v.get("hits", 0) for v in _PLAYBOOK.values())
        return {"patterns": len(_PLAYBOOK), "reuses": total_hits}


# ── interest gating ──────────────────────────────────────────────────────────
_RCE_MARKERS = ("config set", "slaveof", "replicaof", "module load", "function load",
                "eval", "system.exec", "/dev/tcp", "wget", "curl", "chmod", "base64",
                "powershell", "certutil", "/bin/sh", "cron", "exp.so", "iex")


def _interesting(rec: dict) -> bool:
    """Only spend an LLM call on sessions that look like real attacks."""
    blob = " ".join(str(o.get("text", "")) for o in rec["obs"]).lower()
    if any(m in blob for m in _RCE_MARKERS):
        return True
    # any module may flag a session as interesting via unhandled=True
    # (http: unclassified request; stratum: mining login; smb: captured creds; …)
    if rec.get("unhandled"):
        return True
    if rec.get("uploads"):
        return True
    # several distinct commands in one session ⇒ interactive, worth a look
    if len({o.get("text", "") for o in rec["obs"]}) >= 4:
        return True
    return False


def _journal(entry: dict):
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        with _jlock:
            with open(JOURNAL, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _prune():
    if len(_sessions) <= MAX_SESS:
        return
    now = time.time()
    for sid in [s for s, r in _sessions.items() if now - r["last"] > TTL]:
        _sessions.pop(sid, None)


# ── public API ───────────────────────────────────────────────────────────────
def note(session_id: str, module: str, text: str, src_ip: str = "",
         unhandled: bool = False, upload: bool = False):
    """Record one observation for a session (cheap, returns immediately).
    Kicks off an async strategy computation when the session turns interesting."""
    if not ENABLE or not session_id:
        return
    now = time.time()
    with _lock:
        rec = _sessions.get(session_id)
        if rec is None:
            rec = {"module": module, "src_ip": src_ip, "obs": [], "tactic": None,
                   "first": now, "last": now, "inflight": False, "decided_n": 0,
                   "uploads": False, "unhandled": False}
            _sessions[session_id] = rec
            _prune()
        rec["last"] = now
        rec["module"] = module or rec["module"]
        if src_ip:
            rec["src_ip"] = src_ip
        if upload:
            rec["uploads"] = True
        if unhandled:
            rec["unhandled"] = True
        if text:
            rec["obs"].append({"text": str(text)[:300], "t": now})
            rec["obs"] = rec["obs"][-30:]
        # decide whether to (re)compute a tactic
        n = len(rec["obs"])
        interesting = _interesting(rec)
        fresh = n > rec["decided_n"]      # new activity since last decision
        if not (interesting and fresh and not rec["inflight"]):
            return
        # ── LEARNED PATH: is this attack pattern already in the playbook? ──
        # If yes, reuse the stored tactic instantly — ZERO tokens, no LLM call.
        fp = _fingerprint(rec)
        with _pb_lock:
            entry = _PLAYBOOK.get(fp)
        if entry:
            rec["tactic"] = dict(entry["tactic"])
            rec["decided_n"] = n
            with _pb_lock:
                entry["hits"] = entry.get("hits", 0) + 1
                entry["last"] = now
            _journal({"event": "reused", "session": session_id, "module": rec["module"],
                      "src_ip": rec.get("src_ip", ""), "fingerprint": fp,
                      "stance": entry["tactic"].get("stance", ""),
                      "hits": entry["hits"],
                      "hypothesis": entry["tactic"].get("hypothesis", "")})
            # persist the bumped hit-count occasionally (every 10th reuse)
            if entry["hits"] % 10 == 0:
                _POOL.submit(_pb_save)
            return
        # ── MISS: spend one LLM call, then LEARN the result ──
        if available():
            rec["inflight"] = True
            rec["decided_n"] = n
            _POOL.submit(_compute, session_id, fp)


def stance(session_id: str) -> dict | None:
    """Return the current active tactic for a session, or None (→ deterministic
    fallback). In shadow mode (ACTIVE=0) always returns None so live behaviour is
    unchanged while the journal still records what the strategist WOULD do."""
    if not ENABLE or not ACTIVE or not session_id:
        return None
    with _lock:
        rec = _sessions.get(session_id)
        if not rec or not rec.get("tactic"):
            return None
        t = rec["tactic"]
        if t.get("stance") in STANCES and t.get("stance") != "default":
            return t
    return None


def record_outcome(session_id: str, outcome: str):
    """Modules call this when steering paid off (next stage / C2 / payload)."""
    if not session_id:
        return
    with _lock:
        rec = _sessions.get(session_id)
        tac = rec.get("tactic") if rec else None
    _journal({"event": "outcome", "session": session_id,
              "outcome": outcome, "tactic": tac})


# ── the brain (async) ────────────────────────────────────────────────────────
_PROMPT = (
    "Du bist der Täuschungs-Stratege eines Honeypots. Ziel: aus dem Angreifer "
    "MEHR Intelligence herausholen (C2 enthüllen, nächste Loader-Stufe / Payload "
    "provozieren, ihn am Reden halten). Du steuerst NUR unsere Antworten — niemals "
    "Angreifer-Code ausführen/verändern.\n"
    "Gegeben Modul + bisherige Angreifer-Aktivität, antworte AUSSCHLIESSLICH als JSON:\n"
    '{"hypothesis": "was ist das für ein Bot/Angriff (deutsch, knapp)", '
    '"family": "vermutete Malware-/Tool-Familie oder leer", '
    '"goal": "was der Angreifer als nächstes will", '
    '"stance": "einer von: engage|mimic_vuln|probe|tarpit|default", '
    '"reasoning": "1 Satz warum diese Taktik mehr Intel bringt", '
    '"suggestion": "optional: konkreter Fake-Antwort-TEXT den wir zurückgeben sollen, '
    'um die nächste Stufe zu provozieren (nur Plaintext, kein Markdown), sonst leer", '
    '"confidence": "high|medium|low"}\n'
    "Stance-Bedeutung: engage=alles als Erfolg bestätigen damit er weitermacht; "
    "mimic_vuln=verwundbar wirken um Exploit/Payload zu locken; probe=führende "
    "Fehler/Prompts die ihn mehr preisgeben lassen; tarpit=hinhalten; default=nicht eingreifen."
)


def _compute(session_id: str, fingerprint: str = ""):
    try:
        with _lock:
            rec = _sessions.get(session_id)
            if not rec:
                return
            module = rec["module"]
            src_ip = rec.get("src_ip", "")
            obs = [o["text"] for o in rec["obs"]][-20:]
        user = f"Modul: {module}\nAngreifer-Aktivität (chronologisch):\n" + \
               "\n".join(f"  - {o}" for o in obs)
        out = _llm.chat(
            [{"role": "system", "content": _PROMPT},
             {"role": "user", "content": user}],
            max_tokens=350, temperature=0.2, timeout=25,
        )
        tactic = _parse(out)
        with _lock:
            rec = _sessions.get(session_id)
            if rec is not None:
                rec["tactic"] = tactic
                rec["inflight"] = False
        # ── LEARN: store this freshly computed tactic in the playbook so the
        # next identical/near-identical case is answered for free ──
        if tactic and fingerprint:
            now = time.time()
            with _pb_lock:
                if len(_PLAYBOOK) >= _PLAYBOOK_MAX:
                    # evict least-recently-used
                    old = min(_PLAYBOOK, key=lambda k: _PLAYBOOK[k].get("last", 0))
                    _PLAYBOOK.pop(old, None)
                _PLAYBOOK[fingerprint] = {"tactic": tactic, "hits": 0,
                                          "first": now, "last": now,
                                          "module": module}
            _POOL.submit(_pb_save)
        if tactic:
            _journal({"event": "decision", "session": session_id, "module": module,
                      "src_ip": src_ip, "observed": obs[-6:],
                      "hypothesis": tactic.get("hypothesis", ""),
                      "family": tactic.get("family", ""),
                      "goal": tactic.get("goal", ""),
                      "stance": tactic.get("stance", "default"),
                      "reasoning": tactic.get("reasoning", ""),
                      "suggestion": (tactic.get("suggestion", "") or "")[:200],
                      "confidence": tactic.get("confidence", ""),
                      "active": ACTIVE})
    except Exception as e:
        with _lock:
            rec = _sessions.get(session_id)
            if rec is not None:
                rec["inflight"] = False
        print(f"[strategist] compute error: {e}", flush=True)


def _parse(text: str) -> dict | None:
    if not text:
        return None
    import re
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except Exception:
        return None
    st = str(d.get("stance", "default")).strip().lower()
    if st not in STANCES:
        st = "default"
    d["stance"] = st
    # sanity: cap suggestion length, must be plain text
    sug = str(d.get("suggestion", "") or "")[:1500]
    d["suggestion"] = sug
    return d
