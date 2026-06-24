"""Adaptive personas + LLM-backed live shell for the SSH honeypot.

Three capabilities in one module:
  * PERSONA  — pick a believable host identity based on what the bot hunts for
               (GPU miner rig vs. corporate secrets server …).
  * FAKE-FS  — a small, deterministic seeded file tree per persona so ls/cat/cd
               stay self-consistent across a session.
  * LLM SHELL— when a command isn't handled deterministically, ask a small local
               model (ollama on 127.0.0.1) for a plausible Linux response instead
               of leaking `command not found`. Cached; degrades gracefully.

Nothing here ever executes attacker input — the LLM only generates text.
"""
import json
import os
import re
import threading
import time
import urllib.request

OLLAMA_URL   = os.environ.get("OLLAMA_URL",   "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:1.5b")
LLM_ENABLED  = os.environ.get("LLM_SHELL",   "1") == "1"
LLM_TIMEOUT  = float(os.environ.get("LLM_TIMEOUT",   "25"))
LLM_KEEPALIVE = os.environ.get("LLM_KEEPALIVE", "30m")

try:
    import groq_client as _groq
except Exception:
    _groq = None

# ── Personas ────────────────────────────────────────────────────────────────
# Each persona supplies the host identity + a seeded file tree + an LLM brief.
PERSONAS = {
    "gpu-miner": {
        "host": "gpu-node-07",
        "user": "root",
        "home": "/root",
        "uid": 0,
        "fs": {
            "/root": ["xmrig", "srbminer", "scripts", "share", "config.json",
                      "miner.log", ".env", ".wallet", "wallet.dat", ".ssh"],
            "/opt": ["miner", "cuda", "scripts"],
        },
        "llm_brief": (
            "You are a Linux shell on an Ubuntu 22.04 GPU mining server named "
            "gpu-node-07 with 8x NVIDIA A100 GPUs, 256 CPUs, running xmrig. The "
            "user is root in /root."
        ),
    },
    "corp-secrets": {
        "host": "app-prod-01",
        "user": "deploy",
        "home": "/home/deploy",
        "uid": 1000,
        "fs": {
            "/home/deploy": ["app", ".env", ".env.production", ".git",
                             "docker-compose.yml", "terraform.tfstate", ".aws"],
            "/opt": ["app", "backups"],
            "/var/www": ["html", "api"],
        },
        "llm_brief": (
            "You are a Linux shell on an Ubuntu 22.04 corporate application "
            "server named app-prod-01 hosting a production web app. The user is "
            "'deploy' in /home/deploy. There are .env, terraform and git files."
        ),
    },
    "crypto-validator": {
        "host": "solana-val-03",
        "user": "sol",
        "home": "/home/sol",
        "uid": 1001,
        "fs": {
            "/home/sol": [
                "validator-keypair.json", "vote-account-keypair.json",
                "ledger", "mev-boost", ".config", ".env", "start-validator.sh",
                "monitoring", "snapshots", ".ssh",
            ],
            "/home/sol/.config": ["solana"],
            "/home/sol/.config/solana": ["id.json", "cli", "keypairs"],
            "/opt": ["solana", "jito-solana", "mev-boost", "scripts"],
            "/var/log": ["solana", "mev-boost"],
        },
        "llm_brief": (
            "You are a Linux shell on an Ubuntu 22.04 Solana validator node named "
            "solana-val-03 with a 40-core AMD EPYC CPU, 256 GB RAM and 1 TB NVMe. "
            "Running Jito-Solana with MEV boost. The user is 'sol' in /home/sol. "
            "There are keypair JSON files, a ledger directory, and MEV bot configs. "
            "Current vote account balance is 847.3 SOL. "
            "Validator identity: solana-val-03.validator.network"
        ),
    },
}
DEFAULT_PERSONA = "gpu-miner"

# Signals that the bot is hunting infrastructure secrets → corp-secrets persona.
_SECRET_HINTS = re.compile(
    r"\.env|terraform|tfstate|\.git|docker-compose|aws|credential|secret|"
    r"\.aws|id_rsa|wp-config|\.npmrc|kubeconfig", re.I)

# Signals that the bot targets crypto validator/trading infrastructure.
_CRYPTO_HINTS = re.compile(
    r"\bsol\b|solana|validator|vote.account|keypair|mev|jito|"
    r"\btrader?\b|ethereum|geth|besu|prysm|lighthouse|eth2|"
    r"soldocker|solnode|metatrader|binance|crypto.bot", re.I)


_KERNEL = "6.5.0-44-generic"
_UTS = "#55-Ubuntu SMP Mon Jun 10 14:22:11 UTC 2026"


def identity_answer(cmd: str, persona: dict):
    """Answer host/user/home-dependent commands from the persona so identity is
    consistent (hostname/uname/whoami/id/pwd). Returns str or None (→ fall back
    to the generic handlers). For the default gpu-miner this matches the old
    hardcoded values, so nothing changes there."""
    c = cmd.strip()
    host = persona["host"]; user = persona["user"]
    home = persona.get("home", "/root"); uid = persona.get("uid", 0)
    if c == "hostname" or c == "uname -n":
        return host + "\n"
    if c == "whoami":
        return user + "\n"
    if c == "pwd":
        return home + "\n"
    if c == "id":
        if uid == 0:
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return (f"uid={uid}({user}) gid={uid}({user}) "
                f"groups={uid}({user}),27(sudo),100(users)\n")
    if c == "uname -a":
        return f"Linux {host} {_KERNEL} {_UTS} x86_64 x86_64 x86_64 GNU/Linux\n"
    # uname combinations that include the nodename (-n) → rebuild with host
    if c.startswith("uname") and re.search(r"(?<![\w-])-\w*n", c):
        parts = []
        if "s" in c: parts.append("Linux")
        if "v" in c: parts.append(_UTS)
        if "n" in c: parts.append(host)
        if "r" in c: parts.append(_KERNEL)
        if "m" in c: parts.append("x86_64")
        return " ".join(parts) + "\n"
    # Home-dir listing — only for non-default personas (gpu-miner keeps its rich
    # static listing). Lets corp-secrets show .env/terraform/git instead of xmrig.
    if host != "gpu-node-07" and (c == "ls" or c.startswith("ls ")):
        files = persona.get("fs", {}).get(home, [])
        if c in ("ls", "ls -a", "ls -1", "ls --color"):
            return "  ".join(files) + "\n"
        if any(f in c for f in ("-l", "-la", "-al", "-lah", "-a")):
            out = [f"total {len(files) * 4}"]
            for f in files:
                isdir = f in (".ssh", ".aws", ".git", "app", "backups", "html", "api")
                d, perm = ("d", "rwxr-xr-x") if isdir else ("-", "rw-r--r--")
                out.append(f"{d}{perm} 1 {user} {user} 4096 Jun 22 03:42 {f}")
            return "\n".join(out) + "\n"
    return None


def pick_persona(sess: dict) -> dict:
    """Choose a persona from the session's behaviour. Sticky once chosen."""
    if sess is None:
        return PERSONAS[DEFAULT_PERSONA]
    if sess.get("_persona"):
        return sess["_persona"]
    blob = " ".join(str(c) for c in sess.get("commands", []) + sess.get("creds", []))
    if _CRYPTO_HINTS.search(blob):
        name = "crypto-validator"
    elif _SECRET_HINTS.search(blob):
        name = "corp-secrets"
    else:
        name = DEFAULT_PERSONA
    sess["_persona"] = PERSONAS[name]
    sess["_persona_name"] = name
    return sess["_persona"]


# ── LLM client (ollama) ──────────────────────────────────────────────────────
_LLM_OK = None            # tri-state: None=unknown, True/False=probed
_LLM_LOCK = threading.Lock()
_CACHE: dict = {}         # "persona\x00cmd" -> response (PERSISTENT)
_CACHE_MAX = 2000

# Persist fake-shell LLM answers to disk so identical commands cost ZERO tokens
# even across container restarts (same principle as the analyst/strategist caches).
_CACHE_FILE = os.environ.get("PERSONA_CACHE", "/data/persona_cache.json")
_cache_last_save = 0.0

try:
    with open(_CACHE_FILE, encoding="utf-8") as _f:
        _CACHE.update(json.load(_f))
except Exception:
    pass


def _cache_save(force: bool = False):
    global _cache_last_save
    now = time.time()
    if not force and (now - _cache_last_save) < 20.0:
        return
    _cache_last_save = now
    try:
        with _LLM_LOCK:
            snap = dict(_CACHE)
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False)
        os.replace(tmp, _CACHE_FILE)
    except Exception:
        pass


def _cache_flush_loop():
    while True:
        time.sleep(30)
        _cache_save(force=True)


threading.Thread(target=_cache_flush_loop, daemon=True).start()


def _llm_available() -> bool:
    global _LLM_OK
    if _LLM_OK is not None:
        return _LLM_OK
    try:
        req = urllib.request.Request(OLLAMA_URL + "/api/tags")
        with urllib.request.urlopen(req, timeout=3) as r:
            tags = json.load(r)
        names = [m.get("name", "") for m in tags.get("models", [])]
        _LLM_OK = any(OLLAMA_MODEL.split(":")[0] in n for n in names)
    except Exception:
        _LLM_OK = False
    return _LLM_OK


# Commands whose output depends on the current time → never cache (always fresh).
_TIME_SENSITIVE = re.compile(
    r"^\s*(date|uptime|w|who|last|top|free|vmstat|timedatectl|hwclock|cal|"
    r"cat\s+/proc/uptime|cat\s+/proc/stat)\b", re.I)


def llm_answer(cmd: str, persona: dict, history=None) -> str | None:
    """Return a plausible shell output for `cmd`. Mistral primary, Ollama fallback.
    Cached persistently (same cmd → 0 tokens), except time-sensitive commands.
    The CURRENT date/time is always passed so date/uptime/log timestamps are real."""
    if not LLM_ENABLED:
        return None
    pname = persona.get("host", "?")
    cmd_s = cmd.strip()
    time_sensitive = bool(_TIME_SENSITIVE.match(cmd_s))
    key = f"{pname}\x00{cmd_s[:120]}"
    if not time_sensitive:
        with _LLM_LOCK:
            if key in _CACHE:
                return _CACHE[key]
    # Always give the model the real current date/time (UTC) for realism.
    now_utc = time.strftime("%a %b %d %H:%M:%S UTC %Y", time.gmtime())
    ctx = ""
    if history:
        ctx = "\nRecent commands:\n" + "\n".join(history[-4:])
    system = (
        f"{persona['llm_brief']}\n"
        f"The current system date/time is: {now_utc} (timezone UTC). Use it for any "
        "date, time, uptime, log-timestamp or scheduling output so it is consistent.\n"
        "You are simulating a REAL Linux shell. Output ONLY the exact raw terminal "
        "output the command would produce on this host — correct format, plausible "
        "values, no explanations, no markdown, no code fences, no prompt. If the "
        "command would error, output the real error text. Be precise and consistent "
        "with previous commands in this session."
    )
    user = f"{ctx}\nCommand: {cmd}\nOutput:"

    # Try Groq first (fast ~0.5s, 70b quality)
    out = ""
    if _groq and _groq.available():
        out = _groq.chat(
            [{"role": "system", "content": system},
             {"role": "user",   "content": user}],
            max_tokens=150, temperature=0.4, timeout=10,
        )
    # Fallback: local Ollama
    if not out and _llm_available():
        body = json.dumps({
            "model": OLLAMA_MODEL, "prompt": system + "\n" + user,
            "stream": False, "keep_alive": LLM_KEEPALIVE,
            "options": {"temperature": 0.4, "num_predict": 120,
                        "stop": ["\nCommand:", "Command:"]},
        }).encode()
        try:
            req = urllib.request.Request(OLLAMA_URL + "/api/generate", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as r:
                out = json.load(r).get("response", "")
        except Exception:
            return None

    out = out.strip("`\n ")
    if out and not out.endswith("\n"):
        out += "\n"
    if not time_sensitive:
        with _LLM_LOCK:
            if len(_CACHE) < _CACHE_MAX:
                _CACHE[key] = out
        if out:
            _cache_save()
    return out or None


def llm_generate(prompt: str, num_predict: int = 200, timeout: float = None) -> str | None:
    """Generic LLM call for triage/analysis. Groq primary, Ollama fallback."""
    # Groq first
    if _groq and _groq.available():
        result = _groq.quick(prompt, max_tokens=num_predict,
                             system="You are a cybersecurity threat analyst.")
        if result:
            return result
    # Ollama fallback
    if not (LLM_ENABLED and _llm_available()):
        return None
    body = json.dumps({
        "model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
        "keep_alive": LLM_KEEPALIVE,
        "options": {"temperature": 0.1, "num_predict": num_predict},
    }).encode()
    try:
        req = urllib.request.Request(OLLAMA_URL + "/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout or LLM_TIMEOUT) as r:
            return json.load(r).get("response", "") or None
    except Exception:
        return None


def _keepalive_loop():
    """Keep the model resident so unknown-command responses stay ~10s, not 25s
    cold. Pings ollama every 4 min (under the keep_alive window)."""
    while True:
        try:
            if LLM_ENABLED:
                body = json.dumps({"model": OLLAMA_MODEL, "prompt": "ok",
                                   "stream": False, "keep_alive": LLM_KEEPALIVE,
                                   "options": {"num_predict": 1}}).encode()
                req = urllib.request.Request(OLLAMA_URL + "/api/generate", data=body,
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=30).read()
        except Exception:
            pass
        time.sleep(240)


if LLM_ENABLED:
    threading.Thread(target=_keepalive_loop, daemon=True).start()
