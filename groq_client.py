"""Unified multi-provider LLM client — stdlib only, zero pip deps.

Single backend for the whole honeypot (briefing, strategist, persona shell,
TTP/zero-day triage, sample analysis). Supports Claude (Anthropic), Mistral,
Groq, Grok (xAI) and Gemini (Google) behind ONE interface.

Configuration is read LIVE from /data/llm_config.json (written by the dashboard
config UI) so changing the provider/key takes effect across all containers
without a restart. Env vars are the fallback. The PROMPTS are provider-agnostic;
only the request/response format differs per provider — handled here.

Public interface (unchanged for all callers):
    chat(messages, max_tokens, temperature, timeout) -> str
    quick(prompt, max_tokens, system) -> str
    available() -> bool
    remaining() -> int
    provider_info() -> dict   (for the dashboard config panel)
"""
import json
import os
import threading
import time
import urllib.request
import urllib.error

_CONFIG_FILE = os.environ.get("LLM_CONFIG", "/data/llm_config.json")

# provider -> endpoint/model/format/auth
PROVIDERS = {
    "mistral": {"url": "https://api.mistral.ai/v1/chat/completions",
                "model": "mistral-small-latest", "fmt": "openai", "label": "Mistral"},
    "groq":    {"url": "https://api.groq.com/openai/v1/chat/completions",
                "model": "llama-3.3-70b-versatile", "fmt": "openai", "label": "Groq"},
    "xai":     {"url": "https://api.x.ai/v1/chat/completions",
                "model": "grok-2-latest", "fmt": "openai", "label": "Grok (xAI)"},
    "claude":  {"url": "https://api.anthropic.com/v1/messages",
                "model": "claude-haiku-4-5-20251001", "fmt": "anthropic", "label": "Claude"},
    "gemini":  {"url": "https://generativelanguage.googleapis.com/v1beta/models",
                "model": "gemini-2.0-flash", "fmt": "gemini", "label": "Gemini"},
}


def detect_provider(key: str) -> str:
    """Guess the provider from the key prefix."""
    k = (key or "").strip()
    if k.startswith("sk-ant-"):
        return "claude"
    if k.startswith("gsk_"):
        return "groq"
    if k.startswith("AIza"):
        return "gemini"
    if k.startswith("xai-"):
        return "xai"
    return "mistral"


# ── live config (file → env fallback) ────────────────────────────────────────
_cfg_lock = threading.Lock()
_cfg = {"mtime": -1.0, "provider": "", "key": "", "model": ""}


def _load_cfg():
    with _cfg_lock:
        try:
            st = os.stat(_CONFIG_FILE)
            if st.st_mtime != _cfg["mtime"]:
                with open(_CONFIG_FILE, encoding="utf-8") as f:
                    d = json.load(f)
                _cfg.update(mtime=st.st_mtime,
                            provider=str(d.get("provider", "")).strip().lower(),
                            key=str(d.get("key", "")).strip(),
                            model=str(d.get("model", "")).strip())
        except Exception:
            pass
        provider, key, model = _cfg["provider"], _cfg["key"], _cfg["model"]
    # env fallback when no config file key
    if not key:
        key = (os.environ.get("MISTRAL_API_KEY")
               or os.environ.get("GROQ_API_KEY") or "").strip()
        provider = provider or os.environ.get("LLM_PROVIDER", "").strip().lower()
    if key and provider not in PROVIDERS:
        provider = detect_provider(key)
    if provider not in PROVIDERS:
        provider = "mistral"
    if not model:
        model = PROVIDERS[provider]["model"]
    return provider, key, model


def set_config(provider: str, key: str, model: str = "") -> dict:
    """Persist a new provider/key/model (called by the dashboard config API)."""
    provider = (provider or "").strip().lower()
    if provider not in PROVIDERS:
        provider = detect_provider(key)
    payload = {"provider": provider, "key": (key or "").strip(),
               "model": (model or "").strip()}
    tmp = _CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, _CONFIG_FILE)
    with _cfg_lock:
        _cfg["mtime"] = -1.0   # force reload on next call
    return provider_info()


def provider_info() -> dict:
    """Status for the dashboard — never returns the raw key."""
    provider, key, model = _load_cfg()
    masked = ""
    if key:
        masked = ("•" * max(0, len(key) - 4)) + key[-4:] if len(key) > 4 else "••••"
    return {
        "provider": provider,
        "model": model,
        "configured": bool(key),
        "key_masked": masked,
        "providers": [{"id": k, "label": v["label"], "default_model": v["model"]}
                      for k, v in PROVIDERS.items()],
    }


# ── daily quota guard (cheap runaway protection) ─────────────────────────────
_DAILY_MAX = int(os.environ.get("LLM_DAILY_MAX", "1200"))
_qlock = threading.Lock()
_count = 0
_day = ""


def _quota() -> bool:
    global _count, _day
    today = time.strftime("%Y-%m-%d", time.gmtime())
    with _qlock:
        if _day != today:
            _day, _count = today, 0
        if _count >= _DAILY_MAX:
            return False
        _count += 1
        return True


def remaining() -> int:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    with _qlock:
        if _day != today:
            return _DAILY_MAX
        return max(0, _DAILY_MAX - _count)


# ── shared cross-container usage counter (so the dashboard shows TOTAL calls) ──
_USAGE_FILE = os.environ.get("LLM_USAGE", "/data/llm_usage.json")
_usage_lock = threading.Lock()


def _bump_usage():
    today = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        with _usage_lock:
            d = {}
            try:
                with open(_USAGE_FILE, encoding="utf-8") as f:
                    d = json.load(f)
            except Exception:
                d = {}
            if d.get("date") != today:
                d = {"date": today, "count": 0, "errors": 0, "last_error": ""}
            d["count"] = d.get("count", 0) + 1
            tmp = _USAGE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, _USAGE_FILE)
    except Exception:
        pass


def _bump_error(msg: str):
    today = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        with _usage_lock:
            d = {}
            try:
                with open(_USAGE_FILE, encoding="utf-8") as f:
                    d = json.load(f)
            except Exception:
                d = {}
            if d.get("date") != today:
                d = {"date": today, "count": 0, "errors": 0, "last_error": ""}
            d["errors"] = d.get("errors", 0) + 1
            d["last_error"] = str(msg)[:120]
            tmp = _USAGE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, _USAGE_FILE)
    except Exception:
        pass


def usage() -> dict:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        with open(_USAGE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if d.get("date") == today:
            used = d.get("count", 0)
            return {"used": used, "remaining": max(0, _DAILY_MAX - used),
                    "errors": d.get("errors", 0),
                    "last_error": d.get("last_error", ""), "date": today,
                    "cap": _DAILY_MAX}
    except Exception:
        pass
    return {"used": 0, "remaining": _DAILY_MAX, "errors": 0, "last_error": "",
            "date": today, "cap": _DAILY_MAX}


def available() -> bool:
    _p, key, _m = _load_cfg()
    return bool(key)


# ── rate-limit backoff ────────────────────────────────────────────────────────
_rl_lock = threading.Lock()
_rate_limited_until = 0.0   # epoch seconds; 0 = not rate-limited


def _check_rate_limit() -> bool:
    """Return True if we're currently in a rate-limit backoff window."""
    with _rl_lock:
        return time.time() < _rate_limited_until


def _set_rate_limit(retry_after: int = 60):
    with _rl_lock:
        global _rate_limited_until
        _rate_limited_until = time.time() + retry_after
    print(f"[llm] rate-limited, backing off {retry_after}s", flush=True)


# ── the call ─────────────────────────────────────────────────────────────────
def _post(url, headers, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def chat(messages: list, max_tokens: int = 800, temperature: float = 0.2,
         timeout: int = 25) -> str:
    provider, key, model = _load_cfg()
    if not key or not _quota():
        return ""
    if _check_rate_limit():
        return ""
    _bump_usage()
    p = PROVIDERS[provider]
    fmt = p["fmt"]
    try:
        if fmt == "anthropic":
            sys_txt = "\n".join(m["content"] for m in messages if m["role"] == "system")
            msgs = [{"role": m["role"], "content": m["content"]}
                    for m in messages if m["role"] != "system"]
            body = {"model": model, "max_tokens": max_tokens,
                    "temperature": temperature, "messages": msgs}
            if sys_txt:
                body["system"] = sys_txt
            r = _post(p["url"], {"x-api-key": key, "anthropic-version": "2023-06-01",
                                 "content-type": "application/json"}, body, timeout)
            return "".join(b.get("text", "") for b in r.get("content", [])).strip()

        if fmt == "gemini":
            sys_txt = "\n".join(m["content"] for m in messages if m["role"] == "system")
            contents = []
            for m in messages:
                if m["role"] == "system":
                    continue
                role = "model" if m["role"] == "assistant" else "user"
                contents.append({"role": role, "parts": [{"text": m["content"]}]})
            if not contents:
                contents = [{"role": "user", "parts": [{"text": ""}]}]
            body = {"contents": contents,
                    "generationConfig": {"maxOutputTokens": max_tokens,
                                         "temperature": temperature}}
            if sys_txt:
                body["systemInstruction"] = {"parts": [{"text": sys_txt}]}
            url = f"{p['url']}/{model}:generateContent?key={key}"
            r = _post(url, {"content-type": "application/json"}, body, timeout)
            cands = r.get("candidates", [])
            if not cands:
                return ""
            return "".join(pt.get("text", "")
                           for pt in cands[0].get("content", {}).get("parts", [])).strip()

        # default: OpenAI-compatible (mistral / groq / xai)
        body = {"model": model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature}
        r = _post(p["url"], {"Authorization": f"Bearer {key}",
                             "Content-Type": "application/json"}, body, timeout)
        return r["choices"][0]["message"]["content"].strip()

    except urllib.error.HTTPError as e:
        body_err = e.read()[:200]
        print(f"[llm:{provider}] HTTP {e.code}: {body_err}", flush=True)
        if e.code == 429:
            try:
                retry_after = int(e.headers.get("Retry-After", "60"))
            except (ValueError, TypeError):
                retry_after = 60
            _set_rate_limit(max(retry_after, 60))
        _bump_error(f"HTTP {e.code} ({provider})")
        return ""
    except Exception as e:
        print(f"[llm:{provider}] error: {e}", flush=True)
        _bump_error(str(e))
        return ""


def quick(prompt: str, max_tokens: int = 300, system: str = "") -> str:
    msgs = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    return chat(msgs, max_tokens=max_tokens)
