"""Active C2 payload puller — retrieves the second stage that RCE chains install.

Redis (and similar) worms deliver their payload over channels our passive
capture layer never fetched:
  * raw /dev/tcp sockets — `echo -n 'GET /linux' >&6 && cat 0<&6 > file`
    (a bare request line, NOT HTTP, to a custom listener), and
  * the Redis rogue-master replication protocol — `SLAVEOF <c2>` makes the
    victim a replica and the malicious master pushes `exp.so` as the RDB.

This module actively pulls those payloads FOR OFFLINE ANALYSIS ONLY. Samples are
stored by sha256 and NEVER executed — pure retrieval, same intent as capture.py's
HTTP dropper fetch, just over the non-HTTP transports the worms actually use.

Generic by design: host/port/request are parsed from whatever the attacker sent,
so it works for this C2 and any future one, not a hardcoded target.
"""
import hashlib
import os
import re
import socket
import threading
import time

try:
    import capture as _cap          # reuse filetype/triage
except Exception:
    _cap = None

SAMPLE_DIR  = os.environ.get("SAMPLE_DIR", "/data/samples")
PULL_ENABLE = os.environ.get("C2_PULL", "1") == "1"
PULL_MAX    = int(os.environ.get("C2_PULL_MAX_BYTES", str(15 * 1024 * 1024)))
PULL_TTL    = int(os.environ.get("C2_PULL_TTL", str(6 * 3600)))

# Never connect to ourselves or private space (egress also blocks these).
_SKIP_RE = re.compile(r"^(127\.|10\.|192\.168\.|169\.254\.|0\.|255\.|::1|localhost)")
_OWN_IPS = {ip.strip() for ip in os.environ.get(
    "ADMIN_IPS", "188.192.204.246,164.68.121.252,127.0.0.1,::1").split(",") if ip.strip()}

# host:port:request -> {"t": ts, "result": entry|None}
_CACHE: dict = {}
_LOCK = threading.Lock()

_DEVTCP_RE = re.compile(r"/dev/tcp/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/(\d{1,5})")
_REDIS_URL_RE = re.compile(r"redis://([0-9]{1,3}(?:\.[0-9]{1,3}){3}):(\d{1,5})")
# the bare request the loader sends, e.g.  echo -n 'GET /linux'
_GETREQ_RE = re.compile(r"\b(GET\s+/[^\s'\"&>;|]+)")


def _skip(host: str) -> bool:
    return (not host) or host in _OWN_IPS or bool(_SKIP_RE.match(host))


def _store(data: bytes, source: str) -> dict | None:
    """Write a pulled payload into the shared sample store (sha256-named)."""
    if not data:
        return None
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    sha = hashlib.sha256(data).hexdigest()
    path = os.path.join(SAMPLE_DIR, sha)
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(data)
    ftype = _cap.filetype(data) if _cap else "unknown"
    tri = _cap.triage(data) if _cap else {"embedded_urls": [], "embedded_ips": []}
    return {
        "source": source, "sha256": sha, "size": len(data), "path": path,
        "filetype": ftype,
        "embedded_urls": tri.get("embedded_urls", []),
        "embedded_ips": tri.get("embedded_ips", []),
    }


def fetch_raw(host: str, port: int, request: bytes, timeout: int = 12) -> bytes:
    """Connect, send the EXACT request line the loader uses (no HTTP framing),
    half-close, then read the binary the custom listener streams back."""
    data = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if request:
                s.sendall(request)
                try:
                    s.shutdown(socket.SHUT_WR)   # signal request complete (cat reads to EOF)
                except OSError:
                    pass
            while len(data) <= PULL_MAX:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
    except Exception:
        return data
    return data[:PULL_MAX]


def _parse_resp_commands(stream: bytes) -> list[str]:
    """Parse RESP3 command stream after the RDB dump.
    Returns list of human-readable command strings for logging."""
    cmds = []
    i = 0
    while i < len(stream) and len(cmds) < 200:
        if stream[i:i+1] != b"*":
            i += 1
            continue
        end = stream.find(b"\r\n", i)
        if end < 0:
            break
        try:
            argc = int(stream[i+1:end])
        except ValueError:
            i = end + 2
            continue
        i = end + 2
        args = []
        for _ in range(argc):
            if i >= len(stream) or stream[i:i+1] != b"$":
                break
            end2 = stream.find(b"\r\n", i)
            if end2 < 0:
                break
            try:
                arglen = int(stream[i+1:end2])
            except ValueError:
                break
            i = end2 + 2
            args.append(stream[i:i+arglen].decode("latin-1", "replace"))
            i += arglen + 2
        if args:
            cmds.append(" ".join(args))
    return cmds


def fetch_redis_module(host: str, port: int, timeout: int = 20) -> tuple[bytes, list[str]]:
    """Speak replica protocol (PSYNC) to receive the RDB dump AND the live
    replication command stream the rogue master pushes afterwards.

    Returns (rdb_payload, repl_commands) where repl_commands is a list of
    decoded command strings (MODULE LOAD, CONFIG SET, SET key cron, …).
    These are the actual RCE payloads delivered via the replication channel —
    previously discarded after the RDB was captured."""
    rdb = b""
    repl_cmds: list[str] = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)

            def cmd(b):
                s.sendall(b)
                return s.recv(4096)

            cmd(b"PING\r\n")
            cmd(b"REPLCONF listening-port 6379\r\n")
            cmd(b"REPLCONF capa eof capa psync2\r\n")
            s.sendall(b"PSYNC ? -1\r\n")

            buf = b""
            t0 = time.time()
            while b"\n" not in buf or not buf.lstrip().startswith(b"+FULLRESYNC"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if time.time() - t0 > timeout:
                    break
            if b"\r\n" in buf:
                _, _, rest = buf.partition(b"\r\n")
            else:
                rest = buf

            # ── Phase 1: RDB bulk ─────────────────────────────────────────
            stream_tail = b""
            if rest.startswith(b"$"):
                hdr, _, after = rest.partition(b"\r\n")
                spec = hdr[1:]
                if spec.startswith(b"EOF:"):
                    marker = spec[4:]
                    payload = after
                    while marker not in payload and len(payload) <= PULL_MAX:
                        c = s.recv(65536)
                        if not c:
                            break
                        payload += c
                    parts = payload.split(marker, 1)
                    rdb = parts[0]
                    stream_tail = parts[1] if len(parts) > 1 else b""
                else:
                    try:
                        need = int(spec)
                    except ValueError:
                        need = PULL_MAX
                    payload = after
                    while len(payload) < need and len(payload) <= PULL_MAX:
                        c = s.recv(65536)
                        if not c:
                            break
                        payload += c
                    rdb = payload[:need]
                    stream_tail = payload[need:]
            else:
                rdb = rest

            # ── Phase 2: live replication command stream ──────────────────
            # The master keeps the connection open and streams RESP commands:
            # MODULE LOAD, CONFIG SET dir/dbfilename, SET key <cron/script>, …
            # We read for up to 8 more seconds to catch everything it sends.
            stream_buf = stream_tail
            s.settimeout(4)
            t1 = time.time()
            try:
                while time.time() - t1 < 8:
                    try:
                        chunk = s.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    stream_buf += chunk
                    if len(stream_buf) > 2 * 1024 * 1024:
                        break
            except Exception:
                pass

            if stream_buf:
                repl_cmds = _parse_resp_commands(stream_buf)
                if repl_cmds:
                    print(f"[c2pull] redis-repl stream from {host}:{port}: "
                          f"{len(repl_cmds)} commands: {repl_cmds[:5]}", flush=True)

    except Exception:
        pass
    return rdb[:PULL_MAX], repl_cmds


def parse_targets(ev: dict) -> list:
    """Discover every fetchable C2 target from a (redis) event. Generic — reads
    whatever the attacker actually sent. Returns list of dicts:
      {method: 'raw'|'redis', host, port, request(bytes|None)}
    """
    targets = []
    seen = set()
    blob = " ".join(str(c) for c in (ev.get("redis_commands") or []))
    blob += " " + str(ev.get("redis_cron") or "")
    for extra in ("redis_c2_urls", "c2_urls"):
        blob += " " + " ".join(ev.get(extra) or [])

    # bare request line(s) the loader uses, e.g. "GET /linux"
    requests = [m.strip() for m in _GETREQ_RE.findall(blob)]
    req_bytes = requests[0].encode() if requests else None

    # raw /dev/tcp/<host>/<port> sockets
    for host, port in set(_DEVTCP_RE.findall(blob)):
        if _skip(host):
            continue
        key = ("raw", host, port)
        if key in seen:
            continue
        seen.add(key)
        targets.append({"method": "raw", "host": host, "port": int(port),
                        "request": req_bytes})

    # redis rogue masters (SLAVEOF/REPLICAOF) → try BOTH replica pull AND, if we
    # found a GET request, a raw fetch on the same port (worms often serve both).
    for host, port in set(_REDIS_URL_RE.findall(blob)):
        if _skip(host):
            continue
        rkey = ("redis", host, port)
        if rkey not in seen:
            seen.add(rkey)
            targets.append({"method": "redis", "host": host, "port": int(port),
                            "request": None})
        if req_bytes:
            rawkey = ("raw", host, port)
            if rawkey not in seen:
                seen.add(rawkey)
                targets.append({"method": "raw", "host": host, "port": int(port),
                                "request": req_bytes})
    return targets


def pull_all(ev: dict) -> list:
    """Pull every discoverable C2 payload referenced by the event. Cached so we
    don't re-hammer the same C2 across the thousands of repeat events."""
    if not PULL_ENABLE:
        return []
    out = []
    now = time.time()
    for t in parse_targets(ev):
        host, port, method = t["host"], t["port"], t["method"]
        req = t.get("request")
        ck = f"{method}:{host}:{port}:{(req or b'').decode('latin-1')}"
        with _LOCK:
            hit = _CACHE.get(ck)
            if hit and now - hit["t"] < PULL_TTL:
                if hit["result"]:
                    out.append({**hit["result"], "cached": True})
                continue
        repl_cmds: list[str] = []
        if method == "raw":
            data = fetch_raw(host, port, req or b"GET /linux")
            src = f"raw://{host}:{port}{(' ' + req.decode('latin-1')) if req else ''}"
        else:
            data, repl_cmds = fetch_redis_module(host, port)
            src = f"redis-replica://{host}:{port}"
        entry = _store(data, src) if data else None
        # Attach replication-stream commands even when RDB was empty/tiny —
        # the commands themselves (MODULE LOAD, CONFIG SET, cron SET) are IOCs.
        if repl_cmds:
            if entry is None:
                entry = {"source": src, "sha256": "", "size": 0, "path": "",
                         "filetype": "redis-repl-stream",
                         "embedded_urls": [], "embedded_ips": []}
            entry["repl_commands"] = repl_cmds
        with _LOCK:
            _CACHE[ck] = {"t": now, "result": entry}
            if len(_CACHE) > 5000:
                cutoff = now - PULL_TTL
                for k in [k for k, v in _CACHE.items() if v["t"] < cutoff]:
                    _CACHE.pop(k, None)
        if entry:
            print(f"[c2-pull] GOT {entry.get('size',0)}B {entry.get('filetype','?')} "
                  f"sha={entry.get('sha256','')[:12]} repl_cmds={len(repl_cmds)} "
                  f"from {src}", flush=True)
            out.append(entry)
    return out
