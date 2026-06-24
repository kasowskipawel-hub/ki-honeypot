"""
Ultra-attractive fake Redis — REDTAIL / C2 Edition.

Presents a completely pwnable, root-running, data-rich Redis that also looks
like it's already used as a botnet C2 / task relay. Goals:
  * STATEFUL — SET/GET/LPUSH/HSET round-trip correctly so the classic
    "SET probe; GET probe" honeypot-detection check passes. (Critical: a
    stateless fake gets fingerprinted instantly.)
  * MAXIMUM CAPTURE — every RCE vector (CONFIG-write, SLAVEOF rogue-master,
    MODULE/FUNCTION LOAD, EVAL, RESTORE, MIGRATE) is recorded, and every value
    is mined for URLs, IPs, cron, SSH keys, crypto wallets and base64 layers.
  * C2/RELAY look — pre-seeded tasking keys + working pub/sub & queues so a
    Redis-C2 bot believes it found a live channel and reveals its commands.

We never execute anything. Pure observation.
"""

import asyncio, os, hashlib, time, random, re, base64, binascii
try:
    import strategist as _strat
except Exception:
    _strat = None
try:
    import ai_analyst as _ai
except Exception:
    _ai = None

_URL_RE   = re.compile(r'(?:https?|ftp|ldap|redis|tftp)://[^\s\'"<>\x00-\x1f]{4,300}', re.I)
_CRON_RE  = re.compile(r'(?:\*/\d+|\d+)\s+\*\s+\*\s+\*\s+\*|@(?:reboot|hourly|daily|weekly|monthly)')
_SSHKEY   = re.compile(r'(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{20,}')
_IP_RE    = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_XMR_RE   = re.compile(r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}')
_BTC_RE   = re.compile(r'\b(?:bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_B64_RE   = re.compile(r'[A-Za-z0-9+/]{24,}={0,2}')
_PRIV_IP  = ("10.", "192.168.", "127.", "0.", "255.", "169.254.")

REDIS_VERSION = "7.2.4"
PORT = os.environ.get("REDIS_PORT", "6379")


# ── Deep payload intel extraction ──────────────────────────────────────────
def _extract(value: str, sess: dict, _depth: int = 0):
    """Mine a value for every IOC; recurse once through base64 layers."""
    if not value or _depth > 2:
        return
    for u in _URL_RE.findall(value):
        if u not in sess["c2_urls"]:
            sess["c2_urls"].append(u)
    for ip in _IP_RE.findall(value):
        if not ip.startswith(_PRIV_IP) and ip not in sess["ips"]:
            sess["ips"].append(ip)
    if _CRON_RE.search(value):
        sess["cron_payload"] = value[:2000]
    if _SSHKEY.search(value):
        sess["ssh_payload"] = value[:2000]
    for w in _XMR_RE.findall(value):
        sess["wallets"].append({"type": "XMR", "addr": w})
    for w in _BTC_RE.findall(value):
        sess["wallets"].append({"type": "BTC", "addr": w})
    # base64 layer → decode and rescan (droppers love base64 cron/scripts)
    for blob in _B64_RE.findall(value)[:5]:
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            s = dec.decode("utf-8", "replace")
            if sum(c.isprintable() for c in s) > len(s) * 0.8 and len(s) > 8:
                sess["decoded"].append(s[:500])
                _extract(s, sess, _depth + 1)
        except (binascii.Error, ValueError):
            pass


# ── Pre-seeded keys: data-rich AND C2-tasking flavoured ────────────────────
FAKE_KEYS = {
    "session:admin": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiJ9.fake",
    "session:deploy": "eyJ1c2VyIjoiZGVwbG95Iiwicm9sZSI6ImFkbWluIiwiZW52IjoicHJvZCJ9.fake",
    "token:api": "sk-proj-abc123def456ghi789jklm012nopq345rst678uvw901xyz",
    "token:github": "github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    "token:slack": "x0xb-123456789012-123456789012-abcdefghijklmnopqrstuv",  # honeytoken (intentionally fake)
    "token:aws": "AKIAQ7YBT4N2XK9WERTY:wJalrXq+8sNz/Pr0dK3yM1nBv6cEXAMPLEkey",
    "cache:config": '{"db_host":"10.0.1.50","db_user":"app_prod","db_pass":"Pr0d!DB!2024","redis_host":"127.0.0.1"}',
    "cache:users": '[{"id":1,"name":"admin","role":"superadmin"},{"id":2,"name":"deploy","role":"admin"}]',
    "ssh:authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... admin@prod-db-01",
    "cron:backup": "0 2 * * * /opt/scripts/backup.sh --db prod --s3 bucket=prod-backups",
    "queue:emails": '{"to":"admin@company.local","subject":"Password Reset","body":"Click here..."}',
    "counter:visits": "8472910",
    "ratelimit:api": "1000",
    # C2-tasking flavour — makes a Redis-C2 bot think it found an active channel
    "bot:config": '{"sleep":60,"jitter":15,"c2":"hxxp://update-cdn[.]net/gate.php","kill":false}',
    "tasks:pending": "0",
    "campaign:id": "rt-2026-06",
    # ── Omicron worm bait: env-var-style keys Omicron reads via redis:env() ──
    # Omicron reads these to get C2/pool config. We point it back at ourselves:
    # → stratum wallet capture on port 3333
    # → any C2_URL fetch lands in our enricher (fetch_c2_wallet + hash_intel)
    "C2_URL":     "http://164.68.121.252/update",
    "UPDATE_URL":  "http://164.68.121.252/update",
    "POOL_URL":    "164.68.121.252:3333",
    "POOL_PASS":   "x",
    "POOL_USER":   "44AFFq5kNgsspqEkX4KtMR6RhFGNFKEBfKBXCGFcjQfGnY6VWf5UgzXaLDpxjUWyENhERnMCUMKFkRCEJC4BNzt4JZFi",
    "XMR_WALLET":  "44AFFq5kNgsspqEkX4KtMR6RhFGNFKEBfKBXCGFcjQfGnY6VWf5UgzXaLDpxjUWyENhERnMCUMKFkRCEJC4BNzt4JZFi",
}

INFO = (
    "# Server\r\n"
    f"redis_version:{REDIS_VERSION}\r\n"
    "redis_git_sha1:00000000\r\nredis_git_dirty:0\r\n"
    "redis_build_id:7a1c0e\r\nredis_mode:standalone\r\n"
    "os:Linux 5.15.0-101-generic x86_64\r\narch_bits:64\r\n"
    "process_id:1\r\n"
    f"run_id:{hashlib.md5(str(time.time()).encode()).hexdigest()}\r\n"
    f"tcp_port:{PORT}\r\nconfig_file:/etc/redis/redis.conf\r\n"
    "executable:/usr/bin/redis-server\r\n"
    f"uptime_in_seconds:{random.randint(2000000, 9000000)}\r\n\r\n"
    "# Clients\r\nconnected_clients:1\r\nmaxclients:10000\r\nblocked_clients:0\r\n\r\n"
    "# Memory\r\n"
    f"used_memory:{random.randint(400000000, 2000000000)}\r\n"
    f"used_memory_human:{random.randint(400, 2000)}M\r\n"
    "maxmemory:0\r\nmaxmemory_policy:noeviction\r\n\r\n"
    "# Persistence\r\nloading:0\r\nrdb_bgsave_in_progress:0\r\naof_enabled:0\r\n\r\n"
    "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n"
    f"master_replid:{hashlib.md5(b'repl').hexdigest()}\r\nmaster_repl_offset:0\r\n\r\n"
    "# CPU\r\n"
    f"used_cpu_sys:{random.uniform(10,500):.2f}\r\nused_cpu_user:{random.uniform(10,500):.2f}\r\n\r\n"
    "# Server\r\nrun_as_user:root\r\n\r\n"
    "# Keyspace\r\n"
    f"db0:keys={len(FAKE_KEYS)},expires={random.randint(1,4)},avg_ttl={random.randint(3600,86400)}\r\n"
)

CONFIG_DEFAULTS = {
    "dir": "/var/lib/redis", "dbfilename": "dump.rdb",
    "save": "900 1 300 10 60 10000", "maxmemory": "0", "requirepass": "",
    "protected-mode": "no", "bind": "0.0.0.0", "appendonly": "no",
    "logfile": "/var/log/redis/redis-server.log", "slave-read-only": "yes",
    "repl-diskless-sync": "yes",
}

MAX_CMDS = 2000          # was 500 — let chatty bots run longer, capture more
MAX_BULK = 2 * 1024 * 1024

def _simple(s): return b"+" + (s if isinstance(s, bytes) else s.encode()) + b"\r\n"
def _err(s):    return b"-" + (s if isinstance(s, bytes) else s.encode()) + b"\r\n"
def _int(n):    return b":" + str(n).encode() + b"\r\n"
def _bulk(s):
    if s is None: return b"$-1\r\n"
    b = s.encode() if isinstance(s, str) else s
    return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
def _arr(items):
    out = b"*" + str(len(items)).encode() + b"\r\n"
    for it in items:
        out += it if isinstance(it, bytes) and it[:1] in (b"$", b"*", b":", b"+") else _bulk(it)
    return out


async def _read_command(reader):
    line = await reader.readuntil(b"\r\n")
    line = line.rstrip(b"\r\n")
    if not line: return []
    if line[:1] == b"*":
        try: n = int(line[1:])
        except ValueError: return []
        if n <= 0 or n > 4096: return []
        args = []
        for _ in range(n):
            hdr = await reader.readuntil(b"\r\n")
            if hdr[:1] != b"$": return args
            try: ln = int(hdr[1:].rstrip(b"\r\n"))
            except ValueError: return args
            if ln < 0 or ln > MAX_BULK: return args
            data = await reader.readexactly(ln)
            await reader.readexactly(2)
            args.append(data)
        return args
    return line.split()


def _respond(cmd, args, sess):
    args = [a.decode("utf-8", "replace") if isinstance(a, bytes) else str(a) for a in args]
    kv, lists, hashes, sets = sess["kv"], sess["lists"], sess["hashes"], sess["sets"]

    if cmd == b"PING":
        return _bulk(args[0]) if args else _simple("PONG")
    if cmd == b"HELLO":
        # RESP3 handshake — answer like a real server (map reply simplified)
        return _arr(["server", "redis", "version", REDIS_VERSION, "proto", "2",
                     "id", "1", "mode", "standalone", "role", "master"])
    if cmd == b"AUTH":
        return _err("ERR Client sent AUTH, but no password is set")

    if cmd == b"INFO":
        section = args[0].lower() if args else "all"
        if section == "keyspace":
            return _bulk(f"# Keyspace\r\ndb0:keys={len(kv)},expires=3,avg_ttl=7200\r\n")
        if section == "replication":
            return _bulk("# Replication\r\nrole:master\r\nconnected_slaves:2\r\n")
        if section == "server":
            return _bulk("# Server\r\nredis_version:" + REDIS_VERSION + "\r\nrun_as_user:root\r\n")
        return _bulk(INFO)

    if cmd == b"CONFIG":
        sub = args[0].upper() if args else "GET"
        if sub == "GET":
            key = args[1].lower() if len(args) > 1 else "*"
            if key == "*":
                items = []
                for k, v in {**CONFIG_DEFAULTS, **sess["config"]}.items():
                    items.extend([k, v])
                return _arr(items)
            val = sess["config"].get(key, CONFIG_DEFAULTS.get(key, ""))
            return _arr([key, val])
        if sub == "SET" and len(args) >= 3:
            k, v = args[1].lower(), args[2]
            sess["config"][k] = v
            sess["config_set"].append(f"{args[1]} = {v}")
            if k in ("dir", "dbfilename"):
                sess["rce"].append(f"CONFIG SET {k} {v}")
                if k == "dir":
                    vl = v.lower()
                    if any(x in vl for x in ("/cron", "/var/spool", "/etc/cron")):
                        sess["_dir_type"] = "cron"
                    elif "/.ssh" in vl or "/ssh/" in vl:
                        sess["_dir_type"] = "ssh_keys"
                    elif any(x in vl for x in ("/www", "/html", "/inetpub", "/webroot")):
                        sess["_dir_type"] = "webshell"
            return _simple("OK")
        return _simple("OK")

    if cmd == b"KEYS":
        pattern = args[0] if args else "*"
        allk = list(kv) + list(lists) + list(hashes) + list(sets)
        if pattern == "*":
            return _arr(allk)
        needle = pattern.replace("*", "")
        return _arr([k for k in allk if needle in k])

    # ── stateful strings ───────────────────────────────────────
    if cmd == b"GET":
        return _bulk(kv.get(args[0]) if args else None)
    if cmd == b"MGET":
        return _arr([kv.get(k) for k in args])
    if cmd == b"SET":
        if len(args) >= 2:
            key, val = args[0], args[1]
            kv[key] = val
            sess["set_values"].append([key, val[:4000]])
            _extract(val, sess)
        return _simple("OK")
    if cmd == b"SETEX" and len(args) >= 3:
        kv[args[0]] = args[2]; sess["set_values"].append([args[0], args[2][:4000]]); _extract(args[2], sess)
        return _simple("OK")
    if cmd == b"GETSET" and len(args) >= 2:
        old = kv.get(args[0]); kv[args[0]] = args[1]; _extract(args[1], sess)
        return _bulk(old)
    if cmd == b"APPEND" and len(args) >= 2:
        kv[args[0]] = kv.get(args[0], "") + args[1]; _extract(args[1], sess)
        return _int(len(kv[args[0]]))
    if cmd == b"STRLEN":
        return _int(len(kv.get(args[0], "")) if args else 0)
    if cmd in (b"INCR", b"DECR") and args:
        try: n = int(kv.get(args[0], "0"))
        except ValueError: return _err("ERR value is not an integer or out of range")
        n += 1 if cmd == b"INCR" else -1; kv[args[0]] = str(n); return _int(n)

    # ── stateful lists (task queues — C2 flavour) ──────────────
    if cmd in (b"LPUSH", b"RPUSH") and len(args) >= 2:
        lst = lists.setdefault(args[0], [])
        for v in args[1:]:
            (lst.insert(0, v) if cmd == b"LPUSH" else lst.append(v)); _extract(v, sess)
        return _int(len(lst))
    if cmd in (b"LPOP", b"RPOP") and args:
        lst = lists.get(args[0], [])
        if not lst: return _bulk(None)
        return _bulk(lst.pop(0) if cmd == b"LPOP" else lst.pop())
    if cmd == b"LLEN":
        return _int(len(lists.get(args[0], [])) if args else 0)
    if cmd == b"LRANGE" and len(args) >= 3:
        lst = lists.get(args[0], [])
        try: s, e = int(args[1]), int(args[2])
        except ValueError: return _arr([])
        e = len(lst) if e == -1 else e + 1
        return _arr(lst[s:e])
    if cmd in (b"BLPOP", b"BRPOP") and len(args) >= 2:
        lst = lists.get(args[0], [])
        return _arr([args[0], lst.pop(0)]) if lst else _bulk(None)

    # ── stateful hashes ────────────────────────────────────────
    if cmd == b"HSET" and len(args) >= 3:
        h = hashes.setdefault(args[0], {})
        for i in range(1, len(args) - 1, 2):
            h[args[i]] = args[i + 1]; _extract(args[i + 1], sess)
        return _int(1)
    if cmd == b"HGET" and len(args) >= 2:
        return _bulk(hashes.get(args[0], {}).get(args[1]))
    if cmd == b"HGETALL" and args:
        out = []
        for k, v in hashes.get(args[0], {}).items(): out += [k, v]
        return _arr(out)
    if cmd == b"HLEN":
        return _int(len(hashes.get(args[0], {})) if args else 0)

    # ── stateful sets ──────────────────────────────────────────
    if cmd == b"SADD" and len(args) >= 2:
        s = sets.setdefault(args[0], set())
        for v in args[1:]: s.add(v); _extract(v, sess)
        return _int(len(args) - 1)
    if cmd == b"SMEMBERS" and args:
        return _arr(list(sets.get(args[0], set())))
    if cmd == b"SCARD":
        return _int(len(sets.get(args[0], set())) if args else 0)

    if cmd == b"SCAN":
        cursor = args[0] if args else "0"
        allk = list(kv)
        if cursor == "0":
            return _arr(["10", *allk[:10]]) if len(allk) > 10 else _arr(["0", *allk])
        return _arr(["0", *allk[10:]])
    if cmd == b"DBSIZE":
        return _int(len(kv) + len(lists) + len(hashes) + len(sets))
    if cmd == b"EXISTS":
        return _int(sum(1 for k in args if k in kv or k in lists or k in hashes or k in sets))
    if cmd == b"TYPE" and args:
        k = args[0]
        t = ("string" if k in kv else "list" if k in lists else
             "hash" if k in hashes else "set" if k in sets else "none")
        return _simple(t)
    if cmd in (b"DEL", b"UNLINK"):
        n = 0
        for k in args:
            for store in (kv, lists, hashes, sets):
                if k in store: del store[k]; n += 1
        return _int(n)

    # ── RCE vector: SLAVEOF / REPLICAOF rogue master ───────────
    if cmd in (b"SLAVEOF", b"REPLICAOF") and len(args) >= 2:
        host, port = args[0], args[1]
        sess["slaveof"] = f"{host}:{port}"
        sess["rce"].append(f"REPLICAOF {host}:{port}")
        if host.upper() not in ("NO", ""):
            c2 = f"redis://{host}:{port}"
            if c2 not in sess["c2_urls"]: sess["c2_urls"].append(c2)
            if not host.startswith(_PRIV_IP) and host not in sess["ips"]:
                sess["ips"].append(host)
        return _simple("OK")

    # ── RCE vector: MODULE LOAD ────────────────────────────────
    if cmd == b"MODULE":
        sub = args[0].upper() if args else ""
        if sub == "LOAD" and len(args) > 1:
            sess["module"] = args[1]; sess["rce"].append("MODULE LOAD " + args[1]); _extract(args[1], sess)
            return _simple("OK")
        if sub == "LIST":
            return _arr([])
        return _simple("OK")

    # ── RCE vector: FUNCTION LOAD (Redis 7) ────────────────────
    if cmd == b"FUNCTION":
        sub = args[0].upper() if args else ""
        if sub == "LOAD" and len(args) > 1:
            payload = args[-1]
            sess["functions"].append(payload[:2000]); sess["rce"].append("FUNCTION LOAD"); _extract(payload, sess)
            return _bulk("mylib")
        if sub == "LIST":
            return _arr([])
        return _simple("OK")

    # ── RCE vector: EVAL / EVALSHA (full Lua capture) ──────────
    if cmd in (b"EVAL", b"EVALSHA"):
        if args:
            sess["scripts"].append(args[0][:4000]); sess["rce"].append(f"{cmd.decode()} {args[0][:120]}")
            sess["eval_count"] += 1; _extract(args[0], sess)
        return _bulk(f"OK")
    if cmd == b"SCRIPT":
        return _bulk(hashlib.sha1(b"x").hexdigest()) if (args and args[0].upper() == "LOAD") else _simple("OK")

    # ── RESTORE (binary key injection) / MIGRATE (exfil) ───────
    if cmd == b"RESTORE" and len(args) >= 3:
        sess["rce"].append("RESTORE " + args[0]); sess["restore"] = args[2][:200]
        kv[args[0]] = "<restored>"; return _simple("OK")
    if cmd == b"MIGRATE" and len(args) >= 2:
        tgt = f"{args[0]}:{args[1]}"; sess["exfil"] = tgt
        if not args[0].startswith(_PRIV_IP) and args[0] not in sess["ips"]: sess["ips"].append(args[0])
        sess["rce"].append("MIGRATE " + tgt); return _simple("NOKEY")

    if cmd in (b"SAVE", b"BGSAVE", b"BGREWRITEAOF"):
        sess["rce"].append(cmd.decode()); return _simple("Background saving started")

    # ── pub/sub — Redis-as-C2 channel (proper subscribe reply) ─
    if cmd in (b"SUBSCRIBE", b"PSUBSCRIBE"):
        kind = "subscribe" if cmd == b"SUBSCRIBE" else "psubscribe"
        ch = args[0] if args else "*"
        sess["subscribed"] = ch
        return _arr([kind, ch, _int(1)])
    if cmd == b"PUBLISH" and len(args) >= 2:
        sess["published"].append([args[0], args[1][:500]]); _extract(args[1], sess)
        return _int(1)

    if cmd == b"CLUSTER":
        sub = args[0].upper() if args else ""
        if sub == "INFO":
            return _bulk("cluster_state:ok\r\ncluster_slots_assigned:16384\r\ncluster_slots_ok:16384\r\n")
        if sub == "NODES":
            return _bulk("0000000000000000000000000000000000000000 :6379@16379 myself,master - 0 0 0 connected")
        return _simple("OK")

    if cmd == b"COMMAND":
        return _int(240) if (args and args[0].upper() == "COUNT") else _arr([])

    if cmd == b"ACL":
        if args and args[0].upper() == "WHOAMI": return _bulk("default")
        if args and args[0].upper() == "LIST":  return _arr(["user default on nopass ~* &* +@all"])
        return _simple("OK")

    if cmd == b"CLIENT":
        sub = args[0].upper() if args else ""
        if sub == "LIST":
            return _bulk("id=1 addr=REPLACE_ME:12345 fd=8 name= age=300 idle=0 flags=N db=0 cmd=client user=default\n")
        if sub == "INFO":
            return _bulk("id=1 addr=REPLACE_ME:12345 name= db=0 user=default")
        if sub == "GETNAME":
            return _bulk(sess.get("clientname", ""))
        if sub == "SETNAME" and len(args) > 1:
            sess["clientname"] = args[1]; return _simple("OK")
        return _simple("OK")

    if cmd == b"SLOWLOG":
        sub = args[0].upper() if args else ""
        return _int(0) if sub == "LEN" else _arr([])
    if cmd == b"MEMORY":
        sub = args[0].upper() if args else ""
        if sub == "USAGE" and len(args) > 1: return _int(len(kv.get(args[1], "")))
        if sub == "DOCTOR": return _bulk("Sam, I detected a few issues in this Redis instance memory implants:\n")
        return _arr([])
    if cmd == b"TIME":
        t = time.time(); return _arr([str(int(t)), str(int((t % 1) * 1e6))])
    if cmd == b"DEBUG":
        if args and args[0].upper() == "SLEEP": return _simple("OK")
        return _simple("OK")
    if cmd == b"OBJECT":
        return _bulk("embstr") if (args and args[0].upper() == "ENCODING") else _int(1)
    if cmd == b"ROLE":
        return _arr(["master", _int(0), _arr([])])
    if cmd == b"WAIT":
        return _int(0)
    if cmd == b"RANDOMKEY":
        return _bulk(next(iter(kv), None))
    if cmd == b"QUIT":
        return _simple("OK")

    # Generic — keep the bot engaged
    if cmd in (b"SELECT", b"FLUSHALL", b"FLUSHDB", b"MULTI", b"EXEC", b"WATCH",
               b"RESET", b"ECHO", b"EXPIRE", b"PEXPIRE", b"TTL", b"PTTL",
               b"PERSIST", b"RENAME", b"INCRBY", b"DECRBY", b"SETNX",
               b"ZADD", b"ZREM", b"ZRANGE", b"ZCARD", b"UNSUBSCRIBE",
               b"LATENCY", b"REPLCONF", b"PSYNC", b"SYNC", b"SHUTDOWN",
               b"DUMP", b"TOUCH", b"PFADD", b"PFCOUNT", b"XADD", b"XLEN",
               b"READONLY", b"READWRITE", b"LASTSAVE", b"FCALL", b"GEOADD"):
        if cmd == b"ECHO" and args: return _bulk(args[0])
        if cmd in (b"TTL", b"PTTL"): return _int(-1)
        if cmd == b"DUMP": return _bulk(None)
        return _simple("OK")

    return _simple("OK")


def _finalize_sess(sess: dict) -> dict:
    config = sess.get("config", {})
    d  = config.get("dir", "").lower()
    fn = config.get("dbfilename", "").lower()
    dt = sess.get("_dir_type", "")
    chains = []
    if dt == "cron" or sess.get("cron_payload") or "/cron" in d or "crontab" in fn:
        chains.append("cron-injection")
    if dt == "ssh_keys" or sess.get("ssh_payload") or "authorized_keys" in fn or "/.ssh" in d:
        chains.append("ssh-key-injection")
    if dt == "webshell" and fn:
        chains.append("webshell-drop")
    if sess.get("module"):   chains.append("module-load-rce")
    if sess.get("functions"): chains.append("function-load-rce")
    sv = sess.get("slaveof") or ""
    if sv and not sv.upper().startswith("NO"): chains.append("slaveof-rogue-server")
    if sess.get("eval_count", 0) > 0: chains.append("lua-eval-rce")
    if sess.get("restore"): chains.append("restore-injection")
    if sess.get("exfil"):   chains.append("migrate-exfil")
    sess["rce_chains"] = chains
    sess["c2_urls"] = list(dict.fromkeys(sess.get("c2_urls", [])))[:30]
    sess["ips"]     = list(dict.fromkeys(sess.get("ips", [])))[:30]
    # dedupe wallets
    seen = set(); uw = []
    for w in sess.get("wallets", []):
        if w["addr"] not in seen: seen.add(w["addr"]); uw.append(w)
    sess["wallets"] = uw
    return sess


async def handle(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    sess = {
        "commands": [], "rce": [], "set_values": [], "config": {},
        "slaveof": None, "module": None, "eval_count": 0, "config_set": [],
        "peer": peer, "c2_urls": [], "ips": [], "cron_payload": None,
        "ssh_payload": None, "rce_chains": [], "_dir_type": "",
        "kv": dict(FAKE_KEYS), "lists": {}, "hashes": {}, "sets": {},
        "wallets": [], "decoded": [], "scripts": [], "functions": [],
        "restore": None, "exfil": None, "published": [], "subscribed": None,
    }

    for _ in range(MAX_CMDS):
        try:
            args = await asyncio.wait_for(_read_command(reader), timeout=90)
        except Exception:
            break
        if args is None: break
        if not args:
            if reader.at_eof(): break
            continue

        cmd_raw = args[0]
        cmd = cmd_raw.upper()
        a = [x.decode("latin-1", "replace") for x in args[1:]]
        cmd_str = f"{cmd_raw.decode('latin-1','replace')} {' '.join(a)}"[:400]
        sess["commands"].append(cmd_str)
        if _strat is not None:
            try:
                _strat.note(f"redis:{peer[0]}", "redis", cmd_str, src_ip=str(peer[0]))
            except Exception:
                pass

        # Mistral-backed believable value for GET on an unknown key → instance
        # looks like a full prod cache, attacker explores/exfiltrates more.
        # Runs in an executor so the async loop never blocks; cached = 0 tokens.
        if (cmd == b"GET" and len(args) > 1 and _ai is not None
                and args[1].decode("utf-8", "replace") not in sess["kv"]
                and _ai.available()):
            try:
                k = args[1].decode("utf-8", "replace")
                loop = asyncio.get_running_loop()
                val = await asyncio.wait_for(
                    loop.run_in_executor(None, _ai.fake_redis_value, k), timeout=20)
                if val:
                    # _respond decodes keys to str → store under the str key so the
                    # subsequent GET lookup matches.
                    sess["kv"][k] = val
                    print(f"[redis-ai] GET {k} -> {len(val)}B believable value", flush=True)
            except Exception as e:
                print(f"[redis-ai] error: {e}", flush=True)

        try:
            writer.write(_respond(cmd, args[1:], sess))
            await writer.drain()
        except Exception:
            break
        if cmd == b"QUIT":
            break

    _finalize_sess(sess)
    return sess
