"""
Fake Stratum Mining Pool — Wallet Catcher.
Listens on TCP ports and responds as a real Monero mining pool.
When miners connect and authenticate, captures their WALLET ADDRESS
from mining.authorize. Never actually validates shares — just logs.

Protocol: JSON-RPC over TCP (Stratum v1)
"""

import asyncio, json, hashlib, os, struct, time, uuid
from datetime import datetime, timezone
try:
    import strategist as _strat
except Exception:
    _strat = None

# Plaintext stratum on every common mining-pool port (no collision with the
# honeypot's other listeners). More ports = more scan hits = more login attempts.
STRATUM_PORTS = [3333, 3334, 4444, 5555, 7777, 9999, 14444, 24444, 3032, 5550,
                 1314, 12321, 20580, 45700, 33333, 6666, 17777, 19999]
# Stratum-over-TLS (stratum+ssl) — many modern miners connect encrypted; without
# this we miss every TLS miner. Wrapped with the honeypot's cert.
STRATUM_SSL_PORTS = [9000, 13333, 14433, 20128, 23333, 30000, 7778, 5151]
_EVENTS = os.path.join(os.getenv("DATA_DIR", "/data"), "events.jsonl")

def _log_event(ev: dict):
    try:
        with open(_EVENTS, "a") as f:
            f.write(json.dumps(ev) + "\n")
    except Exception:
        pass

def _ts():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# ── Fake job templates ──────────────────────────────────────
JOB_ID = lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
EXTRANONCE = lambda: hashlib.md5(os.urandom(16)).hexdigest()[:8]


def _xmr_job() -> dict:
    """A fresh Monero/RandomX job (used by login result + getjob)."""
    return {
        "blob": hashlib.sha256(os.urandom(8)).hexdigest() + "00000000",
        "job_id": JOB_ID(),
        "target": "b88d0600",   # low diff → miner "accepts" quickly
        "algo": "rx/0",
        "height": 3210000,
        "seed_hash": hashlib.sha256(b"seed").hexdigest(),
    }


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    sock = writer.get_extra_info("sockname") or ("?", 0)
    dst_port = sock[1]   # the pool port the miner actually targeted (3333/4444/…)
    wallet = None
    agent = None
    session_id = uuid.uuid4().hex[:8]
    log_lines = []
    shares = 0          # accepted shares this session (miner commitment signal)
    authorized = False  # miner logged in (wallet captured) → keep pushing jobs
    proto = None        # "btc" | "xmr" | "eth" — which job format to push
    share_times = []    # timestamps of each share submission for hashrate calc
    current_diff = 2048 # difficulty we sent the miner (BTC default)

    def log(msg):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{session_id}] {msg}"
        log_lines.append(line)
        print(f"[stratum] {line}", flush=True)

    async def send(method, params, id=None):
        msg = json.dumps({
            "id": id,
            "method": method,
            "params": params,
        }, ensure_ascii=False) + "\n"
        try:
            writer.write(msg.encode())
            await writer.drain()
        except Exception:
            pass

    async def send_result(id, result):
        msg = json.dumps({
            "id": id,
            "result": result,
            "error": None,
        }, ensure_ascii=False) + "\n"
        try:
            writer.write(msg.encode())
            await writer.drain()
        except Exception:
            pass

    try:
        log(f"Connected: {peer[0]}:{peer[1]}")

        # Read JSON-RPC lines
        buf = b""
        subscriber = None
        extra_nonce = EXTRANONCE()

        for _ in range(400):
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=60)
            except asyncio.TimeoutError:
                # Idle: if the miner is logged in, push a fresh job so we look
                # like a live pool — keeps it connected and hashing for us.
                if authorized:
                    if proto == "xmr":
                        await send("job", _xmr_job())
                    elif proto == "btc":
                        await send("mining.notify", [
                            JOB_ID(), hashlib.sha256(os.urandom(8)).hexdigest(),
                            hashlib.sha256(b"c1").hexdigest()[:64],
                            hashlib.sha256(b"c2").hexdigest()[:32],
                            [], "01000000", "1c2f4e6a",
                            hashlib.sha256(os.urandom(4)).hexdigest()[:8], True])
                    continue        # eth miners poll; just stay alive
                break
            if not data:
                break
            buf += data

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue

                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    log(f"Invalid JSON: {line[:200]}")
                    continue

                method = msg.get("method", "")
                msg_id = msg.get("id")
                params = msg.get("params", [])

                log(f"<< {msg_str(msg)[:300]}")

                # AI strategist: mining login/subscribe = interesting (wallet/agent
                # intel). Flag unhandled so a tactic gets computed for the session.
                if _strat is not None and method:
                    try:
                        interesting = method in ("mining.subscribe", "mining.authorize",
                                                 "login", "mining.submit", "submit")
                        _strat.note(f"stratum:{peer[0]}", "stratum",
                                    f"{method} {str(params)[:160]}",
                                    src_ip=str(peer[0]), unhandled=interesting)
                    except Exception:
                        pass

                if method == "mining.subscribe":
                    agent = params[0] if params else "unknown"
                    subscriber = params[0] if params else agent
                    log(f"  AGENT: {agent}")
                    await send_result(msg_id, [
                        ["mining.set_difficulty", "mining.notify"],
                        extra_nonce,
                        4,  # extranonce2 size
                    ])
                    # Send difficulty but NO job yet — job comes after authorize.
                    # Sending a job before auth confuses cpuminer/cgminer and
                    # causes immediate disconnect before they send their wallet.
                    current_diff = 2048
                    await send("mining.set_difficulty", [current_diff])

                elif method == "mining.authorize":
                    username = params[0] if params else ""
                    password = params[1] if len(params) > 1 else "x"
                    wallet = username

                    # Extract wallet address (sometimes it's "wallet.worker")
                    if "." in username:
                        parts = username.split(".")
                        wallet_addr = parts[0]
                        worker = ".".join(parts[1:]) if len(parts) > 1 else "x"
                    else:
                        wallet_addr = username
                        worker = "x"

                    log(f"  ⚡ WALLET: {wallet_addr}")
                    log(f"  WORKER: {worker}")
                    log(f"  PASS: {password}")

                    # Save to file IMMEDIATELY
                    with open(f"/data/trap_logs/wallets_{time.strftime('%Y%m%d')}.jsonl", "a") as f:
                        f.write(json.dumps({
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "peer": f"{peer[0]}:{peer[1]}",
                            "session": session_id,
                            "agent": agent,
                            "wallet": wallet_addr,
                            "worker": worker,
                            "password": password,
                        }, ensure_ascii=False) + "\n")

                    authorized = True; proto = "btc"
                    await send_result(msg_id, True)

                    # Send fake mining job
                    job = JOB_ID()
                    await send("mining.notify", [
                        job,
                        hashlib.sha256(b"prev").hexdigest(),
                        hashlib.sha256(b"coinbase1").hexdigest()[:64],
                        hashlib.sha256(b"coinbase2").hexdigest()[:32],
                        [hashlib.sha256(f"tx{i}".encode()).hexdigest() for i in range(3)],
                        "01000000",
                        "1c2f4e6a",
                        hashlib.sha256(b"ntime").hexdigest()[:8],
                        True,
                    ])

                elif method == "mining.submit":
                    # BTC/sha256 share — accept it so the miner keeps hashing for us.
                    shares += 1
                    share_times.append(time.time())
                    log(f"  SUBMIT #{shares}: worker={params[0] if params else '?'}")
                    await send_result(msg_id, True)

                elif method == "mining.suggest_difficulty":
                    await send_result(msg_id, True)

                elif method in ("mining.extranonce.subscribe", "mining.configure"):
                    await send_result(msg_id, True)

                elif method in ("mining.ping",):
                    await send_result(msg_id, "pong")

                # ── Monero / XMRig post-login methods ───────────────────────
                elif method == "submit":
                    shares += 1
                    share_times.append(time.time())
                    log(f"  ⚡ XMR-SHARE #{shares} (miner committed)")
                    await send_result(msg_id, {"status": "OK"})

                elif method == "keepalived":
                    await send_result(msg_id, {"status": "KEEPALIVED"})

                elif method == "getjob":
                    await send_result(msg_id, _xmr_job())

                # ── Ethereum / ethash (ethproxy + NiceHash EthereumStratum) ──
                elif method == "eth_submitLogin":
                    wallet = (params[0] if params else "") or wallet
                    log(f"  ⚡ ETH-LOGIN WALLET: {wallet}")
                    try:
                        with open(f"/data/trap_logs/wallets_{time.strftime('%Y%m%d')}.jsonl", "a") as f:
                            f.write(json.dumps({
                                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "peer": f"{peer[0]}:{peer[1]}", "session": session_id,
                                "proto": "eth", "agent": agent, "wallet": wallet,
                                "worker": (params[1] if len(params) > 1 else "x"),
                                "password": "x",
                            }, ensure_ascii=False) + "\n")
                    except Exception:
                        pass
                    authorized = True; proto = "eth"
                    await send_result(msg_id, True)

                elif method == "eth_getWork":
                    await send_result(msg_id, [
                        "0x" + hashlib.sha256(b"header").hexdigest(),
                        "0x" + hashlib.sha256(b"seed").hexdigest(),
                        "0x00000000ffff0000000000000000000000000000000000000000000000000000",
                        "0x" + format(3210000, "x"),
                    ])

                elif method in ("eth_submitWork", "eth_submitHashrate"):
                    if method == "eth_submitWork":
                        log("  ⚡ ETH-SHARE (miner committed)")
                    await send_result(msg_id, True)

                elif method == "login":
                    # Monero / RandomX miners (xmrig default) use JSON-RPC `login`.
                    # The wallet is in params["login"]; respond with a job so the
                    # miner stays connected and believes the pool is real.
                    p = params if isinstance(params, dict) else {}
                    wallet_addr = p.get("login", "")
                    password = p.get("pass", "x")
                    agent = p.get("agent", agent) or "unknown"
                    rigid = p.get("rigid", "")
                    wallet = wallet_addr

                    if "." in wallet_addr:
                        parts = wallet_addr.split(".")
                        wallet_addr, worker = parts[0], ".".join(parts[1:])
                    else:
                        worker = rigid or "x"

                    log(f"  ⚡ MONERO-LOGIN AGENT: {agent}")
                    log(f"  ⚡ WALLET: {wallet_addr}")
                    log(f"  WORKER: {worker}")
                    log(f"  PASS: {password}")

                    try:
                        with open(f"/data/trap_logs/wallets_{time.strftime('%Y%m%d')}.jsonl", "a") as f:
                            f.write(json.dumps({
                                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "peer": f"{peer[0]}:{peer[1]}",
                                "session": session_id,
                                "proto": "monero-login",
                                "agent": agent,
                                "wallet": wallet_addr,
                                "worker": worker,
                                "password": password,
                            }, ensure_ascii=False) + "\n")
                    except Exception as e:
                        log(f"  wallet-save error: {e}")

                    authorized = True; proto = "xmr"
                    # Monero stratum login result: { id, status, job:{...} }
                    await send_result(msg_id, {
                        "id": session_id,
                        "job": _xmr_job(),
                        "status": "OK",
                    })

                else:
                    log(f"  Unknown method: {method}")

        log(f"Disconnected: wallet={wallet or 'NONE'}")
    except Exception as e:
        log(f"Error: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass
        # ── Hashrate estimation ───────────────────────────────────────────
        # H/s ≈ difficulty × shares / elapsed_time
        # Use last 10 shares for a rolling window; fall back to session average.
        hashrate_hs = 0.0
        hashrate_str = ""
        if len(share_times) >= 2:
            window = share_times[-10:]
            elapsed = window[-1] - window[0]
            if elapsed > 0:
                # XMR target "b88d0600" → diff ≈ 0x0006_d8b8 ≈ 449_720
                # BTC diff 2048 is sent explicitly
                xmr_diff = int.from_bytes(bytes.fromhex("b88d0600"), "little") if proto == "xmr" else 0
                eff_diff = xmr_diff if xmr_diff else current_diff
                hashrate_hs = eff_diff * (len(window) - 1) / elapsed
                # human-readable
                if hashrate_hs >= 1e9:
                    hashrate_str = f"{hashrate_hs/1e9:.2f} GH/s"
                elif hashrate_hs >= 1e6:
                    hashrate_str = f"{hashrate_hs/1e6:.2f} MH/s"
                elif hashrate_hs >= 1e3:
                    hashrate_str = f"{hashrate_hs/1e3:.2f} KH/s"
                else:
                    hashrate_str = f"{hashrate_hs:.0f} H/s"
                log(f"  📊 HASHRATE: {hashrate_str} ({shares} shares, diff={eff_diff})")

        # Log to events.jsonl pipeline
        _log_event({
            "service":        "stratum",
            "ts":             _ts(),
            "src_ip":         peer[0],
            "src_port":       peer[1],
            "dst_port":       dst_port,
            "session_id":     f"stratum-{session_id}",
            "lure":           "stratum-mining" if wallet else "stratum-probe",
            "stratum_wallet": wallet,
            "stratum_agent":  agent,
            "stratum_authorized": bool(wallet),
            "stratum_shares": shares,
            "stratum_hashrate_hs":  round(hashrate_hs, 1),
            "stratum_hashrate_str": hashrate_str,
            "stratum_proto":  proto or "",
            "stratum_diff":   current_diff,
        })
        # Emit event to main pipeline
        return {
            "session": session_id,
            "peer": peer,
            "wallet": wallet,
            "agent": agent,
            "log": log_lines,
        }


def msg_str(msg):
    """Compact JSON representation for logging."""
    d = {}
    for k in ("id", "method", "params"):
        if k in msg:
            v = msg[k]
            if isinstance(v, list) and len(str(v)) > 100:
                v = str(v)[:100] + "..."
            d[k] = v
    return json.dumps(d, ensure_ascii=False)


def start(log_event=None, extract_iocs=None, capture_samples=None):
    """Start the fake stratum pool on all ports (plaintext + TLS) in one loop."""
    import threading, ssl

    ctx = None
    cert = os.environ.get("CERT", "/data/cert.pem")
    key = os.environ.get("KEY", "/data/key.pem")
    try:
        if os.path.exists(cert) and os.path.exists(key):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
    except Exception as e:
        print(f"[stratum] TLS disabled: {e}", flush=True)

    async def _serve_all():
        servers = []
        for port in STRATUM_PORTS:
            try:
                s = await asyncio.start_server(handle_client, "0.0.0.0", port)
                servers.append(s)
            except Exception as e:
                print(f"[stratum] port {port}: {e}", flush=True)
        if ctx:
            for port in STRATUM_SSL_PORTS:
                try:
                    s = await asyncio.start_server(handle_client, "0.0.0.0", port, ssl=ctx)
                    servers.append(s)
                except Exception as e:
                    print(f"[stratum] tls port {port}: {e}", flush=True)
        print(f"[stratum] Listening on {len(servers)} ports "
              f"({len(STRATUM_PORTS)} plain + {len(STRATUM_SSL_PORTS) if ctx else 0} TLS)", flush=True)
        await asyncio.gather(*(s.serve_forever() for s in servers))

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_serve_all())
        except Exception as e:
            print(f"[stratum] loop error: {e}", flush=True)

    threading.Thread(target=_run, daemon=True).start()
