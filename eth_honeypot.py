"""Ethereum JSON-RPC honeypot — Port 8545.

Attackers scan for exposed Ethereum nodes and use eth_sendTransaction /
personal_sendTransaction to drain wallets, or eth_accounts to enumerate
addresses. This honeypot fakes a Geth/go-ethereum node with plausible
account balances, captures the full JSON-RPC request, and logs wallet
addresses, transaction targets, and private key attempts.

Protocol: plain HTTP (JSON-RPC over HTTP, no WebSocket needed for the bots).
"""
import asyncio
import datetime
import json
import os
import re
import threading
import time
import uuid

_PORT   = int(os.getenv("ETH_PORT", "8545"))
_EVENTS = os.getenv("EVENTS", "/data/events.jsonl")
_HOST   = "0.0.0.0"

# Fake Ethereum accounts with juicy-looking balances (in wei, hex-encoded)
_FAKE_ACCOUNTS = [
    "0x742d35cc6634c0532925a3b844bc454e4438f44e",
    "0xa1b2c3d4e5f6789012345678901234567890abcd",
    "0xdeadbeef0000000000000000000000000000cafe",
]
# ~2.7 ETH in wei, hex
_FAKE_BALANCE = "0x25C7B58B7DD3E0000"
_FAKE_BLOCK   = "0x12A8F4B"
_FAKE_CHAINID = "0x1"  # mainnet

_log_lock = threading.Lock()


def _ts():
    return datetime.datetime.utcnow().isoformat() + "Z"


def _log(ev: dict):
    line = json.dumps(ev, ensure_ascii=False)
    with _log_lock:
        try:
            with open(_EVENTS, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
    print(line, flush=True)


def _rpc_ok(id_, result):
    return json.dumps({"jsonrpc": "2.0", "id": id_, "result": result}).encode()


def _rpc_err(id_, code, msg):
    return json.dumps({"jsonrpc": "2.0", "id": id_,
                       "error": {"code": code, "message": msg}}).encode()


def _http_resp(body: bytes, status="200 OK"):
    return (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        "\r\n"
    ).encode() + body


# Ethereum address regex
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_KEY_RE  = re.compile(r"0x[0-9a-fA-F]{64}")


def _handle_rpc(req: dict) -> tuple[bytes, dict]:
    """Process one JSON-RPC request. Returns (response_bytes, ioc_dict)."""
    method = req.get("method", "")
    params = req.get("params") or []
    id_    = req.get("id", 1)
    iocs   = {"addresses": [], "tx_targets": [], "keys": [], "method": method}

    # Scrape any addresses/keys from params
    raw = json.dumps(params)
    iocs["addresses"] = list(dict.fromkeys(_ADDR_RE.findall(raw)))
    iocs["keys"]      = list(dict.fromkeys(_KEY_RE.findall(raw)))

    if method == "eth_accounts":
        return _rpc_ok(id_, _FAKE_ACCOUNTS), iocs

    if method == "eth_getBalance":
        return _rpc_ok(id_, _FAKE_BALANCE), iocs

    if method == "eth_blockNumber":
        return _rpc_ok(id_, _FAKE_BLOCK), iocs

    if method == "net_version":
        return _rpc_ok(id_, "1"), iocs

    if method == "eth_chainId":
        return _rpc_ok(id_, _FAKE_CHAINID), iocs

    if method == "web3_clientVersion":
        return _rpc_ok(id_, "Geth/v1.13.14-stable/linux-amd64/go1.21.7"), iocs

    if method in ("eth_sendTransaction", "personal_sendTransaction",
                  "eth_sendRawTransaction"):
        # This is the money shot — attacker is trying to drain the wallet
        if params and isinstance(params[0], dict):
            tx = params[0]
            iocs["tx_targets"] = [tx.get("to", "")]
            iocs["tx_value"]   = tx.get("value", "0x0")
            iocs["tx_data"]    = str(tx.get("data", ""))[:200]
        # Return a fake tx hash (looks successful)
        fake_hash = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:32]
        return _rpc_ok(id_, fake_hash), iocs

    if method == "personal_unlockAccount":
        # Attacker tries to unlock an account with a passphrase
        if len(params) >= 2:
            iocs["unlock_account"]    = str(params[0])[:64]
            iocs["unlock_passphrase"] = str(params[1])[:128]
        return _rpc_ok(id_, True), iocs

    if method == "eth_call":
        return _rpc_ok(id_, "0x"), iocs

    if method == "eth_gasPrice":
        return _rpc_ok(id_, "0x6FC23AC00"), iocs  # ~30 Gwei

    if method == "eth_estimateGas":
        return _rpc_ok(id_, "0x5208"), iocs  # 21000

    if method == "eth_getTransactionCount":
        return _rpc_ok(id_, "0x1a"), iocs

    # Unknown method — still respond to not tip off the scanner
    return _rpc_ok(id_, None), iocs


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername") or ("?", 0)
    src_ip, src_port = addr[0], addr[1]
    session_id = f"eth-{src_ip}-{int(time.time()*1000)}"

    async def send(data: bytes):
        try:
            writer.write(data)
            await writer.drain()
        except Exception:
            pass

    try:
        raw = await asyncio.wait_for(reader.read(65536), timeout=15)
        if not raw:
            return

        # Parse HTTP envelope
        body_bytes = b""
        if b"\r\n\r\n" in raw:
            head, _, body_bytes = raw.partition(b"\r\n\r\n")
            # Try to get Content-Length
            for ln in head.split(b"\r\n")[1:]:
                if ln.lower().startswith(b"content-length:"):
                    try:
                        clen = int(ln.split(b":", 1)[1].strip())
                        while len(body_bytes) < clen:
                            chunk = await asyncio.wait_for(reader.read(65536), 5)
                            if not chunk:
                                break
                            body_bytes += chunk
                    except Exception:
                        pass
                    break
        else:
            body_bytes = raw  # bare JSON-RPC (some bots skip HTTP)

        # Parse JSON-RPC (may be single request or batch array)
        all_iocs: dict = {"addresses": [], "tx_targets": [], "keys": [], "methods": []}
        responses = []
        try:
            payload = json.loads(body_bytes)
        except Exception:
            await send(_http_resp(_rpc_err(1, -32700, "Parse error")))
            return

        requests = payload if isinstance(payload, list) else [payload]
        for req in requests:
            resp_body, iocs = _handle_rpc(req)
            responses.append(resp_body)
            all_iocs["methods"].append(iocs.get("method", ""))
            all_iocs["addresses"].extend(iocs.get("addresses", []))
            all_iocs["tx_targets"].extend(iocs.get("tx_targets", []))
            all_iocs["keys"].extend(iocs.get("keys", []))
            for k in ("tx_value", "tx_data", "unlock_account", "unlock_passphrase"):
                if k in iocs:
                    all_iocs[k] = iocs[k]

        combined = (b"[" + b",".join(responses) + b"]"
                    if len(responses) > 1 else responses[0])
        await send(_http_resp(combined))

        # Deduplicate
        all_iocs["addresses"] = list(dict.fromkeys(all_iocs["addresses"]))
        all_iocs["tx_targets"] = list(dict.fromkeys(all_iocs["tx_targets"]))
        all_iocs["keys"]       = list(dict.fromkeys(all_iocs["keys"]))

        lure = "eth-wallet-drain" if any(
            m in ("eth_sendTransaction", "personal_sendTransaction",
                  "eth_sendRawTransaction", "personal_unlockAccount")
            for m in all_iocs["methods"]
        ) else "eth-rpc-probe"

        _log({
            "ts":          _ts(),
            "src_ip":      src_ip,
            "src_port":    src_port,
            "dst_port":    _PORT,
            "session_id":  session_id,
            "service":     "ethereum-rpc",
            "protocol":    "eth-jsonrpc",
            "lure":        lure,
            "method":      ",".join(all_iocs["methods"])[:120],
            "path":        "/",
            "eth_methods": all_iocs["methods"],
            "eth_addresses": all_iocs["addresses"],
            "eth_tx_targets": all_iocs["tx_targets"],
            "eth_keys_seen": len(all_iocs["keys"]),  # count only — don't log raw keys
            "eth_tx_value": all_iocs.get("tx_value", ""),
            "eth_unlock_account": all_iocs.get("unlock_account", ""),
            "response_status": "200 OK",
            "body_preview": body_bytes[:400].decode("latin-1", "replace"),
        })

    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def start():
    """Start the Ethereum RPC honeypot in a background thread."""

    async def _run():
        try:
            srv = await asyncio.start_server(_handle, _HOST, _PORT)
            print(f"[eth-rpc] listening on {_HOST}:{_PORT}", flush=True)
            await srv.serve_forever()
        except Exception as e:
            print(f"[eth-rpc] FAILED to bind {_PORT}: {e}", flush=True)

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_run())

    t = threading.Thread(target=_thread, daemon=True, name="eth-hp")
    t.start()
    return t
