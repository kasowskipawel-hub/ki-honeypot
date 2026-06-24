"""Fake C2 listener — captures DDoS-bot wire protocol handshakes.

When a bot binary is dropped via Redis RCE (or similar), the binary calls
home to a C2 server after execution. By listening on common bot C2 ports we
can:
  • capture the bot's initial auth packet (reveals protocol format)
  • log system diagnostics the bot sends (loadAvg, memTotalMB, OS info)
  • enumerate how many infected nodes call the same port
  • potentially keep bots talking to extract their command set

Protocol-agnostic: we accept any TCP connection, read the first N bytes,
try known response patterns (from static analysis of captured binaries),
and log everything to events.jsonl as service="fake_c2".

Known GoBot-DDoS/ujak protocol hints (from binary strings analysis):
  - Bot sends: Authenticate command
  - Server responds: "[bot] authenticated"  (or similar — exact framing TBD)
  - Bot then sends: Diagnostic / heartbeat
  - Server responds: "heartbeat_response"

Since we don't have the exact wire framing, we use a probe approach:
  1. Read the initial packet (up to 4096 bytes)
  2. Try each registered responder in order
  3. Log the raw bytes as hex + ASCII for later protocol analysis
"""
import asyncio
import hashlib
import json
import os
import struct
import time

EVENTS_FILE = os.environ.get("EVENTS_FILE", "/data/events.jsonl")
LISTEN_PORTS = [int(p) for p in os.environ.get(
    "FAKE_C2_PORTS", "7777,9999,4444,1337,31337,6666,8888").split(",") if p.strip()]
READ_TIMEOUT  = 30   # seconds to wait for bot's first packet
SESSION_TTL   = 120  # max seconds to keep a session alive
MAX_SESSIONS  = 500

_active = 0
_lock   = asyncio.Lock()


# ── Responder registry ────────────────────────────────────────────────────────
# Each responder: (name, match_fn, respond_fn)
# match_fn(data: bytes) -> bool
# respond_fn(data: bytes) -> list[bytes]  (frames to send back, in order)

def _match_gobot_ujak(data: bytes) -> bool:
    """GoBot-DDoS/ujak: auth packet likely starts with a length-prefixed struct
    containing 'Authenticate'. We heuristically check for printable payload
    with keywords, or a binary packet with a small type byte up front."""
    return (b"Authenticate" in data or b"authenticate" in data
            or b"heartbeat" in data or b"auth" in data.lower()[:32])


def _respond_gobot_ujak(data: bytes) -> list[bytes]:
    """Respond to GoBot auth. We don't know the exact framing, so we try:
    1. Echo back a single-byte 0x00 (success code) — matches 'bad auth
       response: %d' check where non-zero = failure.
    2. Then send a heartbeat_response string probe."""
    return [
        b"\x00",                          # auth success (type=0 / code=0)
        b"heartbeat_response\x00",        # keepalive probe
    ]


def _match_mirai(data: bytes) -> bool:
    return data[:4] == b"\x00\x00\x00\x00" or b"scanning" in data or b"REPORT" in data


def _respond_mirai(data: bytes) -> list[bytes]:
    return [b"\x00\x00\x00\x00"]  # ACK


def _match_gafgyt(data: bytes) -> bool:
    return (b"PING" in data[:32] or b"GETLOCALIP" in data
            or b"SCANNER" in data)


def _respond_gafgyt(data: bytes) -> list[bytes]:
    return [b"PONG\n"]


_RESPONDERS = [
    ("GoBot-DDoS/ujak",   _match_gobot_ujak,  _respond_gobot_ujak),
    ("Mirai",             _match_mirai,        _respond_mirai),
    ("Gafgyt/Bashlite",   _match_gafgyt,       _respond_gafgyt),
]


def _classify(data: bytes) -> tuple[str, list[bytes]]:
    """Return (family_name, response_frames)."""
    for name, match_fn, respond_fn in _RESPONDERS:
        if match_fn(data):
            return name, respond_fn(data)
    return "unknown", [b"\x00"]  # generic probe response


def _log(ev: dict):
    try:
        line = json.dumps(ev, ensure_ascii=False) + "\n"
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception as e:
        print(f"[fake-c2] log error: {e}", flush=True)


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                  port: int):
    global _active
    async with _lock:
        if _active >= MAX_SESSIONS:
            writer.close()
            return
        _active += 1

    peer = writer.get_extra_info("peername") or ("?", 0)
    src_ip   = peer[0]
    src_port = peer[1]
    t0 = time.time()
    session_id = hashlib.sha256(
        f"{src_ip}:{src_port}:{t0}".encode()).hexdigest()[:16]

    packets = []
    family  = "unknown"
    try:
        # Phase 1: initial packet
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""

        if data:
            family, responses = _classify(data)
            packets.append({
                "dir": "bot→c2",
                "hex": data.hex(),
                "ascii": data.decode("latin-1", "replace"),
                "len": len(data),
            })
            # Send responses
            for frame in responses:
                try:
                    writer.write(frame)
                    await writer.drain()
                except Exception:
                    break
                packets.append({"dir": "c2→bot", "hex": frame.hex(),
                                 "ascii": frame.decode("latin-1", "replace")})

        # Phase 2: gather more packets (diagnostics, commands)
        deadline = t0 + SESSION_TTL
        while time.time() < deadline:
            try:
                more = await asyncio.wait_for(reader.read(4096), timeout=10)
            except asyncio.TimeoutError:
                break
            if not more:
                break
            packets.append({
                "dir": "bot→c2",
                "hex": more.hex(),
                "ascii": more.decode("latin-1", "replace"),
                "len": len(more),
            })
            # Respond to heartbeats with a generic ACK
            if b"heartbeat" in more.lower() or b"ping" in more.lower():
                ack = b"heartbeat_response\x00"
                try:
                    writer.write(ack)
                    await writer.drain()
                except Exception:
                    break
                packets.append({"dir": "c2→bot", "hex": ack.hex(),
                                 "ascii": ack.decode()})

    except Exception as e:
        print(f"[fake-c2] session {session_id} error: {e}", flush=True)
    finally:
        try:
            writer.close()
        except Exception:
            pass
        async with _lock:
            _active -= 1

    duration = round(time.time() - t0, 2)
    print(f"[fake-c2] {src_ip}:{src_port} port={port} family={family} "
          f"pkts={len(packets)} dur={duration}s", flush=True)

    _log({
        "ts":           time.time(),
        "service":      "fake_c2",
        "src_ip":       src_ip,
        "src_port":     src_port,
        "dst_port":     port,
        "session_id":   session_id,
        "bot_family":   family,
        "packets":      packets,
        "session_secs": duration,
        "lure":         "fake-c2-listener",
        "technique":    "C2-protocol-capture",
    })


async def _serve(port: int):
    try:
        srv = await asyncio.start_server(
            lambda r, w: _handle(r, w, port),
            "0.0.0.0", port, reuse_port=True)
        print(f"[fake-c2] listening on :{port}", flush=True)
        async with srv:
            await srv.serve_forever()
    except Exception as e:
        print(f"[fake-c2] port {port} failed: {e}", flush=True)


async def main():
    print(f"[fake-c2] starting on ports {LISTEN_PORTS}", flush=True)
    await asyncio.gather(*[_serve(p) for p in LISTEN_PORTS])


if __name__ == "__main__":
    asyncio.run(main())
