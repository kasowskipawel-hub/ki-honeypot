"""Telnet honeypot — Port 23.

Mirai and its variants use Telnet as their primary infection vector. This
honeypot mimics a stripped-down BusyBox/OpenWRT login prompt, accepts any
credentials (first attempt = success), and captures whatever command sequence
the bot runs after login. Credentials, commands, and any download attempts
(wget/curl/tftp/busybox) are logged to events.jsonl.

Protocol: raw TCP, no TLS. Pure stdlib, no pip deps.
"""
import asyncio
import datetime
import os
import re
import threading
import time

_PORTS   = [int(p) for p in os.getenv("TELNET_PORTS", "23").split(",") if p.strip()]
_EVENTS  = os.getenv("EVENTS", "/data/events.jsonl")
_HOST    = "0.0.0.0"

# Telnet IAC negotiation — respond to anything with DO/DONT/WILL/WONT ECHO
_IAC   = b"\xff"
_WILL  = b"\xfb"
_WONT  = b"\xfc"
_DO    = b"\xfd"
_DONT  = b"\xfe"
_ECHO  = b"\x01"
_SGA   = b"\x03"
_NAWS  = b"\x1f"

_BANNER = (
    b"\r\n"
    b"BusyBox v1.26.2 (2019-07-15 11:44:46 UTC) built-in shell (ash)\r\n"
    b"\r\n"
    b"  _______                     ________        __\r\n"
    b" |       |.-----.-----.-----.|  |  |  |.----.|  |_\r\n"
    b" |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|\r\n"
    b" |_______||   __|_____|__|__||________||__|  |____|\r\n"
    b"          |__| W I R E L E S S   F R E E D O M\r\n"
    b"\r\n"
    b"OpenWrt SNAPSHOT, r0+1-2fd7143\r\n"
    b" -------------------------------------------------------\r\n"
    b"  * 1st milestone  : 3sTuning\r\n"
    b" -------------------------------------------------------\r\n"
    b"\r\n"
)

_PROMPT    = b"root@OpenWrt:~# "
_FAKE_CMDS = {
    "id":        b"uid=0(root) gid=0(root) groups=0(root)\r\n",
    "uname -a":  b"Linux OpenWrt 4.14.195 #0 SMP Mon Aug 17 11:11:38 2020 mips GNU/Linux\r\n",
    "uname":     b"Linux\r\n",
    "cat /proc/cpuinfo": b"system type\t: MT7621\r\nprocessor\t: 0\r\ncpu model\t: MIPS 1004Kc V2.15\r\n",
    "cat /proc/meminfo": b"MemTotal:\t      61868 kB\r\nMemFree:\t      23416 kB\r\n",
    "ifconfig":   b"br-lan    Link encap:Ethernet  HWaddr 74:DA:38:XX:XX:XX\r\n"
                  b"          inet addr:192.168.1.1  Bcast:192.168.1.255\r\n",
    "ls":         b"bin  dev  etc  lib  mnt  overlay  proc  rom  root  sbin  sys  tmp  usr  var  www\r\n",
    "pwd":        b"/root\r\n",
    "whoami":     b"root\r\n",
    "ps":         b"  PID USER       VSZ STAT COMMAND\r\n    1 root      1428 S    /sbin/init\r\n",
    "env":        b"HOME=/root\r\nPATH=/usr/local/bin:/usr/bin:/bin\r\nSHELL=/bin/ash\r\n",
    "echo":       b"\r\n",
}

_DOWNLOAD_RE = re.compile(
    r"(?:wget|curl|tftp|busybox\s+wget|busybox\s+tftp)\s+"
    r"(?:-q\s+|-O\s+\S+\s+)?(?:-\s+)?(?:https?://|ftp://|tftp://)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::\d+)?(?:/\S+)?)",
    re.I,
)

try:
    import ai_analyst as _ai
except Exception:
    _ai = None

_log_lock = threading.Lock()


def _ts():
    return datetime.datetime.utcnow().isoformat() + "Z"


def _log(ev: dict):
    import json
    line = json.dumps(ev, ensure_ascii=False)
    with _log_lock:
        try:
            with open(_EVENTS, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
    print(line, flush=True)


def _negotiate(data: bytes) -> tuple[bytes, bytes]:
    """Strip IAC negotiation sequences from data, respond with WONTs."""
    clean  = b""
    reply  = b""
    i = 0
    while i < len(data):
        if data[i:i+1] == _IAC and i + 2 < len(data):
            cmd = data[i+1:i+2]
            opt = data[i+2:i+3]
            if cmd in (_DO, _WILL):
                reply += _IAC + _WONT + opt
            elif cmd in (_DONT, _WONT):
                reply += _IAC + _DONT + opt
            i += 3
        else:
            clean += data[i:i+1]
            i += 1
    return clean, reply


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
    addr = writer.get_extra_info("peername") or ("?", 0)
    src_ip, src_port = addr[0], addr[1]
    session_id = f"telnet-{src_ip}-{int(time.time()*1000)}"

    async def send(data: bytes):
        try:
            writer.write(data)
            await writer.drain()
        except Exception:
            pass

    async def readline(timeout: float = 20.0) -> bytes:
        buf = b""
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    b = await asyncio.wait_for(reader.read(256), timeout=min(5.0, deadline - time.time()))
                except asyncio.TimeoutError:
                    break
                if not b:
                    break
                clean, reply = _negotiate(b)
                if reply:
                    await send(reply)
                buf += clean
                if b"\r" in buf or b"\n" in buf:
                    break
        except Exception:
            pass
        return buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n").rstrip(b"\n")

    try:
        # Send IAC WILL ECHO + IAC WILL SGA to suppress local echo
        await send(_IAC + _WILL + _ECHO + _IAC + _WILL + _SGA)

        # Login prompt
        await send(b"\r\nlogin: ")
        user_raw = await readline(30)
        user = user_raw.decode("latin-1", "replace").strip()

        await send(b"\r\nPassword: ")
        pw_raw = await readline(20)
        pw = pw_raw.decode("latin-1", "replace").strip()

        # Always accept — log the credentials
        await send(b"\r\n\r\n")
        await send(_BANNER)
        await send(_PROMPT)

        commands = []
        downloads = []
        net_downloads = []
        replay = []   # [{t: ms_since_start, text: str, dir: "in"|"out"}]
        t0 = time.time()

        def _rel_ms() -> int:
            return int((time.time() - t0) * 1000)

        while time.time() - t0 < 120:
            line_raw = await readline(30)
            if not line_raw:
                break
            cmd = line_raw.decode("latin-1", "replace").strip()
            if not cmd:
                await send(_PROMPT)
                continue
            commands.append(cmd)
            replay.append({"t": _rel_ms(), "text": cmd, "dir": "in"})

            # Check for download attempts
            for m in _DOWNLOAD_RE.finditer(cmd):
                downloads.append(m.group(0))
                net_downloads.append(m.group(1))

            # Respond with fake output — static dict first, then Mistral fallback
            cmd_lower = cmd.lower().split(";")[0].strip()
            resp = _FAKE_CMDS.get(cmd_lower) or _FAKE_CMDS.get(cmd_lower.split()[0] if cmd_lower else "") or b""
            if any(cmd_lower.startswith(k) for k in ("echo ", "printf ")):
                arg = cmd[cmd.index(" ")+1:] if " " in cmd else ""
                resp = arg.encode("latin-1", "replace") + b"\r\n"
            if not resp and _ai and _ai.available():
                try:
                    ai_out = _ai.fake_cmd_output(cmd, device="openwrt")
                    if ai_out:
                        resp = (ai_out + "\r\n").encode("latin-1", "replace")
                except Exception:
                    pass

            if b"exit" in line_raw or b"logout" in line_raw:
                await send(b"\r\n")
                replay.append({"t": _rel_ms(), "text": "logout", "dir": "out"})
                break
            resp_text = (resp + _PROMPT).decode("latin-1", "replace")
            replay.append({"t": _rel_ms(), "text": resp_text, "dir": "out"})
            await send(resp + _PROMPT)

        _log({
            "ts":           _ts(),
            "src_ip":       src_ip,
            "src_port":     src_port,
            "dst_port":     port,
            "session_id":   session_id,
            "service":      "telnet",
            "protocol":     "telnet",
            "lure":         "telnet-mirai",
            "method":       "TELNET",
            "path":         "(shell)",
            "telnet_user":  user,
            "telnet_pass":  pw,
            "ssh_creds":    [f"{user}:{pw}"] if user or pw else [],
            "ssh_commands": commands,
            "net_downloads": net_downloads,
            "telnet_downloads": downloads,
            "ssh_replay": replay,
            "response_status": "OK",
        })
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def start(log_fn=None):
    """Start the Telnet honeypot in background threads (called from honeypot.py)."""

    async def _run():
        servers = []
        for port in _PORTS:
            try:
                srv = await asyncio.start_server(
                    lambda r, w, p=port: _handle(r, w, p), _HOST, port
                )
                servers.append(srv)
                print(f"[telnet] listening on {_HOST}:{port}", flush=True)
            except Exception as e:
                print(f"[telnet] FAILED to bind {port}: {e}", flush=True)
        if servers:
            await asyncio.gather(*(s.serve_forever() for s in servers))

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_run())

    t = threading.Thread(target=_thread, daemon=True, name="telnet-hp")
    t.start()
    return t
