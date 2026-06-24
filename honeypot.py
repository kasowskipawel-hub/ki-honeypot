#!/usr/bin/env python3
"""win443-honeypot — multi-port honeypot for Windows-botnet capture.

Per connection:
  1. peek first bytes -> auto-detect TLS (0x16) vs. plaintext vs. raw probe
  2. TLS: read ClientHello -> JA3, terminate via MemoryBIO (plaintext to us)
  3. parse HTTP, extract + auto-decode payloads/IOCs
  4. answer with a believable vulnerable Windows/IIS response (the trap)
  5. capture referenced second-stage binaries (recursively), never execute
  6. append a rich JSON event (enricher + command center consume it)

Listens on PORTS (default 443,80,8080,445). HTTP-style ports get the full
lure pipeline; non-HTTP probes (SMB/RDP scanners) are logged raw. stdlib only.
"""
import asyncio
import datetime
import json
import os
import ssl
import sys
import uuid

import license_check
license_check.check_and_start()

from ja3 import parse_client_hello
from capture import extract_iocs, capture_samples
from lures import select_response
try:
    import zero_day_detector as zd
except Exception:
    zd = None
import redis_honeypot
import ssh_honeypot
import stratum_honeypot
import rdp_honeypot
import counter_intel
import c2_mirror
import smb_honeypot
import devapi_honeypot
import telnet_honeypot
import eth_honeypot

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "443"))
PORTS = [int(p) for p in os.environ.get("PORTS", str(PORT)).split(",") if p.strip()]
REDIS_PORTS = [int(p) for p in os.environ.get("REDIS_PORTS", "6379").split(",") if p.strip()]
SSH_PORTS = [int(p) for p in os.environ.get("SSH_PORTS", "2222").split(",") if p.strip()]
CERT = os.environ.get("CERT", "/data/cert.pem")
KEY = os.environ.get("KEY", "/data/key.pem")
EVENTS = os.environ.get("EVENTS", "/data/events.jsonl")
MAX_REQ = 256 * 1024
CTX = None


def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except Exception:
        pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception:
        pass
    return ctx


def log_event(ev):
    line = json.dumps(ev, ensure_ascii=False)
    try:
        with open(EVENTS, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def parse_http(raw):
    try:
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        parts = lines[0].decode("latin-1", "replace").split(" ")
        if len(parts) < 2 or parts[0] not in (
                "GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "PATCH",
                "PROPFIND", "CONNECT", "TRACE"):
            return "", "", "", {}, [], body if body else raw
        method, path = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else ""
        headers, order = {}, []
        for ln in lines[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                k = k.decode("latin-1", "replace").strip()
                headers[k] = v.decode("latin-1", "replace").strip()
                order.append(k)
        return method, path, version, headers, order, body
    except Exception:
        return "", "", "", {}, [], b""


def safe_close(writer):
    try:
        writer.close()
    except Exception:
        pass


# ---- MemoryBIO TLS pumping --------------------------------------------------
async def drive(fn, inc, out, reader, writer, timeout=15):
    while True:
        try:
            res = fn()
            data = out.read()
            if data:
                writer.write(data); await writer.drain()
            return res
        except ssl.SSLWantReadError:
            data = out.read()
            if data:
                writer.write(data); await writer.drain()
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                inc.write_eof()
            else:
                inc.write(chunk)
        except ssl.SSLWantWriteError:
            data = out.read()
            if data:
                writer.write(data); await writer.drain()


async def assemble_record(first, reader):
    """Read enough bytes to hold the full first TLS record (ClientHello)."""
    buf = first
    while len(buf) < 5:
        c = await asyncio.wait_for(reader.read(4096), 10)
        if not c:
            return buf
        buf += c
    ln = (buf[3] << 8) | buf[4]
    while len(buf) < 5 + ln:
        c = await asyncio.wait_for(reader.read(4096), 10)
        if not c:
            break
        buf += c
    return buf


async def read_http_tls(tls, inc, out, reader, writer):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < MAX_REQ:
        chunk = await drive(lambda: tls.read(65536), inc, out, reader, writer, 12)
        if not chunk:
            return buf
        buf += chunk
    return await _read_body_tls(buf, tls, inc, out, reader, writer)


async def _read_body_tls(buf, tls, inc, out, reader, writer):
    head, _, body = buf.partition(b"\r\n\r\n")
    clen = _clen(head)
    while len(body) < clen and len(buf) < MAX_REQ:
        try:
            chunk = await drive(lambda: tls.read(65536), inc, out, reader, writer, 8)
        except Exception:
            break
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


async def read_http_plain(reader, initial):
    buf = initial
    while b"\r\n\r\n" not in buf and len(buf) < MAX_REQ:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), 8)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    clen = _clen(head)
    while len(body) < clen and len(buf) < MAX_REQ:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), 8)
        except Exception:
            break
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def _clen(head):
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(b"content-length:"):
            try:
                return int(ln.split(b":", 1)[1].strip())
            except Exception:
                return 0
    return 0


# ---- connection handler -----------------------------------------------------
async def handle(reader, writer, port):
    peer = writer.get_extra_info("peername") or ("?", 0)
    ev = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "src_ip": peer[0], "src_port": peer[1], "dst_port": port,
        "session_id": uuid.uuid4().hex[:12], "service": "http",
    }
    try:
        first = await asyncio.wait_for(reader.read(4096), timeout=10)
    except Exception:
        safe_close(writer); return
    if not first:
        safe_close(writer); return

    raw_req = b""
    responder = None

    if first[:1] == b"\x16":                       # TLS
        ev["tls"] = True
        rec = await assemble_record(first, reader)
        j = parse_client_hello(rec) or {}
        ev.update({"ja3": j.get("ja3"), "ja3_string": j.get("ja3_string"),
                   "tls_client_version": j.get("tls_version"), "sni": j.get("sni")})
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = CTX.wrap_bio(inc, out, server_side=True)
        inc.write(rec)
        try:
            await drive(tls.do_handshake, inc, out, reader, writer)
        except Exception as e:
            ev["error"] = "tls_handshake: " + str(e)
            log_event(ev); safe_close(writer); return
        try:
            ev["tls_version"] = tls.version()
            c = tls.cipher(); ev["cipher"] = c[0] if c else None
        except Exception:
            pass
        try:
            raw_req = await read_http_tls(tls, inc, out, reader, writer)
        except Exception as e:
            ev["error"] = "read: " + str(e)

        def responder(resp, _tls=tls, _out=out):
            _tls.write(resp)
            d = _out.read()
            if d:
                writer.write(d)
    else:                                          # plaintext
        ev["tls"] = False
        try:
            raw_req = await read_http_plain(reader, first)
        except Exception as e:
            ev["error"] = "read: " + str(e)

        def responder(resp):
            writer.write(resp)

    method, path, version, headers, order, body = parse_http(raw_req)
    if not method:                                 # non-HTTP probe (SMB/RDP/…)
        ev["raw_hex"] = raw_req[:96].hex()
    ev.update({
        "method": method, "path": path, "http_version": version,
        "headers": headers, "header_order": order,
        "user_agent": headers.get("User-Agent", ""),
        "host": headers.get("Host", ""),
        "body_len": len(body),
        "body_preview": body[:4000].decode("latin-1", "replace"),
    })
    ev["iocs"] = extract_iocs(raw_req)

    # Zero-day behavioral analysis (runs before lure so it sees novel paths)
    if method and zd is not None:
        try:
            zd_result = zd.analyze(method, path, headers, body, peer[0])
            if zd_result.get("threat_score", 0) > 0 or zd_result.get("indicators"):
                ev["threat_score"]  = zd_result["threat_score"]
                ev["indicators"]    = zd_result["indicators"]
                ev["technique"]     = zd_result["technique"]
                ev["attack_phase"]  = zd_result["attack_phase"]
                ev["is_rce_verify"] = zd_result["is_rce_verify"]
                ev["novel"]         = zd_result["novel"]
                ev["tool"]          = zd_result["tool"]
                ev["upload_magic"]  = zd_result["upload_magic"]
        except Exception:
            pass

    if method:
        resp, status, lure = select_response(method, path, headers, body, src_ip=peer[0])
        ev["lure"] = lure
        ev["response_status"] = status
        try:
            responder(resp)
            await writer.drain()
        except Exception:
            pass
    else:
        ev["lure"] = f"raw-probe:{port}"

    log_event(ev)
    safe_close(writer)
    urls = ev["iocs"]["urls"]
    if urls:
        asyncio.create_task(_capture_and_log(ev["src_ip"], ev["session_id"], urls))


async def _capture_and_log(src_ip, sid, urls):
    loop = asyncio.get_running_loop()
    try:
        samples = await loop.run_in_executor(None, capture_samples, urls)
    except Exception:
        return
    if samples:
        log_event({
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "src_ip": src_ip, "session_id": sid,
            "event": "sample_capture", "captured_samples": samples,
        })


async def redis_cb(reader, writer, port):
    """Fake unauthenticated root Redis: play along, capture the RCE chain."""
    peer = writer.get_extra_info("peername") or ("?", 0)
    ev = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "src_ip": peer[0], "src_port": peer[1], "dst_port": port,
        "session_id": uuid.uuid4().hex[:12], "service": "redis", "tls": False,
    }
    sess = None
    try:
        sess = await redis_honeypot.handle(reader, writer)
    except Exception as e:
        ev["error"] = "redis: " + str(e)
    if sess is not None:
        rce = bool(sess["rce"] or sess.get("module") or sess.get("slaveof")
                   or "dir" in sess["config"])
        transcript = "\n".join(sess["commands"])
        ev.update({
            "method": "REDIS",
            "path": sess["commands"][0] if sess["commands"] else "(connect only)",
            "lure": "redis-rce" if rce else "redis-recon",
            "response_status": "OK",
            "redis_commands": sess["commands"][:60],
            "redis_config": sess["config"],
            "redis_slaveof": sess.get("slaveof"),
            "redis_module": sess.get("module"),
            "redis_rce_chains": sess.get("rce_chains", []),
            "redis_c2_urls": sess.get("c2_urls", [])[:10],
            "redis_cron": (sess.get("cron_payload") or "")[:500] or None,
            "redis_ssh_key": (sess.get("ssh_payload") or "")[:200] or None,
            "redis_set_count": len(sess.get("set_values", [])),
            "body_preview": transcript[:4000],
        })
        blob = (transcript + "\n" + "\n".join(v for _, v in sess["set_values"])
                + "\n" + (sess.get("module") or "")).encode("utf-8", "replace")
        ev["iocs"] = extract_iocs(blob)
    log_event(ev)
    safe_close(writer)
    urls = (ev.get("iocs") or {}).get("urls", [])
    if urls:
        asyncio.create_task(_capture_and_log(ev["src_ip"], ev["session_id"], urls))


async def main():
    global CTX
    CTX = make_ctx()
    os.makedirs(os.path.dirname(EVENTS) or ".", exist_ok=True)
    listeners = [(p, handle) for p in PORTS] + [(p, redis_cb) for p in REDIS_PORTS]
    servers = []
    for p, cb in listeners:
        try:
            srv = await asyncio.start_server(lambda r, w, pp=p, c=cb: c(r, w, pp), HOST, p)
            servers.append(srv)
            print(f"[win443-honeypot] listening on {HOST}:{p}", flush=True)
        except Exception as e:
            print(f"[win443-honeypot] FAILED to bind {p}: {e}", flush=True)
    if SSH_PORTS:                                  # threaded SSH honeypot (paramiko)
        try:
            ssh_honeypot.start(SSH_PORTS, log_event, extract_iocs, capture_samples)
            stratum_honeypot.start(log_event, extract_iocs, capture_samples)
            rdp_honeypot.start(log_event, extract_iocs, capture_samples)
            counter_intel.start(log_event, extract_iocs, capture_samples)
            c2_mirror.start()
            smb_honeypot.start()
            devapi_honeypot.start(log_event, extract_iocs, capture_samples)
            telnet_honeypot.start()
            eth_honeypot.start()
        except Exception as e:
            print(f"[win443-honeypot] SSH honeypot failed: {e}", flush=True)
    if not servers:
        sys.exit("no listeners")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
