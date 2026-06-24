"""
SMB2 Honeypot — MAXIMUM DATA CAPTURE edition.

Captures per session:
  - Net-NTLMv2 hashes (hashcat -m 5600) → dedicated daily log file
  - Username, domain, workstation from NTLM Type 3
  - Share names, file paths, write payload previews
  - QueryDirectory listings with realistic file trees
  - DCERPC named pipe RPC calls (SAMR/LSARPC/SRVSVC/SVCCTL/WINREG)
  - Ransomware detection (unique write threshold)
  - Canary file reads (tracker URLs in wallet/AWS/env files)

State machine: Negotiate → SessionSetup(1) → SessionSetup(2) → TreeConnect → ops

DCERPC support:
  - Proper BIND_ACK forces PSExec/Mimikatz/BloodHound/Impacket to continue
  - Fake success responses to all common RPC opnums
  - All opnum calls logged with pipe name + body hex
"""

import asyncio, struct, uuid, os, json, secrets, time, re
from datetime import datetime, timezone

SMB_PORT      = 445
HOSTNAME      = "FILESRV01"
DOMAIN        = "CORP"
DATA_DIR      = os.getenv("DATA_DIR", "/data")
EVENTS        = os.path.join(DATA_DIR, "events.jsonl")
HASH_LOG_DIR  = os.path.join(DATA_DIR, "trap_logs")

# NT Status
ST_OK     = 0x00000000
ST_MORE   = 0xC0000016   # MORE_PROCESSING_REQUIRED
ST_BADNET = 0xC00000CC
ST_NOFILE = 0xC000000F
ST_NOTIMPL= 0xC0000002
ST_IOERR  = 0xC000016A
ST_ACCESS = 0xC0000022   # ACCESS_DENIED — used on service create to look authentic

# SMB2 commands
CMD_NEGOTIATE   = 0x0000
CMD_SESS_SETUP  = 0x0001
CMD_LOGOFF      = 0x0002
CMD_TREE_CONN   = 0x0003
CMD_TREE_DISC   = 0x0004
CMD_CREATE      = 0x0005
CMD_CLOSE       = 0x0006
CMD_READ        = 0x0008
CMD_WRITE       = 0x0009
CMD_IOCTL       = 0x000B
CMD_ECHO        = 0x000C
CMD_QUERY_DIR   = 0x000E
CMD_QUERY_INFO  = 0x0010
CMD_SET_INFO    = 0x0011

# DCERPC packet types
DCERPC_REQUEST  = 0x00
DCERPC_RESPONSE = 0x02
DCERPC_BIND     = 0x0b
DCERPC_BIND_ACK = 0x0c

SMB2_MAGIC  = b"\xfeSMB"
SMB1_MAGIC  = b"\xffSMB"
NTLMSSP_SIG = b"NTLMSSP\x00"
HDR_LEN     = 64

_SERVER_GUID = uuid.UUID("4e544c4d-5353-5073-6572-766572303100").bytes_le


# ── Helpers ─────────────────────────────────────────────────────────────────

def _ts():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

try:
    import strategist as _strat
except Exception:
    _strat = None


def _log_event(ev: dict):
    try:
        with open(EVENTS, "a") as f:
            f.write(json.dumps(ev) + "\n")
    except Exception:
        pass
    # Feed NTLM identity signals to the AI strategist (attribution/journal).
    if _strat is not None:
        try:
            ip = ev.get("src_ip", "")
            sig = " ".join(str(ev.get(k, "")) for k in
                           ("username", "domain", "workstation", "lure") if ev.get(k))
            if ip and sig.strip():
                # captured NTLM identity (username) = interesting → compute a tactic
                _strat.note(f"smb:{ip}", "smb", sig.strip(), src_ip=str(ip),
                            unhandled=bool(ev.get("username")))
        except Exception:
            pass

def _log_ntlm_hash(hashcat_line: str, src_ip: str):
    """Write Net-NTLMv2 hash to daily log for offline cracking."""
    try:
        os.makedirs(HASH_LOG_DIR, exist_ok=True)
        today = datetime.now().strftime("%Y%m%d")
        path  = os.path.join(HASH_LOG_DIR, f"ntlm_hashes_{today}.txt")
        with open(path, "a") as f:
            f.write(f"# src={src_ip} ts={_ts()}\n{hashcat_line}\n")
    except Exception:
        pass

# Rate-limit: probe-only sessions → max 1 per IP per 60s
_PROBE_CACHE = os.path.join(DATA_DIR, "smb_probe_cache.json")

def _probe_cache_load() -> dict:
    try:
        with open(_PROBE_CACHE) as f:
            data = json.load(f)
        cutoff = time.time() - 60
        return {k: v for k, v in data.items() if v > cutoff}
    except Exception:
        return {}

_probe_last: dict[str, float] = _probe_cache_load()

def _probe_cache_save():
    try:
        cutoff = time.time() - 60
        fresh = {k: v for k, v in _probe_last.items() if v > cutoff}
        with open(_PROBE_CACHE, "w") as f:
            json.dump(fresh, f)
    except Exception:
        pass

def _should_log_probe(src_ip: str) -> bool:
    now = time.time()
    if now - _probe_last.get(src_ip, 0) < 60:
        return False
    _probe_last[src_ip] = now
    _probe_cache_save()
    return True

# TCP Tarpit: IPs that send >8 probes within 10 minutes
_tarpit_hits: dict[str, list] = {}
_TARPIT_WINDOW = 600
_TARPIT_THRESH = 8

def _tarpit_check(src_ip: str) -> bool:
    now = time.time()
    hits = _tarpit_hits.setdefault(src_ip, [])
    hits.append(now)
    _tarpit_hits[src_ip] = [t for t in hits if now - t < _TARPIT_WINDOW]
    return len(_tarpit_hits[src_ip]) > _TARPIT_THRESH

def _nb_wrap(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data

def _nb_read(data: bytes):
    if len(data) < 4:
        return None, data
    nb_len = struct.unpack(">I", data[:4])[0]
    total = 4 + nb_len
    if len(data) < total:
        return None, data
    return data[4:total], data[total:]


# ── SMB2 header ──────────────────────────────────────────────────────────────

def _make_hdr(cmd, msg_id=0, status=ST_OK, session_id=0, tree_id=0):
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        SMB2_MAGIC, 64, 0,
        status, cmd, 1,
        0x00000001,
        0, msg_id,
        0, tree_id, session_id,
        b"\x00" * 16,
    )

def _parse_hdr(data: bytes):
    if len(data) < HDR_LEN or data[:4] != SMB2_MAGIC:
        return None
    _, ss, cc, status, cmd, crd, flags, nxt, msg_id, pid, tree_id, sess_id, sig = \
        struct.unpack_from("<4sHHIHHIIQIIQ16s", data)
    return dict(cmd=cmd, status=status, msg_id=msg_id,
                session_id=sess_id, tree_id=tree_id,
                body=data[HDR_LEN:])


# ── NTLM ─────────────────────────────────────────────────────────────────────

NTLM_FLAGS_CHALLENGE = (
    0x00000001 | 0x00000004 | 0x00000020 | 0x00000200 |
    0x00008000 | 0x00010000 | 0x00020000 | 0x00400000 |
    0x02000000 | 0x20000000 | 0x40000000 | 0x80000000
)

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    enc = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(enc)]) + enc

def _der_tag(tag, data):
    return bytes([tag]) + _der_len(len(data)) + data

_NTLMSSP_OID = b"\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"

# Full AD identity advertised in the NTLM challenge — makes us look like a real,
# juicy domain-joined member (signing NOT required), so credential-spray/relay
# tools that fingerprint first proceed to actually authenticate (→ we get Type3).
_DNS_DOMAIN = os.environ.get("SMB_DNS_DOMAIN", "corp.local")
_DNS_HOST   = os.environ.get("SMB_DNS_HOST", HOSTNAME.lower() + "." + "corp.local")


def _av(t, val_utf16):
    return struct.pack("<HH", t, len(val_utf16)) + val_utf16


def _make_ntlm_type2(challenge8: bytes, domain: str = DOMAIN) -> bytes:
    domain_enc   = domain.encode("utf-16-le")
    hostname_enc = HOSTNAME.encode("utf-16-le")
    dnsdom_enc   = _DNS_DOMAIN.encode("utf-16-le")
    dnshost_enc  = _DNS_HOST.encode("utf-16-le")
    # FILETIME (100ns ticks since 1601) — present on real servers; its absence is a tell.
    ft = int((time.time() + 11644473600) * 10_000_000)
    av_pairs = (
        _av(2, domain_enc)    +   # NetBIOS domain
        _av(1, hostname_enc)  +   # NetBIOS computer
        _av(4, dnsdom_enc)    +   # DNS domain
        _av(3, dnshost_enc)   +   # DNS computer (FQDN)
        _av(5, dnsdom_enc)    +   # DNS forest/tree
        struct.pack("<HH", 7, 8) + struct.pack("<Q", ft) +   # timestamp
        struct.pack("<HH", 0, 0)  # EOL
    )
    target_name_offset = 56
    target_info_offset = target_name_offset + len(domain_enc)
    return (
        NTLMSSP_SIG +
        struct.pack("<I", 2) +
        struct.pack("<HHI", len(domain_enc), len(domain_enc), target_name_offset) +
        struct.pack("<I", NTLM_FLAGS_CHALLENGE) +
        challenge8 +
        b"\x00" * 8 +
        struct.pack("<HHI", len(av_pairs), len(av_pairs), target_info_offset) +
        b"\x00" * 8 +
        domain_enc +
        av_pairs
    )

def _wrap_spnego_challenge(ntlm_type2: bytes) -> bytes:
    tok      = _der_tag(0x04, ntlm_type2)
    state    = _der_tag(0x0a, b"\x01")
    seq_body = _der_tag(0xa0, state) + _der_tag(0xa1, _NTLMSSP_OID) + _der_tag(0xa2, tok)
    return _der_tag(0xa1, _der_tag(0x30, seq_body))

def _find_ntlmssp(data: bytes) -> bytes | None:
    idx = data.find(NTLMSSP_SIG)
    return data[idx:] if idx >= 0 else None

def _parse_ntlm_type3(blob: bytes) -> dict:
    result = {}
    if len(blob) < 12 or blob[:8] != NTLMSSP_SIG:
        return result
    if struct.unpack_from("<I", blob, 8)[0] != 3:
        return result
    def _field(offset):
        ln, mx, off = struct.unpack_from("<HHI", blob, offset)
        return blob[off:off+ln] if off + ln <= len(blob) else b""
    def _utf16(b):
        try:
            return b.decode("utf-16-le")
        except Exception:
            return b.hex()
    lm_resp     = _field(12)
    nt_resp     = _field(20)
    domain      = _utf16(_field(28))
    username    = _utf16(_field(36))
    workstation = _utf16(_field(44))
    result["username"]    = username
    result["domain"]      = domain
    result["workstation"] = workstation
    if len(nt_resp) >= 16:
        result["nt_proof_str"] = nt_resp[:16].hex()
        result["nt_blob"]      = nt_resp[16:].hex()
        result["lm_response"]  = lm_resp.hex()
    return result

def _make_hashcat(username, domain, challenge8, ntlm3: dict) -> str | None:
    if not ntlm3.get("nt_proof_str") or not ntlm3.get("nt_blob"):
        return None
    return f"{username}::{domain}:{challenge8.hex()}:{ntlm3['nt_proof_str']}:{ntlm3['nt_blob']}"

def _make_spnego_negotiate_blob() -> bytes:
    mech_list    = _der_tag(0x30, _NTLMSSP_OID)
    seq_body     = _der_tag(0xa0, mech_list)
    negtokeninit = _der_tag(0x30, seq_body)
    inner = _der_tag(0x06, b"\x2b\x06\x01\x05\x05\x02") + _der_tag(0xa0, negtokeninit)
    return _der_tag(0x60, inner)


# ── DCERPC named pipe support ─────────────────────────────────────────────────

def _is_dcerpc(data: bytes) -> bool:
    return len(data) >= 16 and data[0] == 5 and data[1] == 0

# NDR32 transfer syntax UUID {8a885d04-1ceb-11c9-9fe8-08002b104860} v2.0
_NDR32_UUID = bytes.fromhex("045d888aeb1cc9119fe808002b104860")
_NDR32_XFER = _NDR32_UUID + struct.pack("<HH", 2, 0)

# Consistent fake context handle — 20 bytes, makes tools think they have a valid handle
_FAKE_HANDLE = b"\x77\x55\x33\x11\xaa\xbb\xcc\xdd" * 2 + b"\x00\x00\x00\x00"

def _make_dcerpc_bind_ack(call_id: int) -> bytes:
    """
    Proper DCERPC BIND_ACK that accepts any interface with NDR32.
    Without this, Impacket/Mimikatz/BloodHound hang waiting for a valid response.
    """
    sec_addr_str = b"\x00"  # NUL → empty port spec
    pad = 1                  # align after length(2)+str(1) = 3 bytes, pad to 4
    body = (
        struct.pack("<HHI", 0x1000, 0x1000, 0x1A2B3C4D) +  # max_xmit, max_recv, assoc_group
        struct.pack("<H", len(sec_addr_str)) + sec_addr_str + b"\x00" * pad +
        struct.pack("<HH", 1, 0) +     # ctx_items=1, align
        struct.pack("<HH", 0, 0) +     # result=acceptance, reason=0
        _NDR32_XFER                    # transfer syntax accepted
    )
    frag_len = 16 + len(body)
    hdr = struct.pack("<BBBBIHHI",
        5, 0, DCERPC_BIND_ACK, 0x03, 0x10000000,
        frag_len, 0, call_id)
    return hdr + body

def _make_dcerpc_response(call_id: int, payload: bytes) -> bytes:
    resp_body = struct.pack("<IHBx", len(payload), 0, 0) + payload
    frag_len  = 16 + len(resp_body)
    hdr = struct.pack("<BBBBIHHI",
        5, 0, DCERPC_RESPONSE, 0x03, 0x10000000,
        frag_len, 0, call_id)
    return hdr + resp_body

def _dcerpc_rpc_response(pipe_name: str, call_id: int, opnum: int, body: bytes) -> bytes:
    """
    Fake RPC response for common attack-tool opnums.
    Returning SUCCESS (NTSTATUS=0) keeps bots running through their full attack chain,
    maximizing the amount of intelligence we capture.
    """
    ok  = b"\x00\x00\x00\x00"    # NTSTATUS_SUCCESS
    p   = pipe_name.lower().strip("\\").split("\\")[-1]

    if p == "samr":
        if opnum in (0, 64, 65):       # SamrConnect, Connect2, Connect5
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 1:               # SamrCloseHandle
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 5:               # SamrEnumerateDomainsInSamServer
            corp_w    = "CORP".encode("utf-16-le")
            builtin_w = "Builtin".encode("utf-16-le")
            # Minimal domain list: count=2, then two UNICODE_STRING entries
            payload = (struct.pack("<II", 2, 2) +
                       struct.pack("<HHI", len(corp_w), len(corp_w) + 2, 0x20) + corp_w + b"\x00\x00" +
                       struct.pack("<HHI", len(builtin_w), len(builtin_w) + 2, 0x20) + builtin_w + b"\x00\x00" +
                       struct.pack("<I", 2) + ok)
            return _make_dcerpc_response(call_id, payload)
        elif opnum in (7, 8, 34, 36):  # SamrOpenDomain, SamrLookup*, SamrOpenUser
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 13:              # SamrEnumerateGroupsInDomain — empty
            return _make_dcerpc_response(call_id, struct.pack("<III", 0, 0, 0) + ok)
        elif opnum == 14:              # SamrEnumerateAliasesInDomain
            return _make_dcerpc_response(call_id, struct.pack("<III", 0, 0, 0) + ok)
        elif opnum == 18:              # SamrCreateUserInDomain — deny (looks like sec control)
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + b"\x22\x00\x00\xC0")
        elif opnum in (57, 58, 59, 60):# SamrGetMembersInGroup etc.
            return _make_dcerpc_response(call_id, struct.pack("<II", 0, 0) + ok)
        else:
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)

    elif p == "lsarpc":
        if opnum in (6, 72):           # LsarOpenPolicy, LsarOpenPolicy2
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 7:               # LsarQueryInformationPolicy
            corp_w = "CORP".encode("utf-16-le")
            payload = (_FAKE_HANDLE +
                       struct.pack("<HHI", len(corp_w), len(corp_w)+2, 0) + corp_w +
                       ok)
            return _make_dcerpc_response(call_id, payload)
        elif opnum in (14, 15):        # LsarLookupNames, LsarLookupSids
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 44:              # LsarLookupNames2
            return _make_dcerpc_response(call_id, struct.pack("<III", 0, 0, 0) + ok)
        elif opnum in (1, 2, 40, 41):  # LsarClose, EnumeratePrivileges etc.
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        else:
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)

    elif p == "srvsvc":
        if opnum == 15:                # NetrShareEnum — return our real share list
            names = ["SHARE", "C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "PRINT$"]
            payload = struct.pack("<II", 1, len(names))
            for n in names:
                nw = n.encode("utf-16-le")
                payload += struct.pack("<HHI", len(nw), len(nw)+2, 0) + nw + b"\x00\x00"
            payload += struct.pack("<I", len(names)) + ok
            return _make_dcerpc_response(call_id, payload)
        elif opnum in (16, 1, 2):      # NetrShareGetInfo / ServerGetInfo etc.
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 11:              # NetrPathCanonicalizeW
            return _make_dcerpc_response(call_id, struct.pack("<I", 0) + ok)
        else:
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)

    elif p == "svcctl":
        if opnum in (0, 15, 16):       # ROpenSCManagerW, ROpenServiceW, RQueryServiceConfigW
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 12:              # RCreateServiceW — let them "succeed" to capture start attempt
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 6:               # RQueryServiceStatus: RUNNING
            status = struct.pack("<IIIIIII", 0x20, 4, 5, 0x01FF, 0, 0, 0)
            return _make_dcerpc_response(call_id, status + ok)
        elif opnum in (19, 31):        # RStartServiceW, RControlService
            return _make_dcerpc_response(call_id, ok)
        elif opnum == 24:              # RDeleteService
            return _make_dcerpc_response(call_id, ok)
        else:
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)

    elif p == "winreg":
        if opnum in (0, 1, 2, 3, 4):  # OpenHive ops (HKLM, HKCU, HKCR, etc.)
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        elif opnum == 6:               # RegQueryInfoKey
            return _make_dcerpc_response(call_id,
                struct.pack("<IIIIIIIIIIII", 5, 0, 32, 0, 5, 64, 0, 1, 0, 0, 0, 0) + ok)
        elif opnum == 10:              # RegSetValueEx
            return _make_dcerpc_response(call_id, ok)
        elif opnum == 17:              # RegQueryValueEx
            val = "gpu-node-07".encode("utf-16-le")
            return _make_dcerpc_response(call_id,
                struct.pack("<II", 1, len(val)) + val + ok)
        elif opnum in (5, 15, 16, 22): # RegCloseKey, RegEnumKey, RegEnumValue, RegOpenKeyEx
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        else:
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)

    elif p == "eventlog":
        if opnum in (0, 7):            # ElfrOpenBELW, ElfrReadELW
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)
        else:
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)

    elif p == "wkssvc":
        if opnum == 0:                 # NetrWkstaGetInfo
            return _make_dcerpc_response(call_id, struct.pack("<I", 100) + _FAKE_HANDLE + ok)
        else:
            return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)

    else:
        return _make_dcerpc_response(call_id, _FAKE_HANDLE + ok)


def _handle_dcerpc_write(pipe_name: str, data: bytes, rpc_log: list) -> bytes | None:
    """
    Process a DCERPC packet written to a named pipe.
    Returns the response to queue for next READ, or None if not DCERPC.
    """
    if not _is_dcerpc(data):
        return None
    ptype   = data[2]
    call_id = struct.unpack_from("<I", data, 12)[0] if len(data) >= 16 else 0

    if ptype == DCERPC_BIND:
        rpc_log.append({"op": "BIND", "pipe": pipe_name, "call_id": call_id})
        return _make_dcerpc_bind_ack(call_id)

    elif ptype == DCERPC_REQUEST and len(data) >= 24:
        opnum = struct.unpack_from("<H", data, 22)[0]
        rpc_log.append({
            "op":      "CALL",
            "pipe":    pipe_name,
            "opnum":   opnum,
            "call_id": call_id,
            "body_hex":data[24:min(len(data), 96)].hex(),
        })
        return _dcerpc_rpc_response(pipe_name, call_id, opnum, data[24:])

    return None


# ── SMB2 response builders ────────────────────────────────────────────────────

def _resp_negotiate(msg_id: int) -> bytes:
    spnego = _make_spnego_negotiate_blob()
    sec_buf_offset = HDR_LEN + 65
    ft = int((time.time() + 11644473600) * 1e7)
    body = (
        struct.pack("<HHH", 65, 0x0001, 0x0300) +
        b"\x00\x00" +
        _SERVER_GUID +
        struct.pack("<IIIIQQHHxxxx",
            0x0000007f, 0x00800000, 0x00800000, 0x00800000,
            ft, 0, sec_buf_offset, len(spnego))
    )
    hdr = _make_hdr(CMD_NEGOTIATE, msg_id=msg_id)
    return _nb_wrap(hdr + body + spnego)

def _resp_sess_challenge(msg_id: int, sess_id: int, spnego_blob: bytes) -> bytes:
    sec_buf_offset = HDR_LEN + 9
    body = struct.pack("<HHHH", 9, 0, sec_buf_offset, len(spnego_blob))
    hdr  = _make_hdr(CMD_SESS_SETUP, msg_id=msg_id, status=ST_MORE, session_id=sess_id)
    return _nb_wrap(hdr + body + spnego_blob)

def _resp_sess_ok(msg_id: int, sess_id: int) -> bytes:
    body = struct.pack("<HHHH", 9, 0, HDR_LEN + 9, 0)
    hdr  = _make_hdr(CMD_SESS_SETUP, msg_id=msg_id, session_id=sess_id)
    return _nb_wrap(hdr + body)

def _resp_tree_connect(msg_id: int, sess_id: int, tree_id: int, share_type: int = 0x01) -> bytes:
    body = struct.pack("<HBBHIIII",
        16, share_type, 0, 0, 0x00000000, 0x001f01ff, 0, 0)
    hdr = _make_hdr(CMD_TREE_CONN, msg_id=msg_id, session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body)

def _resp_tree_disconnect(msg_id: int, sess_id: int) -> bytes:
    body = struct.pack("<HH", 4, 0)
    hdr  = _make_hdr(CMD_TREE_DISC, msg_id=msg_id, session_id=sess_id)
    return _nb_wrap(hdr + body)

def _resp_create_with_size(msg_id: int, sess_id: int, tree_id: int,
                            fid: bytes, eof_size: int = 4096, is_dir: bool = False) -> bytes:
    ft    = int((time.time() + 11644473600) * 1e7)
    attrs = 0x10 if is_dir else 0x20
    alloc = 0 if is_dir else max(4096, ((eof_size + 4095) // 4096) * 4096)
    body  = struct.pack("<HBBI", 89, 0, 0, 0x00000001)
    body += struct.pack("<QQQQ", ft, ft, ft, ft)
    body += struct.pack("<QQII", alloc, eof_size, attrs, 0)
    body += fid
    body += struct.pack("<II", 0, 0)
    hdr   = _make_hdr(CMD_CREATE, msg_id=msg_id, session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body)

def _resp_close(msg_id: int, sess_id: int, tree_id: int) -> bytes:
    body = struct.pack("<HHI", 60, 0, 0) + b"\x00" * 52
    hdr  = _make_hdr(CMD_CLOSE, msg_id=msg_id, session_id=sess_id)
    return _nb_wrap(hdr + body)

def _resp_read(msg_id: int, sess_id: int, tree_id: int) -> bytes:
    body = struct.pack("<HBxIIxx", 17, HDR_LEN + 16, 0, 0)
    hdr  = _make_hdr(CMD_READ, msg_id=msg_id, session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body)

def _resp_read_data(msg_id: int, sess_id: int, tree_id: int, data: bytes) -> bytes:
    data_off = HDR_LEN + 16
    body = struct.pack("<HBxIIxx", 17, data_off, len(data), 0)
    hdr  = _make_hdr(CMD_READ, msg_id=msg_id, session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body + data)

def _resp_write(msg_id: int, sess_id: int, tree_id: int, count: int) -> bytes:
    body = struct.pack("<HHIIxx", 17, 0, count, 0)
    hdr  = _make_hdr(CMD_WRITE, msg_id=msg_id, session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body)

def _resp_query_dir(msg_id: int, sess_id: int, tree_id: int) -> bytes:
    body = struct.pack("<HHI", 9, HDR_LEN + 8, 0)
    hdr  = _make_hdr(CMD_QUERY_DIR, msg_id=msg_id, status=ST_NOFILE,
                     session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body)

def _resp_query_dir_real(msg_id: int, sess_id: int, tree_id: int, data: bytes) -> bytes:
    if not data:
        return _resp_query_dir(msg_id, sess_id, tree_id)
    body = struct.pack("<HHI", 9, HDR_LEN + 8, len(data))
    hdr  = _make_hdr(CMD_QUERY_DIR, msg_id=msg_id, status=ST_OK,
                     session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body + data)

def _resp_ioctl(msg_id: int, sess_id: int, tree_id: int, ctl_code: int,
                out_data: bytes = b"") -> bytes:
    out_off = HDR_LEN + 48 if out_data else 0
    body = (struct.pack("<HHI", 49, 0, ctl_code) +
            b"\xff" * 16 +
            struct.pack("<IIIIII", 0, 0, out_off, len(out_data), 0, 0))
    hdr = _make_hdr(CMD_IOCTL, msg_id=msg_id, session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body + out_data)

def _resp_query_info(msg_id: int, sess_id: int, tree_id: int,
                     payload: bytes = b"") -> bytes:
    off  = HDR_LEN + 8 if payload else 0
    body = struct.pack("<HHI", 9, off, len(payload))
    hdr  = _make_hdr(CMD_QUERY_INFO, msg_id=msg_id, session_id=sess_id, tree_id=tree_id)
    return _nb_wrap(hdr + body + payload)

def _resp_ok_empty(cmd: int, msg_id: int, sess_id: int) -> bytes:
    body = struct.pack("<HHI", 9, 0, 0)
    hdr  = _make_hdr(cmd, msg_id=msg_id, status=ST_OK, session_id=sess_id)
    return _nb_wrap(hdr + body)

def _resp_generic_error(cmd: int, msg_id: int, sess_id: int, status=ST_NOTIMPL) -> bytes:
    body = struct.pack("<HHI", 9, 0, 0)
    hdr  = _make_hdr(cmd, msg_id=msg_id, status=status, session_id=sess_id)
    return _nb_wrap(hdr + body)

def _resp_echo(msg_id: int) -> bytes:
    body = struct.pack("<HH", 4, 0)
    hdr  = _make_hdr(CMD_ECHO, msg_id=msg_id)
    return _nb_wrap(hdr + body)


# ── SMB1 response builders ────────────────────────────────────────────────────

_SMB1_FLAGS  = 0x88
_SMB1_FLAGS2 = 0xC853

def _make_smb1_hdr(cmd: int, status: int = 0, pid: int = 0,
                   uid: int = 0, mid: int = 0, tid: int = 0xFFFF) -> bytes:
    return (
        b"\xffSMB" + bytes([cmd]) +
        struct.pack("<I", status) + bytes([_SMB1_FLAGS]) +
        struct.pack("<H", _SMB1_FLAGS2) +
        b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" +
        struct.pack("<HHHH", tid, pid & 0xFFFF, uid, mid)
    )

def _parse_smb1_dialect_index(payload: bytes) -> int:
    try:
        body = payload[32:]
        wc   = body[0]
        bc   = struct.unpack_from("<H", body, 1 + wc * 2)[0]
        data = body[3 + wc * 2 : 3 + wc * 2 + bc]
        idx, pos, found = 0, 0, -1
        while pos < len(data):
            if data[pos] != 0x02: break
            end = data.find(b"\x00", pos + 1)
            if end < 0: break
            if data[pos+1:end] == b"NT LM 0.12":
                found = idx
            idx += 1
            pos = end + 1
        return found if found >= 0 else max(0, idx - 1)
    except Exception:
        return 7

def _resp_smb1_negotiate(pid=0, mid=0, dialect_idx=7) -> bytes:
    spnego = _make_spnego_negotiate_blob()
    ft     = int((time.time() + 11644473600) * 1e7)
    params = struct.pack("<HBHHIIIIQhB",
        dialect_idx, 0x07, 50, 1, 65535, 65536, 0, 0x800083fd, ft, 0, 0)
    sec_data = _SERVER_GUID + spnego
    body = bytes([0x11]) + params + struct.pack("<H", len(sec_data)) + sec_data
    return _nb_wrap(_make_smb1_hdr(0x72, pid=pid, mid=mid) + body)

def _resp_smb1_sess_challenge(pid, uid, mid, spnego) -> bytes:
    params = struct.pack("<BBHHH", 0xFF, 0, 0, 0, len(spnego))
    body   = bytes([0x04]) + params + struct.pack("<H", len(spnego)) + spnego
    return _nb_wrap(_make_smb1_hdr(0x73, status=0xC0000016, pid=pid, uid=uid, mid=mid) + body)

def _resp_smb1_sess_ok(pid, uid, mid) -> bytes:
    params = struct.pack("<BBHHH", 0xFF, 0, 0, 0, 0)
    body   = bytes([0x04]) + params + struct.pack("<H", 0)
    return _nb_wrap(_make_smb1_hdr(0x73, status=0, pid=pid, uid=uid, mid=mid) + body)


# ── Fake file system ──────────────────────────────────────────────────────────
# (name, size_bytes, is_dir)
_FAKE_SHARE_DIRS: dict[str, list] = {
    "SHARE": [
        ("passwords.txt",         1523,         False),
        ("accounts_2026.xlsx",    89432,        False),
        ("backup_db_export.sql",  234567,       False),
        ("employee_data.csv",     145023,       False),
        ("wallet.dat",            87432,        False),
        ("keystore.json",         3241,         False),
        ("aws-credentials.txt",   892,          False),
        ("config.json",           3421,         False),
        ("ssh_keys.zip",          45231,        False),
        (".env",                  1842,         False),
        ("terraform.tfstate",     52348,        False),
        ("Documents",             0,            True),
        ("Backups",               0,            True),
        ("Scripts",               0,            True),
    ],
    "C$": [
        ("Program Files",         0,            True),
        ("Program Files (x86)",   0,            True),
        ("Windows",               0,            True),
        ("Users",                 0,            True),
        ("inetpub",               0,            True),
        ("Temp",                  0,            True),
        ("pagefile.sys",          4294967296,   False),
        ("hiberfil.sys",          2147483648,   False),
    ],
    "ADMIN$": [
        ("explorer.exe",          4456448,      False),
        ("regedit.exe",           369664,       False),
        ("notepad.exe",           228352,       False),
        ("System32",              0,            True),
        ("SysWOW64",              0,            True),
        ("WinSxS",                0,            True),
        ("Temp",                  0,            True),
    ],
    "IPC$": [
        ("PIPE",                  0,            True),
        ("srvsvc",                0,            False),
        ("samr",                  0,            False),
        ("lsarpc",                0,            False),
        ("netlogon",              0,            False),
        ("winreg",                0,            False),
        ("svcctl",                0,            False),
        ("eventlog",              0,            False),
        ("wkssvc",                0,            False),
        ("browser",               0,            False),
    ],
    "NETLOGON": [
        ("netlogon.pol",          2048,         False),
        ("GptTmpl.inf",           4096,         False),
        ("Scripts",               0,            True),
    ],
    "SYSVOL": [
        ("CORP",                  0,            True),
        ("Policies",              0,            True),
        ("Default Domain Policy.admx", 8192,   False),
        ("scripts",               0,            True),
    ],
    "PRINT$": [
        ("W32X86",                0,            True),
        ("x64",                   0,            True),
        ("win40",                 0,            True),
        ("COLOR",                 0,            True),
    ],
    "default": [
        ("readme.txt",            512,          False),
        ("System Volume Information", 0,        True),
        ("$RECYCLE.BIN",          0,            True),
    ],
}

# Subdirectory listings — keyed by normalized UNC path (uppercased, no leading \\HOST\)
_SUBDIR_LISTINGS: dict[str, list] = {
    "C$\\WINDOWS": [
        ("System32",          0,           True),
        ("SysWOW64",          0,           True),
        ("Temp",              0,           True),
        ("Logs",              0,           True),
        ("inf",               0,           True),
        ("explorer.exe",      4456448,     False),
        ("notepad.exe",       228352,      False),
        ("regedit.exe",       369664,      False),
        ("win.ini",           92,          False),
    ],
    "C$\\WINDOWS\\SYSTEM32": [
        ("cmd.exe",           392704,      False),
        ("powershell.exe",    456704,      False),
        ("net.exe",           92160,       False),
        ("net1.exe",          92160,       False),
        ("schtasks.exe",      226304,      False),
        ("reg.exe",           172032,      False),
        ("whoami.exe",        73216,       False),
        ("wmic.exe",          543232,      False),
        ("rundll32.exe",      71168,       False),
        ("mshta.exe",         135168,      False),
        ("certutil.exe",      1312256,     False),
        ("bitsadmin.exe",     303616,      False),
        ("sc.exe",            189440,      False),
        ("tasklist.exe",      111104,      False),
        ("wevtutil.exe",      244736,      False),
        ("ntdll.dll",         2019328,     False),
        ("kernel32.dll",      1012224,     False),
        ("advapi32.dll",      718848,      False),
        ("drivers",           0,           True),
        ("config",            0,           True),
        ("spool",             0,           True),
    ],
    "C$\\USERS": [
        ("Administrator",     0,           True),
        ("deploy",            0,           True),
        ("svc_gpu",           0,           True),
        ("Public",            0,           True),
        ("Default",           0,           True),
    ],
    "C$\\USERS\\ADMINISTRATOR": [
        ("Desktop",           0,           True),
        ("Documents",         0,           True),
        ("Downloads",         0,           True),
        (".ssh",              0,           True),
        (".aws",              0,           True),
        (".env",              1842,        False),
        ("wallet.dat",        87432,       False),
        ("config.json",       3421,        False),
        ("aws-credentials.txt", 892,       False),
    ],
    "C$\\USERS\\ADMINISTRATOR\\.SSH": [
        ("id_ed25519",        464,         False),
        ("id_ed25519.pub",    120,         False),
        ("authorized_keys",   120,         False),
        ("known_hosts",       2048,        False),
    ],
    "C$\\USERS\\ADMINISTRATOR\\.AWS": [
        ("credentials",       892,         False),
        ("config",            64,          False),
    ],
    "C$\\USERS\\DEPLOY": [
        ("Desktop",           0,           True),
        ("Documents",         0,           True),
        (".ssh",              0,           True),
        (".aws",              0,           True),
        (".env",              1842,        False),
        ("docker-compose.yml",1024,        False),
        ("terraform.tfstate", 52348,       False),
    ],
    "SHARE\\DOCUMENTS": [
        ("Q4_Strategy_2026.docx",   89231,  False),
        ("salary_review_2026.xlsx", 45123,  False),
        ("board_presentation.pptx", 234567, False),
        ("employee_contracts",      0,      True),
    ],
    "SHARE\\BACKUPS": [
        ("backup_2026-06-01.tar.gz",  12345678, False),
        ("backup_2026-05-01.tar.gz",  11234567, False),
        ("db_dump_2026-06-01.sql.gz", 2345678,  False),
        ("keys_backup.zip",           45231,    False),
    ],
    "SHARE\\SCRIPTS": [
        ("deploy.sh",             4096,    False),
        ("backup.sh",             2048,    False),
        ("cleanup.sh",            1024,    False),
        ("install_miner.sh",      8192,    False),
    ],
    "NETLOGON\\SCRIPTS": [
        ("logon.bat",             512,     False),
        ("logoff.bat",            256,     False),
        ("MapDrives.ps1",         2048,    False),
    ],
    "SYSVOL\\CORP": [
        ("Policies",              0,       True),
        ("scripts",               0,       True),
        ("DfsrPrivate",           0,       True),
    ],
}

# Named pipes that indicate post-exploitation tools
_EXPLOIT_PIPES = {
    "srvsvc": "net-enum", "samr": "credential-dump", "netlogon": "pass-the-hash",
    "lsarpc": "lsa-dump", "winreg": "registry-enum", "svcctl": "service-enum",
    "wkssvc": "workstation-enum", "eventlog": "log-clearing",
}

RANSOMWARE_THRESHOLD = 6


def _pack_dir_entries(full_path: str) -> bytes:
    """Build FILE_ID_BOTH_DIR_INFORMATION for a directory listing."""
    # Normalize: strip \\HOSTNAME\ prefix and trailing slashes
    norm = full_path.upper()
    for pfx in (f"\\\\{HOSTNAME.upper()}\\", f"//{HOSTNAME.upper()}/"):
        if norm.startswith(pfx):
            norm = norm[len(pfx):]
    norm = norm.strip("\\").strip("/")

    # Try full-path subdir listing first, then fall back to share root
    entries = (_SUBDIR_LISTINGS.get(norm) or
               _SUBDIR_LISTINGS.get(norm.replace("/", "\\")) or
               _FAKE_SHARE_DIRS.get(norm.split("\\")[-1]) or
               _FAKE_SHARE_DIRS.get(norm.split("/")[-1]) or
               _FAKE_SHARE_DIRS["default"])

    ft_now  = int((time.time() + 11644473600) * 1e7)
    ft_week = ft_now - int(86400 * 7 * 1e7)
    blobs   = []

    for i, (name, size, is_dir) in enumerate(entries):
        name_enc = name.encode("utf-16-le")
        attrs    = 0x10 if is_dir else 0x20
        alloc    = 0 if is_dir else max(4096, ((size + 4095) // 4096) * 4096)
        blob     = struct.pack("<II", 0, 0)
        blob    += struct.pack("<QQQQ", ft_week, ft_now, ft_now, ft_now)
        blob    += struct.pack("<QQ", size, alloc)
        blob    += struct.pack("<III", attrs, len(name_enc), 0)
        blob    += struct.pack("<BB", 0, 0) + b"\x00" * 24
        blob    += struct.pack("<Q", i + 1) + name_enc
        pad      = (8 - len(blob) % 8) % 8
        blob    += b"\x00" * pad
        blobs.append(bytearray(blob))

    for i in range(len(blobs) - 1):
        struct.pack_into("<I", blobs[i], 0, len(blobs[i]))

    return b"".join(blobs)


# ── Canary file content ────────────────────────────────────────────────────────

_CANARY_READ: dict | None = None

# Inline canary for files not in data_theft.py
_BACKUP_SQL = """-- GPU Cluster Production DB Dump
-- Host: prod-db-cluster.internal  Database: gpu_cluster
-- Server version: 8.0.36-MySQL Community Server

SET NAMES utf8mb4;

CREATE TABLE users (
  id int NOT NULL AUTO_INCREMENT,
  username varchar(64) NOT NULL,
  password_hash varchar(255) NOT NULL,
  email varchar(255),
  role enum('admin','user','readonly') DEFAULT 'user',
  PRIMARY KEY (id)
);

INSERT INTO users VALUES
(1,'admin','$2y$12$Kx7.2Xn9mPnotreadhashXXXXXX','admin@corp.internal','admin'),
(2,'svc_gpu','$2y$12$Pr0dpasshashXXXXXXXXXXXXXX','svc@corp.internal','user'),
(3,'deploy','$2y$12$deploypassXXXXXXXXXXXXXXXX','deploy@corp.internal','admin');

CREATE TABLE api_keys (
  id int NOT NULL AUTO_INCREMENT,
  user_id int NOT NULL,
  api_key varchar(64) NOT NULL,
  created_at timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

INSERT INTO api_keys VALUES
(1,1,'sk-prod-5f3a2b1c4d8e9f0a1b2c3d4e5f6a7b8c','2026-01-15 03:22:11'),
(2,3,'sk-deploy-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6','2026-03-01 11:45:00');

CREATE TABLE gpu_jobs (
  id int NOT NULL AUTO_INCREMENT,
  job_name varchar(255),
  wallet_addr varchar(255),
  pool_host varchar(255),
  created_at timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);
"""

_EMPLOYEE_CSV = """id,first_name,last_name,email,department,salary,phone
1,Michael,Hoffman,m.hoffman@corp.internal,Engineering,145000,+49-171-5550001
2,Sarah,Chen,s.chen@corp.internal,Engineering,138000,+49-171-5550002
3,Andreas,Mueller,a.mueller@corp.internal,IT Operations,122000,+49-171-5550003
4,Jennifer,Torres,j.torres@corp.internal,Finance,118000,+49-171-5550004
5,David,Nakamura,d.nakamura@corp.internal,Engineering,152000,+49-171-5550005
6,Lisa,Weber,l.weber@corp.internal,HR,98000,+49-171-5550006
7,Robert,Schmidt,r.schmidt@corp.internal,Engineering,141000,+49-171-5550007
8,Anna,Fischer,a.fischer@corp.internal,Management,210000,+49-171-5550008
9,Thomas,Bauer,t.bauer@corp.internal,IT Operations,115000,+49-171-5550009
10,Maria,Wagner,m.wagner@corp.internal,Finance,109000,+49-171-5550010
"""

_TERRAFORM_STATE = json.dumps({
    "version": 4,
    "terraform_version": "1.7.4",
    "serial": 42,
    "resources": [
        {
            "type": "aws_instance",
            "name": "gpu_node",
            "instances": [{
                "attributes": {
                    "ami": "ami-0c55b159cbfafe1f0",
                    "instance_type": "p3.8xlarge",
                    "private_ip": "10.0.1.50",
                    "tags": {"Name": "gpu-node-07", "Env": "prod"},
                }
            }]
        },
        {
            "type": "aws_iam_access_key",
            "name": "deploy",
            "instances": [{
                "attributes": {
                    "id": "AKIAIOSFODNN7EXAMPLE",
                    "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "user": "deploy",
                }
            }]
        }
    ]
}, indent=2)


def _get_canary_content(path: str) -> bytes | None:
    global _CANARY_READ
    if _CANARY_READ is None:
        try:
            from data_theft import (
                AWS_CREDENTIALS_FILE, FAKE_ENV_FILE, FAKE_CONFIG_JSON,
                FAKE_BITCOIN_WALLET, FAKE_ETHEREUM_KEYSTORE, FAKE_XMR_WALLET_FILE,
                CANARY_SSH_PRIVATE_KEY, CANARY_SSH_PUBLIC,
            )
            _CANARY_READ = {
                # Core credential files
                "passwords.txt": (
                    "# GPU Cluster — Credentials\r\n"
                    "PROD-DB host: prod-db-cluster.internal\r\n"
                    "  user: svc_gpu  pass: Kx7!2Xn9mP\r\n"
                    "REDIS:  redisPass2026!\r\n"
                    "SSH root: !Sup3rS3cr3t#\r\n"
                    "AWS: see aws-credentials.txt\r\n"
                    "Miner pool: pool.hashvault.pro:443\r\n"
                ).encode(),
                "aws-credentials.txt":  AWS_CREDENTIALS_FILE.encode(),
                "credentials":          AWS_CREDENTIALS_FILE.encode(),  # .aws/credentials
                "config.json":          FAKE_CONFIG_JSON.encode(),
                "wallet.dat":           FAKE_BITCOIN_WALLET.encode(),
                "keystore.json":        FAKE_ETHEREUM_KEYSTORE.encode(),
                ".env":                 FAKE_ENV_FILE.encode(),
                # SSH keys
                "id_ed25519":           CANARY_SSH_PRIVATE_KEY.encode(),
                "id_ed25519.pub":       (CANARY_SSH_PUBLIC + "\n").encode(),
                "authorized_keys":      (CANARY_SSH_PUBLIC + "\n").encode(),
                # Crypto
                ".wallet":              FAKE_XMR_WALLET_FILE.encode(),
                # Generated inline
                "backup_db_export.sql": _BACKUP_SQL.encode(),
                "employee_data.csv":    _EMPLOYEE_CSV.encode(),
                "terraform.tfstate":    _TERRAFORM_STATE.encode(),
                # Stubs
                "ssh_keys.zip":         b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 26,
                "accounts_2026.xlsx": (
                    b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00" + b"\x00" * 30 +
                    b"[Content_Types].xml" + b"\x00" * 8
                ),
                "netlogon.pol": (
                    b"\x50\x52\x65\x67\x01\x00\x00\x00"  # PReg signature
                    b"[Software\\Policies\\Microsoft]\r\n"
                    b"EnableFirewall=DWORD:0\r\n"
                    b"DisableAntiSpyware=DWORD:1\r\n"
                ),
            }
        except Exception:
            _CANARY_READ = {}

    fname = path.replace("\\", "/").split("/")[-1]
    return _CANARY_READ.get(fname)


def _lookup_file_size(path: str) -> tuple[int, bool]:
    """Return (size, is_dir) for a path in our fake tree."""
    fname = path.replace("\\", "/").split("/")[-1]
    # Check canary first
    content = _get_canary_content(path)
    if content is not None:
        return len(content), False
    # Walk share dirs
    for share_key, entries in _FAKE_SHARE_DIRS.items():
        for (name, size, is_dir) in entries:
            if name.upper() == fname.upper():
                return size, is_dir
    # Walk subdir listings
    for entries in _SUBDIR_LISTINGS.values():
        for (name, size, is_dir) in entries:
            if name.upper() == fname.upper():
                return size, is_dir
    return 4096, False


# ── Connection handler ────────────────────────────────────────────────────────

async def handle_smb(reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter):
    peer   = writer.get_extra_info("peername") or ("?", 0)
    src_ip = peer[0]

    if _tarpit_check(src_ip):
        print(f"[smb-tarpit] {src_ip} — parking connection 120s", flush=True)
        try:
            await asyncio.sleep(120)
        finally:
            try: writer.close()
            except Exception: pass
        return

    # Per-session state
    sess_id   = int.from_bytes(secrets.token_bytes(4), "little")
    challenge = secrets.token_bytes(8)
    tree_ids  : dict[str, str]   = {}   # tree_id → share_name
    next_tree = 1
    authed    = False
    ntlm_phase= 0
    fid_to_path: dict[str, str]  = {}   # fid.hex() → full path
    pending_reads: dict[str, bytes] = {} # fid.hex() → buffered DCERPC response
    dir_listed: set[str]         = set()
    write_paths: set[str]        = set()
    pipe_hits : list[str]        = []
    pipe_rpc_calls: list[dict]   = []   # DCERPC ops captured

    intel = {
        "src_ip":       src_ip,
        "ts":           _ts(),
        "service":      "smb",
        "dst_port":     445,
        "ntlm_user":    None,
        "ntlm_domain":  None,
        "ntlm_workstation": None,
        "hashcat":      None,
        "shares":       [],
        "file_paths":   [],
        "writes":       [],
        "ioctls":       [],
        "queries":      [],
        "ransomware":   False,
        "pipe_exploits": [],
        "pipe_rpc_calls": [],
        "attack_phase": "scan",
    }

    smb1_uid       = 0x0100
    handshake_seen = False
    buf = b""

    try:
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=120.0)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk

            while True:
                payload, buf = _nb_read(buf)
                if payload is None:
                    break

                # ── SMB1 ──────────────────────────────────────────────────────
                if payload[:4] == SMB1_MAGIC:
                    handshake_seen = True
                    smb1_cmd = payload[4] if len(payload) > 4 else 0xFF
                    smb1_pid = struct.unpack_from("<H", payload, 26)[0] if len(payload) > 27 else 0
                    smb1_mid = struct.unpack_from("<H", payload, 30)[0] if len(payload) > 31 else 0

                    if smb1_cmd == 0x72:   # NEGOTIATE
                        didx = _parse_smb1_dialect_index(payload)
                        print(f"[smb] {src_ip} SMB1 NEGOTIATE → replying in SMB1 (dialect {didx})", flush=True)
                        writer.write(_resp_smb1_negotiate(smb1_pid, smb1_mid, didx))
                        await writer.drain()

                    elif smb1_cmd == 0x73:  # SESSION SETUP ANDX
                        smb1_body = payload[32:]
                        wc = smb1_body[0] if smb1_body else 0
                        if wc >= 12 and len(smb1_body) >= 29:
                            sec_blob_len = struct.unpack_from("<H", smb1_body, 15)[0]
                            sec_blob = smb1_body[27:27 + sec_blob_len]
                        else:
                            sec_blob = smb1_body[3:] if len(smb1_body) > 3 else b""

                        ntlm = _find_ntlmssp(sec_blob)
                        if ntlm and len(ntlm) >= 12:
                            msg_type = struct.unpack_from("<I", ntlm, 8)[0]
                            if msg_type == 1:
                                print(f"[smb] {src_ip} SMB1 NTLM Type1 → sending challenge", flush=True)
                                ntlm_phase = 1
                                type2  = _make_ntlm_type2(challenge)
                                spnego = _wrap_spnego_challenge(type2)
                                writer.write(_resp_smb1_sess_challenge(smb1_pid, smb1_uid, smb1_mid, spnego))
                                await writer.drain()
                            elif msg_type == 3:
                                parsed = _parse_ntlm_type3(ntlm)
                                hc = _make_hashcat(
                                    parsed.get("username", "?"),
                                    parsed.get("domain",   "?"),
                                    challenge, parsed,
                                )
                                intel["ntlm_user"]        = parsed.get("username")
                                intel["ntlm_domain"]      = parsed.get("domain")
                                intel["ntlm_workstation"] = parsed.get("workstation")
                                intel["hashcat"]          = hc
                                intel["attack_phase"]     = "auth"
                                ntlm_phase = 2
                                authed     = True
                                print(f"[smb] {src_ip} SMB1 NTLM Type3 "
                                      f"user={parsed.get('username')}@{parsed.get('domain')}", flush=True)
                                if hc:
                                    print(f"[smb-hash] {hc}", flush=True)
                                    _log_ntlm_hash(hc, src_ip)
                                writer.write(_resp_smb1_sess_ok(smb1_pid, smb1_uid, smb1_mid))
                                await writer.drain()
                        else:
                            authed = True
                            writer.write(_resp_smb1_sess_ok(smb1_pid, smb1_uid, smb1_mid))
                            await writer.drain()
                    continue

                h = _parse_hdr(payload)
                if not h:
                    continue

                cmd    = h["cmd"]
                msg_id = h["msg_id"]
                body   = h["body"]
                tid    = h["tree_id"]
                s_id   = h["session_id"] or sess_id

                # ── NEGOTIATE ─────────────────────────────────────────────────
                if cmd == CMD_NEGOTIATE:
                    handshake_seen = True
                    print(f"[smb] {src_ip} NEGOTIATE", flush=True)
                    writer.write(_resp_negotiate(msg_id))

                # ── SESSION SETUP ─────────────────────────────────────────────
                elif cmd == CMD_SESS_SETUP:
                    if len(body) < 24:
                        writer.write(_resp_generic_error(cmd, msg_id, sess_id))
                        await writer.drain()
                        continue

                    sec_offset = struct.unpack_from("<H", body, 12)[0] - HDR_LEN
                    sec_len    = struct.unpack_from("<H", body, 14)[0]
                    sec_blob   = body[sec_offset:sec_offset+sec_len] if sec_offset >= 0 else body[4:]
                    ntlm = _find_ntlmssp(sec_blob)

                    if ntlm and len(ntlm) >= 12:
                        msg_type = struct.unpack_from("<I", ntlm, 8)[0]
                        if msg_type == 1:
                            print(f"[smb] {src_ip} SESS SETUP → NTLM Type1", flush=True)
                            ntlm_phase = 1
                            type2  = _make_ntlm_type2(challenge)
                            spnego = _wrap_spnego_challenge(type2)
                            writer.write(_resp_sess_challenge(msg_id, sess_id, spnego))
                        elif msg_type == 3:
                            parsed = _parse_ntlm_type3(ntlm)
                            hc = _make_hashcat(
                                parsed.get("username", "?"),
                                parsed.get("domain",   "?"),
                                challenge, parsed)
                            intel["ntlm_user"]        = parsed.get("username")
                            intel["ntlm_domain"]      = parsed.get("domain")
                            intel["ntlm_workstation"] = parsed.get("workstation")
                            intel["hashcat"]          = hc
                            intel["attack_phase"]     = "auth"
                            ntlm_phase = 2
                            authed     = True
                            print(f"[smb] {src_ip} SESS SETUP NTLM Type3 "
                                  f"user={parsed.get('username')}@{parsed.get('domain')} "
                                  f"ws={parsed.get('workstation')}", flush=True)
                            if hc:
                                print(f"[smb-hash] {hc}", flush=True)
                                _log_ntlm_hash(hc, src_ip)
                            writer.write(_resp_sess_ok(msg_id, sess_id))
                        else:
                            writer.write(_resp_sess_ok(msg_id, sess_id))
                    else:
                        authed = True
                        writer.write(_resp_sess_ok(msg_id, sess_id))

                # ── LOGOFF ────────────────────────────────────────────────────
                elif cmd == CMD_LOGOFF:
                    body_out = struct.pack("<HH", 4, 0)
                    hdr_ = _make_hdr(CMD_LOGOFF, msg_id=msg_id, session_id=s_id)
                    writer.write(_nb_wrap(hdr_ + body_out))
                    break

                # ── TREE CONNECT ──────────────────────────────────────────────
                elif cmd == CMD_TREE_CONN:
                    if len(body) >= 8:
                        path_offset = struct.unpack_from("<H", body, 4)[0] - HDR_LEN
                        path_len    = struct.unpack_from("<H", body, 6)[0]
                        raw_path    = body[path_offset:path_offset+path_len] if path_offset >= 0 else b""
                        try:
                            share_path = raw_path.decode("utf-16-le").strip("\x00")
                        except Exception:
                            share_path = raw_path.hex()
                    else:
                        share_path = "?"

                    tree_key = next_tree
                    next_tree += 1
                    tree_ids[tree_key] = share_path
                    if share_path not in intel["shares"]:
                        intel["shares"].append(share_path)

                    # IPC$ → pipe share (type=0x02), all others disk (type=0x01)
                    share_upper = share_path.upper()
                    if share_upper.endswith("IPC$"):
                        s_type = 0x02
                    else:
                        s_type = 0x01

                    if intel["attack_phase"] == "auth":
                        intel["attack_phase"] = "post-auth"

                    print(f"[smb] {src_ip} TREE CONNECT {share_path!r} → tid={tree_key}", flush=True)
                    writer.write(_resp_tree_connect(msg_id, s_id, tree_key, s_type))

                # ── TREE DISCONNECT ───────────────────────────────────────────
                elif cmd == CMD_TREE_DISC:
                    tree_ids.pop(tid, None)
                    writer.write(_resp_tree_disconnect(msg_id, s_id))

                # ── CREATE ────────────────────────────────────────────────────
                elif cmd == CMD_CREATE:
                    if len(body) >= 57:
                        name_offset = struct.unpack_from("<H", body, 44)[0] - HDR_LEN
                        name_len    = struct.unpack_from("<H", body, 46)[0]
                        raw_name    = body[name_offset:name_offset+name_len] if name_offset >= 0 else b""
                        try:
                            fname = raw_name.decode("utf-16-le").strip("\x00")
                        except Exception:
                            fname = raw_name.hex()
                    else:
                        fname = "?"

                    share     = tree_ids.get(tid, "?")
                    full_path = f"{share}\\{fname}" if fname else share
                    if full_path not in intel["file_paths"]:
                        intel["file_paths"].append(full_path)

                    fid = secrets.token_bytes(16)
                    fid_to_path[fid.hex()] = full_path

                    # Look up file size for a realistic response
                    eof_size, is_dir = _lookup_file_size(full_path)
                    print(f"[smb] {src_ip} CREATE {full_path!r}", flush=True)
                    writer.write(_resp_create_with_size(msg_id, s_id, tid, fid, eof_size, is_dir))

                # ── CLOSE ─────────────────────────────────────────────────────
                elif cmd == CMD_CLOSE:
                    if len(body) >= 24:
                        close_fid = body[8:24]
                        fid_hex = close_fid.hex()
                        fid_to_path.pop(fid_hex, None)
                        pending_reads.pop(fid_hex, None)
                    writer.write(_resp_close(msg_id, s_id, tid))

                # ── READ ──────────────────────────────────────────────────────
                elif cmd == CMD_READ:
                    read_fid = body[16:32] if len(body) >= 32 else b""
                    fid_hex  = read_fid.hex()

                    # Priority 1: pending DCERPC response from a previous WRITE
                    if fid_hex in pending_reads:
                        dcerpc_resp = pending_reads.pop(fid_hex)
                        print(f"[smb] {src_ip} READ (DCERPC pipe response {len(dcerpc_resp)}B)", flush=True)
                        writer.write(_resp_read_data(msg_id, s_id, tid, dcerpc_resp))

                    # Priority 2: canary file content
                    elif fid_hex:
                        fpath       = fid_to_path.get(fid_hex, "")
                        canary_data = _get_canary_content(fpath) if fpath else None
                        if canary_data is not None:
                            print(f"[smb] {src_ip} READ canary {fpath!r} ({len(canary_data)}B)", flush=True)
                            if intel["attack_phase"] in ("post-auth", "scan"):
                                intel["attack_phase"] = "data-theft"
                            writer.write(_resp_read_data(msg_id, s_id, tid, canary_data))
                        else:
                            writer.write(_resp_read(msg_id, s_id, tid))
                    else:
                        writer.write(_resp_read(msg_id, s_id, tid))

                # ── WRITE ─────────────────────────────────────────────────────
                elif cmd == CMD_WRITE:
                    if len(body) >= 8:
                        data_offset = struct.unpack_from("<H", body, 2)[0] - HDR_LEN
                        data_len    = struct.unpack_from("<I", body, 4)[0]
                        payload_raw = body[data_offset:data_offset + min(data_len, 4096)] \
                                      if data_offset >= 0 else b""
                        wr_fid      = body[16:32] if len(body) >= 32 else b""
                        wr_path     = fid_to_path.get(wr_fid.hex(), "") if wr_fid else ""
                        preview     = payload_raw[:256].hex()

                        # Check for DCERPC on named pipe
                        dcerpc_resp = None
                        if wr_path and _is_dcerpc(payload_raw):
                            pipe_name = wr_path.replace("\\", "/").split("/")[-1].lower()
                            dcerpc_resp = _handle_dcerpc_write(pipe_name, payload_raw, pipe_rpc_calls)
                            if dcerpc_resp and wr_fid:
                                pending_reads[wr_fid.hex()] = dcerpc_resp
                                print(f"[smb] {src_ip} DCERPC WRITE pipe={pipe_name!r} "
                                      f"opnum={pipe_rpc_calls[-1].get('opnum','BIND') if pipe_rpc_calls else '?'} "
                                      f"→ queued {len(dcerpc_resp)}B response", flush=True)

                        if wr_path:
                            write_paths.add(wr_path)
                    else:
                        data_len = 0; preview = ""

                    share = tree_ids.get(tid, "?")
                    intel["writes"].append({"share": share, "path": wr_path or "", "len": data_len, "preview": preview})

                    if len(write_paths) >= RANSOMWARE_THRESHOLD and not intel["ransomware"]:
                        intel["ransomware"]   = True
                        intel["attack_phase"] = "ransomware"
                        print(f"[smb] {src_ip} *** RANSOMWARE PATTERN: {len(write_paths)} files written ***",
                              flush=True)

                    print(f"[smb] {src_ip} WRITE {data_len}B → {wr_path or share!r}", flush=True)
                    writer.write(_resp_write(msg_id, s_id, tid, data_len))

                # ── QUERY DIRECTORY ───────────────────────────────────────────
                elif cmd == CMD_QUERY_DIR:
                    info_cls = body[2] if len(body) > 2 else 0
                    # Resolve directory being listed via FileId
                    dir_fid  = body[16:32] if len(body) >= 32 else b""
                    dir_path = fid_to_path.get(dir_fid.hex(), "") if dir_fid else ""
                    share    = tree_ids.get(tid, "?")
                    full_dir = dir_path or share

                    if len(body) >= 28:
                        fn_offset = struct.unpack_from("<H", body, 24)[0] - HDR_LEN
                        fn_len    = struct.unpack_from("<H", body, 26)[0]
                        raw_pat   = body[fn_offset:fn_offset+fn_len] if fn_offset >= 0 else b""
                        try:
                            pattern = raw_pat.decode("utf-16-le").strip("\x00")
                        except Exception:
                            pattern = "*"
                    else:
                        pattern = "*"

                    entry = f"{full_dir}::{pattern}"
                    if entry not in intel["queries"]:
                        intel["queries"].append(entry)

                    list_key = f"{full_dir.upper()}:{pattern}"
                    if list_key not in dir_listed and info_cls in (0, 1, 0x25, 0x3, 0x0b, 0x25):
                        dir_listed.add(list_key)
                        entries = _pack_dir_entries(full_dir)
                        print(f"[smb] {src_ip} QUERY_DIR {full_dir!r} pattern={pattern!r} "
                              f"→ {len(entries)}B", flush=True)
                        writer.write(_resp_query_dir_real(msg_id, s_id, tid, entries))
                    else:
                        writer.write(_resp_query_dir(msg_id, s_id, tid))

                # ── IOCTL ─────────────────────────────────────────────────────
                elif cmd == CMD_IOCTL:
                    ctl_code  = struct.unpack_from("<I", body, 4)[0] if len(body) >= 8 else 0
                    share     = tree_ids.get(tid, "?")
                    pipe_name = ""

                    if len(body) >= 24:
                        io_fid    = body[8:24]
                        io_path   = fid_to_path.get(io_fid.hex(), "")
                        pipe_name = io_path.lower().split("\\")[-1]
                        exploit   = _EXPLOIT_PIPES.get(pipe_name, "")
                        if exploit and exploit not in intel["pipe_exploits"]:
                            intel["pipe_exploits"].append(exploit)
                            intel["attack_phase"] = "post-exploit"
                            print(f"[smb] {src_ip} PIPE EXPLOIT via {pipe_name!r} → {exploit}", flush=True)

                    intel["ioctls"].append({"share": share, "ctl": hex(ctl_code), "pipe": pipe_name})

                    # FSCTL_DFS_GET_REFERRALS (0x00060194) — return minimal DFS error
                    if ctl_code == 0x00060194:
                        writer.write(_resp_generic_error(cmd, msg_id, s_id, status=0xC0000034))
                    # FSCTL_PIPE_WAIT (0x00110018) — tell client pipe is ready
                    elif ctl_code == 0x00110018:
                        writer.write(_resp_ioctl(msg_id, s_id, tid, ctl_code))
                    # FSCTL_PIPE_TRANSCEIVE (0x0011C017) — RPC call via transceive
                    elif ctl_code == 0x0011C017 and len(body) >= 56:
                        in_offset = struct.unpack_from("<I", body, 24)[0] - HDR_LEN
                        in_len    = struct.unpack_from("<I", body, 28)[0]
                        in_data   = body[in_offset:in_offset+in_len] if in_offset >= 0 else b""
                        dcerpc_r  = _handle_dcerpc_write(pipe_name, in_data, pipe_rpc_calls)
                        if dcerpc_r:
                            writer.write(_resp_ioctl(msg_id, s_id, tid, ctl_code, dcerpc_r))
                        else:
                            writer.write(_resp_ioctl(msg_id, s_id, tid, ctl_code))
                    else:
                        writer.write(_resp_ioctl(msg_id, s_id, tid, ctl_code))

                    print(f"[smb] {src_ip} IOCTL 0x{ctl_code:08x} on {share!r}", flush=True)

                # ── QUERY INFO ────────────────────────────────────────────────
                elif cmd == CMD_QUERY_INFO:
                    info_type = body[0] if body else 0
                    # InfoType 1 = FileBasicInformation: return timestamps + attrs
                    if info_type == 1 and len(body) >= 8:
                        qfid = body[8:24] if len(body) >= 24 else b""
                        fpath = fid_to_path.get(qfid.hex(), "") if qfid else ""
                        eof, is_dir = _lookup_file_size(fpath)
                        ft = int((time.time() + 11644473600) * 1e7)
                        attrs = 0x10 if is_dir else 0x20
                        payload = struct.pack("<QQQQII",
                            ft - int(86400 * 7 * 1e7), ft, ft, ft,  # timestamps
                            attrs, 0)
                        writer.write(_resp_query_info(msg_id, s_id, tid, payload))
                    else:
                        writer.write(_resp_query_info(msg_id, s_id, tid))

                # ── SET INFO (rename, delete, timestamps) → accept silently ──
                elif cmd == CMD_SET_INFO:
                    writer.write(_resp_ok_empty(CMD_SET_INFO, msg_id, s_id))

                # ── ECHO ──────────────────────────────────────────────────────
                elif cmd == CMD_ECHO:
                    writer.write(_resp_echo(msg_id))

                # ── UNKNOWN ───────────────────────────────────────────────────
                else:
                    print(f"[smb] {src_ip} cmd=0x{cmd:04x} (unhandled)", flush=True)
                    writer.write(_resp_generic_error(cmd, msg_id, s_id))

                await writer.drain()

    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        print(f"[smb] {src_ip} error: {e}", flush=True)
    finally:
        try: writer.close()
        except Exception: pass

    # Update event with DCERPC intel
    intel["pipe_rpc_calls"] = pipe_rpc_calls[:50]
    intel["dcerpc_opnums"]  = sorted({r["opnum"] for r in pipe_rpc_calls if r.get("opnum") is not None})

    has_data = (intel["shares"] or intel["hashcat"] or intel["ntlm_user"]
                or intel["file_paths"] or intel["writes"] or pipe_rpc_calls)
    if has_data or (handshake_seen and _should_log_probe(src_ip)):
        intel["session_id"]  = f"smb-{secrets.token_hex(6)}"
        intel["write_count"] = len(write_paths)
        intel["pipe_hits"]   = pipe_hits
        _log_event(intel)
        ransom_flag = " *** RANSOMWARE ***" if intel["ransomware"] else ""
        rpc_info    = f" dcerpc={len(pipe_rpc_calls)}" if pipe_rpc_calls else ""
        print(f"[smb] {src_ip} session done → user={intel['ntlm_user']} "
              f"shares={intel['shares']} files={len(intel['file_paths'])} "
              f"writes={len(write_paths)}{rpc_info}{ransom_flag}", flush=True)


# ── Entry points ──────────────────────────────────────────────────────────────

async def start_smb():
    server = await asyncio.start_server(handle_smb, "0.0.0.0", SMB_PORT)
    print(f"[smb] Listening on 0.0.0.0:{SMB_PORT}", flush=True)
    return server

def start():
    loop = asyncio.get_event_loop()
    loop.create_task(start_smb())
    print("[smb] Started", flush=True)
