"""
RDP Honeypot — Credential & NTLM Hash Capture.
Implements enough RDP protocol to capture:
  - NTLMv2 challenge-response hashes (crackable offline)
  - Username, domain, hostname
  - Client OS version, screen resolution
  - X.224 → MCS Connect → Basic RDP Security + NLA support
Listens on port 3389, async stdlib socket.
"""

import asyncio, hashlib, hmac, os, socket, struct, time, uuid, binascii, json
from datetime import datetime, timezone

RDP_PORT = int(os.environ.get("RDP_PORT", "3389"))
DATA_DIR  = os.getenv("DATA_DIR", "/data")
EVENTS    = os.path.join(DATA_DIR, "events.jsonl")

def _log_event(ev: dict):
    try:
        with open(EVENTS, "a") as f:
            f.write(json.dumps(ev) + "\n")
    except Exception:
        pass

def _ts():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
HOSTNAME = "DC01"
DOMAIN = "CORP"
WINDOWS_VERSION = "Windows Server 2022 Datacenter"
PRODUCT_ID = 1  # Windows Server

# ── RDP Protocol Constants ────────────────────────────────────
TPKT_VERSION = 3
X224_TPDU_CONNECTION_REQUEST = 0xE0
X224_TPDU_CONNECTION_CONFIRM = 0xD0
X224_TPDU_DATA = 0xF0

# MCS
MCS_TYPE_CONNECT_INITIAL = 0x65
MCS_TYPE_CONNECT_RESPONSE = 0x66
MCS_TYPE_ATTACH_USER_REQUEST = 0x28
MCS_TYPE_ATTACH_USER_CONFIRM = 0x2E
MCS_TYPE_CHANNEL_JOIN_REQUEST = 0x38
MCS_TYPE_CHANNEL_JOIN_CONFIRM = 0x3E
MCS_TYPE_SEND_DATA_REQUEST = 0x44

# RDP Security
RDP_NEG_REQ = 0x01
RDP_NEG_RSP = 0x02
RDP_NEG_FAILURE = 0x03
RDP_CORRELATION_INFO = 0x06

# Security protocols
PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002  # CredSSP / NLA
PROTOCOL_HYBRID_EX = 0x00000008

# NTLMSSP
NTLMSSP_NEGOTIATE = 1
NTLMSSP_CHALLENGE = 2
NTLMSSP_AUTHENTICATE = 3

# GCC
TS_UD_CS_CORE = 0x0C01
TS_UD_CS_SECURITY = 0x0C02
TS_UD_CS_NET = 0x0C03
TS_UD_CS_CLUSTER = 0x0C04
TS_UD_SC_CORE = 0x0C01
TS_UD_SC_SECURITY = 0x0C02
TS_UD_SC_NET = 0x0C03


def build_tpkt(data, tpdu_type=X224_TPDU_DATA):
    """Wrap data in TPKT + X.224 header."""
    length = len(data) + 7
    tpkt = struct.pack(">BBH", TPKT_VERSION, 0, length)
    x224 = struct.pack(">BBHBB", length - 4, tpdu_type, 0, 0, 0)
    return tpkt + x224 + data


def parse_tpkt(data):
    """Parse TPKT + X.224 header. Returns (tpdu_type, payload)."""
    if len(data) < 7:
        return None, None
    tpkt_ver, _, tpkt_len = struct.unpack(">BBH", data[:4])
    if tpkt_ver != TPKT_VERSION:
        return None, None
    x224_len = data[4]
    tpdu_type = data[5]
    payload = data[6:tpkt_len] if tpkt_len <= len(data) else data[6:]
    return tpdu_type, bytes(payload)


def generate_nonce(length):
    return os.urandom(length)


class RDPHoneypot:
    def __init__(self):
        self.server_cert = None
        self.nonce = generate_nonce(32)

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        session_id = uuid.uuid4().hex[:12]
        creds = {"username": "", "domain": "", "hostname": "", "os": "",
                 "screen": "", "ntlm_hash": "", "ntlm_challenge": "", "raw_auth": ""}
        
        def log(msg):
            print(f"[rdp] [{session_id}] {msg}", flush=True)

        try:
            # 1. Wait for X.224 Connection Request
            data = await asyncio.wait_for(reader.read(4096), timeout=15)
            if not data or len(data) < 19:
                log(f"Short connection from {peer[0]}")
                return

            tpdu_type, payload = parse_tpkt(data)
            if tpdu_type != X224_TPDU_CONNECTION_REQUEST:
                log(f"Not RDP: tpdu={tpdu_type!r}")
                return

            log(f"Connection from {peer[0]}:{peer[1]}")

            # Parse RDP Negotiation Request
            neg_req_cookie = b""
            rdp_neg_data = b""
            if len(payload) > 8:
                cookie_len = payload[6]
                if cookie_len > 0:
                    neg_req_cookie = payload[7:7 + cookie_len]
                    rdp_neg_data = payload[7 + cookie_len:]

            client_protocols = PROTOCOL_RDP
            if len(rdp_neg_data) >= 8:
                neg_type, neg_flags, neg_len, neg_requested = struct.unpack("<BBHI", rdp_neg_data[:8])
                client_protocols = neg_requested
                log(f"Client supports: RDP={bool(client_protocols&PROTOCOL_RDP)} "
                    f"SSL={bool(client_protocols&PROTOCOL_SSL)} "
                    f"CredSSP={bool(client_protocols&PROTOCOL_HYBRID)}")

            # We select CredSSP if client supports it (best hash capture)
            # Otherwise fall back to basic RDP
            selected_proto = PROTOCOL_RDP
            if client_protocols & PROTOCOL_HYBRID:
                selected_proto = PROTOCOL_HYBRID
            elif client_protocols & PROTOCOL_SSL:
                selected_proto = PROTOCOL_SSL

            log(f"Selected protocol: 0x{selected_proto:08x}")

            # 2. Send X.224 Connection Confirm
            rdp_neg_rsp = struct.pack("<BBHI", RDP_NEG_RSP, 0, 8, selected_proto)
            
            conn_confirm = b"\x00" * 8  # padding
            conn_confirm += rdp_neg_rsp
            
            response = build_tpkt(conn_confirm, X224_TPDU_CONNECTION_CONFIRM)
            writer.write(response)
            await writer.drain()

            # 3. If CredSSP selected, do NTLMSSP handshake
            if selected_proto == PROTOCOL_HYBRID:
                await self.do_credssp(reader, writer, creds, log)
            elif selected_proto == PROTOCOL_SSL:
                await self.do_ssl_fallback(reader, writer, creds, log)
            else:
                await self.do_basic_rdp(reader, writer, creds, log)

            if creds["username"]:
                log(f"CAPTURED: {creds['domain']}\\{creds['username']} "
                    f"from {creds['hostname']} ({creds['os']})")
                if creds["ntlm_hash"]:
                    log(f"NTLM_AUTH: {creds['ntlm_hash'][:60]}...")

        except asyncio.TimeoutError:
            log("Timeout")
        except Exception as e:
            log(f"Error: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

        # Log to events.jsonl so dashboard picks it up
        ev = {
            "service":    "rdp",
            "ts":         _ts(),
            "src_ip":     peer[0],
            "dst_port":   RDP_PORT,
            "session_id": f"rdp-{session_id}",
            "rdp_user":   creds.get("username", ""),
            "rdp_domain": creds.get("domain", ""),
            "rdp_host":   creds.get("hostname", ""),
            "rdp_os":     creds.get("os", ""),
            "rdp_screen": creds.get("screen", ""),
            "ntlm_hash":  creds.get("ntlm_hash", ""),
            "ntlm_challenge": creds.get("ntlm_challenge", ""),
        }
        if creds.get("ntlm_hash"):
            # format as hashcat-compatible Net-NTLMv2
            ev["hashcat"]    = creds["ntlm_hash"]
            ev["ntlm_user"]  = creds.get("username", "")
            ev["ntlm_domain"]= creds.get("domain", "")
            ev["ntlm_workstation"] = creds.get("hostname", "")
        _log_event(ev)
        log(f"Session done → user={creds.get('username','')} hash={'yes' if creds.get('ntlm_hash') else 'no'}")

        return {
            "session": session_id, "peer": peer, "creds": creds,
        }

    async def do_credssp(self, reader, writer, creds, log):
        """CredSSP / NLA handshake — capture NTLMv2 hash."""
        try:
            # 1. Read MCS Connect Initial from client
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            tpdu_type, payload = parse_tpkt(data)
            if tpdu_type != X224_TPDU_DATA:
                return

            # Parse MCS Connect Initial - extract client info
            if len(payload) > 2 and payload[0] == MCS_TYPE_CONNECT_INITIAL:
                # Extract client hostname from GCC Client Core data
                self._extract_client_info(payload, creds)
                log(f"Client: {creds.get('hostname','?')} OS: {creds.get('os','?')}")

            # 2. Send MCS Connect Response with GCC
            gcc_response = self._build_gcc_response(selected_proto=PROTOCOL_HYBRID)
            mcs_connect_resp = struct.pack(">B", MCS_TYPE_CONNECT_RESPONSE)
            # MCS result
            mcs_connect_resp += b"\x00"  # result = success
            mcs_connect_resp += b"\x00"  # calledConnectId
            mcs_connect_resp += struct.pack(">B", 5)  # domainParameters length
            mcs_connect_resp += b"\x00\x00\x00\x00\x00"  # domain params (dummy)
            mcs_connect_resp += gcc_response
            
            response = build_tpkt(mcs_connect_resp, X224_TPDU_DATA)
            writer.write(response)
            await writer.drain()

            # 3. CredSSP: Receive NTLMSSP NEGOTIATE
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            tpdu_type, payload = parse_tpkt(data)
            
            ntlm_negotiate = self._extract_ntlmssp(payload)
            if ntlm_negotiate:
                log("Got NTLMSSP NEGOTIATE")

                # 4. Send NTLMSSP CHALLENGE
                server_challenge = generate_nonce(8)
                creds["ntlm_challenge"] = server_challenge.hex()
                
                ntlm_challenge_msg = self._build_ntlm_challenge(server_challenge)
                
                # Wrap in CredSSP / TSPacket
                credssp_resp = self._wrap_credssp(ntlm_challenge_msg)
                
                tpkt = build_tpkt(credssp_resp, X224_TPDU_DATA)
                writer.write(tpkt)
                await writer.drain()
                log("Sent NTLMSSP CHALLENGE")

                # 5. Receive NTLMSSP AUTHENTICATE
                data = await asyncio.wait_for(reader.read(8192), timeout=10)
                tpdu_type, payload = parse_tpkt(data)
                
                ntlm_auth = self._extract_ntlmssp(payload)
                if ntlm_auth and len(ntlm_auth) > 100:
                    # Parse NTLMv2 response
                    parsed = self._parse_ntlm_auth(ntlm_auth, server_challenge)
                    creds.update(parsed)
                    creds["raw_auth"] = ntlm_auth.hex()[:500]
                    creds["ntlm_hash"] = self._format_hash_for_cracking(
                        creds["username"], creds["domain"],
                        server_challenge, ntlm_auth)

                # Send final CredSSP accept
                final = self._build_credssp_final()
                tpkt_final = build_tpkt(final, X224_TPDU_DATA)
                writer.write(tpkt_final)
                await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log(f"CredSSP error: {e}")

    async def do_basic_rdp(self, reader, writer, creds, log):
        """Basic RDP Security — capture username from MCS Attach User."""
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            tpdu_type, payload = parse_tpkt(data)
            
            # MCS Connect Initial
            if payload and payload[0] == MCS_TYPE_CONNECT_INITIAL:
                self._extract_client_info(payload, creds)
            
            # Send MCS Connect Response
            gcc = self._build_gcc_response()
            mcs_resp = struct.pack(">BB", MCS_TYPE_CONNECT_RESPONSE, 0) + b"\x00" + struct.pack(">B5s", 5, b"\x00"*5) + gcc
            writer.write(build_tpkt(mcs_resp, X224_TPDU_DATA))
            await writer.drain()

            # MCS Attach User
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            tpdu_type, payload = parse_tpkt(data)
            if payload and payload[0] == MCS_TYPE_ATTACH_USER_REQUEST:
                user_data = payload[1:]
                # Username is after 2 bytes of userDataLength + userChannelId
                log(f"Attach User: {user_data.hex()[:100]}")
            
            # MCS Attach User Confirm
            attach_confirm = struct.pack(">BB", MCS_TYPE_ATTACH_USER_CONFIRM, 0)
            writer.write(build_tpkt(attach_confirm, X224_TPDU_DATA))
            await writer.drain()

            # MCS Channel Join
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            tpdu_type, payload = parse_tpkt(data)
            if payload and payload[0] == MCS_TYPE_CHANNEL_JOIN_REQUEST:
                # Confirm
                join_confirm = struct.pack(">BB", MCS_TYPE_CHANNEL_JOIN_CONFIRM, 0)
                writer.write(build_tpkt(join_confirm, X224_TPDU_DATA))
                await writer.drain()

            # Client Info PDU — contains username!
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            tpdu_type, payload = parse_tpkt(data)
            
            if payload and payload[0] == MCS_TYPE_SEND_DATA_REQUEST:
                creds.update(self._parse_client_info_pdu(payload[1:]))
                log(f"Got client info: user={creds.get('username','?')}")

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log(f"Basic RDP error: {e}")

    async def do_ssl_fallback(self, reader, writer, creds, log):
        """SSL fallback — not fully implemented, capture what we can."""
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
            tpdu_type, payload = parse_tpkt(data)
            if payload:
                self._extract_client_info(payload, creds)
            
            # Send MCS response
            gcc = self._build_gcc_response(PROTOCOL_SSL)
            mcs_resp = struct.pack(">BB", MCS_TYPE_CONNECT_RESPONSE, 0) + b"\x00" + struct.pack(">B5s", 5, b"\x00"*5) + gcc
            writer.write(build_tpkt(mcs_resp, X224_TPDU_DATA))
            await writer.drain()
        except Exception:
            pass

    def _extract_client_info(self, payload, creds):
        """Extract hostname, OS from GCC Client Core data."""
        try:
            idx = 2  # skip MCS header
            while idx < len(payload) - 4:
                ts_type = struct.unpack_from("<H", payload, idx)[0]
                ts_len = struct.unpack_from("<H", payload, idx + 2)[0]
                if ts_len == 0 or idx + ts_len > len(payload):
                    break
                ts_data = payload[idx + 4:idx + ts_len]
                
                if ts_type == TS_UD_CS_CORE:  # Client Core
                    # Parse version, desktop, etc.
                    if len(ts_data) >= 32:
                        # RDP version
                        ver_major = ts_data[0]
                        ver_minor = ts_data[1]
                        # desktop width/height
                        desktop_w = struct.unpack_from("<H", ts_data, 2)[0]
                        desktop_h = struct.unpack_from("<H", ts_data, 4)[0]
                        creds["screen"] = f"{desktop_w}x{desktop_h}"
                        creds["os"] = f"RDP v{ver_major}.{ver_minor}"
                
                elif ts_type == TS_UD_CS_NET:  # Client Network
                    if len(ts_data) >= 4:
                        channel_count = struct.unpack_from("<I", ts_data, 0)[0]
                        creds["channels"] = channel_count
                
                idx += ts_len
            
            # Also look for hostname in the raw data
            # Hostname might be at offset after cookie
            for i in range(min(100, len(payload) - 15)):
                try:
                    chunk = payload[i:i+30]
                    if b"RDP" in chunk or b"mstsc" in chunk.lower():
                        # Found RDP client info proximity
                        pass
                except:
                    pass
        except Exception:
            pass

    def _build_gcc_response(self, selected_proto=PROTOCOL_RDP):
        """Build GCC Conference Create Response."""
        # GCC header
        gcc = b""
        gcc += b"\x00\x05\x00\x14\x7c\x00\x01"  # UserData header
        
        # Server Core Data
        core = struct.pack("<HH", TS_UD_SC_CORE, 12)  # type, length
        core += struct.pack("<HHBB", 0x0800, 0x0001, 0x04, 0x00)  # version + flags
        gcc += core
        
        # Server Security Data
        sec = struct.pack("<HH", TS_UD_SC_SECURITY, 12)
        sec += struct.pack("<II", selected_proto, 0)  # encryption methods
        gcc += sec
        
        # Server Network Data
        net = struct.pack("<HH", TS_UD_SC_NET, 12)
        net += struct.pack("<HHBB", 1, 0x03E8, 0x03, 0)  # MCS channel 1001
        net += b"\x00\x00\x00\x00"
        gcc += net
        
        return gcc

    def _extract_ntlmssp(self, data):
        """Extract NTLMSSP message from MCS data."""
        if not data or len(data) < 20:
            return None
        # Look for NTLMSSP signature
        idx = data.find(b"NTLMSSP\x00")
        if idx == -1:
            return None
        return data[idx:]

    def _build_ntlm_challenge(self, server_challenge):
        """Build NTLMSSP CHALLENGE message."""
        # Target name
        target_name = DOMAIN.encode("utf-16le")
        target_info = self._build_av_pairs()
        
        # Calculate offsets
        target_name_offset = 56
        target_info_offset = target_name_offset + len(target_name)
        msg_len = target_info_offset + len(target_info)
        
        msg = bytearray(msg_len)
        # Signature
        msg[0:8] = b"NTLMSSP\x00"
        # MessageType = 2 (Challenge)
        struct.pack_into("<I", msg, 8, 2)
        # TargetName
        struct.pack_into("<HHII", msg, 12, len(target_name), len(target_name), target_name_offset, 0)
        # NegotiateFlags
        struct.pack_into("<I", msg, 20, 0xE28A8215)  # Standard flags
        # ServerChallenge
        msg[24:32] = server_challenge
        # Reserved
        msg[32:40] = b"\x00" * 8
        # TargetInfo
        struct.pack_into("<HHII", msg, 40, len(target_info), len(target_info), target_info_offset, 0)
        # Version
        struct.pack_into("<BBHBBH", msg, 48, 10, 0, 20348, 0, 0, 0)  # Windows 10 / Server 2022
        # TargetName value
        msg[target_name_offset:target_name_offset + len(target_name)] = target_name
        # TargetInfo value
        msg[target_info_offset:target_info_offset + len(target_info)] = target_info
        
        return bytes(msg)

    def _build_av_pairs(self):
        """Build AV_PAIRs for NTLM challenge."""
        pairs = bytearray()
        # NetBIOS domain name
        domain = DOMAIN.encode("utf-16le")
        pairs += struct.pack("<HH", 2, len(domain)) + domain
        # NetBIOS computer name  
        host = HOSTNAME.encode("utf-16le")
        pairs += struct.pack("<HH", 1, len(host)) + host
        # DNS domain name
        dns_domain = f"{DOMAIN}.local".encode("utf-16le")
        pairs += struct.pack("<HH", 4, len(dns_domain)) + dns_domain
        # DNS host name
        dns_host = f"{HOSTNAME}.{DOMAIN}.local".encode("utf-16le")
        pairs += struct.pack("<HH", 3, len(dns_host)) + dns_host
        # Timestamp
        import datetime
        ts = bytearray(8)
        struct.pack_into("<Q", ts, 0, int(time.time() * 10000000) + 116444736000000000)
        pairs += struct.pack("<HH", 7, 8) + bytes(ts)
        # Terminator
        pairs += struct.pack("<HH", 0, 0)
        return bytes(pairs)

    def _parse_ntlm_auth(self, data, challenge):
        """Parse NTLMSSP AUTHENTICATE message."""
        result = {}
        try:
            if len(data) < 20 or data[0:8] != b"NTLMSSP\x00":
                return result
            
            # LM Response
            lm_len, lm_max, lm_offset = struct.unpack_from("<HHI", data, 12)
            # NTLM Response (NTLMv2)
            nt_len, nt_max, nt_offset = struct.unpack_from("<HHI", data, 20)
            # Domain name
            dm_len, dm_max, dm_offset = struct.unpack_from("<HHI", data, 28)
            # User name
            un_len, un_max, un_offset = struct.unpack_from("<HHI", data, 36)
            # Host name
            hn_len, hn_max, hn_offset = struct.unpack_from("<HHI", data, 44)
            
            if 0 < un_len < 256 and un_offset + un_len <= len(data):
                result["username"] = data[un_offset:un_offset+un_len].decode("utf-16le", "replace")
            if 0 < dm_len < 256 and dm_offset + dm_len <= len(data):
                result["domain"] = data[dm_offset:dm_offset+dm_len].decode("utf-16le", "replace")
            if 0 < hn_len < 256 and hn_offset + hn_len <= len(data):
                result["hostname"] = data[hn_offset:hn_offset+hn_len].decode("utf-16le", "replace")
            
            # Extract NTLMv2 Response for hash cracking
            if 0 < nt_len < 2048 and nt_offset + nt_len <= len(data):
                nt_response = data[nt_offset:nt_offset+nt_len]
                result["ntlm_hash"] = nt_response.hex()
                result["ntlm_challenge"] = challenge.hex()
        except Exception:
            pass
        return result

    def _format_hash_for_cracking(self, user, domain, challenge, ntlm_auth):
        """Format hash for hashcat/john cracking."""
        try:
            if len(ntlm_auth) < 60:
                return ""
            # Extract NT response
            nt_offset = struct.unpack_from("<I", ntlm_auth, 20)[0]
            nt_len = struct.unpack_from("<H", ntlm_auth, 20)[0]
            if nt_len > 16 and nt_offset + nt_len <= len(ntlm_auth):
                nt_response = ntlm_auth[nt_offset:nt_offset+nt_len]
            else:
                return ""
            
            # Format: user::domain:challenge:HMAC-MD5:blob
            # NTLMv2 response = HMAC-MD5(blob) + blob
            if len(nt_response) > 16:
                nt_proof = nt_response[:16].hex()
                blob = nt_response[16:].hex()
                return f"{user}::{domain}:{challenge.hex()}:{nt_proof}:{blob}"
            return nt_response.hex()
        except Exception:
            return ""

    def _wrap_credssp(self, ntlm_challenge_msg):
        """Wrap NTLMSSP message in CredSSP ASN.1 wrapper."""
        # Simple CredSSP wrapper (TSPasswordCreds)
        # We'll keep it minimal for the honeypot
        ts_request = b"\x30" + struct.pack(">B", len(ntlm_challenge_msg) + 4)
        ts_request += b"\xa0" + struct.pack(">B", len(ntlm_challenge_msg) + 2)
        ts_request += b"\x30" + struct.pack(">B", len(ntlm_challenge_msg))
        ts_request += ntlm_challenge_msg
        return ts_request

    def _build_credssp_final(self):
        """Build final CredSSP accept message."""
        # Minimal "OK" response
        return b"\x30\x06\xa0\x04\x30\x02\xa0\x00"

    def _parse_client_info_pdu(self, data):
        """Parse Client Info PDU from basic RDP."""
        result = {}
        try:
            if len(data) < 20:
                return result
            
            # Client Info PDU structure
            code_page = struct.unpack_from("<I", data, 0)[0]
            flags = struct.unpack_from("<I", data, 4)[0]
            # Domain, Username, Password, AlternateShell, WorkingDir are variable
            # They're encoded as UTF-16LE strings with 2-byte length prefix
            
            offset = 16  # After flags and fixed fields
            
            fields = ["domain", "username", "password", "alternate_shell", "working_dir"]
            for field in fields[:3]:  # Only need domain, username, password
                if offset + 2 > len(data):
                    break
                strlen = struct.unpack_from("<H", data, offset)[0]
                offset += 2
                if strlen > 0 and strlen < 512 and offset + strlen * 2 <= len(data):
                    val = data[offset:offset + strlen * 2].decode("utf-16le", "replace")
                    offset += strlen * 2
                    if field == "password" and val:
                        result["password"] = val
                        result["password_len"] = strlen
                    elif field == "username":
                        result["username"] = val
                    elif field == "domain":
                        result["domain"] = val
                else:
                    # String is present but with different length encoding
                    # Skip null-terminated
                    end = data.find(b"\x00\x00", offset)
                    if end != -1 and end - offset < 512:
                        val = data[offset:end].decode("utf-16le", "replace")
                        if field == "password" and val:
                            result["password"] = val
                        elif field == "username":
                            result["username"] = val
                        elif field == "domain":
                            result["domain"] = val
                        offset = end + 2
                    else:
                        break
        except Exception:
            pass
        return result


async def handle_client(reader, writer):
    hp = RDPHoneypot()
    result = await hp.handle(reader, writer)
    return result


def start(log_event=None, extract_iocs=None, capture_samples=None):
    """Start RDP honeypot."""
    import threading
    
    async def run_server():
        server = await asyncio.start_server(handle_client, "0.0.0.0", RDP_PORT)
        print(f"[rdp] Listening on 0.0.0.0:{RDP_PORT}", flush=True)
        async with server:
            await server.serve_forever()
    
    def _start():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_server())
    
    t = threading.Thread(target=_start, daemon=True)
    t.start()
