"""Deception layer: look like a juicy, attackable on-prem Windows server.

Strategy for Windows botnets on 443: present a believable, *vulnerable-looking*
Microsoft Exchange / IIS box plus a wide set of high-value RCE targets, and
answer each probe in a way that makes the bot believe it hit a real, exploitable
host -> so it proceeds to deliver its actual exploit / second-stage payload,
which we capture and (after TLS termination) read in plaintext.

Medium interaction: we never execute anything; we only return convincing bait.
"""
import datetime
import hashlib
import os
import re
import secrets

try:
    import honeytoken as _ht
except Exception:
    _ht = None

try:
    import strategist as _strat
except Exception:
    _strat = None

try:
    import ai_analyst as _ai
except Exception:
    _ai = None

# RedTail-Wurm-Trap: erkennt den libredtail-http-Scanner und liefert
# spezialisierte Köder (md5-Reflect, CVE-2024-4577-Decode, Payload-Capture
# nach /data/trap_logs/). Muss VOR allen normalen Lures geprüft werden.
try:
    from redtail_lure import get_redtail_lure_response
except Exception:
    def get_redtail_lure_response(*_a, **_k):
        return None

try:
    from vmware_lure import get_vmware_response, is_vmware_request
except Exception:
    def is_vmware_request(*_a, **_k): return False
    def get_vmware_response(*_a, **_k): return None

# A real-looking, ProxyShell-era Exchange build (very attractive to scanners).
EXCHANGE_VERSION = "15.2.792.3"
SERVER_HEADER = "Microsoft-IIS/10.0"


def _http_date():
    return datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")


# ── SMB coercion (Responder-style) ──────────────────────────────────────────
# We can't force pure port-scanners to authenticate, but Windows-based attacker
# tooling that RENDERS our served HTML will auto-resolve a UNC path and
# authenticate to our SMB honeypot → we capture the Net-NTLMv2 hash. So every
# HTML response carries a hidden UNC beacon pointing at our own SMB (port 445).
_UNC_HOST = os.environ.get("BEACON_HOST", "164.68.121.252")
_EVENTS_FILE = os.environ.get("EVENTS", "/data/events.jsonl")


def _log_owa_cred(src_ip: str, user: str, pw: str):
    """Write a captured OWA/Exchange brute-force credential as an event."""
    import json as _j
    tok = _ht.mint(src_ip, kind="owa") if _ht is not None else ""
    ev = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "src_ip": src_ip, "service": "owa", "method": "POST", "path": "/owa/auth.owa",
        "lure": "owa-cred-capture", "http_user": user, "http_pass": pw,
        "http_creds": [f"{user}:{pw}"], "honeytoken": tok,
    }
    try:
        with open(_EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(_j.dumps(ev) + "\n")
    except Exception:
        pass
    print(f"[owa-cred] {src_ip} {user}:{pw}", flush=True)


_WEBSHELL_CMD_RE = re.compile(
    r"(?:cmd|exec|command|c|cmd0|shell|q|x|run|do|arg|payload)=([^&\r\n]{1,300})", re.I)
_SHELL_VERB_RE = re.compile(
    r"\b(whoami|id|uname|hostname|ipconfig|ifconfig|systeminfo|ver|net user|net1 user|"
    r"cat |ls |dir|pwd|ps |tasklist|wget |curl |powershell|cmd\.exe|echo |type |"
    r"nslookup|arp |netstat|wmic )[^\r\n&;|]{0,200}", re.I)


def _extract_webshell_cmd(path: str, body) -> str:
    """Pull the injected command out of a webshell request (cmd=/exec= params or
    a shell command in the body). Returns '' if none recognised."""
    from urllib.parse import unquote_plus
    blob = (path or "") + "\n" + (body.decode("latin-1", "replace") if body else "")
    m = _WEBSHELL_CMD_RE.search(blob)
    if m:
        return unquote_plus(m.group(1)).strip()[:300]
    m = _SHELL_VERB_RE.search(blob)
    if m:
        return m.group(0).strip()[:300]
    return ""


def _log_webshell_replay(src_ip: str, cmd: str, out: str):
    """Record a webshell command+response as a replay (SSH-REPLAY tab, tagged
    WEBSHELL) so the operator can see exactly what we answered the attacker."""
    import json as _j
    ev = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "src_ip": src_ip, "service": "webshell", "method": "POST",
        "lure": "webshell-interactive", "proto": "webshell",
        "ssh_commands": [cmd],
        "ssh_replay": [{"t": 0, "i": cmd}, {"t": 1, "o": out[:2000]}],
    }
    try:
        with open(_EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(_j.dumps(ev) + "\n")
    except Exception:
        pass
    print(f"[webshell] {src_ip} cmd={cmd[:60]!r}", flush=True)


def _log_owa_access(src_ip: str, path: str, operation: str):
    """Log a post-auth OWA/EWS mailbox operation — what the attacker tried to do
    AFTER 'getting in' (the real intel: searches, exfil, mailbox enumeration)."""
    import json as _j
    ev = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "src_ip": src_ip, "service": "owa", "method": "POST", "path": path,
        "lure": "owa-post-auth-access", "owa_operation": operation[:400],
    }
    try:
        with open(_EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(_j.dumps(ev) + "\n")
    except Exception:
        pass
    print(f"[owa-access] {src_ip} {path} op={operation[:80]!r}", flush=True)


def _smb_beacon_html() -> str:
    h = _UNC_HOST
    # multiple vectors: hidden <img>, CSS background, and a stylesheet link —
    # different Windows clients trigger on different ones.
    return (
        f'<img src="\\\\{h}\\s\\i.png" width="1" height="1" alt="" '
        f'style="position:absolute;left:-9999px;top:-9999px">'
        f'<link rel="stylesheet" href="file://{h}/s/t.css">'
        f'<div style="background-image:url(\'\\\\{h}\\s\\b.jpg\')"></div>'
    )


def _inject_beacon(body: bytes) -> bytes:
    low = body[:512].lstrip().lower()
    if not (low.startswith((b"<!doctype html", b"<html")) or b"<body" in body.lower()):
        return body
    beacon = _smb_beacon_html().encode("utf-8")
    if b"</body>" in body:
        return body.replace(b"</body>", beacon + b"</body>", 1)
    return body + beacon


def _resp(status, body=b"", ctype="text/html", extra=None, server=None):
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    if "html" in ctype:
        body = _inject_beacon(body)
    h = [
        f"HTTP/1.1 {status}",
        f"Date: {_http_date()}",
        f"Server: {server or SERVER_HEADER}",
    ]
    # ASP.NET headers only make sense for the default IIS persona; a custom
    # `server` (e.g. an embedded device) must not leak them — that's a tell.
    if server is None:
        h += ["X-Powered-By: ASP.NET", "X-AspNet-Version: 4.0.30319"]
    h += [
        f"Content-Type: {ctype}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    for k, v in (extra or {}).items():
        h.append(f"{k}: {v}")
    return ("\r\n".join(h) + "\r\n\r\n").encode("latin-1") + body, status


# ---- believable bait bodies ------------------------------------------------

OWA_LOGIN = """<!DOCTYPE html><html><head><title>Outlook</title>
<meta http-equiv="X-UA-Compatible" content="IE=edge"></head>
<body><form action="/owa/auth.owa" method="POST">
<h1>Outlook</h1><p>Microsoft Exchange</p>
Domain\\user name: <input name="username" type="text"/>
Password: <input name="password" type="password"/>
<input type="submit" value="sign in"/></form></body></html>"""

AUTODISCOVER_XML = """<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
 <Response><Account><Action>settings</Action>
 <Protocol><Type>EXCH</Type><Server>EXCH01.contoso.local</Server>
 <ServerVersion>%s</ServerVersion></Protocol></Account></Response></Autodiscover>""" % EXCHANGE_VERSION

EXCH_HDRS = {"X-FEServer": "EXCH01", "X-OWA-Version": EXCHANGE_VERSION,
             "request-id": "8f1c2b00-1a2b-4c3d-9e8f-000000000001"}


def _has(p, *subs):
    return any(s in p for s in subs)


# Canned, believable Windows command output -> higher interaction. When a bot's
# RCE/webshell request contains a recognised command, we answer as if it ran on
# a popped Windows box, so the bot proceeds to its real post-exploitation chain.
FAKE_CMDS = [
    (("whoami /priv",), "PRIVILEGES INFORMATION\r\n----------------------\r\n"
        "SeDebugPrivilege  Debug programs  Enabled\r\n"
        "SeImpersonatePrivilege  Impersonate a client  Enabled\r\n"),
    (("whoami",), "nt authority\\system\r\n"),
    (("hostname",), "EXCH01\r\n"),
    (("ver",), "\r\nMicrosoft Windows [Version 10.0.17763.3406]\r\n"),
    (("ipconfig",), "\r\nWindows IP Configuration\r\n\r\nEthernet adapter Ethernet0:\r\n"
        "   IPv4 Address. . . . : 10.20.0.15\r\n   Default Gateway . . : 10.20.0.1\r\n"),
    (("net user",), "\r\nUser accounts for \\\\EXCH01\r\n\r\n"
        "Administrator  deploy  Guest  krbtgt  svc_sql\r\n"),
    (("systeminfo",), "\r\nHost Name:   EXCH01\r\nOS Name:     Microsoft Windows Server 2019 Standard\r\n"
        "OS Version:  10.0.17763 N/A Build 17763\r\nSystem Type: x64-based PC\r\n"
        "Domain:      contoso.local\r\n"),
    (("tasklist",), "\r\nImage Name              PID\r\n=============== ========\r\n"
        "System                     4\r\nlsass.exe                684\r\n"
        "w3wp.exe                 4120\r\nMSExchangeFrontEnd.exe   5012\r\n"),
    (("dir", "ls "), " Volume in drive C has no label.\r\n Directory of C:\\inetpub\\wwwroot\r\n\r\n"
        "web.config\r\naspnet_client\r\n"),
    (("arp -a",), "\r\nInterface: 10.20.0.15\r\n  10.20.0.1   00-0c-29-ab-cd-ef  dynamic\r\n"),
]


# --- Adaptive RCE-confirmation reflector --------------------------------------
# Many RCE exploits run a verification step (echo a marker / print md5) and only
# proceed to deliver the real payload if the response contains the expected
# value. We compute/echo exactly what they expect -> the bot believes RCE worked
# and sends its next stage (which we capture). CVE-2024-4577 uses echo(md5(...)).
_MD5 = re.compile(r"md5\((['\"])(.*?)\1\)")
_ECHO = re.compile(r"echo\s+['\"]?([A-Za-z0-9]{6,40})['\"]?")
_PRINT = re.compile(r"print\((['\"])([A-Za-z0-9]{4,40})\1\)")
# Shell arithmetic expansion $((42234*40845)) — Node/RSC & shell RCE verifiers use it.
_ARITH = re.compile(r"\$\(\(\s*([0-9][0-9\s+\-*/%()]{0,80}?)\s*\)\)")
# expr-style: expr 1234 \* 5678   /   1234 * 5678 inside echo/print
_EXPR = re.compile(r"\bexpr\s+([0-9][0-9\s+\-*/%()\\]{1,80})")
# JS verifiers: console.log(1234*5), process.stdout.write(String(1234+5))
_JSMATH = re.compile(r"(?:console\.log|stdout\.write|String|print)\s*\(\s*([0-9][0-9\s+\-*/%()]{2,80}?)\s*\)")
_HEXMARK = re.compile(r"\b(0x[0-9a-fA-F]{4,16})\b")


def _safe_arith(expr: str):
    """Evaluate a pure-arithmetic expression (only digits/operators allowed)."""
    expr = expr.replace("\\", "").strip()
    if not expr or not re.fullmatch(r"[0-9\s+\-*/%()]+", expr):
        return None
    try:
        v = eval(expr, {"__builtins__": {}}, {})   # charset-restricted → safe
        return str(int(v)) if isinstance(v, (int, float)) else None
    except Exception:
        return None


def rce_reflect(blob: bytes):
    try:
        t = blob.decode("utf-8", "replace")
    except Exception:
        return None
    out = []
    for m in _MD5.finditer(t):
        out.append(hashlib.md5(m.group(2).encode("utf-8", "replace")).hexdigest())
    for m in _ECHO.finditer(t):
        out.append(m.group(1))
    for m in _PRINT.finditer(t):
        out.append(m.group(2))
    # arithmetic RCE-verification (shell $(()), expr, JS console.log/String)
    for rx in (_ARITH, _EXPR, _JSMATH):
        for m in rx.finditer(t):
            r = _safe_arith(m.group(1))
            if r:
                out.append(r)
    return "\n".join(dict.fromkeys(out)) if out else None


def fake_shell(blob: bytes):
    """If the request carries a known command, return believable output."""
    low = blob.lower()
    parts = []
    for keys, out in FAKE_CMDS:
        if any(k.encode() in low for k in keys):
            parts.append(out)
    return "".join(parts) if parts else None


def select_response(method: str, path: str, headers: dict, body: bytes, src_ip: str = ""):
    """Return (raw_response_bytes, status_str, lure_name)."""
    # --- Honeytoken beacon: did this request carry a token we handed out? -----
    # Fires when an attacker *uses* leaked secrets (validation bot hits a beacon
    # URL). Logged as a high-value correlation event; we still answer normally.
    if _ht is not None:
        try:
            scan_text = (path or "") + " " + (body or b"").decode("latin-1", "replace")
            for hv in headers.values():
                scan_text += " " + str(hv)
            _ht.scan(scan_text, src_ip)
        except Exception:
            pass

    p = (path or "/").lower()
    host = (headers.get("Host") or "").lower()

    # --- Public-IP reflection (Omicron worm: GET /ip HTTP/1.1 curl/7.68.0) ---
    # Omicron queries its own public IP before deciding next steps. We answer
    # with the real attacker IP (bare, like ifconfig.me) so it parses correctly.
    # Must run BEFORE redtail trap which has a richer /ip response that Omicron
    # can't parse (it expects a bare IP line, no headers/location).
    _ua = (headers.get("User-Agent") or headers.get("user-agent") or "")
    if p in ("/ip", "/ip.json", "/checkip", "/checkip.dyndns.org", "/check_ip",
             "/what-is-my-ip", "/myip", "/api/ip", "/plain") or \
       (p == "/h" and "curl" in _ua.lower()):
        _src = src_ip or "164.68.121.252"
        return (*_resp("200 OK", _src + "\n", ctype="text/plain"), "omicron-ip-probe")

    # --- RedTail-Wurm zuerst: eigener Köder + Payload-Capture ----------------
    # Signatur des Trap-Moduls ist (path, method, headers, body) -- bewusst
    # andere Argument-Reihenfolge als hier. Gibt None -> normale Lures greifen.
    trap = get_redtail_lure_response(path, method, headers, body or b"")
    if trap is not None:
        return trap

    # --- AWS EC2 Instance Metadata Service (SSRF / cloud credential theft) ---
    # Bots trigger this via SSRF: curl http://169.254.169.254/latest/meta-data/
    if "169.254.169.254" in host or p.startswith("/latest/"):
        import json as _j, time as _t
        _role = "ec2-default-ssm"
        _aid  = "ASIA" + "".join(__import__("random").choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
        _sak  = __import__("secrets").token_hex(20)
        _tok  = "FQoGZXIvYXdzEJ3//////////wEaDGVjMi1kZWZhdWx0LXNzbSK" + __import__("secrets").token_hex(60)
        _exp  = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if p.rstrip("/") in ("/latest/meta-data", "/latest/meta-data/"):
            body_txt = "ami-id\nami-launch-index\nami-manifest-path\nhostname\niam/\ninstance-id\nlocal-ipv4\nplacement/\npublic-ipv4\n"
            return (*_resp("200 OK", body_txt, ctype="text/plain"), "aws-metadata-ssrf")
        if p.startswith("/latest/meta-data/iam/security-credentials") and not p.endswith(_role):
            return (*_resp("200 OK", _role, ctype="text/plain"), "aws-metadata-ssrf")
        if p.endswith(_role) or p.endswith(_role + "/"):
            creds = _j.dumps({"Code":"Success","LastUpdated":_exp,"Type":"AWS-HMAC",
                              "AccessKeyId":_aid,"SecretAccessKey":_sak,"Token":_tok,
                              "Expiration":_exp}, indent=2)
            return (*_resp("200 OK", creds, ctype="application/json"), "aws-iam-creds")
        if "instance-id" in p:
            return (*_resp("200 OK", "i-0a1b2c3d4e5f67890", ctype="text/plain"), "aws-metadata-ssrf")
        if "local-ipv4" in p:
            return (*_resp("200 OK", "10.0.1.42", ctype="text/plain"), "aws-metadata-ssrf")
        if "public-ipv4" in p or "public-hostname" in p:
            return (*_resp("200 OK", "3.92.118.47", ctype="text/plain"), "aws-metadata-ssrf")
        if "user-data" in p:
            return (*_resp("200 OK", "#!/bin/bash\nexport DB_PASSWORD=Sup3rS3cr3t!\nexport API_KEY=sk-prod-xK9mN2pQ4rT\n", ctype="text/plain"), "aws-userdata-ssrf")
        return (*_resp("200 OK", "", ctype="text/plain"), "aws-metadata-ssrf")

    # --- static fingerprint files scanners fetch -----------------------------
    if p == "/favicon.ico":
        return (*_resp("200 OK", b"\x00\x00\x01\x00", ctype="image/x-icon"), "favicon")
    if p == "/robots.txt":
        return (*_resp("200 OK", "User-agent: *\nDisallow: /owa/\nDisallow: /ecp/\n",
                       ctype="text/plain"), "robots")

    # --- Microsoft Exchange (ProxyShell / ProxyLogon / ProxyNotShell) --------
    if "/autodiscover/" in p:
        return (*_resp("200 OK", AUTODISCOVER_XML, ctype="text/xml", extra=EXCH_HDRS),
                "exchange-autodiscover")
    if "/ews/" in p or "/mapi/" in p or "/powershell" in p or "/rpc/" in p:
        # POST-AUTH surface: an attacker who 'has access' uses EWS/MAPI to read &
        # exfiltrate mailboxes. Log WHAT they request (the real intel) and return
        # a believable mailbox response (Mistral, cached) so they keep going.
        body_s = (body or b"").decode("latin-1", "replace")
        if method == "POST" and body_s.strip():
            op = body_s[:400]
            _log_owa_access(src_ip, p, op)
            resp_body = ""
            if _ai is not None:
                try:
                    resp_body = _ai.fake_owa(f"{p} :: {op}")
                except Exception:
                    resp_body = ""
            ct = "text/xml" if ("<" in (resp_body or "")) else "application/json"
            return (*_resp("200 OK", resp_body or "", ctype=ct, extra=EXCH_HDRS),
                    "owa-post-auth-access")
        return (*_resp("200 OK", "", extra=EXCH_HDRS), "exchange-backend")
    if "/ecp/" in p:
        return (*_resp("200 OK", "<html><body>Exchange Admin Center</body></html>",
                       extra=EXCH_HDRS), "exchange-ecp")
    if "/owa" in p:
        # OWA credential capture: brute-forcers POST username/password here.
        # Grab them, mint a honeytoken, and return a believable "logon failed"
        # so the bot keeps trying → we collect the whole password list.
        if method == "POST" and body:
            try:
                from urllib.parse import parse_qs
                q = parse_qs(body.decode("latin-1", "replace"))
                user = (q.get("username") or q.get("destination") or [""])[0][:120]
                pw   = (q.get("password") or [""])[0][:120]
            except Exception:
                user = pw = ""
            if user or pw:
                _log_owa_cred(src_ip, user, pw)
                return (*_resp("200 OK", OWA_LOGIN.replace(
                    "</form>",
                    "</form><div style='color:#a80000'>The user name or password "
                    "you entered isn't correct. Try entering it again.</div>"),
                    extra=EXCH_HDRS), "owa-cred-capture")
        return (*_resp("200 OK", OWA_LOGIN, extra=EXCH_HDRS), "exchange-owa")

    # --- Citrix ADC / NetScaler (CVE-2019-19781, CVE-2023-3519) --------------
    if _has(p, "/vpn/", "/nsconfig/", "/netscaler", "/citrix", "/vpns/", "/oauth/idp"):
        return (*_resp("200 OK", "<html><body>Citrix Gateway</body></html>",
                       extra={"Set-Cookie": "NSC_AAAC=1; httponly"}), "citrix-netscaler")

    # --- F5 BIG-IP iControl REST (CVE-2022-1388) -> pretend RCE works ---------
    if "/mgmt/tm/util/bash" in p or "/mgmt/shared/" in p:
        return (*_resp("200 OK",
                       '{"kind":"tm:util:bash:runstate","commandResult":"uid=0(root) gid=0(root)\\n"}',
                       ctype="application/json"), "f5-bigip")

    # --- Hikvision IP camera / DVR (CVE-2021-36260 command injection) --------
    # MUST run before the VMware block ('/sdk' would otherwise match vCenter).
    # Scanners GET /SDK/webLanguage to fingerprint, then PUT the injection.
    # We mimic a real vulnerable device so they escalate and reveal the payload.
    if "/sdk/weblanguage" in p:
        body_s = (body or b"").decode("latin-1", "replace")
        m = re.search(r"<language>(.*?)</language>", body_s, re.I | re.S)
        if method in ("PUT", "POST") and m:
            # Extract the injected shell command ($(...) / `...`) and REFLECT
            # believable output (Mistral, cached) so the bot confirms RCE and
            # escalates to delivering its payload. URLs auto-IOC'd upstream.
            inj = m.group(1)
            cm = re.search(r"\$\((.*?)\)|`(.*?)`|;\s*(.+)$", inj, re.S)
            injected = (cm.group(1) or cm.group(2) or cm.group(3)).strip() if cm else ""
            cmd_out = ""
            if injected and _ai is not None:
                try:
                    cmd_out = _ai.fake_cmd_output(injected, device="hikvision")
                except Exception:
                    cmd_out = ""
            lang_val = cmd_out if cmd_out else "EN"
            from xml.sax.saxutils import escape as _xesc
            return (*_resp("200 OK",
                    '<?xml version="1.0" encoding="UTF-8"?>\r\n'
                    f'<language version="1.0">{_xesc(lang_val)[:1500]}</language>',
                    ctype="application/xml", server="App-webs/"),
                    "hikvision-cve-2021-36260")
        # GET (or PUT without payload) → look like a live, vulnerable Hikvision box.
        return (*_resp("200 OK",
                '<?xml version="1.0" encoding="UTF-8"?>\r\n'
                '<language version="1.0">EN</language>',
                ctype="application/xml", server="App-webs/"),
                "hikvision-probe")

    # --- VMware vCenter / Horizon (Log4Shell delivery) -----------------------
    # Delegate to full vCenter simulation — CVE-2021-21972, -22005, -22954,
    # Log4Shell, file upload capture, webshell command reflection.
    if is_vmware_request(path, headers, body or b""):
        vmr = get_vmware_response(path, method, headers, body or b"")
        if vmr is not None:
            return vmr

    # --- Spring (actuator / Spring4Shell) ------------------------------------
    if "/actuator" in p:
        return (*_resp("200 OK", '{"status":"UP","groups":["liveness","readiness"]}',
                       ctype="application/json"), "spring-actuator")

    # --- Atlassian Confluence (CVE-2022-26134 OGNL) --------------------------
    if _has(p, "/confluence", "/pages/", "/wiki/", "${"):
        return (*_resp("200 OK", "<html><body>Atlassian Confluence</body></html>"), "confluence")

    # --- GitLab / Struts / ThinkPHP / generic PHP RCE ------------------------
    if _has(p, "/users/sign_in", "/api/v4/"):
        return (*_resp("200 OK", "GitLab"), "gitlab")
    if _has(p, ".action", ".do", "struts"):
        return (*_resp("200 OK", "<html><body>OK</body></html>"), "struts")
    if _has(p, "/vendor/phpunit", "eval-stdin.php"):
        return (*_resp("200 OK", "PHPUNIT"), "phpunit-rce")
    if _has(p, "thinkphp", "/index.php?s=", "invokefunction"):
        return (*_resp("200 OK", "ThinkPHP"), "thinkphp")
    if p.endswith(".php") or "phpmyadmin" in p:
        return (*_resp("200 OK", "<html><head><title>phpMyAdmin</title></head><body>ok</body></html>"),
                "php-app")

    # --- WordPress / Joomla --------------------------------------------------
    if _has(p, "/wp-login", "/wp-admin", "/xmlrpc.php", "/wp-content", "/wp-json"):
        return (*_resp("200 OK", "<html><body>WordPress</body></html>"), "wordpress")

    # --- git-dumper bait: serve a coherent fake .git so the dumper keeps pulling,
    # with a Mistral-generated commit history (cached) that leaks honeytoken+UNC.
    # config falls through to the secret-leak block below (it mints the beacon).
    if "/.git/" in p and ".git/config" not in p:
        gp = p.split("/.git/", 1)[1].split("?")[0].rstrip("/")   # p is lowercased
        _fakesha = "9f3a1c0b7e6d4a2f8c5b1e0d9a7c6f4b2e1d3a8c"
        if gp == "head":
            return (*_resp("200 OK", "ref: refs/heads/main\n", ctype="text/plain"), "git-dump")
        if gp == "description":
            return (*_resp("200 OK", "Unnamed repository; edit this file 'description' to name the repository.\n",
                           ctype="text/plain"), "git-dump")
        if gp == "packed-refs":
            return (*_resp("200 OK", "# pack-refs with: peeled fully-peeled sorted \n"
                           f"{_fakesha} refs/heads/main\n", ctype="text/plain"), "git-dump")
        if gp.startswith("refs/heads/") or gp == "orig_head":
            return (*_resp("200 OK", _fakesha + "\n", ctype="text/plain"), "git-dump")
        if gp == "logs/head":
            tok = _ht.mint(src_ip, kind="git") if _ht is not None else "htk_0000000000000000"
            host = _ht.beacon_host() if _ht is not None else _UNC_HOST
            log = _ai.fake_git_log() if _ai is not None else ""
            if log:
                log = log.replace("{HOST}", host).replace("{TOKEN}", tok)
            else:
                log = (f"0000000000000000000000000000000000000000 {_fakesha} "
                       f"deploy <ci@corp.local> 1739000000 +0000\tcommit (initial): import app; "
                       f"backup to \\\\{host}\\backups (token {tok})\n")
            return (*_resp("200 OK", log, ctype="text/plain"), "git-dump-log")
        # objects/index/etc. — let the dumper think the rest is unreachable
        return (*_resp("404 Not Found", "", ctype="text/plain"), "git-dump")

    # --- Source / secret leakage probes — convincing bait + honeytoken beacon -
    # Serve realistic, persona-consistent secrets stamped with a unique token in
    # beacon URLs that point back at us. When the attacker's tooling validates
    # the leaked creds, the beacon fires (see honeytoken.scan above).
    if (p.endswith((".env", ".env.production", ".env.local", ".env.bak", ".env.prod",
                    ".git/config", ".aws/credentials", "docker-compose.yml",
                    "terraform.tfstate", "terraform.tfstate.backup"))
            or "/.git/" in p or "tfstate" in p):
        tok = _ht.mint(src_ip, kind="env") if _ht is not None else "htk_0000000000000000"
        host = _ht.beacon_host() if _ht is not None else "164.68.121.252"
        akid = "AKIA" + secrets.choice("XYZQ") + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(15))
        asec = "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(40))
        if "tfstate" in p:
            body_txt = (
                '{\n  "version": 4,\n  "terraform_version": "1.7.5",\n'
                '  "resources": [{\n    "type": "aws_db_instance", "name": "prod",\n'
                '    "instances": [{ "attributes": {\n'
                f'      "username": "appuser", "password": "Tf_Pr0d!{tok[-6:]}",\n'
                f'      "endpoint": "prod-db.cluster-cqx.eu-central-1.rds.amazonaws.com:5432",\n'
                f'      "aws_access_key_id": "{akid}", "aws_secret_access_key": "{asec}"\n'
                '    }}]\n  }],\n'
                f'  "outputs": {{ "sentry_dsn": {{ "value": "https://{tok}@{host}/4" }} }}\n}}\n')
        elif ".git/config" in p or "/.git/" in p:
            body_txt = (
                "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
                f"\turl = http://deploy:{tok}@{host}:8080/git/app-prod.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n")
        elif "credentials" in p:
            body_txt = (f"[default]\naws_access_key_id = {akid}\n"
                        f"aws_secret_access_key = {asec}\n"
                        f"# rotation webhook: http://{host}:8080/iam/rotate?t={tok}\n")
        elif "docker-compose" in p:
            body_txt = (
                "version: '3.8'\nservices:\n  api:\n    image: app-prod:latest\n"
                "    environment:\n"
                f"      - DATABASE_URL=postgres://appuser:Pr0d_{tok[-6:]}@10.0.0.20:5432/app\n"
                f"      - SENTRY_DSN=https://{tok}@{host}/4\n"
                f"      - INTERNAL_API=http://{host}:8080/v2\n")
        else:  # .env family
            body_txt = (
                "APP_ENV=production\nAPP_KEY=base64:" + asec[:24] + "=\n"
                "DB_CONNECTION=pgsql\nDB_HOST=10.0.0.20\nDB_PORT=5432\n"
                "DB_DATABASE=app_prod\nDB_USERNAME=appuser\n"
                f"DB_PASSWORD=Pr0d_DB_{tok[-6:]}!\n"
                f"AWS_ACCESS_KEY_ID={akid}\nAWS_SECRET_ACCESS_KEY={asec}\n"
                "AWS_DEFAULT_REGION=eu-central-1\n"
                f"SENTRY_DSN=https://{tok}@{host}/4\n"
                f"INTERNAL_API_URL=http://{host}:8080/v2\n"
                f"SLACK_WEBHOOK=http://{host}:8080/hooks/{tok}\n"
                # SMB coercion: Windows tooling resolving these UNC paths
                # auto-authenticates to our SMB → Net-NTLM hash captured.
                f"DB_BACKUP_PATH=\\\\{_UNC_HOST}\\backups\\app_prod.bak\n"
                f"LOG_SHARE=\\\\{_UNC_HOST}\\logs\\app\n"
                # Stratum bait: attacker automation that redeploys a miner from
                # scraped configs may point it at OUR pool → wallet/rig captured.
                f"XMRIG_POOL=stratum+tcp://{_UNC_HOST}:3333\n"
                f"XMRIG_WALLET=4AdUndeR{tok[-6:]}xMiNeRfAkEwAlLeTpLaCeHoLdEr0000000000000000\n")
        return (*_resp("200 OK", body_txt, ctype="text/plain"), "secret-leak")

    # --- IoT/router CGI (some Windows droppers piggyback these) ---------------
    if _has(p, "/boaform", "/cgi-bin", "/goform", "/hnap1", "/setup.cgi"):
        return (*_resp("200 OK", "OK"), "cgi-device")

    # --- Cisco Smart License Utility (CVE-2024-20439 static creds) -----------
    if "/cslu/" in p:
        return (*_resp("200 OK", '{"status":"success","data":{}}',
                       ctype="application/json"), "cisco-cslu")

    # --- Webshell / command-exec / RCE confirmation --------------------------
    # Reflect verification (echo/md5), answer known commands, and for any OTHER
    # injected command open a Mistral-backed FAKE SHELL → believable output so the
    # bot keeps going. Every command+response is recorded as a 'webshell' replay
    # (shows in the SSH-REPLAY tab tagged WEBSHELL).
    probe = (path or "").encode("latin-1", "replace") + b" " + (body or b"")
    refl = rce_reflect(probe)
    out = fake_shell(probe)
    inj = _extract_webshell_cmd(path, body)
    if inj and not (refl or out) and _ai is not None:
        try:
            out = _ai.fake_cmd_output(inj, device="windows")   # cached → 0 tokens on repeat
        except Exception:
            out = None
    combined = "\n".join(x for x in (refl, out) if x)
    if combined:
        if inj:
            _log_webshell_replay(src_ip, inj, combined)
        return (*_resp("200 OK", combined + "\n", ctype="text/plain"), "webshell-interactive")
    if method in ("POST", "PUT") and (
            _has(p, "upload", "shell", "cmd", "exec", "eval", "ajax", "/api/")
            or body):
        return (*_resp("200 OK", "OK"), "webshell-bait")

    # --- Default: real Exchange boxes redirect / to OWA ----------------------
    if p == "/" or p == "":
        return (*_resp("302 Found", "", extra={"Location": "/owa/"}), "root-redirect")

    # AI strategist: this request matched no specific lure (= possibly a novel
    # exploit). Observe it keyed by attacker IP; if the strategist has chosen an
    # active tactic with a concrete fake response, serve that to elicit the next
    # stage. Otherwise fall through to the generic IIS page (deterministic).
    if _strat is not None and src_ip:
        try:
            _sid = f"http:{src_ip}"
            _strat.note(_sid, "http", f"{method} {path}", src_ip=src_ip, unhandled=True)
            tac = _strat.stance(_sid)
            if tac and tac.get("stance") in ("mimic_vuln", "engage", "probe"):
                sug = (tac.get("suggestion") or "").strip()
                if sug:
                    _strat.record_outcome(src_ip, f"steered:{tac['stance']}")
                    return (*_resp("200 OK", sug), f"ai-{tac['stance']}")
        except Exception:
            pass

    # everything else: believable IIS 200 so scanners log us as a live target
    body_html = ("<!DOCTYPE html><html><head><title>IIS Windows Server</title></head>"
                 "<body><h1>Internet Information Services</h1></body></html>")
    return (*_resp("200 OK", body_html), "iis-default")
