"""
VMware vCenter 7.x Honeypot Lure.

Simulates a fully exploitable vCenter 7.0.3 installation.
Captures: file uploads (CVE-2021-21972), path-traversal probes (CVE-2021-22005),
SSTI payloads (CVE-2022-22954), Log4Shell JNDI strings, credentials, webshell commands.

Strategy: appear exploitable, serve believable API responses so attackers commit
to delivering their real second stage, which we capture.
"""

import hashlib, json, os, re, secrets, time
from datetime import datetime, timezone

DATA_DIR   = os.environ.get("DATA_DIR",    "/data")
EVENTS     = os.environ.get("EVENTS",      "/data/events.jsonl")
SAMPLE_DIR = os.environ.get("SAMPLE_DIR",  "/data/samples")
os.makedirs(SAMPLE_DIR, exist_ok=True)

VCENTER_VERSION  = "7.0.3.01800"
VCENTER_BUILD    = "21784236"
VCENTER_HOST     = "vcenter.corp.local"

# Fake /etc/passwd for CVE-2021-22005 path-traversal
FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "vsphere-ui:x:500:500:VMware vSphere UI:/home/vsphere-ui:/bin/bash\n"
    "vpostgres:x:501:501:VMware Postgres:/home/vpostgres:/bin/sh\n"
    "vpxd:x:502:502:VMware VPX Daemon:/opt/vmware/vpxd:/bin/false\n"
    "rhttpproxy:x:503:503:VMware HTTP Proxy:/var/lib/vmware/rhttpproxy:/bin/false\n"
    "vmdird:x:504:504:VMware Directory Service:/home/vmdird:/bin/false\n"
)

# Believable Linux vCenter webshell command responses
_WEBSHELL_CMDS = {
    "id":          "uid=0(root) gid=0(root) groups=0(root)\n",
    "whoami":      "root\n",
    "hostname":    VCENTER_HOST + "\n",
    "uname -a":    f"Linux {VCENTER_HOST} 5.10.203 #1 SMP PREEMPT x86_64 GNU/Linux\n",
    "cat /etc/passwd": FAKE_PASSWD,
    "ifconfig":    "eth0: inet 10.20.0.10  netmask 255.255.255.0  broadcast 10.20.0.255\n",
    "ip a":        "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 10.20.0.10/24\n",
    "ls /":        "bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var\n",
    "ls /root":    ".bash_history  .ssh  certs  scripts  .vmware\n",
    "ls /tmp":     "\n",
    "ps aux":      "root  1  vpxd\nroot  2  vsphere-ui\nroot  3  python3 /opt/vmware/rhttpproxy\n",
    "env":         f"PATH=/usr/bin:/bin\nVCENTER_VERSION={VCENTER_VERSION}\nHOME=/root\n",
    "pwd":         "/\n",
    "netstat -tlnp": "tcp  0  0  0.0.0.0:443  0.0.0.0:*  LISTEN  1/vpxd\ntcp  0  0  0.0.0.0:80   0.0.0.0:*  LISTEN  1/vpxd\n",
    "crontab -l":  "# no crontab for root\n",
}

# vCenter login page (realistic 7.x design)
_LOGIN_HTML = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>vSphere Client</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'VMware Clarity','Helvetica Neue',Arial,sans-serif;
  background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);
  min-height:100vh;display:flex;align-items:center;justify-content:center;color:#fff}}
.card{{background:rgba(255,255,255,.05);backdrop-filter:blur(20px);
  border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:40px;
  width:400px;max-width:90vw;box-shadow:0 25px 50px rgba(0,0,0,.5)}}
.title{{text-align:center;margin-bottom:30px}}
.title h1{{font-size:20px;font-weight:300;letter-spacing:2px}}
.title .v{{color:#60b4f4;font-weight:600}}
label{{display:block;color:#8899aa;font-size:11px;text-transform:uppercase;
  letter-spacing:1px;margin-bottom:6px;margin-top:16px}}
input{{width:100%;padding:12px 16px;background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.15);border-radius:6px;color:#fff;font-size:14px}}
button{{width:100%;padding:12px;background:#0091da;border:none;border-radius:6px;
  color:#fff;font-size:15px;font-weight:600;cursor:pointer;margin-top:22px}}
.footer{{text-align:center;margin-top:18px;font-size:11px;color:#557088}}
.version{{color:#3a5570;font-size:10px;text-align:center;margin-top:8px}}
</style></head>
<body><div class=card>
  <div class=title>
    <svg width=64 height=64 viewBox="0 0 64 64"><rect width=64 height=64 rx=10 fill="#0091da"/>
    <text x=32 y=46 text-anchor=middle fill="#fff" font-size=32 font-weight=700>V</text></svg>
    <h1 style="margin-top:10px">VMware <span class=v>vSphere</span></h1>
  </div>
  <form method=POST action="/ui/login">
    <label>User name</label>
    <input type=text name=username placeholder="administrator@vsphere.local" autocomplete=username>
    <label>Password</label>
    <input type=password name=password placeholder="Password" autocomplete=current-password>
    <button type=submit>LOGIN</button>
  </form>
  <div class=footer><a href="/sdk/" style=color:#60b4f4>SDK</a> · <a href="/mob/" style=color:#60b4f4>MOB</a> · <a href="/api/vcenter/vm" style=color:#60b4f4>API</a></div>
  <div class=version>vCenter Server {VCENTER_VERSION} · build {VCENTER_BUILD}</div>
</div></body></html>"""

_VCENTER_API = {
    "/api/vcenter/vm": '[{{"vm":"WIN-DC01","power_state":"POWERED_ON","cpu":4,"memory_MiB":16384}},'
                       '{{"vm":"WIN-SQL01","power_state":"POWERED_ON","cpu":8,"memory_MiB":65536}},'
                       '{{"vm":"LINUX-WEB01","power_state":"POWERED_ON","cpu":2,"memory_MiB":8192}}]',
    "/api/vcenter/host": '[{{"host":"esxi01.corp.local","connection_state":"CONNECTED","cpu_count":56,"memory_GiB":512}}]',
    "/api/vcenter/datastore": '[{{"datastore":"datastore1","type":"VMFS","capacity_GiB":4096,"free_GiB":1024}}]',
}

# ── Patterns ──────────────────────────────────────────────────────────────────

_LOG4J    = re.compile(r'\$\{[jJ][nN][dD][iI]:', re.IGNORECASE)
_URL_RE   = re.compile(r'(?:https?|ldap|rmi|dns)://[^\s\'"<>]{4,200}', re.IGNORECASE)
_SSTI_RE  = re.compile(r'\$\{[^}]{1,200}\}')
_PARAM_RE = re.compile(r'(?:cmd|command|exec|c|shell|run)=([^&\n\r]{1,200})', re.IGNORECASE)

# Paths that imply specific CVEs
_CVE_PATHS = {
    "cve_2021_21972": ["sdktunnel", "uploadova", "uploadservlet", "/ui/vropspluginui"],
    "cve_2021_22005": ["/analytics/telemetry", "/eam/vib", "/guestFile"],
    "cve_2022_22954": ["/gateway/api", "/catalog-portal", "serverbypass", "freemarker"],
    "log4shell":      ["/websso/", "/pcma-query"],
}


def _ts():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _log(ev: dict):
    try:
        with open(EVENTS, "a") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _resp(status: str, body: str | bytes = b"", ctype="text/html",
          extra: dict | None = None) -> bytes:
    if isinstance(body, str):
        body = body.encode()
    h = [f"HTTP/1.1 {status}",
         "Server: Apache",
         f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}",
         f"Content-Type: {ctype}; charset=utf-8",
         f"Content-Length: {len(body)}",
         "Connection: close"]
    for k, v in (extra or {}).items():
        h.append(f"{k}: {v}")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def _detect_cves(path: str, headers: dict, body_str: str) -> list[str]:
    pl = path.lower()
    cves = []
    for cve, pats in _CVE_PATHS.items():
        if any(p in pl for p in pats):
            cves.append(cve)
    # Log4Shell in any header value
    for v in headers.values():
        if _LOG4J.search(str(v)):
            if "log4shell" not in cves:
                cves.append("log4shell")
            break
    if _LOG4J.search(body_str):
        if "log4shell" not in cves:
            cves.append("log4shell")
    return cves


def _extract_intel(path: str, headers: dict, body_str: str) -> dict:
    full = path + " " + body_str
    for v in headers.values():
        full += " " + str(v)
    return {
        "urls": list(dict.fromkeys(_URL_RE.findall(full)[:15])),
        "log4j": list(dict.fromkeys(_LOG4J.findall(full)[:5])),
        "ssti":  list(dict.fromkeys(_SSTI_RE.findall(full)[:5])),
    }


def _save_upload(body: bytes, cve: str) -> dict | None:
    if len(body) < 4:
        return None
    sha256 = hashlib.sha256(body).hexdigest()
    ext = ".bin"
    if body[:5] in (b"ustar", b"\x1f\x8b\x08") or body[:2] == b"\x1f\x8b":
        ext = ".tgz"
    elif body[:2] == b"PK":
        ext = ".zip"
    elif body[:4] == b"\xca\xfe\xba\xbe":
        ext = ".class"
    fname = f"vmware_{cve}_{sha256[:12]}{ext}"
    try:
        with open(os.path.join(SAMPLE_DIR, fname), "wb") as f:
            f.write(body)
    except OSError:
        pass
    return {"sha256": sha256, "size": len(body), "file": fname}


def _webshell_output(body_str: str, path: str = "") -> str | None:
    text = (body_str + " " + path).lower()
    m = _PARAM_RE.search(body_str)
    if m:
        cmd_val = m.group(1).strip().lower()
        for pat, out in _WEBSHELL_CMDS.items():
            if cmd_val.startswith(pat) or pat in cmd_val:
                return out
        return f"sh: {m.group(1).strip()}: not found\n"
    for pat, out in _WEBSHELL_CMDS.items():
        if pat in text:
            return out
    return None


def _login_html_with_error() -> bytes:
    return _LOGIN_HTML.replace(
        "<button type=submit>LOGIN</button>",
        '<div style="color:#f54f47;font-size:12px;margin-bottom:8px">Invalid credentials.</div>'
        "<button type=submit>LOGIN</button>"
    ).encode()


# ── Public API ─────────────────────────────────────────────────────────────────

def is_vmware_request(path: str, headers: dict, body: bytes) -> bool:
    pl = path.lower()
    indicators = [
        "/ui/", "/vsphere", "/sdk", "/websso", "/saml", "/eam/",
        "/vropspluginui", "/analytics/telemetry", "/gateway/api",
        "/lookupservice", "/pcma-query", "/guestFile", "/sdkTunnel",
        "/sdktunnel", "vmware", "vcenter", "vsphere", "/mob/",
        "/api/session", "/rest/com/vmware",
    ]
    if any(x in pl for x in indicators):
        return True
    for v in headers.values():
        if _LOG4J.search(str(v)):
            return True
    return False


def get_vmware_response(path: str, method: str, headers: dict,
                        body: bytes) -> tuple[bytes, str, str] | None:
    """
    Handle a VMware-targeted request.
    Returns (response_bytes, http_status, lure_name) or None.
    """
    pl     = path.lower()
    body_s = body.decode("latin1", "replace") if body else ""
    cves   = _detect_cves(path, headers, body_s)
    intel  = _extract_intel(path, headers, body_s)
    sid    = secrets.token_hex(16)

    # ── CVE-2021-21972: vSphere Client file-upload RCE ─────────────────────
    if "cve_2021_21972" in cves or "sdktunnel" in pl or "uploadova" in pl or "uploadservlet" in pl:
        upload = None
        if method in ("POST", "PUT") and body and len(body) > 10:
            upload = _save_upload(body, "CVE-2021-21972")
        _log({
            "ts": _ts(), "service": "http", "type": "vmware_exploit",
            "lure": "vmware-cve-2021-21972", "cves": cves,
            "path": path, "method": method,
            "upload": upload, "intel": intel,
            "body_preview": body_s[:500],
        })
        if upload:
            webshell = "/ui/vropspluginui/rest/services/shell.jsp"
            return (_resp("301 Moved Permanently", "", extra={
                "Location": webshell,
                "Server": f"VMware vCenter Server {VCENTER_VERSION}",
                "X-Powered-By": "JSP/2.3",
            }), "301 Moved Permanently", "vmware-cve-2021-21972")
        return (_resp("200 OK",
                      json.dumps({"status": "success", "taskId": sid}),
                      ctype="application/json",
                      extra={"Server": f"VMware vCenter Server {VCENTER_VERSION}"}),
                "200 OK", "vmware-cve-2021-21972")

    # ── CVE-2021-22005: analytics telemetry SSRF / path traversal ──────────
    if "cve_2021_22005" in cves:
        if re.search(r'(?:\.\.\/|%2e%2e|%252e){1,}', path, re.I) or "etc/passwd" in pl:
            _log({
                "ts": _ts(), "service": "http", "type": "vmware_exploit",
                "lure": "vmware-cve-2021-22005", "cves": cves,
                "path": path, "intel": intel,
            })
            return (_resp("200 OK", FAKE_PASSWD, ctype="text/plain"),
                    "200 OK", "vmware-cve-2021-22005")
        if method == "POST" and body:
            upload = _save_upload(body, "CVE-2021-22005")
            _log({
                "ts": _ts(), "service": "http", "type": "vmware_exploit",
                "lure": "vmware-cve-2021-22005", "cves": cves,
                "path": path, "upload": upload, "intel": intel,
            })
            return (_resp("200 OK", '{"status":"ok"}', ctype="application/json"),
                    "200 OK", "vmware-cve-2021-22005")

    # ── CVE-2022-22954: gateway API SSTI ────────────────────────────────────
    if "cve_2022_22954" in cves:
        ssti   = _SSTI_RE.findall(path + " " + body_s)[:5]
        shell  = _webshell_output(body_s)
        _log({
            "ts": _ts(), "service": "http", "type": "vmware_exploit",
            "lure": "vmware-cve-2022-22954", "cves": cves,
            "path": path, "ssti_payloads": ssti, "intel": intel,
            "shell_output": shell,
        })
        body_out = shell or json.dumps({"id": sid, "email": "admin@vsphere.local"})
        return (_resp("200 OK", body_out, ctype="application/json"),
                "200 OK", "vmware-cve-2022-22954")

    # ── Log4Shell via headers ────────────────────────────────────────────────
    if "log4shell" in cves:
        payloads = [f"{k}: {v}" for k, v in headers.items() if _LOG4J.search(str(v))]
        if _LOG4J.search(body_s):
            payloads.append("BODY: " + body_s[:200])
        _log({
            "ts": _ts(), "service": "http", "type": "vmware_exploit",
            "lure": "vmware-log4shell-trap", "cves": cves,
            "path": path, "log4j_payloads": payloads[:10], "intel": intel,
        })
        return (_resp("200 OK", _LOGIN_HTML, extra={
            "Set-Cookie": f"VSPHERE-UI-JSESSIONID={sid}; Secure; HttpOnly",
            "Server": f"VMware vCenter Server {VCENTER_VERSION}",
        }), "200 OK", "vmware-log4shell-trap")

    # ── Post-exploit webshell invocation ────────────────────────────────────
    if any(x in pl for x in [".jsp", ".jspx", "shell.jsp", "cmd.jsp", "tomcatwar"]):
        shell = _webshell_output(body_s, path)
        _log({
            "ts": _ts(), "service": "http", "type": "vmware_exploit",
            "lure": "vmware-webshell-exec",
            "path": path, "method": method,
            "shell_command": body_s[:200], "shell_output": shell,
            "intel": intel,
        })
        return (_resp("200 OK", shell or "OK\n", ctype="text/plain"),
                "200 OK", "vmware-webshell-exec")

    # ── vCenter API session (credential capture) ────────────────────────────
    if pl in ("/api/session", "/rest/com/vmware/cis/session"):
        try:
            creds = json.loads(body) if body else {}
        except Exception:
            creds = {}
        _log({
            "ts": _ts(), "service": "http", "type": "vmware_exploit",
            "lure": "vmware-session-captured",
            "path": path, "method": method,
            "vcenter_user": creds.get("username", "?"),
            "vcenter_pass": creds.get("password", "?"),
        })
        token = json.dumps({"value": "CAPTURED-" + sid,
                            "user": creds.get("username", "admin@vsphere.local")})
        return (_resp("201 Created", token, ctype="application/json"),
                "201 Created", "vmware-session-captured")

    # ── vCenter login form POST (credential capture) ─────────────────────────
    if method == "POST" and any(x in pl for x in ["/ui/login", "/owa/", "/auth"]):
        user = re.search(r'username=([^&\n]+)', body_s)
        pw   = re.search(r'password=([^&\n]+)', body_s)
        if user or pw:
            _log({
                "ts": _ts(), "service": "http", "type": "vmware_exploit",
                "lure": "vmware-vcenter-login",
                "path": path,
                "vcenter_user": (user.group(1) if user else "?"),
                "vcenter_pass": (pw.group(1) if pw else "?"),
            })
        return (_resp("200 OK", _login_html_with_error()), "200 OK", "vmware-vcenter-login")

    # ── vCenter API endpoints ────────────────────────────────────────────────
    if pl in _VCENTER_API:
        resp_body = _VCENTER_API[pl]
        return (_resp("200 OK", resp_body, ctype="application/json",
                      extra={"Server": f"VMware vCenter Server {VCENTER_VERSION}"}),
                "200 OK", "vmware-api")

    # ── .env / WSDL leak probes ──────────────────────────────────────────────
    if pl.endswith(".env"):
        env = f"VCENTER_USER=administrator@vsphere.local\nVCENTER_PASS=VMware123!\nDB_PASS=changeme\n"
        return (_resp("200 OK", env, ctype="text/plain"), "200 OK", "vmware-env-leak")
    if "/sdk/vimservice.wsdl" in pl:
        wsdl = '<?xml version="1.0"?><definitions targetNamespace="urn:vim25Service"/>'
        return (_resp("200 OK", wsdl, ctype="text/xml"), "200 OK", "vmware-sdk-wsdl")

    # ── SDK / MOB ────────────────────────────────────────────────────────────
    if "/sdk" in pl:
        soap = (
            '<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><RetrieveServiceContentResponse>'
            f'<returnval><about><name>VMware vCenter Server</name>'
            f'<version>{VCENTER_VERSION}</version><build>{VCENTER_BUILD}</build>'
            '</about></returnval></RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>'
        )
        return (_resp("200 OK", soap, ctype="text/xml"), "200 OK", "vmware-sdk")
    if "/mob" in pl:
        return (_resp("200 OK", f"<html><body><h2>Managed Object Browser</h2>"
                      f"<p>vCenter {VCENTER_VERSION}</p></body></html>"),
                "200 OK", "vmware-mob")

    # ── vCenter login page (catch-all for /ui/* /vsphere /websso) ───────────
    return (_resp("200 OK", _LOGIN_HTML, extra={
        "Set-Cookie": f"VSPHERE-UI-JSESSIONID={sid}; Secure; HttpOnly; Path=/",
        "Server": f"VMware vCenter Server {VCENTER_VERSION}",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
    }), "200 OK", "vmware-vcenter-login")
