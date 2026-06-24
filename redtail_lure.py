"""
Köder-Erweiterung für lures.py - RedTail-Wurm-Trap.
Importiere dieses Modul und rufe get_redtail_lure_response() VOR 
den normalen Lures auf. Wenn None zurückkommt → normale Lure verwenden.
"""

import hashlib, os, json, re, base64
from datetime import datetime

REDTAIL_UA = "libredtail-http"
LOG_DIR = os.environ.get("TRAP_LOG_DIR", "/data/trap_logs")
os.makedirs(LOG_DIR, exist_ok=True)

def is_redtail_scanner(headers: dict) -> bool:
    """Erkenne libredtail-http Scanner."""
    ua = headers.get("User-Agent", headers.get("user-agent", ""))
    return REDTAIL_UA in ua

def get_redtail_lure_response(path: str, method: str, headers: dict, body: bytes):
    """
    Wenn RedTail-Scanner erkannt: liefere spezielle Köder-Antwort.
    Gibt (response_bytes, http_status, lure_name) oder None zurück.
    """
    ua = headers.get("User-Agent", headers.get("user-agent", ""))
    if REDTAIL_UA not in ua:
        return None
    
    # === REDTAIL ERKANNT ===
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    
    # Logge den Angriff
    event = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "scanner": REDTAIL_UA,
        "method": method,
        "path": path,
        "headers": {k: str(v)[:500] for k, v in headers.items()},
        "body": body.decode("latin-1", errors="replace")[:4000],
    }
    
    log_file = os.path.join(LOG_DIR, f"redtail_{ts}.json")
    with open(log_file, "w") as f:
        json.dump(event, f, indent=2)
    
    p = (path or "/").lower()
    body_str = body.decode("latin-1", errors="replace")
    
    # --- EXPLOIT-TYPEN ---
    
    # 1. CGI Path-Traversal
    if "cgi-bin" in p and ("%2e" in p or "bin/sh" in p):
        # Extrahiere den Payload
        if "wget" in body_str or "curl" in body_str:
            payload_file = os.path.join(LOG_DIR, "payloads_captured.txt")
            with open(payload_file, "a") as f:
                f.write(f"\n{'='*60}\n{ts}\n{body_str}\n")
        
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"OK\n"
        ), "200 OK", "redtail-cgi-trap"
    
    # 2. PHPUnit RCE (CVE-2017-9841)
    if "eval-stdin.php" in p:
        md5_match = re.search(r'md5\("([^"]+)"\)', body_str)
        if md5_match:
            h = hashlib.md5(md5_match.group(1).encode()).hexdigest()
            return (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{h}\n".encode(),
                "200 OK", "redtail-phpunit-trap"
            )
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nPHPUNIT_OK\n",
            "200 OK", "redtail-phpunit-trap"
        )
    
    # 3. CVE-2024-4577 (PHP CGI Injection)
    if "allow_url_include" in p or "auto_prepend" in p:
        # Dekodiere base64 Payload
        b64_match = re.search(r'base64_decode\("([^"]+)"\)', body_str)
        if b64_match:
            try:
                decoded = base64.b64decode(b64_match.group(1)).decode()
                dec_file = os.path.join(LOG_DIR, "cve2024_decoded.txt")
                with open(dec_file, "a") as f:
                    f.write(f"\n{'='*60}\n{ts}\n{decoded}\n")
            except:
                pass
        
        md5_match = re.search(r'md5\("([^"]+)"\)', body_str)
        if md5_match:
            h = hashlib.md5(md5_match.group(1).encode()).hexdigest()
            return (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{h}\n".encode(),
                "200 OK", "redtail-cve2024-trap"
            )
    
    # 4. ThinkPHP RCE
    if "think" in p and "invokefunction" in p:
        md5_match = re.search(r'md5\("([^"]+)"\)', body_str) or re.search(r'md5=([a-f0-9]+)', p)
        if md5_match:
            h = hashlib.md5(md5_match.group(1).encode()).hexdigest()
            return (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{h}\n".encode(),
                "200 OK", "redtail-thinkphp-trap"
            )
    
    # 5. Exchange/OWA
    if any(x in p for x in ["owa", "ecp", "ews", "autodiscover", "mapi"]):
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Microsoft-IIS/10.0\r\n"
            b"X-Powered-By: ASP.NET\r\n"
            b"X-OWA-Version: 15.2.792.3\r\n"
            b"X-FEServer: EXCH01\r\n"
            b"Content-Type: text/html\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b'<html><body><form action="/owa/auth.owa" method="POST">'
            b'<h1>Outlook Web App</h1>'
            b'<input name="username"/><input name="password" type="password"/>'
            b'<input type="submit" value="Sign in"/>'
            b'</form></body></html>\n'
        ), "200 OK", "redtail-exchange-trap"
    
    # 6. Generic - wir tun so als wären wir verwundbar
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\nOK\n",
        "200 OK", "redtail-generic-trap"
    )
