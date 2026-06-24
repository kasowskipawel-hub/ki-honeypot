"""
Auto Counter-Intelligence — fingerprint attackers in real-time.
When a new IP connects, automatically probes back:
  - Reverse DNS lookup
  - Banner grab on common ports (22, 80, 443, 3389, 8080, 6379)
  - Quick port scan (top 10 ports)
  - GeoIP enrichment
Results cached and shown in dashboard. Async, non-blocking.
"""

import asyncio, json, os, socket, time, threading
from concurrent.futures import ThreadPoolExecutor

SCAN_PORTS = [22, 80, 443, 3389, 8080, 8443, 6379, 3306, 5432, 25, 21, 23]
SCAN_TIMEOUT = 2  # seconds per port
CACHE_FILE = os.environ.get("COUNTER_INTEL_CACHE", "/data/counter_intel.json")
MAX_CACHE = 5000

os.makedirs(os.path.dirname(CACHE_FILE) if os.path.dirname(CACHE_FILE) else "/data", exist_ok=True)

# Simple cache
_cache = {}
_cache_lock = threading.Lock()

def _load_cache():
    global _cache
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE) as f:
                _cache = json.load(f)
    except: pass

def _save_cache():
    try:
        with open(CACHE_FILE, "w") as f:
            # Keep only last MAX_CACHE entries
            items = list(_cache.items())[-MAX_CACHE:]
            json.dump(dict(items), f)
    except: pass

_load_cache()


def probe_port(ip, port, timeout=SCAN_TIMEOUT):
    """Try to connect and grab banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024)
        sock.close()
        text = banner.decode("utf-8", "replace").split("\n")[0].strip()
        return {"port": port, "open": True, "banner": text[:200]}
    except Exception:
        return {"port": port, "open": False}


def reverse_dns(ip):
    """Get reverse DNS hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None


def geoip(ip):
    """Quick GeoIP lookup using free API."""
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,city,isp,org,as"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def shodan_lookup(ip):
    """Shodan lookup if API key is set."""
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        return None
    try:
        import urllib.request
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            return {
                "ports": data.get("ports", []),
                "org": data.get("org", ""),
                "os": data.get("os", ""),
                "tags": data.get("tags", []),
                "vulns": list(data.get("vulns", []))[:10],
                "last_update": data.get("last_update", ""),
            }
    except Exception:
        return None


def scan_ip(ip):
    """Full counter-intel scan of an IP."""
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]
    
    result = {
        "ip": ip,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    # Reverse DNS
    rdns = reverse_dns(ip)
    if rdns:
        result["rdns"] = rdns
    
    # Port scan (parallel)
    open_ports = []
    banners = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(probe_port, ip, p): p for p in SCAN_PORTS}
        for future in futures:
            try:
                r = future.result(timeout=SCAN_TIMEOUT + 1)
                if r["open"]:
                    open_ports.append(r["port"])
                    if r.get("banner"):
                        banners.append(r)
            except Exception:
                pass
    
    result["open_ports"] = sorted(open_ports)
    result["banners"] = banners[:10]
    
    # GeoIP
    geo = geoip(ip)
    if geo:
        result["geo"] = geo
    
    # Shodan (if available)
    shodan = shodan_lookup(ip)
    if shodan:
        result["shodan"] = shodan
    
    with _cache_lock:
        _cache[ip] = result
        # Async save (don't block)
        threading.Thread(target=_save_cache, daemon=True).start()
    
    return result


def get_intel(ip):
    """Get cached or fresh intel for an IP."""
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]
    return None


def trigger_scan(ip):
    """Trigger background scan of an IP."""
    t = threading.Thread(target=scan_ip, args=(ip,), daemon=True)
    t.start()


# ── Dashboard endpoint handler ────────────────────────────────
def get_intel_endpoint(ip):
    """Return intel JSON for a specific IP. For dashboard API."""
    # Return cached or trigger fresh scan
    result = get_intel(ip)
    if result:
        return result
    
    # Trigger async scan
    trigger_scan(ip)
    return {"ip": ip, "status": "scanning", "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def get_recent_intel(limit=50):
    """Get most recent intel results."""
    with _cache_lock:
        items = list(_cache.values())
        # Sort by scanned_at
        items.sort(key=lambda x: x.get("scanned_at", ""), reverse=True)
        return items[:limit]


def start(log_event=None, extract_iocs=None, capture_samples=None):
    """Start the counter-intel module (just initializes)."""
    _load_cache()
    print(f"[counter-intel] Loaded {len(_cache)} cached intel entries", flush=True)
