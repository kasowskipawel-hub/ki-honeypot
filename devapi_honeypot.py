"""
DevAPI Honeypot — fakes Docker Engine, Kubernetes API, Jupyter, Elasticsearch.

Ports:
  2375  Docker Engine REST API (unauthenticated, the classic mistake)
  6443  Kubernetes API server
  8888  Jupyter Notebook
  9200  Elasticsearch
  27017 MongoDB wire protocol
"""
import asyncio, json, os, uuid, time, re, struct
from datetime import datetime, timezone

DATA_DIR = os.getenv("DATA_DIR", "/data")
EVENTS   = os.path.join(DATA_DIR, "events.jsonl")

_PORTS = {
    "docker":   int(os.getenv("DOCKER_PORT",  "2375")),
    "k8s":      int(os.getenv("K8S_PORT",     "6443")),
    "jupyter":  int(os.getenv("JUPYTER_PORT", "8888")),
    "elastic":  int(os.getenv("ELASTIC_PORT", "9200")),
    "mongo":    int(os.getenv("MONGO_PORT",   "27017")),
}

def _ts():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _log(ev: dict):
    try:
        with open(EVENTS, "a") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except Exception:
        pass

def _http_resp(status: str, body, ctype="application/json", extra_headers=""):
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    elif isinstance(body, str):
        body = body.encode()
    return (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"{extra_headers}"
        f"\r\n"
    ).encode() + body

async def _read_http(reader) -> tuple[str, str, dict, bytes]:
    """Read one HTTP request. Returns (method, path, headers, body)."""
    try:
        raw = await asyncio.wait_for(reader.read(16384), timeout=15)
    except Exception:
        return "", "", {}, b""
    if not raw:
        return "", "", {}, b""
    try:
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        parts = lines[0].split(" ", 2)
        method = parts[0] if parts else ""
        path   = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        clen = int(headers.get("content-length", 0))
        return method, path, headers, body[:clen] if clen else body
    except Exception:
        return "", "", {}, b""


# ── Docker Engine API (port 2375) ────────────────────────────────────────────

_DOCKER_CONTAINERS = [
    {"Id": "a1b2c3d4e5f6", "Names": ["/nginx-proxy"], "Image": "nginx:1.25",
     "State": "running", "Status": "Up 14 days", "Ports": [{"PrivatePort":80,"Type":"tcp"}]},
    {"Id": "b2c3d4e5f6a7", "Names": ["/db-postgres"], "Image": "postgres:15",
     "State": "running", "Status": "Up 14 days", "Ports": [{"PrivatePort":5432,"Type":"tcp"}]},
]
_DOCKER_IMAGES = [
    {"Id": "sha256:abc123", "RepoTags": ["nginx:1.25"], "Size": 192000000},
    {"Id": "sha256:def456", "RepoTags": ["postgres:15"], "Size": 374000000},
    {"Id": "sha256:ghi789", "RepoTags": ["ubuntu:22.04"], "Size": 77000000},
]

async def _handle_docker(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    method, path, headers, body = await _read_http(reader)
    if not method:
        writer.close(); return

    p = path.split("?")[0].rstrip("/").lower()
    payload = None
    captured = {}

    if p in ("/version", "/_ping"):
        payload = {"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64","KernelVersion":"5.15.0-91-generic"}
    elif p == "/containers/json":
        payload = _DOCKER_CONTAINERS
    elif p == "/images/json":
        payload = _DOCKER_IMAGES
    elif p == "/info":
        payload = {"ID":"NODE1","Containers":2,"ContainersRunning":2,"Images":3,"MemTotal":67108864000,"NCPU":16,"DockerRootDir":"/var/lib/docker","ServerVersion":"24.0.7"}
    elif p == "/networks":
        payload = [{"Name":"bridge","Id":"net001","Driver":"bridge","Scope":"local"}]
    elif "/containers/create" in p or (p.endswith("/create") and "container" in p):
        try:
            spec = json.loads(body) if body else {}
        except Exception:
            spec = {}
        captured = {"docker_create_spec": spec, "docker_image": spec.get("Image","?"), "docker_cmd": spec.get("Cmd",[])}
        payload = {"Id": uuid.uuid4().hex[:12], "Warnings": []}
    elif re.search(r"/containers/[a-f0-9]+/start", p):
        payload = ""
        status = "204 No Content"
    elif re.search(r"/exec/[a-f0-9]+/(start|inspect)", p):
        payload = {"Id": uuid.uuid4().hex[:12]}
    elif "/exec" in p:
        try:
            spec = json.loads(body) if body else {}
        except Exception:
            spec = {}
        captured = {"docker_exec_cmd": spec.get("Cmd",[])}
        payload = {"Id": uuid.uuid4().hex[:12]}
    elif "/volumes" in p:
        payload = {"Volumes": [], "Warnings": []}
    else:
        payload = {"message": "Not found"}
        status = "404 Not Found"

    status = locals().get("status", "200 OK")
    body_out = json.dumps(payload).encode() if payload != "" else b""
    writer.write(_http_resp(status, body_out,
                            extra_headers="Server: Docker/24.0.7 (linux)\r\n"))
    await writer.drain()
    writer.close()

    ev = {"service": "docker", "ts": _ts(), "src_ip": peer[0], "dst_port": _PORTS["docker"],
          "session_id": f"docker-{uuid.uuid4().hex[:8]}",
          "docker_path": path, "docker_method": method,
          "lure": "docker-api" if not captured else "docker-deploy",
          "docker_user_agent": headers.get("user-agent", "")}
    ev.update(captured)
    _log(ev)


# ── Kubernetes API (port 6443) ────────────────────────────────────────────────

_K8S_PODS = {"apiVersion":"v1","kind":"PodList","items":[
    {"metadata":{"name":"nginx-7d5b8","namespace":"default"},"spec":{"containers":[{"name":"nginx","image":"nginx:1.25"}]},"status":{"phase":"Running"}},
    {"metadata":{"name":"coredns-8","namespace":"kube-system"},"spec":{"containers":[{"name":"coredns","image":"coredns/coredns:1.10"}]},"status":{"phase":"Running"}},
]}
_K8S_NODES = {"apiVersion":"v1","kind":"NodeList","items":[
    {"metadata":{"name":"node-01"},"status":{"capacity":{"cpu":"16","memory":"65536Ki"},"conditions":[{"type":"Ready","status":"True"}]}}
]}

async def _handle_k8s(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    method, path, headers, body = await _read_http(reader)
    if not method:
        writer.close(); return

    p = path.split("?")[0].rstrip("/").lower()
    captured = {}

    if p in ("", "/", "/api", "/apis"):
        payload = {"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"k8s-api:6443"}]}
    elif p == "/api/v1":
        payload = {"kind":"APIResourceList","groupVersion":"v1","resources":[{"name":"pods","kind":"Pod"},{"name":"services","kind":"Service"},{"name":"nodes","kind":"Node"}]}
    elif "pods" in p and method == "GET":
        payload = _K8S_PODS
    elif "pods" in p and method == "POST":
        try:
            spec = json.loads(body) if body else {}
        except Exception:
            spec = {}
        captured = {"k8s_pod_spec": spec, "k8s_image": (spec.get("spec",{}).get("containers",[{}])[0] if spec.get("spec",{}).get("containers") else {}).get("image","?")}
        payload = {"kind":"Pod","metadata":{"name":spec.get("metadata",{}).get("name","unknown"),"uid":uuid.uuid4().hex},"status":{"phase":"Pending"}}
    elif "nodes" in p:
        payload = _K8S_NODES
    elif "namespaces" in p and method == "GET":
        payload = {"kind":"NamespaceList","items":[{"metadata":{"name":"default"}},{"metadata":{"name":"kube-system"}}]}
    elif "serviceaccounts" in p:
        payload = {"kind":"ServiceAccountList","items":[{"metadata":{"name":"default","namespace":"default"}}]}
    elif p == "/version":
        payload = {"major":"1","minor":"28","gitVersion":"v1.28.4","platform":"linux/amd64"}
    else:
        payload = {"kind":"Status","status":"Failure","message":"Not found","code":404}

    writer.write(_http_resp("200 OK", payload,
                            extra_headers="Server: kube-apiserver\r\nX-Kubernetes-Pf-Flowschema-Uid: 1234\r\n"))
    await writer.drain()
    writer.close()

    ev = {"service": "k8s", "ts": _ts(), "src_ip": peer[0], "dst_port": _PORTS["k8s"],
          "session_id": f"k8s-{uuid.uuid4().hex[:8]}",
          "k8s_path": path, "k8s_method": method,
          "lure": "k8s-api" if not captured else "k8s-deploy",
          "k8s_user_agent": headers.get("user-agent",""),
          "k8s_auth": headers.get("authorization","")}
    ev.update(captured)
    _log(ev)


# ── Jupyter Notebook (port 8888) ──────────────────────────────────────────────

_JUPYTER_TOKEN = "6f3d8a2e1b9c4f7d0e5a2b8c1d4e7f3a"

async def _handle_jupyter(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    method, path, headers, body = await _read_http(reader)
    if not method:
        writer.close(); return

    p = path.split("?")[0].rstrip("/").lower()
    captured = {}

    if p in ("", "/") or p.startswith("/tree") or p.startswith("/lab"):
        html = f"""<!DOCTYPE html><html><head><title>Jupyter</title></head><body>
<h2>Jupyter Notebook</h2><p>Token: {_JUPYTER_TOKEN}</p>
<script>window.jupyter_config={{"token":"{_JUPYTER_TOKEN}","base_url":"/"}}</script>
</body></html>"""
        writer.write(_http_resp("200 OK", html.encode(), ctype="text/html",
                                extra_headers=f"Set-Cookie: username-localhost-8888={_JUPYTER_TOKEN}; Path=/\r\n"))
    elif "/api/kernels" in p and method == "POST":
        try:
            spec = json.loads(body) if body else {}
        except Exception:
            spec = {}
        captured = {"jupyter_kernel_spec": spec}
        kid = uuid.uuid4().hex
        writer.write(_http_resp("201 Created",
                                {"id": kid, "name": spec.get("name","python3"), "execution_state":"starting"}))
    elif "/api/kernels" in p:
        writer.write(_http_resp("200 OK",
                                [{"id": uuid.uuid4().hex, "name":"python3","execution_state":"idle","last_activity":_ts()}]))
    elif "/api/kernelspecs" in p:
        writer.write(_http_resp("200 OK", {"default":"python3","kernelspecs":{"python3":{"name":"python3","spec":{"display_name":"Python 3","language":"python"}}}}))
    elif "/api/sessions" in p and method == "POST":
        try:
            spec = json.loads(body) if body else {}
        except Exception:
            spec = {}
        captured = {"jupyter_session": spec, "jupyter_notebook": spec.get("notebook",{}).get("path","")}
        writer.write(_http_resp("201 Created",
                                {"id": uuid.uuid4().hex, "kernel":{"id": uuid.uuid4().hex,"name":"python3"}}))
    elif "/api/contents" in p and method in ("PUT","POST"):
        try:
            spec = json.loads(body) if body else {}
        except Exception:
            spec = {}
        captured = {"jupyter_upload": spec.get("name","?"), "jupyter_content": str(spec.get("content",""))[:200]}
        writer.write(_http_resp("201 Created", {"path": path.split("/api/contents/")[-1], "type":"notebook"}))
    elif "/api" in p:
        writer.write(_http_resp("200 OK", {}))
    else:
        writer.write(_http_resp("404 Not Found", {"message":"Not found"}))

    try:
        await writer.drain()
    except Exception:
        pass
    writer.close()

    ev = {"service": "jupyter", "ts": _ts(), "src_ip": peer[0], "dst_port": _PORTS["jupyter"],
          "session_id": f"jupyter-{uuid.uuid4().hex[:8]}",
          "jupyter_path": path, "jupyter_method": method,
          "lure": "jupyter-api" if not captured else "jupyter-rce",
          "jupyter_token": headers.get("authorization","").replace("token ",""),
          "jupyter_user_agent": headers.get("user-agent","")}
    ev.update(captured)
    _log(ev)


# ── Elasticsearch (port 9200) ─────────────────────────────────────────────────

async def _handle_elastic(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    method, path, headers, body = await _read_http(reader)
    if not method:
        writer.close(); return

    p = path.split("?")[0].rstrip("/").lower()
    captured = {}

    if p in ("", "/"):
        payload = {"name":"node-1","cluster_name":"prod-cluster","version":{"number":"8.11.1","lucene_version":"9.8.0"},"tagline":"You Know, for Search"}
    elif p == "/_cat/indices":
        payload = "green open .security 1 0 6 0 3.4mb\ngreen open logs-2026 1 0 120000 0 45.2gb\n"
        writer.write(_http_resp("200 OK", payload.encode(), ctype="text/plain"))
        await writer.drain(); writer.close()
        _log({"service":"elastic","ts":_ts(),"src_ip":peer[0],"dst_port":_PORTS["elastic"],
              "session_id":f"es-{uuid.uuid4().hex[:8]}","elastic_path":path,"lure":"elastic-recon"})
        return
    elif p == "/_cluster/health":
        payload = {"cluster_name":"prod-cluster","status":"green","number_of_nodes":3,"active_shards":42}
    elif method in ("POST","PUT") and ("/_doc" in p or "/_bulk" in p or "/_create" in p):
        try:
            spec = json.loads(body.split(b"\n")[0]) if body else {}
        except Exception:
            spec = {}
        captured = {"elastic_index": p.split("/")[1] if "/" in p else "?", "elastic_doc_preview": str(spec)[:200]}
        payload = {"result":"created","_id":uuid.uuid4().hex[:8]}
    elif method == "DELETE":
        captured = {"elastic_deleted_index": p.lstrip("/")}
        payload = {"acknowledged": True}
    else:
        payload = {"error":{"type":"index_not_found_exception","reason":"no such index"},"status":404}

    writer.write(_http_resp("200 OK", payload))
    await writer.drain()
    writer.close()

    ev = {"service": "elastic", "ts": _ts(), "src_ip": peer[0], "dst_port": _PORTS["elastic"],
          "session_id": f"es-{uuid.uuid4().hex[:8]}",
          "elastic_path": path, "elastic_method": method,
          "lure": "elastic-api" if not captured else "elastic-write"}
    ev.update(captured)
    _log(ev)


# ── MongoDB wire protocol (port 27017) ────────────────────────────────────────

async def _handle_mongo(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    try:
        raw = await asyncio.wait_for(reader.read(4096), timeout=10)
    except Exception:
        writer.close(); return
    if not raw:
        writer.close(); return

    _log({"service": "mongo", "ts": _ts(), "src_ip": peer[0], "dst_port": _PORTS["mongo"],
          "session_id": f"mongo-{uuid.uuid4().hex[:8]}",
          "lure": "mongo-probe", "raw_preview": raw[:64].hex()})

    _ISMASTER = json.dumps({"ismaster":True,"maxBsonObjectSize":16777216,"localTime":{"$date":int(time.time()*1000)},"maxWireVersion":17,"ok":1}).encode()
    try:
        msg_len = 16 + len(_ISMASTER)
        hdr = struct.pack("<iiiiI", msg_len, 1, 0, 1, 0)
        writer.write(hdr + _ISMASTER)
        await writer.drain()
    except Exception:
        pass
    writer.close()


# ── Startup ───────────────────────────────────────────────────────────────────

def start(log_event=None, extract_iocs=None, capture_samples=None):
    import threading

    handlers = [
        ("docker",  _PORTS["docker"],  _handle_docker),
        ("k8s",     _PORTS["k8s"],     _handle_k8s),
        ("jupyter", _PORTS["jupyter"], _handle_jupyter),
        ("elastic", _PORTS["elastic"], _handle_elastic),
        ("mongo",   _PORTS["mongo"],   _handle_mongo),
    ]

    def _run_server(name, port, handler):
        async def _serve():
            try:
                srv = await asyncio.start_server(handler, "0.0.0.0", port)
                print(f"[devapi/{name}] listening on 0.0.0.0:{port}", flush=True)
                async with srv:
                    await srv.serve_forever()
            except Exception as e:
                print(f"[devapi/{name}] failed on port {port}: {e}", flush=True)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_serve())
        finally:
            loop.close()

    for name, port, handler in handlers:
        t = threading.Thread(target=_run_server, args=(name, port, handler), daemon=True)
        t.start()
