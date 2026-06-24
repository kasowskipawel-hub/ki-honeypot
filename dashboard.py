#!/usr/bin/env python3
"""WIN443 HUNT DASHBOARD v8 — Live credential capture + SOC threat center."""

import base64, os, time, json, threading, re, hashlib, hmac, urllib.parse
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Premium feed API key — share with paying customers (separate from UI password)
FEED_API_KEY          = os.environ.get("FEED_API_KEY", "").strip()
# Sensor ingest key — sensors authenticate with this to push events
SENSOR_API_KEY        = os.environ.get("SENSOR_API_KEY", FEED_API_KEY).strip()
# RapidAPI proxy secret — set in RapidAPI provider backend security settings;
# RapidAPI forwards it as X-RapidAPI-Proxy-Secret on every request to our backend
RAPIDAPI_PROXY_SECRET = os.environ.get("RAPIDAPI_PROXY_SECRET", "").strip()
TTP_FILE       = os.environ.get("TTP_FILE", "/data/ttp_enriched.jsonl")

try:
    import groq_client as _groq
except Exception:
    _groq = None

try:
    import ai_analyst as _ai
except Exception:
    _ai = None

# ── AI Briefing state ─────────────────────────────────────────────────────────
_BRIEFING: dict = {"text": "", "ts": 0, "generating": False, "error": ""}
_BRIEFING_INTERVAL = int(os.environ.get("AI_BRIEFING_INTERVAL", "3600"))   # hourly

# Daily counter reset: all dashboard stats reflect the CURRENT day only and
# roll over to 0 at local (Berlin) midnight. History replay on restart skips
# events from previous days, so a restart never resurrects old totals.
try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Europe/Berlin")
except Exception:
    _TZ = timezone.utc

def _today_str():
    return datetime.now(_TZ).strftime("%Y-%m-%d")

def _ev_day(ts: str) -> str:
    """Berlin-local date (YYYY-MM-DD) of an event's UTC ISO timestamp."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(_TZ).strftime("%Y-%m-%d")
    except Exception:
        return _today_str()   # unparseable ts → assume today (don't drop)

EVENTS_FILE = (os.environ.get("ENRICHED") or
               os.environ.get("EVENTS")   or
               "/data/enriched.jsonl")
DASH_PORT   = int(os.environ.get("DASH_PORT", "9090"))
DASH_HOST   = os.environ.get("DASH_HOST",     "0.0.0.0")
DASH_PASS   = os.environ.get("DASH_PASSWORD", "honeypot2026").strip()

_EXPLOIT_LURES = {
    "phpunit-rce","thinkphp","webshell-bait","webshell-interactive","redis-rce","f5-bigip",
    "spring-actuator","confluence","struts","exchange-owa",
    "login-jenkins","login-grafana","login-phpmyadmin",
    "redtail-cgi-trap","redtail-cve2024-trap","androxgh0st",
}
_VMWARE_LURES: set = set()
_CVE_MAP = {
    "phpunit-rce":"CVE-2017-9841",
    "thinkphp":"CVE-2018-20062","f5-bigip":"CVE-2020-5902",
    "spring-actuator":"CVE-2022-22965","confluence":"CVE-2023-22527",
    "struts":"CVE-2024-53677",
}

# ── State ─────────────────────────────────────────────────────────────────────

class _State:
    def __init__(self):
        self.lock       = threading.Lock()
        self.events     = []    # last 300 raw events
        self.ssh_creds  = []    # [{ts,ip,cc,user,pw,cmds}]
        self.ntlm       = []    # [{ts,ip,cc,user,domain,ws,hashcat,shares,files,ransomware}] — NTLM only
        self.smb        = []    # [{ts,ip,cc,svc,...}] — ALL SMB sessions incl. negotiate-only
        self.canary     = []    # [{ts,ip,cc,file,cmd}]
        self.exploits   = []    # [{ts,ip,cc,lure,path,cve}]
        self.cmds       = []    # [{ts,ip,cc,cmd}]  SSH shell commands
        self.samples    = []    # [{ts,ip,url,sha256,size}]
        self.redis_rce  = []    # [{ts,ip,cc,chains,config,slaveof,cron,ssh_key,c2_urls,cmds}]
        self.redis_recon = []   # [{ts,ip,cc,cmds}]  all non-RCE redis sessions
        self.threat_intel = []  # [{ts,ip,cc,score,technique,phase,indicators,path,rce_verify,tool,upload_magic}]
        self.ip_stats   = {}    # ip → {n,cc,last,svcs}
        self.n_ev = self.n_ssh = self.n_telnet = self.n_ntlm = 0
        self.n_canary = self.n_exploits = self.n_samples = 0
        self.n_redis_rce = self.n_threats = 0
        self.ssh_replays = []   # SSH sessions with replay recording
        self.campaigns   = {}   # cmd_fingerprint → campaign dict
        self.actors      = {}   # ja3 → actor dict
        self.stratum     = []   # [{ts,ip,cc,dst_port,wallet,agent,authorized}]
        self.n_stratum   = 0
        # Deception effectiveness signals (SSH): how well the disguise holds.
        self.honeytokens  = []  # [{ts,ip,token,issued_ip,kind,lateral}] beacon hits
        self.n_honeytoken = 0
        self.dec_sessions = 0   # SSH sessions seen
        self.dec_engaged  = 0   # ran ≥1 command (got past login)
        self.dec_escalated= 0   # reached loot/exec/upload/relay/key-install
        self.dec_hpprobe  = 0   # tried honeypot-detection creds
        self.dec_deceived = 0   # probed us AND stayed (we fooled the detector)
        self._pos       = 0
        self._sse_q     = []    # list of bytearray queues, one per SSE client
        self._cur_day   = None  # Berlin date the current counters belong to

    def reset_daily(self):
        """Zero every counter/list/dict (call with self.lock held). Keeps _pos,
        _sse_q and _cur_day so tailing + live SSE clients survive the rollover."""
        self.events.clear()
        self.ssh_creds.clear(); self.ntlm.clear(); self.smb.clear()
        self.canary.clear(); self.exploits.clear(); self.cmds.clear()
        self.samples.clear(); self.redis_rce.clear(); self.redis_recon.clear()
        self.threat_intel.clear()
        self.ssh_replays.clear(); self.stratum.clear()
        self.ip_stats.clear(); self.campaigns.clear(); self.actors.clear()
        self.n_ev = self.n_ssh = self.n_telnet = self.n_ntlm = 0
        self.n_canary = self.n_exploits = self.n_samples = 0
        self.n_redis_rce = self.n_threats = 0
        self.n_stratum = 0
        self.dec_sessions = self.dec_engaged = self.dec_escalated = 0
        self.dec_hpprobe = self.dec_deceived = 0
        self.honeytokens = []
        self.n_honeytoken = 0

ST = _State()
T0 = time.time()

# Our own host IPs: loopback + the VPS public IP. Traffic from these is internal
# (NAT hairpin, c2-mirror/sample fetches, health checks, manual tests) — never a
# real attacker, so it must not pollute the live feed or counters.
_OWN_IPS = {"127.0.0.1", "::1", ""}
_own = os.environ.get("OWN_IP", "164.68.121.252")
_OWN_IPS.update(x.strip() for x in _own.split(",") if x.strip())

# Benign internet-wide research scanners & vendor crawlers — identify themselves
# via User-Agent. They're noise, not attackers, so drop them from the live view
# (raw events.jsonl still keeps everything). Extend via ENV BENIGN_UA (comma-sep).
_BENIGN_UA = {
    "censys", "zgrab", "masscan", "paloaltonetworks", "expanse",
    "genomecrawler", "gptbot", "oai-searchbot", "chatgpt-user", "applebot",
    "googlebot", "bingbot", "yandexbot", "internet-measurement.com",
    "stretchoid", "leakix", "ipip.net", "cyberconvoy", "visionheight",
    "shodan", "netsystemsresearch", "criteo", "semrush", "ahrefs",
    "mj12bot", "dotbot", "bytespider", "petalbot", "censysinspect",
    "internetmeasurement", "scrapy", "facebookexternalhit", "driftnet",
}
_BENIGN_UA.update(x.strip().lower() for x in os.environ.get("BENIGN_UA", "").split(",") if x.strip())


def _is_benign_scanner(ev: dict) -> bool:
    ua = (ev.get("user_agent") or "").lower()
    return any(b in ua for b in _BENIGN_UA)


def _cmd_fingerprint(commands: list) -> str:
    normalized = [c.strip().split()[0] for c in commands[:20] if c.strip()]
    return hashlib.md5("|".join(normalized).encode()).hexdigest()[:12]


def _ingest(ev: dict):
    ip = ev.get("src_ip", "")
    # Drop loopback + own-host events from live stats (internal/self-traffic)
    if ip in _OWN_IPS:
        return
    # Drop benign research scanners / vendor crawlers (UA-identified) — noise.
    if _is_benign_scanner(ev):
        return

    svc  = ev.get("service", "")
    lure = ev.get("lure", "")
    ts   = ev.get("ts", "")

    # cc lives in ev["intel"][ip]["country"] (enriched format); fall back to ev["geo"]["cc"]
    intel = (ev.get("intel") or {}).get(ip) or {}
    cc = intel.get("country", "") or (ev.get("geo") or {}).get("cc", "") or ""
    if cc and not ev.get("geo"):
        ev["geo"] = {"cc": cc}  # normalise so JS ev.geo.cc always works

    with ST.lock:
        # Daily rollover: reset all counters at Berlin midnight.
        today = _today_str()
        if ST._cur_day != today:
            ST.reset_daily()
            ST._cur_day = today
        # Count only today's events; skip history from previous days (restart replay).
        if _ev_day(ts) != today:
            return

        ST.n_ev += 1
        s = ST.ip_stats.setdefault(ip, {"n":0,"cc":cc,"last":ts,"svcs":[]})
        s["n"] += 1; s["last"] = ts
        if svc and svc not in s["svcs"]: s["svcs"].append(svc)

        ST.events.append(ev)
        if len(ST.events) > 300: ST.events.pop(0)

        # SSH credentials — field is ssh_creds list of "user:pass" strings
        # OWA / Exchange brute-force credential capture
        if svc == "owa" and ev.get("http_creds"):
            for cred in ev.get("http_creds", []):
                if not cred: continue
                user, _, pw = str(cred).partition(":")
                ST.n_ssh += 1
                ST.ssh_creds.insert(0, {
                    "ts": ts, "ip": ip, "cc": cc,
                    "user": user or "?", "pw": pw or "",
                    "ok": False, "proto": "OWA", "cmds": [],
                    "ai_intent": "OWA/Exchange Brute-Force (Credential-Spraying)",
                })
            if len(ST.ssh_creds) > 300: ST.ssh_creds = ST.ssh_creds[:300]

        if svc == "ssh" and ev.get("ssh_creds"):
            accepted = ev.get("ssh_accepted_cred")
            intent = ev.get("ai_ssh_intent", "")
            for cred in ev.get("ssh_creds", []):
                if not cred: continue
                user, _, pw = str(cred).partition(":")
                ST.n_ssh += 1
                ok = (cred == accepted)
                ST.ssh_creds.insert(0, {
                    "ts": ts, "ip": ip, "cc": cc,
                    "user": user or "?",
                    "pw":   pw or "",
                    "ok":   ok,
                    "proto": "SSH",
                    "cmds": ev.get("ssh_commands", []) if ok else [],
                    "ai_intent": intent if ok else "",
                })
            if len(ST.ssh_creds) > 300: ST.ssh_creds = ST.ssh_creds[:300]

        if svc == "telnet" and ev.get("ssh_creds"):
            for cred in ev.get("ssh_creds", []):
                if not cred: continue
                user, _, pw = str(cred).partition(":")
                ST.n_telnet += 1
                ST.ssh_creds.insert(0, {
                    "ts": ts, "ip": ip, "cc": cc,
                    "user": user or "?",
                    "pw":   pw or "",
                    "ok":   True,  # telnet honeypot always accepts
                    "proto": "TELNET",
                    "cmds": ev.get("ssh_commands", []),
                    "ai_intent": "",
                })
            if len(ST.ssh_creds) > 300: ST.ssh_creds = ST.ssh_creds[:300]

        # SSH commands — field is ssh_commands (not commands)
        for cmd in ev.get("ssh_commands", []):
            if cmd.strip():
                ST.cmds.insert(0, {"ts":ts,"ip":ip,"cc":cc,"cmd":cmd.strip()})
        if len(ST.cmds) > 500: ST.cmds = ST.cmds[:500]

        # Deception effectiveness — score each SSH session.
        if svc == "ssh":
            cmds_ = ev.get("ssh_commands") or []
            creds_ = ev.get("ssh_creds") or []
            self_or = ev
            ST.dec_sessions += 1
            if cmds_:
                ST.dec_engaged += 1
            escalated = any(ev.get(k) for k in (
                "data_theft", "ssh_uploads", "wallet_steals", "binary_execs",
                "net_downloads", "ssh_relay")) or bool(ev.get("ssh_pubkeys"))
            if escalated:
                ST.dec_escalated += 1
            probed = any("345gs5662d34" in str(c) for c in creds_)
            # The honeypot-detector SCRIPT ran against us (echo SSH_HONEYPOT…SSH_REAL).
            # Since our intercept always answers SSH_REAL=1, each such run = a fooled detector.
            ran_detector = any("SSH_HONEYPOT" in str(c) for c in cmds_)
            if probed or ran_detector:
                ST.dec_hpprobe += 1
            if ran_detector:
                ST.dec_deceived += 1

        # SSH / Webshell / Telnet session replay recording
        if svc in ("ssh", "webshell") and ev.get("ssh_replay"):
            ST.ssh_replays.insert(0, {
                "ts": ts, "ip": ip, "cc": cc,
                "cmds": ev.get("ssh_commands", [])[:20],
                "replay": ev.get("ssh_replay", [])[:200],
                "session_id": ev.get("session_id", ""),
                "proto": "WEBSHELL" if svc == "webshell" else "SSH",
            })
            if len(ST.ssh_replays) > 100: ST.ssh_replays.pop()

        if svc == "telnet" and ev.get("ssh_commands"):
            ST.ssh_replays.insert(0, {
                "ts": ts, "ip": ip, "cc": cc,
                "cmds": ev.get("ssh_commands", [])[:20],
                "replay": ev.get("ssh_replay", [])[:300],
                "session_id": ev.get("session_id", ""),
                "proto": "TELNET",
            })
            if len(ST.ssh_replays) > 100: ST.ssh_replays.pop()

        # Bot campaign clustering by command fingerprint
        if svc == "ssh" and ev.get("ssh_commands"):
            fp = _cmd_fingerprint(ev.get("ssh_commands", []))
            camp = ST.campaigns.setdefault(fp, {
                "fp": fp, "ips": [], "count": 0,
                "cmds": ev.get("ssh_commands", [])[:10], "first": ts, "last": ts
            })
            if ip not in camp["ips"]: camp["ips"].append(ip)
            camp["count"] += 1
            camp["last"] = ts

        # Actor tracking via JA3 hash
        if ev.get("ja3"):
            j3 = ev["ja3"]
            actor = ST.actors.setdefault(j3, {
                "ja3": j3, "ips": [], "count": 0, "first": ts, "last": ts,
                "sni": ev.get("sni", ""), "ja3_string": ev.get("ja3_string", ""),
            })
            if ip not in actor["ips"]: actor["ips"].append(ip)
            actor["count"] += 1
            actor["last"] = ts

        # Honeytoken beacon — attacker USED leaked secrets (highest-value signal)
        if svc == "honeytoken":
            ST.n_honeytoken += 1
            ST.honeytokens.insert(0, {
                "ts": ts, "ip": ip, "cc": cc,
                "token": ev.get("token", ""),
                "issued_ip": ev.get("issued_ip", ""),
                "kind": ev.get("kind", ""),
                "lateral": bool(ev.get("lateral")),
            })
            if len(ST.honeytokens) > 200: ST.honeytokens = ST.honeytokens[:200]

        # Stratum / fake mining pool — miner connections + captured wallets
        if svc == "stratum":
            ST.n_stratum += 1
            ST.stratum.insert(0, {
                "ts": ts, "ip": ip, "cc": cc,
                "dst_port":   ev.get("dst_port", ""),
                "wallet":     ev.get("stratum_wallet") or "",
                "agent":      ev.get("stratum_agent") or "",
                "authorized": bool(ev.get("stratum_authorized")),
                "shares":     ev.get("stratum_shares", 0),
                "hashrate":   ev.get("stratum_hashrate_str", ""),
                "hashrate_hs": ev.get("stratum_hashrate_hs", 0),
                "proto":      ev.get("stratum_proto", ""),
                "kind":       "stratum",
            })
            if len(ST.stratum) > 300: ST.stratum = ST.stratum[:300]

        # Ethereum RPC — fold into crypto tab
        if svc == "ethereum-rpc":
            ST.n_stratum += 1
            addrs = ev.get("eth_addresses") or []
            targets = ev.get("eth_tx_targets") or []
            wallet = next((a for a in targets + addrs if a), "")
            ST.stratum.insert(0, {
                "ts": ts, "ip": ip, "cc": cc,
                "dst_port":   ev.get("dst_port", _PORT_ETH := 8545),
                "wallet":     wallet,
                "agent":      "",
                "authorized": ev.get("lure") == "eth-wallet-drain",
                "shares":     0,
                "hashrate":   "",
                "hashrate_hs": 0,
                "proto":      "ETH-RPC",
                "kind":       "eth",
                "eth_methods": ev.get("eth_methods") or [],
                "eth_addresses": addrs,
                "eth_tx_value": ev.get("eth_tx_value", ""),
                "lure":       ev.get("lure", ""),
            })
            if ev.get("lure") == "eth-wallet-drain":
                pass  # badge bumped below in JS
            if len(ST.stratum) > 300: ST.stratum = ST.stratum[:300]

        # SSH canary / data theft (cat of honeytoken file inside shell)
        if svc == "ssh" and ev.get("data_theft"):
            for item in ev.get("data_theft", []):
                if not item: continue
                ST.n_canary += 1
                ST.canary.insert(0, {
                    "ts": ts, "ip": ip, "cc": cc,
                    "file": str(item), "cmd": "cat",
                })
            if len(ST.canary) > 300: ST.canary = ST.canary[:300]

        # SMB — all sessions in ST.smb, only NTLM captures in ST.ntlm
        if svc == "smb":
            smb_entry = {
                "ts":ts,"ip":ip,"cc":cc,"svc":"smb",
                "user":ev.get("ntlm_user") or "",
                "domain":ev.get("ntlm_domain") or "",
                "ws":ev.get("ntlm_workstation") or "",
                "hashcat":ev.get("hashcat"),
                "shares":ev.get("shares",[]),
                "files":ev.get("file_paths",[]),
                "ransomware":ev.get("ransomware",False),
            }
            ST.smb.insert(0, smb_entry)
            if len(ST.smb) > 300: ST.smb.pop()
            if ev.get("hashcat") or ev.get("ntlm_user"):
                ST.n_ntlm += 1
                ST.ntlm.insert(0, smb_entry)
                if len(ST.ntlm) > 300: ST.ntlm.pop()

        # RDP / NTLM
        if svc == "rdp" and (ev.get("hashcat") or ev.get("ntlm_user")):
            ST.n_ntlm += 1
            entry = {
                "ts":ts,"ip":ip,"cc":cc,"svc":"rdp",
                "user":ev.get("ntlm_user","?"),
                "domain":ev.get("ntlm_domain","?"),
                "ws":ev.get("ntlm_workstation","?"),
                "hashcat":ev.get("hashcat"),
                "shares":[],"files":[],"ransomware":False,
            }
            ST.ntlm.insert(0, entry)
            if len(ST.ntlm) > 300: ST.ntlm.pop()

        # Canary access
        if ev.get("type") == "canary_access":
            ST.n_canary += 1
            ST.canary.insert(0, {
                "ts":ts,"ip":ip,"cc":cc,
                "file":ev.get("file","?"),
                "cmd":ev.get("cmd",""),
            })
            if len(ST.canary) > 300: ST.canary.pop()

        # Exploits
        if lure in _EXPLOIT_LURES or ev.get("ransomware"):
            ST.n_exploits += 1
            _xd = ev.get("ai_exploit_desc") or {}
            ST.exploits.insert(0, {
                "ts":ts,"ip":ip,"cc":cc,
                "lure":lure or ("ransomware" if ev.get("ransomware") else "exploit"),
                "path":ev.get("path",""),
                "cve":_xd.get("cve") or _CVE_MAP.get(lure,""),
                "ransomware":ev.get("ransomware",False),
                "ai_desc":_xd.get("desc",""),
                "ai_sev":_xd.get("severity",""),
            })
            if len(ST.exploits) > 300: ST.exploits.pop()

        # Redis sessions (all) + RCE detection
        if svc == "redis":
            cmds = ev.get("redis_commands", [])[:20]
            if ev.get("redis_rce_chains"):
                ST.n_redis_rce += 1
                ST.redis_rce.insert(0, {
                    "ts": ts, "ip": ip, "cc": cc,
                    "chains":   ev.get("redis_rce_chains", []),
                    "config":   ev.get("redis_config", {}),
                    "slaveof":  ev.get("redis_slaveof"),
                    "cron":     ev.get("redis_cron"),
                    "ssh_key":  ev.get("redis_ssh_key"),
                    "c2_urls":  ev.get("redis_c2_urls", []),
                    "cmds":     cmds,
                    "set_count": ev.get("redis_set_count", 0),
                    "module":   ev.get("redis_module"),
                    "repl_cmds": [s.get("repl_commands", []) for s in
                                  (ev.get("c2_pulled_samples") or [])
                                  if s.get("repl_commands")][:1][0] if
                                 any(s.get("repl_commands") for s in
                                     (ev.get("c2_pulled_samples") or [])) else [],
                    "repl_analysis": ev.get("ai_repl_analysis", []),
                })
                if len(ST.redis_rce) > 200: ST.redis_rce.pop()
            else:
                ST.redis_recon.insert(0, {"ts": ts, "ip": ip, "cc": cc, "cmds": cmds})
                if len(ST.redis_recon) > 300: ST.redis_recon.pop()

        # Zero-day / behavioral threat intel — ONLY genuinely new/unknown lands
        # here. Mistral classifies known N-days (CVE-2017 etc.) out via
        # ai_threat_novel/ai_threat_cve. Without AI verdict we fall back to the
        # detector's novel flag minus a known-CVE lure blocklist.
        _KNOWN_CVE_LURES = ("phpunit-rce", "thinkphp", "log4shell", "spring-actuator",
                            "confluence", "struts", "f5-bigip", "citrix",
                            "hikvision-cve-2021-36260", "hikvision-probe", "cisco-cslu")
        if ev.get("threat_score", 0) >= 30 or ev.get("is_rce_verify"):
            ai_novel = ev.get("ai_threat_novel", None)
            ai_cve   = ev.get("ai_threat_cve", "") or _CVE_MAP.get(lure, "")
            if ai_novel is True and not ai_cve:
                is_new = True
            elif ai_novel is False or ai_cve:
                is_new = False                      # AI says known → keep out
            else:                                   # not classified yet → heuristic
                is_new = bool(ev.get("novel")) and lure not in _KNOWN_CVE_LURES
            if is_new:
                ST.n_threats += 1
                ST.threat_intel.insert(0, {
                    "ts": ts, "ip": ip, "cc": cc,
                    "score":      ev.get("threat_score", 0),
                    "technique":  ev.get("technique", ""),
                    "phase":      ev.get("attack_phase", ""),
                    "indicators": ev.get("indicators", []),
                    "path":       ev.get("path", ""),
                    "method":     ev.get("method", ""),
                    "rce_verify": ev.get("is_rce_verify", False),
                    "tool":       ev.get("tool"),
                    "upload_magic": ev.get("upload_magic"),
                    "novel":      True,
                    "lure":       lure,
                    "ai_desc":    ev.get("ai_threat_desc", ""),
                    "family":     ev.get("ai_threat_family", ""),
                })
                if len(ST.threat_intel) > 300: ST.threat_intel.pop()

        # Sample capture (incl. C2-pulled payloads) + AI/VT analysis
        if ev.get("event") == "sample_capture" or ev.get("captured_samples") or ev.get("c2_pulled_samples"):
            ai_by_sha = {a.get("sha256"): a for a in (ev.get("ai_sample_analysis") or [])}
            ai_bin_by_sha = {a.get("sha256"): a for a in (ev.get("ai_binary_analysis") or [])}
            hintel = ev.get("hash_intel") or {}
            allsamp = (ev.get("captured_samples") or []) + (ev.get("c2_pulled_samples") or [])
            for sc in allsamp:
                if not isinstance(sc, dict) or not sc.get("sha256"):
                    continue
                sha = sc.get("sha256", "")
                if any(s.get("sha256") == sha for s in ST.samples[:50]):
                    continue   # dedupe recent
                ST.n_samples += 1
                ai = ai_bin_by_sha.get(sha) or ai_by_sha.get(sha, {})
                vt = (hintel.get(sha) or {})
                vt_det = vt.get("malicious") or vt.get("detections") or vt.get("vt_malicious")
                ST.samples.insert(0, {
                    "ts": ts, "ip": ip,
                    "url": sc.get("url", "") or sc.get("source", ""),
                    "sha256": sha, "size": sc.get("size", 0),
                    "filetype": sc.get("filetype", ""),
                    "summary": ai.get("summary", ""),
                    "family": ai.get("family", "") or (vt.get("suggested_threat_label", "")),
                    "capabilities": ai.get("capabilities", []) or [],
                    "c2": ai.get("c2", []) or [],
                    "vt": vt_det,
                })
            if len(ST.samples) > 200: ST.samples = ST.samples[:200]

        # Push to SSE clients
        msg = ("data: " + json.dumps(ev, ensure_ascii=False) + "\n\n").encode()
        dead = []
        for q in ST._sse_q:
            try:
                q.extend(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            try: ST._sse_q.remove(q)
            except ValueError: pass


def _tail_thread():
    while True:
        try:
            # Roll counters over at midnight even on a quiet night (no new events).
            today = _today_str()
            if ST._cur_day is not None and ST._cur_day != today:
                with ST.lock:
                    ST.reset_daily()
                    ST._cur_day = today
            try:
                sz = os.path.getsize(EVENTS_FILE)
            except OSError:
                time.sleep(1); continue
            if sz < ST._pos: ST._pos = 0
            if sz > ST._pos:
                with open(EVENTS_FILE, "rb") as fh:
                    fh.seek(ST._pos)
                    data = fh.read()
                    ST._pos = fh.tell()
                for line in data.split(b"\n"):
                    line = line.strip()
                    if not line: continue
                    try: _ingest(json.loads(line))
                    except Exception: pass
        except Exception:
            pass
        time.sleep(1)


def _api_data() -> bytes:
    with ST.lock:
        top_ips = sorted(ST.ip_stats.items(), key=lambda x: x[1]["n"], reverse=True)[:60]
        return json.dumps({
            "uptime": int(time.time() - T0),
            "kpis": {
                "events":    ST.n_ev,
                "ips":       len(ST.ip_stats),
                "ssh":       ST.n_ssh,
                "telnet":    ST.n_telnet,
                "ntlm":      ST.n_ntlm,
                "canary":    ST.n_canary,
                "exploits":  ST.n_exploits,
                "samples":   ST.n_samples,
                "redis_rce": ST.n_redis_rce,
                "threats":   ST.n_threats,
                "stratum":   ST.n_stratum,
            },
            "ssh_creds":    ST.ssh_creds[:80],
            "ntlm":         ST.ntlm[:80],
            "smb_sessions": ST.smb[:80],
            "canary":       ST.canary[:80],
            "exploits":     ST.exploits[:80],
            "cmds":         ST.cmds[:120],
            "samples":      ST.samples[:80],
            "redis_rce":    ST.redis_rce[:80],
            "redis_recon":  ST.redis_recon[:100],
            "threat_intel": ST.threat_intel[:100],
            "top_ips":   [{"ip":k,**v} for k,v in top_ips],
            "events":    ST.events[-60:],
            "ssh_replays": ST.ssh_replays[:50],
            "campaigns": sorted(ST.campaigns.values(), key=lambda x: x["count"], reverse=True)[:50],
            "actors":    sorted(ST.actors.values(), key=lambda x: len(x["ips"]), reverse=True)[:50],
            "stratum":   ST.stratum[:100],
            "deception": _deception(),
            "honeytokens": ST.honeytokens[:100],
            "n_honeytoken": ST.n_honeytoken,
        }, ensure_ascii=False).encode()


def _deception() -> dict:
    """Compute the deception-effectiveness score from SSH session signals."""
    s = ST.dec_sessions or 1
    eng = ST.dec_engaged / s
    esc = ST.dec_escalated / s
    # Engagement (got past login) weighted 40%, escalation (deep loot) 60%.
    score = round(100 * (0.4 * eng + 0.6 * esc))
    return {
        "score": score,
        "sessions": ST.dec_sessions,
        "engaged": ST.dec_engaged,
        "escalated": ST.dec_escalated,
        "hp_probes": ST.dec_hpprobe,
        "deceived": ST.dec_deceived,   # probed detectors but stayed fooled
    }


# ── HTTP server ───────────────────────────────────────────────────────────────

_AUTH = base64.b64encode(("admin:" + DASH_PASS).encode()).decode()

HTML = r"""<!DOCTYPE html>
<html lang=de>
<head>
<meta charset=utf-8>
<title>KI Honeypot</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#030810;--bg2:#060e1c;--bg3:#0a1428;--bg4:#0e1b35;
  --br:#0f2040;--br2:#163060;
  --tx:#7a9ab8;--dim:#3a5570;--hi:#c8dcf0;
  --gn:#00ff55;--rd:#ff3355;--or:#ff8c3d;
  --bl:#3d9eff;--pu:#b44dff;--gd:#ffd700;--cy:#00cfff;
  --gn2:rgba(0,255,85,.08);--rd2:rgba(255,50,80,.08);
  --or2:rgba(255,140,60,.08);--bl2:rgba(60,160,255,.08);
  --pu2:rgba(180,77,255,.08);--gd2:rgba(255,215,0,.08);
}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--tx);font:13px/1.45 ui-monospace,Menlo,"SF Mono",Consolas,monospace;display:flex;flex-direction:column}

/* Header */
#hdr{display:flex;align-items:center;gap:10px;padding:6px 14px;
  background:linear-gradient(90deg,#05091a,#0a1025);
  border-bottom:1px solid var(--br);flex-shrink:0}
.logo{font-size:16px;font-weight:800;letter-spacing:4px;
  background:linear-gradient(90deg,#00e0ff,#00ff9d 45%,#7b5cff);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  text-shadow:0 0 18px rgba(0,224,255,.35);animation:logoglow 4s ease-in-out infinite}
.logo .chip{font-size:8px;font-weight:700;letter-spacing:1px;vertical-align:middle;
  -webkit-text-fill-color:#00e0ff;border:1px solid rgba(0,224,255,.4);border-radius:6px;
  padding:1px 5px;margin-left:7px;text-shadow:none;box-shadow:0 0 10px rgba(0,224,255,.25)}
@keyframes logoglow{50%{filter:brightness(1.25)}}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--gn);
  box-shadow:0 0 6px var(--gn);animation:pulse 1.8s infinite}
@keyframes pulse{50%{opacity:.2}}
#clock{color:var(--dim);font-size:10px;margin-left:auto}
#uptime{color:var(--dim);font-size:10px;margin-left:10px}

/* KPI bar */
#kpis{display:flex;gap:4px;padding:5px 14px;background:var(--bg2);
  border-bottom:1px solid var(--br);flex-shrink:0;flex-wrap:wrap}
.kpi{background:var(--bg3);border:1px solid var(--br);border-radius:5px;
  padding:4px 10px;text-align:center;min-width:70px;cursor:default}
.kpi .v{font-size:19px;font-weight:700;line-height:1.2}
.kpi .l{font-size:8px;color:var(--dim);text-transform:uppercase;letter-spacing:.8px}
.kpi.gn .v{color:var(--gn)}.kpi.rd .v{color:var(--rd)}.kpi.or .v{color:var(--or)}
.kpi.bl .v{color:var(--bl)}.kpi.pu .v{color:var(--pu)}.kpi.gd .v{color:var(--gd)}
.kpi.cy .v{color:var(--cy)}

/* Tabs */
#tabs{display:flex;background:var(--bg2);border-bottom:1px solid var(--br);
  flex-shrink:0;overflow-x:auto}
.tab{padding:7px 14px;cursor:pointer;color:var(--dim);font-size:11px;font-weight:600;
  text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid transparent;
  flex-shrink:0;white-space:nowrap;transition:color .15s}
.tab:hover{color:var(--tx)}.tab.on{color:var(--gn);border-bottom-color:var(--gn)}
.badge{display:inline-block;background:var(--rd);color:#fff;border-radius:8px;
  padding:0 5px;font-size:9px;font-weight:700;margin-left:4px;vertical-align:middle}

/* Main content */
#content{flex:1;overflow:hidden;display:flex;min-height:0}
.tab-pane{display:none;flex:1;overflow-y:auto;min-height:0;padding:8px 12px 20px}
.tab-pane.on{display:block}

/* Section headers */
.sec{margin-bottom:12px}
.sech{font-size:10px;font-weight:700;color:var(--bl);text-transform:uppercase;
  letter-spacing:2px;padding:4px 0;border-bottom:1px solid var(--br);margin-bottom:6px}
.sech .ct{color:var(--dim);font-weight:400;margin-left:6px}

/* Cards / rows */
.row{display:flex;align-items:flex-start;gap:6px;flex-wrap:wrap;
  padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.03);
  cursor:pointer;border-radius:4px;margin-bottom:1px;transition:background .1s}
.row:hover{background:var(--bg3)}
.ts{color:var(--dim);font-size:9px;min-width:58px;flex-shrink:0}
.flag{font-size:13px;flex-shrink:0}
.ip{color:var(--or);font-weight:700;font-size:12px;min-width:105px;flex-shrink:0}
.tag{font-size:9px;padding:1px 5px;border-radius:3px;font-weight:700;
  text-transform:uppercase;flex-shrink:0}
.tag-ssh{background:var(--pu2);color:var(--pu);border:1px solid rgba(180,77,255,.3)}
.tag-smb{background:var(--bl2);color:var(--bl);border:1px solid rgba(60,160,255,.3)}
.tag-http{background:var(--or2);color:var(--or);border:1px solid rgba(255,140,60,.3)}
.tag-redis{background:var(--rd2);color:var(--rd);border:1px solid rgba(255,50,80,.3)}
.tag-canary{background:var(--gd2);color:var(--gd);border:1px solid rgba(255,215,0,.4)}
.tag-exploit{background:var(--rd2);color:var(--rd);border:1px solid rgba(255,50,80,.3)}
.tag-sample{background:var(--or2);color:var(--or);border:1px solid rgba(255,140,60,.3)}
.tag-stratum{background:var(--gn2);color:var(--gn);border:1px solid rgba(0,255,85,.3)}
.tag-ransom{background:var(--rd2);color:var(--rd);border:1px solid rgba(255,50,80,.5);animation:blink .6s step-start infinite}
@keyframes blink{50%{opacity:0}}
.main-text{color:var(--hi);font-size:12px;flex:1;word-break:break-all;min-width:120px}
.sub-text{color:var(--tx);font-size:11px;flex:1;word-break:break-all}
.detail{display:none;width:100%;margin-top:4px;padding:6px 8px;
  background:var(--bg);border-radius:4px;font-size:11px;word-break:break-all}
.detail.on{display:block}
.detail .k{color:var(--dim)}.detail .v{color:var(--hi)}

/* Credential tables */
.cred-card{background:var(--bg3);border:1px solid var(--br);border-radius:6px;
  padding:8px 12px;margin-bottom:6px;cursor:pointer}
.cred-card:hover{background:var(--bg4)}
.cred-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cred-user{color:var(--cy);font-weight:700;font-size:13px}
.cred-pw{color:var(--gn);font-weight:700;font-size:13px;background:rgba(0,255,85,.06);
  padding:2px 8px;border-radius:3px;border:1px solid rgba(0,255,85,.2)}
.cred-cmds{color:var(--dim);font-size:10px;margin-top:4px}

/* NTLM hash cards */
.hash-card{background:var(--bg3);border:1px solid var(--br2);border-radius:6px;
  padding:8px 12px;margin-bottom:6px;border-left:3px solid var(--bl)}
.hash-card.ransom{border-left-color:var(--rd);animation:border-pulse 1s ease-in-out infinite}
@keyframes border-pulse{50%{border-left-color:rgba(255,50,80,.3)}}
.hash-val{color:var(--bl);font-size:11px;word-break:break-all;margin-top:4px;
  background:rgba(60,160,255,.06);padding:4px 8px;border-radius:3px;cursor:pointer}
.hash-val:active{background:rgba(60,160,255,.2)}
.copy-btn{background:var(--bl2);color:var(--bl);border:1px solid rgba(60,160,255,.3);
  border-radius:3px;padding:2px 8px;font-size:9px;cursor:pointer;font-weight:700;
  text-transform:uppercase;letter-spacing:.5px;flex-shrink:0}
.copy-btn:hover{background:rgba(60,160,255,.2)}
.copy-btn.ok{background:rgba(0,255,85,.15);color:var(--gn);border-color:rgba(0,255,85,.3)}

/* Command timeline */
.cmd-row{display:flex;gap:6px;align-items:baseline;padding:3px 6px;
  border-bottom:1px solid rgba(255,255,255,.02);flex-wrap:wrap}
.cmd-txt{color:var(--gn);font-size:12px;flex:1;word-break:break-all}
.cmd-txt.dangerous{color:var(--rd)}.cmd-txt.suspicious{color:var(--or)}
.cmd-txt.recon{color:var(--cy)}

/* IP table */
.ip-table{width:100%;border-collapse:collapse;font-size:11px}
.ip-table th{color:var(--dim);font-size:9px;text-transform:uppercase;letter-spacing:1px;
  padding:4px 8px;border-bottom:1px solid var(--br);text-align:left;font-weight:600}
.ip-table td{padding:4px 8px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:top}
.ip-table tr:hover td{background:var(--bg3)}
.ip-bar{height:4px;background:var(--or);border-radius:2px;margin-top:3px;min-width:2px}

/* Canary highlight */
.canary-row{background:var(--gd2);border-left:3px solid var(--gd) !important}
.canary-file{color:var(--gd);font-weight:700}

/* Exploit alert */
.exploit-row{background:var(--rd2);border-left:3px solid var(--rd)}
.cve-badge{background:rgba(255,50,80,.2);color:var(--rd);border:1px solid rgba(255,50,80,.4);
  border-radius:3px;padding:1px 6px;font-size:9px;font-weight:700}

/* Samples */
.sha{color:var(--dim);font-size:10px;font-family:monospace}
.sha .hex{color:var(--bl);letter-spacing:.5px}

/* Empty state */
.empty{color:var(--dim);font-size:11px;padding:12px 4px;font-style:italic}

/* Copy toast */
#toast{position:fixed;bottom:20px;right:20px;background:var(--gn);color:#000;
  padding:6px 14px;border-radius:4px;font-size:12px;font-weight:700;
  opacity:0;transition:opacity .2s;pointer-events:none;z-index:999}
#toast.show{opacity:1}

/* Scrollbars */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--br2);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:var(--dim)}

/* Replay player */
#replay-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.88);
  z-index:200;display:none;align-items:center;justify-content:center}
#replay-modal.open{display:flex}
.replay-win{background:#010810;border:1px solid var(--br2);border-radius:8px;
  width:760px;max-width:95vw;max-height:90vh;display:flex;flex-direction:column}
.replay-hdr{display:flex;align-items:center;gap:8px;padding:8px 12px;
  border-bottom:1px solid var(--br);flex-shrink:0}
#replay-term{font-family:ui-monospace,Menlo,"SF Mono",Consolas,monospace;font-size:12px;
  line-height:1.55;padding:12px;overflow-y:auto;flex:1;min-height:280px;max-height:58vh;
  background:#010810;white-space:pre-wrap;word-break:break-all;color:var(--hi)}
/* Heatmap */
.cc-tile{background:var(--bg3);border:1px solid var(--br);border-radius:6px;
  padding:8px 10px;min-width:100px;text-align:center;cursor:default;transition:background .1s}
.cc-tile:hover{background:var(--bg4)}
/* Actor multi-IP highlight */
.actor-multi{border-left-color:var(--pu) !important}

@media(max-width:700px){
  .kpi{min-width:55px;padding:3px 6px}.kpi .v{font-size:15px}.kpi .l{font-size:7px}
  .ip{min-width:85px;font-size:11px}.cred-row{gap:4px}
  .tab{padding:6px 9px;font-size:10px;letter-spacing:.5px}
}
</style>
</head>
<body>

<div id=hdr>
  <span class=live-dot></span>
  <span class=logo>KI&nbsp;HONEYPOT<span class=chip>AI</span></span>
  <span id=clock></span>
  <span id=uptime></span>
  <span id=ai-usage title="KI-Calls heute (alle Komponenten)" style="margin-left:auto;font-size:10px;color:var(--dim);white-space:nowrap"></span>
  <button id=ai-cfg-btn onclick=openConfig() title="KI-Provider & API-Key"
    style="background:var(--bg2);color:var(--cy);border:1px solid rgba(0,224,255,.4);border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit">&#9881; KI</button>
  <button id=reset-btn onclick=resetCounters() title="Alle Zähler auf 0 setzen"
    style="background:var(--bg2);color:var(--rd);border:1px solid rgba(255,50,80,.4);border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit">&#8635; RESET</button>
</div>

<!-- AI provider config modal -->
<div id=cfg-modal style="display:none;position:fixed;inset:0;background:rgba(0,5,15,.8);z-index:9999;align-items:center;justify-content:center">
  <div style="background:var(--bg2);border:1px solid var(--br);border-radius:10px;padding:22px;width:min(440px,92vw);box-shadow:0 0 40px rgba(0,224,255,.15)">
    <div style="font-size:15px;font-weight:700;color:var(--cy);margin-bottom:4px">&#9881; KI-Provider konfigurieren</div>
    <div id=cfg-status style="font-size:11px;color:var(--dim);margin-bottom:14px"></div>
    <label style="font-size:11px;color:var(--dim)">Provider</label>
    <select id=cfg-provider style="width:100%;margin:4px 0 12px;padding:7px;background:var(--bg);color:var(--tx);border:1px solid var(--br);border-radius:5px;font-family:inherit"></select>
    <label style="font-size:11px;color:var(--dim)">API-Key</label>
    <input id=cfg-key type=password autocomplete=off placeholder="sk-ant-… / gsk_… / AIza… / xai-… / Mistral"
      style="width:100%;margin:4px 0 12px;padding:7px;background:var(--bg);color:var(--tx);border:1px solid var(--br);border-radius:5px;font-family:inherit">
    <label style="font-size:11px;color:var(--dim)">Modell (optional)</label>
    <input id=cfg-model type=text autocomplete=off placeholder="Standard automatisch"
      style="width:100%;margin:4px 0 16px;padding:7px;background:var(--bg);color:var(--tx);border:1px solid var(--br);border-radius:5px;font-family:inherit">
    <div style="display:flex;gap:10px;justify-content:flex-end">
      <button onclick=closeConfig() style="background:var(--bg3);color:var(--dim);border:1px solid var(--br);border-radius:5px;padding:7px 14px;cursor:pointer;font-family:inherit">Abbrechen</button>
      <button onclick=saveConfig() style="background:linear-gradient(90deg,#00e0ff,#00ff9d);color:#001018;border:none;border-radius:5px;padding:7px 18px;font-weight:700;cursor:pointer;font-family:inherit">Speichern</button>
    </div>
  </div>
</div>

<div id=kpis>
  <div class="kpi gn"><div class=v id=k-ev>0</div><div class=l>Events</div></div>
  <div class="kpi bl"><div class=v id=k-ip>0</div><div class=l>IPs</div></div>
  <div class="kpi pu"><div class=v id=k-ss>0</div><div class=l>SSH Logins</div></div>
  <div class="kpi pu"><div class=v id=k-tel>0</div><div class=l>Telnet Logins</div></div>
  <div class="kpi rd"><div class=v id=k-ex>0</div><div class=l>Exploits</div></div>
  <div class="kpi rd"><div class=v id=k-th>0</div><div class=l>0-Day Hits</div></div>
  <div class="kpi gn"><div class=v id=k-dec>0</div><div class=l title="Wie tief Bots in die Tarnung eindringen (Engagement+Eskalation)">Deception</div></div>
  <div class="kpi or"><div class=v id=k-sa>0</div><div class=l>Samples</div></div>
  <div class="kpi rd"><div class=v id=k-rr>0</div><div class=l>Redis RCE</div></div>
  <div class="kpi gd"><div class=v id=k-ca>0</div><div class=l>Canary Trips</div></div>
  <div class="kpi cy"><div class=v id=k-nt>0</div><div class=l>NTLM Hashes</div></div>
  <div class="kpi gd"><div class=v id=k-ht>0</div><div class=l title="Angreifer hat geleakte Honeytoken-Secrets BENUTZT">Honeytokens</div></div>
</div>

<div id=tabs>
  <div class="tab on" data-t=live>LIVE FEED</div>
  <div class="tab" data-t=strategy>AI STRATEGY</div>
  <div class="tab" data-t=briefing>AI BRIEFING</div>
  <div class="tab" data-t=creds>CREDENTIALS<span class=badge id=bd-cr style=display:none></span></div>
  <div class="tab" data-t=replay>COMMANDS REPLAY</div>
  <div class="tab" data-t=samples>SAMPLES</div>
  <div class="tab" data-t=exploits>EXPLOITS<span class=badge id=bd-ex style=display:none></span></div>
  <div class="tab" data-t=redis>REDIS<span class=badge id=bd-rr style=display:none></span></div>
  <div class="tab" data-t=stratum>CRYPTO<span class=badge id=bd-st style=display:none></span></div>
  <div class="tab" data-t=threat>0-DAY INTEL<span class=badge id=bd-th style=display:none></span></div>
  <div class="tab" data-t=camps>CAMPAIGNS</div>
  <div class="tab" data-t=actors>ACTORS</div>
  <div class="tab" data-t=smb>SMB / CANARY</div>
  <div class="tab" data-t=hashes>NTLM HASHES<span class=badge id=bd-nt style=display:none></span></div>
</div>

<div id=content>

<!-- LIVE FEED -->
<div class="tab-pane on" id=t-live>
  <div class=sec>
    <div class=sech>Real-time Event Stream <span class=ct id=live-ct></span></div>
    <div id=live-feed></div>
  </div>
</div>

<!-- CREDENTIALS -->
<div class="tab-pane" id=t-creds>
  <div class=sec>
    <div class=sech>Captured Credentials (SSH / Telnet / OWA) <span class=ct id=cred-ct></span></div>
    <div id=cred-list></div>
    <div class=empty id=cred-empty>No credentials captured yet.</div>
  </div>
</div>

<!-- NTLM HASHES -->
<div class="tab-pane" id=t-hashes>
  <div class=sec>
    <div class=sech>Net-NTLMv2 Hashes (hashcat -m 5600) <span class=ct id=hash-ct></span>
      <button class=copy-btn style="margin-left:10px" onclick=copyAllHashes()>COPY ALL</button>
    </div>
    <div id=hash-list></div>
    <div class=empty id=hash-empty>No NTLM hashes captured yet.</div>
  </div>
</div>

<!-- EXPLOITS -->
<div class="tab-pane" id=t-exploits>
  <div class=sec>
    <div class=sech>Exploit Attempts & Ransomware Detection <span class=ct id=ex-ct></span></div>
    <div id=ex-list></div>
    <div class=empty id=ex-empty>No exploit attempts detected yet.</div>
  </div>
</div>

<!-- TOP IPs -->

<!-- SMB / CANARY -->
<div class="tab-pane" id=t-smb>
  <div class=sec>
    <div class=sech>SMB Sessions <span class=ct id=smb-ct></span></div>
    <div id=smb-list></div>
    <div class=empty id=smb-empty>No SMB sessions yet.</div>
  </div>
  <div class=sec style="margin-top:16px">
    <div class=sech>Canary File Accesses <span class=ct id=can-ct></span></div>
    <div id=can-list></div>
    <div class=empty id=can-empty>No canary trips yet.</div>
  </div>
</div>

<!-- SAMPLES -->
<div class="tab-pane" id=t-samples>
  <div class=sec>
    <div class=sech>Captured Malware Samples <span class=ct id=samp-ct></span></div>
    <div id=samp-list></div>
    <div class=empty id=samp-empty>No samples captured yet.</div>
  </div>
</div>

<!-- REDIS RCE -->
<div class="tab-pane" id=t-redis>
  <div class=sec>
    <div class=sech>Redis RCE Sessions <span class=ct id=redis-ct></span></div>
    <div id=redis-list></div>
    <div class=empty id=redis-empty>No Redis RCE sessions yet.</div>
  </div>
  <div class=sec style="margin-top:16px">
    <div class=sech>Redis Recon / Scanners <span class=ct id=redis-recon-ct></span></div>
    <div id=redis-recon-list></div>
    <div class=empty id=redis-recon-empty>No Redis recon yet.</div>
  </div>
</div>

<!-- THREAT INTEL -->
<div class="tab-pane" id=t-threat>
  <div class=sec>
    <div class=sech>Zero-Day Behavioral Detection <span class=ct id=threat-ct></span></div>
    <div id=threat-list></div>
    <div class=empty id=threat-empty>No behavioral anomalies detected yet.</div>
  </div>
</div>

<!-- CRYPTO -->
<div class="tab-pane" id=t-stratum>
  <div class=sec>
    <div class=sech>Crypto — Mining Pool &amp; Ethereum RPC Probes <span class=ct id=stratum-ct></span></div>
    <div id=stratum-list></div>
    <div class=empty id=stratum-empty>No crypto activity yet.</div>
  </div>
</div>

<!-- COMMANDS REPLAY -->
<div class="tab-pane" id=t-replay>
  <div class=sec>
    <div class=sech>SSH / Telnet / Shell Commands &amp; Session Replays <span class=ct id=replay-ct></span></div>
    <div id=replay-list></div>
    <div class=empty id=replay-empty>No SSH sessions with commands or replay data yet.</div>
  </div>
</div>

<!-- HEATMAP -->
<!-- CAMPAIGNS -->
<div class="tab-pane" id=t-camps>
  <div class=sec>
    <div class=sech>Bot Campaign Clusters (SSH Command Fingerprint) <span class=ct id=camps-ct></span></div>
    <div id=camps-list></div>
    <div class=empty id=camps-empty>No SSH campaigns clustered yet.</div>
  </div>
</div>

<!-- ACTORS -->
<div class="tab-pane" id=t-actors>
  <div class=sec>
    <div class=sech>Actor Fingerprinting — JA3 Multi-IP Correlation <span class=ct id=actors-ct></span></div>
    <div id=actors-list></div>
    <div class=empty id=actors-empty>No multi-IP actors detected yet.</div>
  </div>
</div>

<!-- AI BRIEFING -->
<div class="tab-pane" id=t-briefing>
  <div class=sec>
    <div class=sech style="display:flex;align-items:center;gap:12px">
      <span>KI-Lagebericht — stündlicher Statusreport (Mistral)</span>
      <span id=briefing-quota style="color:var(--dim);font-size:10px"></span>
      <button class=copy-btn id=briefing-refresh-btn onclick=refreshBriefing() style="margin-left:auto">&#8635; JETZT GENERIEREN</button>
    </div>
    <div id=briefing-meta style="color:var(--dim);font-size:10px;margin:4px 0 10px"></div>
    <div id=briefing-spinner style="display:none;color:var(--gn);font-size:11px;margin:8px 0">&#9679; KI generiert Lagebericht…</div>
    <pre id=briefing-text style="white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;font-family:inherit;font-size:12px;line-height:1.7;color:var(--tx);background:var(--bg2);border:1px solid var(--br);border-radius:4px;padding:14px;margin:0;min-height:80px"></pre>
    <div id=briefing-next style="color:var(--dim);font-size:10px;margin-top:8px"></div>
    <div class=empty id=briefing-empty>Erster Bericht wird in ~60s nach dem Start generiert.</div>
  </div>
</div>

<!-- AI STRATEGY -->
<div class="tab-pane" id=t-strategy>
  <div class=sec>
    <div class=sech style="display:flex;align-items:center;gap:12px">
      <span>AI Strategy Journal — was der Stratege entscheidet & warum</span>
      <span id=strategy-stat style="color:var(--dim);font-size:10px"></span>
      <button class=copy-btn onclick=fetchStrategy() style="margin-left:auto">&#8635; REFRESH</button>
    </div>
    <div id=strategy-list></div>
    <div class=empty id=strategy-empty>Noch keine Strategie-Entscheidungen. Der Stratege wird bei „interessanten" Sessions aktiv (RCE-Vektoren, unbekannte Exploits, Uploads).</div>
  </div>
</div>

</div><!-- #content -->

<!-- Replay modal (fixed overlay, outside tab content) -->
<div id=replay-modal>
  <div class=replay-win>
    <div class=replay-hdr>
      <span id=replay-title style="color:var(--gn);font-weight:700;flex:1;font-size:12px">Commands Replay</span>
      <button class=copy-btn id=replay-play-btn onclick=replayPlayPause() style="color:var(--gn);border-color:rgba(0,255,85,.3)">&#9654; PLAY</button>
      <button class=copy-btn id=replay-spd-btn onclick=replaySpeedCycle()>1x</button>
      <button class=copy-btn onclick=replayClose() style="color:var(--rd);border-color:rgba(255,50,80,.3)">&#10005; CLOSE</button>
    </div>
    <div id=replay-term></div>
  </div>
</div>

<div id=toast>Copied!</div>

<script>
// ── Utilities ─────────────────────────────────────────────────────────────
var LIVE_MAX = 120;
function E(s){return String(s||"").replace(/[<>&"]/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;"}[c]))}
function T(ts){if(!ts)return"";try{var d=new Date(ts);return d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"})}catch(e){return ts.slice(11,19)||ts}}
function Tl(ts){if(!ts)return"";try{var d=new Date(ts);return d.toLocaleString([],{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}catch(e){return ts}}
function F(cc){if(!cc||cc.length!=2)return"";try{return cc.toUpperCase().replace(/./g,x=>String.fromCodePoint(127397+x.charCodeAt()))}catch(e){return""}}

// ── i18n: dashboard chrome in the browser's language (de / en) ──────────────
var LANG=((navigator.language||navigator.userLanguage||"en").toLowerCase().slice(0,2)==="de")?"de":"en";
try{document.documentElement.lang=LANG;}catch(e){}
// [english, german] — leaf labels/buttons/empty-states only (tabs keep symbols)
var I18N_PAIRS=[
 ["Events","Ereignisse"],["SSH Logins","SSH-Logins"],["NTLM Hashes","NTLM-Hashes"],
 ["Canary Trips","Canary-Treffer"],["Exploits","Exploits"],["Samples","Samples"],
 ["Redis RCE","Redis-RCE"],["0-Day Hits","0-Day-Treffer"],
 ["Deception","Täuschung"],["Honeytokens","Honeytokens"],["Stratum","Stratum"],
 ["RESET","RESET"],["REFRESH","AKTUALISIEREN"],["GENERATE NOW","JETZT GENERIEREN"],
 ["samples","Samples"],["campaigns","Kampagnen"],
 ["AI Threat Briefing — what did we just find?","AI Threat Briefing — Was haben wir gerade gefunden?"],
 ["AI Strategy Journal — what the strategist decides & why","AI Strategy Journal — was der Stratege entscheidet & warum"]
];
function _i18nApply(){
  var to=(LANG==="de")?1:0, fr=1-to;
  var map={};
  I18N_PAIRS.forEach(function(p){ if(p[fr])map[p[fr].toLowerCase()]=p[to]; });
  // leaf labels + empty states + section headers without child elements
  document.querySelectorAll(".kpi .l,.empty,.sech,#reset-btn").forEach(function(el){
    var t=(el.textContent||"").trim();
    var key=t.replace(/^[^A-Za-z0-9ÄÖÜäöü]+/,"").trim().toLowerCase(); // strip leading icons
    if(map[key]){ el.textContent=(el===document.getElementById("reset-btn")?"↻ ":"")+map[key]; }
  });
  // buttons that carry an icon + word (briefing/strategy/refresh)
  document.querySelectorAll(".copy-btn").forEach(function(b){
    var t=(b.textContent||"").trim().replace(/^[^A-Za-z]+/,"").trim().toLowerCase();
    if(map[t])b.textContent="↻ "+map[t];
  });
}
function svc_tag(svc,lure){
  if(!svc&&!lure)return"";
  var s=(svc||lure||"").toLowerCase();
  if(s=="ssh")return'<span class="tag tag-ssh">SSH</span>';
  if(s=="smb")return'<span class="tag tag-smb">SMB</span>';
  if(s=="redis"||lure=="redis-rce")return'<span class="tag tag-redis">Redis</span>';
  if(s=="stratum")return'<span class="tag tag-stratum">Stratum</span>';
  if((lure||"").includes("canary")||s=="canary_access")return'<span class="tag tag-canary">CANARY</span>';
  if(s=="sample_capture")return'<span class="tag tag-sample">SAMPLE</span>';
  if((lure||"").includes("cve")||(lure||"").includes("exploit")||
     (lure||"").includes("webshell")||(lure||"").includes("rce")||lure=="ransomware")
    return'<span class="tag tag-exploit">'+(lure=="ransomware"?"RANSOMWARE":"EXPLOIT")+'</span>';
  return'<span class="tag tag-http">'+(lure?E(lure.toUpperCase().slice(0,12)):"HTTP")+'</span>';
}
function cmd_class(cmd){
  var c=(cmd||"").toLowerCase();
  var d=["rm -rf","mkfifo","chmod 777","base64 -d","python -c","bash -i","nc -e","/dev/tcp","wget","curl http"];
  var s=["cat /etc","cat /proc","cat ~/.","ls -la","id;","whoami","uname -a","netstat","ps aux","history"];
  var r=["ls","pwd","echo","env","hostname","ifconfig","ip a"];
  for(var i=0;i<d.length;i++)if(c.includes(d[i]))return"dangerous";
  for(var i=0;i<s.length;i++)if(c.includes(s[i]))return"suspicious";
  return"recon";
}
function toast(msg){var t=document.getElementById("toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),1800)}
function copyText(txt){navigator.clipboard.writeText(txt).then(()=>toast("Copied!")).catch(()=>toast("Copy failed"))}

// ── KPIs ──────────────────────────────────────────────────────────────────
var kpis={events:0,ips:0,ssh:0,ntlm:0,canary:0,exploits:0,samples:0};
function updKpis(k){
  if(k.events!==undefined){kpis=Object.assign(kpis,k);
  document.getElementById("k-ev").textContent=kpis.events;
  document.getElementById("k-ip").textContent=kpis.ips;
  document.getElementById("k-ss").textContent=kpis.ssh;
  document.getElementById("k-tel").textContent=kpis.telnet||0;
  document.getElementById("k-nt").textContent=kpis.ntlm;
  document.getElementById("k-ca").textContent=kpis.canary;
  document.getElementById("k-ex").textContent=kpis.exploits;
  document.getElementById("k-sa").textContent=kpis.samples;
  document.getElementById("k-rr").textContent=kpis.redis_rce||0;
  document.getElementById("k-th").textContent=kpis.threats||0;}
}

// ── Delta-badges (reset every 60 s) ───────────────────────────────────────
var _badgeNew={cr:0,nt:0,ex:0,rr:0,th:0,st:0};
function bumpBadge(id){_badgeNew[id]++;var b=document.getElementById("bd-"+id);b.textContent=_badgeNew[id];b.style.display="";}
function resetBadges(){Object.keys(_badgeNew).forEach(function(k){_badgeNew[k]=0;var b=document.getElementById("bd-"+k);if(b){b.textContent="";b.style.display="none";}});}

// ── Tabs ──────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(function(t){
  t.addEventListener("click",function(){
    document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));
    document.querySelectorAll(".tab-pane").forEach(x=>x.classList.remove("on"));
    t.classList.add("on");
    document.getElementById("t-"+t.dataset.t).classList.add("on");
    if(t.dataset.t==="camps")fetch("/api/data").then(r=>r.json()).then(d=>{campaignList=d.campaigns||campaignList;renderCampaigns();}).catch(function(){});
    if(t.dataset.t==="actors")fetch("/api/data").then(r=>r.json()).then(d=>{actorList=d.actors||actorList;renderActors();}).catch(function(){});
    if(t.dataset.t==="replay"&&!replayList.length)fetch("/api/data").then(r=>r.json()).then(d=>{(d.ssh_replays||[]).forEach(s=>replayList.push(s));renderReplays();}).catch(function(){});
    if(t.dataset.t==="stratum")fetch("/api/data").then(r=>r.json()).then(d=>{stratumList=d.stratum||stratumList;renderStratum();}).catch(function(){});
    if(t.dataset.t==="strategy")fetchStrategy();
  });
});

// ── AI Strategy journal ────────────────────────────────────────────────────
function fetchStrategy(){
  fetch("/api/strategy").then(r=>r.json()).then(function(d){
    var el=document.getElementById("strategy-list");
    var emp=document.getElementById("strategy-empty");
    var stat=document.getElementById("strategy-stat");
    if(!el)return;
    var ents=(d.entries||[]).filter(function(e){return e.event==="decision"});
    stat.textContent=(d.active?"AKTIV":"SHADOW")+" · "+(d.n_decisions||0)+" LLM-Entscheidungen · "+(d.learned_patterns||0)+" Muster gelernt · "+(d.token_free_reuses||0)+"× token-frei wiederverwendet · "+(d.n_steered||0)+"× gesteuert";
    emp.style.display=ents.length?"none":"";
    var stColor={engage:"var(--gn)",mimic_vuln:"var(--or)",probe:"var(--cy)",tarpit:"var(--bl)",default:"var(--dim)"};
    el.innerHTML=ents.map(function(e){
      var c=stColor[e.stance]||"var(--dim)";
      var obs=(e.observed||[]).map(function(o){return E(String(o).slice(0,80))}).join("<br>");
      var sug=e.suggestion?('<div style="margin-top:6px;color:var(--dim);font-size:10px">↳ Fake-Antwort: <span style="color:var(--tx)">'+E(e.suggestion.slice(0,160))+'</span></div>'):'';
      return '<div class=cred-card>'+
        '<div class=cred-row style="gap:10px;flex-wrap:wrap">'+
          '<span style="color:var(--dim);font-size:9px">'+Tl(e.ts)+'</span>'+
          '<span class="tag" style="text-transform:uppercase">'+E(e.module||"")+'</span>'+
          '<span style="color:var(--or);font-size:10px">'+E(e.src_ip||"")+'</span>'+
          '<span style="color:'+c+';font-weight:700;font-size:11px">STANCE: '+E(e.stance||"")+'</span>'+
          (e.confidence?'<span style="color:var(--dim);font-size:9px">conf='+E(e.confidence)+'</span>':'')+
        '</div>'+
        '<div style="margin-top:5px;font-size:12px"><span style="color:var(--cy)">🧠 '+E(e.hypothesis||"")+'</span>'+(e.family?' <span style="color:var(--or);font-size:10px">['+E(e.family)+']</span>':'')+'</div>'+
        (e.goal?'<div style="color:var(--dim);font-size:10px;margin-top:2px">Ziel: '+E(e.goal)+'</div>':'')+
        (e.reasoning?'<div style="color:var(--tx);font-size:10px;margin-top:2px">Warum: '+E(e.reasoning)+'</div>':'')+
        sug+
        (obs?'<div style="margin-top:6px;color:var(--dim);font-family:monospace;font-size:9px">'+obs+'</div>':'')+
      '</div>';
    }).join("");
  }).catch(function(){});
}

// ── Live feed ─────────────────────────────────────────────────────────────
function addLiveRow(ev){
  var ip=ev.src_ip||"",svc=ev.service||"",lure=ev.lure||"";
  var type=ev.type||ev.event||"";
  var cc=(ev.geo||{}).cc||"";
  var path=ev.path||ev.file||ev.url||"";
  var extra="";
  if(ev.ssh_pass) extra='<span class=cred-pw>'+E(ev.ssh_pass)+'</span>';
  else if(ev.hashcat) extra='<span style="color:var(--bl);font-size:10px">'+E(ev.hashcat.slice(0,60))+'…</span>';
  else if(path) extra='<span style="color:var(--tx);font-size:11px">'+E(path.slice(0,80))+'</span>';
  var rowCls="row";
  if(type=="canary_access")rowCls+=" canary-row";
  if(ev.ransomware)rowCls+=" exploit-row";
  var h='<div class="'+rowCls+'" onclick=this.querySelector&&this.querySelector(".detail")&&this.querySelector(".detail").classList.toggle("on")>';
  h+='<span class=ts>'+T(ev.ts)+'</span>';
  h+='<span class=flag>'+F(cc)+'</span>';
  h+='<span class=ip>'+E(ip)+'</span>';
  h+=svc_tag(svc=="ssh"?"ssh":svc,lure);
  if(extra)h+=extra;
  h+='</div>';
  var feed=document.getElementById("live-feed");
  feed.insertAdjacentHTML("afterbegin",h);
  while(feed.children.length>LIVE_MAX)feed.lastChild.remove();
  document.getElementById("live-ct").textContent=feed.children.length+" events";
}

// ── Credentials ───────────────────────────────────────────────────────────
var credList=[];
function renderCreds(){
  var el=document.getElementById("cred-list"),ct=document.getElementById("cred-ct");
  var emp=document.getElementById("cred-empty");
  ct.textContent=credList.length+" captured";
  emp.style.display=credList.length?"none":"";
  el.innerHTML=credList.slice(0,80).map(function(c){
    var cmdsHtml=c.cmds&&c.cmds.length?
      '<div class=cred-cmds>Commands: '+c.cmds.slice(0,8).map(x=>E(x)).join(" │ ")+'</div>':"";
    var intentHtml=c.ai_intent?'<div style="margin-top:3px;font-size:11px;color:var(--cy)">🧠 '+E(c.ai_intent)+'</div>':"";
    var deLang=(LANG==="de");
    var badge=c.ok
      ?'<span class="tag" style="background:rgba(0,255,85,.15);color:var(--gn)">'+(deLang?"LOGIN OK":"LOGIN OK")+'</span>'
      :'<span class="tag" style="background:rgba(255,170,0,.12);color:var(--or)" title="'+(deLang?"Passwort abgelehnt":"password rejected")+'">'+(deLang?"BRUTE-FORCE ✗":"FAILED BRUTE-FORCE")+'</span>';
    var dim=c.ok?"":"opacity:.6";
    var proto=c.proto?'<span class="tag" style="background:rgba(0,224,255,.12);color:var(--cy)">'+E(c.proto)+'</span>':"";
    return '<div class=cred-card onclick=void(0) style="'+dim+'">'+
      '<div class=cred-row>'+
      '<span class=ts>'+Tl(c.ts)+'</span>'+
      '<span class=flag>'+F(c.cc)+'</span>'+
      '<span class=ip>'+E(c.ip)+'</span>'+
      proto+
      '<span class=cred-user>'+E(c.user)+'</span>'+
      '<span style="color:var(--dim)">:</span>'+
      '<span class=cred-pw onclick="event.stopPropagation();copyText(\''+E(c.pw)+'\')" title="Click to copy">'+E(c.pw)+'</span>'+
      badge+
      '</div>'+intentHtml+cmdsHtml+'</div>';
  }).join("");
}
function addCred(c){
  credList.unshift(c);if(credList.length>200)credList.pop();
  if(document.getElementById("t-creds").classList.contains("on"))renderCreds();
}

// ── NTLM Hashes ───────────────────────────────────────────────────────────
var hashList=[];
function renderHashes(){
  var el=document.getElementById("hash-list"),ct=document.getElementById("hash-ct");
  var emp=document.getElementById("hash-empty");
  ct.textContent=hashList.length+" hashes";
  emp.style.display=hashList.length?"none":"";
  el.innerHTML=hashList.slice(0,80).map(function(h){
    var ransom=h.ransomware?'class="hash-card ransom"':'class=hash-card';
    var warn=h.ransomware?'<span class="tag tag-ransom" style="margin-left:6px">RANSOMWARE</span>':"";
    var hv=h.hashcat||"(no hash)";
    return '<div '+ransom+'>'+
      '<div class=cred-row>'+
      '<span class=ts>'+Tl(h.ts)+'</span>'+
      '<span class=flag>'+F(h.cc)+'</span>'+
      '<span class=ip>'+E(h.ip)+'</span>'+
      '<span class=cred-user>'+E(h.user)+'@'+E(h.domain)+'</span>'+
      '<span style="color:var(--dim);font-size:10px">WS:'+E(h.ws)+'</span>'+
      warn+
      '</div>'+
      '<div class=hash-val onclick="copyText(\''+E(hv)+'\')" title="Click to copy">'+E(hv)+'</div>'+
      (h.shares&&h.shares.length?'<div style="color:var(--dim);font-size:10px;margin-top:4px">Shares: '+h.shares.map(x=>E(x)).join(", ")+'</div>':"")+
      '</div>';
  }).join("");
}
function copyAllHashes(){
  var all=hashList.filter(h=>h.hashcat).map(h=>h.hashcat).join("\n");
  copyText(all);
}
function addNtlm(h){
  hashList.unshift(h);if(hashList.length>200)hashList.pop();
  if(document.getElementById("t-hashes").classList.contains("on"))renderHashes();
}

// ── Commands ──────────────────────────────────────────────────────────────
var cmdList=[];
function renderCmds(){}
function addCmd(c){
  cmdList.unshift(c);if(cmdList.length>500)cmdList.pop();
}

// ── Exploits ──────────────────────────────────────────────────────────────
var exList=[];
function renderExploits(){
  var el=document.getElementById("ex-list"),ct=document.getElementById("ex-ct");
  var emp=document.getElementById("ex-empty");
  ct.textContent=exList.length+" detected";
  emp.style.display=exList.length?"none":"";
  var sevC={critical:"var(--rd)",high:"var(--or)",medium:"var(--gd)",low:"var(--dim)"};
  el.innerHTML=exList.slice(0,100).map(function(e){
    var cve=e.cve?'<span class=cve-badge>'+E(e.cve)+'</span>':"";
    var rtag=e.ransomware?'<span class="tag tag-ransom">RANSOMWARE</span>':'';
    var sev=e.ai_sev?'<span class="tag" style="background:rgba(255,170,0,.12);color:'+(sevC[e.ai_sev]||"var(--dim)")+'">'+E(e.ai_sev.toUpperCase())+'</span>':'';
    var desc=e.ai_desc?'<div style="margin-top:4px;font-size:11px;color:var(--tx)">🧠 '+E(e.ai_desc)+'</div>':"";
    return '<div class="exploit-row row" style="flex-direction:column;align-items:flex-start">'+
      '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;width:100%">'+
        '<span class=ts>'+Tl(e.ts)+'</span>'+
        '<span class=flag>'+F(e.cc)+'</span>'+
        '<span class=ip>'+E(e.ip)+'</span>'+
        rtag+cve+sev+
        '<span class=main-text>'+E(e.lure)+'</span>'+
        '<span class=sub-text>'+E((e.path||"").slice(0,60))+'</span>'+
      '</div>'+desc+
      '</div>';
  }).join("");
}
function addExploit(e){
  exList.unshift(e);if(exList.length>200)exList.pop();
  if(document.getElementById("t-exploits").classList.contains("on"))renderExploits();
}

// ── IPs ───────────────────────────────────────────────────────────────────
var ipData=[];
function renderIPs(data){
  if(data)ipData=data;
  var el=document.getElementById("ip-body");
  if(!ipData.length){el.innerHTML='<tr><td colspan=5 class=empty>No data yet.</td></tr>';return;}
  var max=ipData[0]?ipData[0].n:1;
  el.innerHTML=ipData.slice(0,60).map(function(r){
    var barW=Math.max(2,Math.round(r.n/max*120));
    return '<tr>'+
      '<td><span style="color:var(--or);font-weight:700">'+E(r.ip)+'</span>'+
      '<div class=ip-bar style="width:'+barW+'px"></div></td>'+
      '<td>'+F(r.cc)+'&nbsp;'+E(r.cc)+'</td>'+
      '<td style="color:var(--gn);font-weight:700">'+r.n+'</td>'+
      '<td style="color:var(--dim);font-size:10px">'+(r.svcs||[]).join(", ")+'</td>'+
      '<td style="color:var(--dim);font-size:10px">'+T(r.last)+'</td>'+
      '</tr>';
  }).join("");
}

// ── SMB + Canary ──────────────────────────────────────────────────────────
var smbList=[], canaryList=[];
function renderSMB(){
  var el=document.getElementById("smb-list"),ct=document.getElementById("smb-ct");
  var emp=document.getElementById("smb-empty");
  ct.textContent=smbList.length+" sessions";
  emp.style.display=smbList.length?"none":"";
  el.innerHTML=smbList.slice(0,60).map(function(s){
    var ransom=s.ransomware?'<span class="tag tag-ransom">RANSOMWARE DETECTED</span>':"";
    var files=s.files&&s.files.length?
      '<div style="color:var(--dim);font-size:10px;margin-top:3px">Files: '+s.files.slice(0,4).map(x=>E(x)).join(" │ ")+'</div>':"";
    return '<div class="hash-card'+(s.ransomware?" ransom":"")+'">'+
      '<div class=cred-row>'+
      '<span class=ts>'+Tl(s.ts)+'</span>'+
      '<span class=flag>'+F(s.cc)+'</span>'+
      '<span class=ip>'+E(s.ip)+'</span>'+
      '<span class=cred-user>'+(s.user?(E(s.user)+'@'+E(s.domain)):'<span style="color:var(--dim)">probe</span>')+'</span>'+
      ransom+
      '</div>'+files+
      (s.hashcat?'<div class=hash-val onclick="copyText(\''+E(s.hashcat)+'\')" title="Click to copy hashcat">'+E(s.hashcat)+'</div>':"")
      +'</div>';
  }).join("");
  var cel=document.getElementById("can-list"),cct=document.getElementById("can-ct");
  var cemp=document.getElementById("can-empty");
  cct.textContent=canaryList.length+" trips";
  cemp.style.display=canaryList.length?"none":"";
  cel.innerHTML=canaryList.slice(0,60).map(function(c){
    return '<div class="row canary-row">'+
      '<span class=ts>'+Tl(c.ts)+'</span>'+
      '<span class=flag>'+F(c.cc)+'</span>'+
      '<span class=ip>'+E(c.ip)+'</span>'+
      '<span class="tag tag-canary">CANARY</span>'+
      '<span class=canary-file>'+E(c.file)+'</span>'+
      (c.cmd?'<span style="color:var(--dim);font-size:10px">cmd: '+E(c.cmd)+'</span>':"")
      +'</div>';
  }).join("");
}

// ── Samples ───────────────────────────────────────────────────────────────
var sampList=[];
function renderSamples(){
  var el=document.getElementById("samp-list"),ct=document.getElementById("samp-ct");
  var emp=document.getElementById("samp-empty");
  ct.textContent=sampList.length+" samples";
  emp.style.display=sampList.length?"none":"";
  el.innerHTML=sampList.slice(0,60).map(function(s){
    var sz=s.size?(s.size>1048576?(s.size/1048576).toFixed(1)+"MB":Math.round(s.size/1024)+"KB"):"";
    var ft=s.filetype?'<span style="color:var(--cy);font-size:10px">'+E(s.filetype)+'</span>':"";
    var vt=(typeof s.vt==="number"&&s.vt>0)?'<span class="tag" style="background:rgba(255,50,80,.15);color:var(--rd)">VT '+s.vt+'</span>':"";
    var fam=s.family?'<span class="tag" style="background:rgba(255,170,0,.15);color:var(--or)">'+E(s.family)+'</span>':"";
    var desc=s.summary?'<div style="margin-top:5px;font-size:12px;color:var(--tx)">🧠 '+E(s.summary)+'</div>':"";
    var caps=(s.capabilities&&s.capabilities.length)?'<div style="margin-top:3px;color:var(--dim);font-size:10px">Fähigkeiten: '+E(s.capabilities.slice(0,8).join(", "))+'</div>':"";
    var c2=(s.c2&&s.c2.length)?'<div style="margin-top:3px;color:var(--rd);font-size:10px">C2: '+E(s.c2.slice(0,5).join(", "))+'</div>':"";
    return '<div class=cred-card>'+
      '<div class=cred-row style="gap:8px;flex-wrap:wrap">'+
        '<span class=ts>'+Tl(s.ts)+'</span>'+
        '<span class=ip>'+E(s.ip)+'</span>'+
        '<span class="tag tag-sample">SAMPLE</span>'+ft+fam+vt+
        (sz?'<span style="color:var(--dim);font-size:10px">'+sz+'</span>':"")+
      '</div>'+
      (s.url?'<div class=sub-text style="font-size:10px;margin-top:3px">'+E(s.url.slice(0,90))+'</div>':"")+
      '<div class=sha style="font-size:10px">SHA256:<span class=hex>'+E((s.sha256||"").slice(0,32))+'…</span></div>'+
      desc+caps+c2+
      '</div>';
  }).join("");
}

// ── Redis RCE ─────────────────────────────────────────────────────────────
var redisList=[];
var _CHAIN_COLORS={"cron-injection":"var(--rd)","ssh-key-injection":"var(--pu)",
  "webshell-drop":"var(--or)","module-load-rce":"var(--or)","slaveof-rogue-server":"var(--cy)",
  "lua-eval-rce":"var(--gn)"};
function renderRedis(){
  var el=document.getElementById("redis-list"),ct=document.getElementById("redis-ct");
  var emp=document.getElementById("redis-empty");
  ct.textContent=redisList.length+" sessions";
  emp.style.display=redisList.length?"none":"";
  el.innerHTML=redisList.slice(0,80).map(function(r){
    var chainHtml=(r.chains||[]).map(function(c){
      var col=_CHAIN_COLORS[c]||"var(--or)";
      return '<span style="background:rgba(255,50,80,.12);color:'+col+';border:1px solid '+col+';border-radius:3px;padding:1px 7px;font-size:9px;font-weight:700;text-transform:uppercase;margin-right:4px">'+E(c)+'</span>';
    }).join("");
    var cfg=r.config||{};
    var cfgHtml=Object.keys(cfg).filter(k=>cfg[k]).slice(0,4).map(k=>'<span style="color:var(--dim)">'+E(k)+'=</span><span style="color:var(--hi)">'+E(String(cfg[k]).slice(0,60))+'</span>').join(" &nbsp;│&nbsp; ");
    var c2Html=(r.c2_urls||[]).slice(0,3).map(u=>'<div style="color:var(--cy);font-size:10px">🔗 '+E(u)+'</div>').join("");
    var cronHtml=r.cron?'<div style="color:var(--rd);font-size:10px;margin-top:3px;background:var(--rd2);padding:3px 6px;border-radius:3px">CRON: '+E(r.cron.slice(0,120))+'</div>':"";
    var sshHtml=r.ssh_key?'<div style="color:var(--pu);font-size:10px;margin-top:3px;background:var(--pu2);padding:3px 6px;border-radius:3px">SSH KEY: '+E(r.ssh_key.slice(0,80))+'…</div>':"";
    var slaveof=r.slaveof&&r.slaveof.toUpperCase()!="NO:NO"?'<span style="color:var(--cy);font-size:10px">SLAVEOF '+E(r.slaveof)+'</span>':"";
    var cmdsHtml=(r.cmds||[]).slice(0,5).map(c=>'<div style="color:var(--gn);font-size:10px">» '+E(c.slice(0,80))+'</div>').join("");
    var replHtml=(r.repl_cmds&&r.repl_cmds.length)?
      '<details style="margin-top:4px"><summary style="color:var(--cy);font-size:10px;cursor:pointer">📡 REPL-STREAM: '+r.repl_cmds.length+' commands (rogue master)</summary>'+
      (r.repl_cmds||[]).slice(0,20).map(c=>'<div style="color:var(--or);font-size:10px;font-family:monospace">» '+E(c.slice(0,120))+'</div>').join("")+
      '</details>':"";
    var raHtml=(r.repl_analysis&&r.repl_analysis.length)?r.repl_analysis.map(function(ra){
      var mHtml=(ra.mitre&&ra.mitre.length)?'<span style="color:var(--dim);font-size:9px"> ['+E(ra.mitre.join(", "))+']</span>':"";
      var pHtml=(ra.persistence&&ra.persistence.length)?'<div style="color:var(--rd);font-size:10px;margin-top:2px">⚓ Persistence: '+E(ra.persistence.join(" / "))+'</div>':"";
      var iHtml=(ra.iocs&&ra.iocs.length)?'<div style="color:var(--cy);font-size:10px">IOCs: '+E(ra.iocs.slice(0,5).join(", "))+'</div>':"";
      return '<div style="margin-top:4px;background:rgba(255,170,0,.08);border-left:2px solid var(--or);padding:4px 6px;border-radius:3px">'+
        '<span style="color:var(--or);font-size:10px;font-weight:700">🧠 AI REPL: </span>'+
        '<span style="color:var(--tx);font-size:11px">'+E(ra.summary||ra.technique||"")+'</span>'+mHtml+
        pHtml+iHtml+'</div>';
    }).join(""):"";
    return '<div class=cred-card style="border-left:3px solid var(--rd)">'+
      '<div class=cred-row>'+
      '<span class=ts>'+Tl(r.ts)+'</span>'+
      '<span class=flag>'+F(r.cc)+'</span>'+
      '<span class=ip>'+E(r.ip)+'</span>'+
      chainHtml+slaveof+
      '</div>'+
      (cfgHtml?'<div style="font-size:10px;margin-top:4px;color:var(--dim)">CONFIG: '+cfgHtml+'</div>':"")+
      c2Html+cronHtml+sshHtml+replHtml+raHtml+
      '<details style="margin-top:4px"><summary style="color:var(--dim);font-size:10px;cursor:pointer">'+
        (r.cmds&&r.cmds.length?r.cmds.length+" commands":"no commands")+
      '</summary>'+cmdsHtml+'</details>'+
      '</div>';
  }).join("");
}
function addRedis(r){
  redisList.unshift(r);if(redisList.length>200)redisList.pop();
  if(document.getElementById("t-redis").classList.contains("on"))renderRedis();
}

// ── Redis Recon ────────────────────────────────────────────────────────────
var redisReconList=[];
function renderRedisRecon(){
  var el=document.getElementById("redis-recon-list"),ct=document.getElementById("redis-recon-ct");
  var emp=document.getElementById("redis-recon-empty");
  ct.textContent=redisReconList.length+" sessions";
  emp.style.display=redisReconList.length?"none":"";
  el.innerHTML=redisReconList.slice(0,100).map(function(r){
    var cmdsHtml=(r.cmds||[]).map(c=>'<span style="font-family:monospace;font-size:10px;color:var(--dim);margin-right:8px">'+E(c)+'</span>').join("");
    return '<div class=card-row style="padding:6px 10px">'+
      '<span class=ts>'+T(r.ts)+'</span>'+
      '<span class=ip>'+E(r.ip)+'</span>'+
      (r.cc?'<span class=fl>'+F(r.cc)+'</span>':'')+
      '<span class="tag tag-redis" style="margin-left:6px">RECON</span>'+
      '<span style="margin-left:8px">'+cmdsHtml+'</span>'+
      '</div>';
  }).join("");
}
function addRedisRecon(r){
  redisReconList.unshift(r);if(redisReconList.length>300)redisReconList.pop();
  if(document.getElementById("t-redis").classList.contains("on"))renderRedisRecon();
}

var vmwareList=[];
function renderVmware(){}
function addVmware(v){}

// ── Threat Intel ──────────────────────────────────────────────────────────
var threatList=[];
var _PHASE_COLORS={"recon":"var(--cy)","probe":"var(--or)","exploit":"var(--rd)","post-exploit":"var(--pu)"};
var _SCORE_COLORS=function(s){if(s>=90)return"var(--pu)";if(s>=70)return"var(--rd)";if(s>=50)return"var(--or)";return"var(--cy)"};
function renderThreat(){
  var el=document.getElementById("threat-list"),ct=document.getElementById("threat-ct");
  var emp=document.getElementById("threat-empty");
  ct.textContent=threatList.length+" detections";
  emp.style.display=threatList.length?"none":"";
  el.innerHTML=threatList.slice(0,100).map(function(t){
    var sc=t.score||0;
    var scoreCol=_SCORE_COLORS(sc);
    var phaseCol=_PHASE_COLORS[t.phase]||"var(--dim)";
    var scoreHtml='<span style="background:rgba(255,50,80,.12);color:'+scoreCol+';border:1px solid '+scoreCol+';border-radius:3px;padding:1px 7px;font-size:11px;font-weight:700;min-width:36px;text-align:center">'+sc+'</span>';
    var phaseHtml='<span style="color:'+phaseCol+';font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:1px">'+E(t.phase)+'</span>';
    var rceHtml=t.rce_verify?'<span style="background:var(--pu2);color:var(--pu);border:1px solid rgba(180,77,255,.5);border-radius:3px;padding:1px 6px;font-size:9px;font-weight:700">RCE VERIFIED</span>':"";
    var novelHtml=t.novel?'<span style="background:rgba(0,255,85,.08);color:var(--gn);border:1px solid rgba(0,255,85,.3);border-radius:3px;padding:1px 6px;font-size:9px;font-weight:700">NOVEL</span>':"";
    var toolHtml=t.tool?'<span style="color:var(--gd);font-size:10px">tool:'+E(t.tool)+'</span>':"";
    var magicHtml=t.upload_magic?'<span style="color:var(--or);font-size:10px">magic:'+E(t.upload_magic)+'</span>':"";
    var indHtml=(t.indicators||[]).slice(0,6).map(function(i){
      return '<span style="background:rgba(255,140,60,.1);color:var(--or);border:1px solid rgba(255,140,60,.3);border-radius:3px;padding:1px 5px;font-size:9px;margin-right:2px">'+E(i)+'</span>';
    }).join("");
    var techHtml=t.technique?'<span style="color:var(--hi);font-weight:700;font-size:11px">'+E(t.technique)+'</span>':"";
    return '<div class="exploit-row row" style="flex-direction:column;align-items:flex-start;padding:7px 10px;margin-bottom:4px">'+
      '<div class=cred-row style="width:100%;flex-wrap:wrap;gap:5px">'+
        '<span class=ts>'+Tl(t.ts)+'</span>'+
        '<span class=flag>'+F(t.cc)+'</span>'+
        '<span class=ip>'+E(t.ip)+'</span>'+
        scoreHtml+phaseHtml+rceHtml+novelHtml+techHtml+
      '</div>'+
      (t.ai_desc?'<div style="margin-top:4px;font-size:11px;color:var(--tx)">🧠 '+E(t.ai_desc)+'</div>':"")+
      (indHtml?'<div style="margin-top:4px">'+indHtml+'</div>':"")+
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:3px">'+
        toolHtml+magicHtml+
        (t.path?'<span style="color:var(--dim);font-size:10px">'+E((t.path||"").slice(0,70))+'</span>':"")+
        (t.lure&&t.lure!="iis-default"&&t.lure!="root-redirect"?'<span style="color:var(--bl);font-size:10px">lure:'+E(t.lure)+'</span>':"")+
      '</div>'+
      '</div>';
  }).join("");
}
function addThreat(t){
  threatList.unshift(t);if(threatList.length>300)threatList.pop();
  if(document.getElementById("t-threat").classList.contains("on"))renderThreat();
}

// ── SSH Replay Player ─────────────────────────────────────────────────────
var replayList=[];
var _rSess=null,_rSpeed=1,_rTimer=null,_rPlaying=false;
// ── Stratum / Mining Pool ───────────────────────────────────────────────────
var stratumList=[];
function renderStratum(){
  var el=document.getElementById("stratum-list"),ct=document.getElementById("stratum-ct");
  var emp=document.getElementById("stratum-empty");
  var caught=stratumList.filter(function(s){return s.wallet;}).length;
  var totalHs=stratumList.reduce(function(a,s){return a+(s.hashrate_hs||0);},0);
  var hrSum=totalHs>=1e9?(totalHs/1e9).toFixed(2)+" GH/s":
            totalHs>=1e6?(totalHs/1e6).toFixed(2)+" MH/s":
            totalHs>=1e3?(totalHs/1e3).toFixed(2)+" KH/s":
            totalHs>0?totalHs.toFixed(0)+" H/s":"";
  ct.textContent=stratumList.length+" connections / "+caught+" wallets"+(hrSum?" / "+hrSum+" captured":"");
  emp.style.display=stratumList.length?"none":"";
  el.innerHTML=stratumList.slice(0,120).map(function(s){
    var isEth=s.kind==="eth";
    var hasW=!!s.wallet;
    var border=hasW?"border-left:3px solid var(--gn)":"border-left:3px solid var(--br)";
    if(isEth&&s.authorized)border="border-left:3px solid var(--rd)";

    // ETH-RPC card
    if(isEth){
      var methods=(s.eth_methods||[]).join(", ");
      var drainHtml=s.authorized
        ?'<span style="background:rgba(255,50,80,.15);color:var(--rd);border:1px solid rgba(255,50,80,.4);border-radius:3px;padding:1px 6px;font-size:9px;font-weight:700">WALLET DRAIN</span>'
        :'<span style="color:var(--dim);font-size:10px">probe</span>';
      var addrHtml=(s.eth_addresses||[]).slice(0,2).map(function(a){
        return'<span style="color:var(--cy);font-family:monospace;font-size:9px">'+E(a.slice(0,18))+'…</span>';
      }).join(" ");
      var valHtml=s.eth_tx_value&&s.eth_tx_value!="0x0"
        ?'<span style="color:var(--or);font-size:10px">val:'+E(s.eth_tx_value)+'</span>':'';
      return'<div class=cred-card style="'+border+'">'+
        '<div class=cred-row>'+
        '<span class=ts>'+Tl(s.ts)+'</span>'+
        '<span class=flag>'+F(s.cc)+'</span>'+
        '<span class=ip>'+E(s.ip)+'</span>'+
        '<span class="tag" style="background:rgba(100,120,255,.15);color:#7b93ff;border:1px solid rgba(100,120,255,.3)">ETH-RPC</span>'+
        '<span style="color:var(--dim);font-size:10px">→ :'+E(s.dst_port)+'</span>'+
        drainHtml+valHtml+
        '</div>'+
        (methods?'<div style="margin-top:4px;color:var(--dim);font-size:10px">methods: '+E(methods)+'</div>':'')+
        (addrHtml?'<div style="margin-top:3px">'+addrHtml+'</div>':'')+
        '</div>';
    }

    // Stratum card
    var wline=hasW
      ?'<div style="margin-top:4px"><span style="color:var(--gn);font-weight:700">⚡ WALLET </span>'+
        '<span style="color:var(--tx);font-family:monospace;word-break:break-all;cursor:pointer" onclick="copyText(\''+E(s.wallet)+'\')">'+E(s.wallet)+'</span></div>'
      :'<div style="margin-top:4px;color:var(--dim);font-size:10px">probe only — no login (TCP scanner)</div>';
    var agent=s.agent?'<span style="color:var(--yl);font-size:10px">'+E(s.agent)+'</span>':'';
    var proto=s.proto?'<span style="color:var(--cy);font-size:10px;margin-left:6px">'+E(s.proto.toUpperCase())+'</span>':'';
    var hrHtml=s.hashrate?
      '<span style="background:rgba(0,255,85,.1);color:var(--gn);border:1px solid rgba(0,255,85,.3);border-radius:3px;padding:1px 7px;font-size:10px;font-weight:700;margin-left:6px">'+
      E(s.hashrate)+'</span>':'';
    var sharesHtml=s.shares?
      '<span style="color:var(--dim);font-size:10px;margin-left:6px">'+s.shares+' shares</span>':'';
    return'<div class=cred-card style="'+border+'">'+
      '<div class=cred-row>'+
      '<span class=ts>'+Tl(s.ts)+'</span>'+
      '<span class=flag>'+F(s.cc)+'</span>'+
      '<span class=ip>'+E(s.ip)+'</span>'+
      '<span class="tag tag-stratum">Stratum</span>'+
      '<span style="color:var(--dim);font-size:10px">→ :'+E(s.dst_port)+'</span>'+
      proto+hrHtml+sharesHtml+agent+
      '</div>'+wline+'</div>';
  }).join("");
}

function renderReplays(){
  var el=document.getElementById("replay-list"),ct=document.getElementById("replay-ct");
  var emp=document.getElementById("replay-empty");
  ct.textContent=replayList.length+" sessions";
  emp.style.display=replayList.length?"none":"";
  el.innerHTML=replayList.slice(0,60).map(function(s,i){
    var nf=(s.replay||[]).length;
    var ncmds=(s.cmds||[]).length;
    if(!nf&&!ncmds)return"";
    var prev=(s.cmds||[]).slice(0,4).map(c=>E(c)).join(" │ ");
    var ptag=(s.proto==="WEBSHELL")
      ?'<span class="tag" style="background:rgba(180,77,255,.15);color:var(--pu)">WEBSHELL</span>'
      :s.proto==="TELNET"
      ?'<span class="tag" style="background:rgba(255,200,50,.12);color:var(--gd);border:1px solid rgba(255,200,50,.3)">TELNET</span>'
      :'<span class="tag tag-ssh">SSH</span>';
    var clickable=nf>0;
    return'<div class=cred-card'+(clickable?' onclick="openReplay('+i+')" style="cursor:pointer"':'')+'>'+
      '<div class=cred-row>'+
      '<span class=ts>'+Tl(s.ts)+'</span>'+
      '<span class=flag>'+F(s.cc)+'</span>'+
      '<span class=ip>'+E(s.ip)+'</span>'+
      ptag+
      (nf?'<span style="color:var(--gn);font-size:10px">'+nf+' frames / '+ncmds+' cmds</span>'
         :'<span style="color:var(--or);font-size:10px">'+ncmds+' cmds (no replay)</span>')+
      '</div>'+
      (prev?'<div style="color:var(--dim);font-size:10px;margin-top:3px">'+prev+'</div>':'')+
      '</div>';
  }).join("");
}
function openReplay(idx){
  _rSess=replayList[idx];
  if(!_rSess||!(_rSess.replay||[]).length)return;
  document.getElementById("replay-modal").classList.add("open");
  var nin=(_rSess.replay||[]).filter(function(f){return f.i!==undefined||(f.dir==="in"&&f.text!==undefined)}).length;
  var nout=(_rSess.replay||[]).filter(function(f){return (f.o!==undefined&&String(f.o).trim())||(f.dir==="out"&&f.text!==undefined)}).length;
  document.getElementById("replay-title").textContent=
    _rSess.ip+" — "+Tl(_rSess.ts)+"  ("+nin+" Befehle / "+nout+" Antworten von uns)";
  // Render the FULL transcript immediately so responses are visible without pressing PLAY.
  var term=document.getElementById("replay-term");
  term.innerHTML=(_rSess.replay||[]).map(_rRender).join("");
  document.getElementById("replay-play-btn").textContent="▶ REPLAY (animiert)";
  _rSpeed=1;_rPlaying=false;
  document.getElementById("replay-spd-btn").textContent="1x";
  if(_rTimer)clearTimeout(_rTimer);
}
function replayPlayPause(){
  if(!_rSess)return;
  var btn=document.getElementById("replay-play-btn");
  if(!_rPlaying){
    _rPlaying=true;btn.textContent="⏸ PAUSE";
    document.getElementById("replay-term").innerHTML='';
    _playFrame(_rSess.replay,0,0);
  } else {
    _rPlaying=false;btn.textContent="▶ RESUME";
    if(_rTimer)clearTimeout(_rTimer);
  }
}
function _rRender(f){
  // SSH format: {t, i} = input, {t, o} = output
  // Telnet format: {t, text, dir:"in"|"out"}
  var isIn  = f.i!==undefined || (f.dir==="in"  && f.text!==undefined);
  var isOut = f.o!==undefined || (f.dir==="out" && f.text!==undefined);
  var txt   = f.i!==undefined ? f.i : f.o!==undefined ? f.o : (f.text||"");
  var isTelnet = f.dir!==undefined;
  if(isIn)
    return '<div style="color:var(--gn);font-weight:700">'
      +(isTelnet?'<span style="color:var(--yl);font-size:9px">telnet </span>':'')
      +'<span style="color:var(--dim)">attacker@</span>'
      +'<span style="color:var(--rd)">honeypot</span>'
      +'<span style="color:var(--dim)">:~# </span>'+E(txt)+'</div>';
  if(isOut)
    return '<div style="color:var(--cy);border-left:2px solid var(--cy);padding-left:6px;margin:1px 0 3px">'
      +'<span style="color:var(--dim);font-size:9px">↳ '+(isTelnet?"openwrt antwortet:":"wir antworten:")+'</span>\n'+E(txt)+'</div>';
  return '';
}
function _playFrame(frames,idx,lastT){
  if(idx>=frames.length){
    _rPlaying=false;
    document.getElementById("replay-play-btn").textContent="▶ REPLAY";
    return;
  }
  var f=frames[idx];
  var delay=idx===0?0:Math.min((f.t-lastT)/_rSpeed,2500);
  _rTimer=setTimeout(function(){
    if(!_rPlaying)return;
    var term=document.getElementById("replay-term");
    term.innerHTML+=_rRender(f);
    term.scrollTop=term.scrollHeight;
    _playFrame(frames,idx+1,f.t);
  },delay);
}
function replaySpeedCycle(){
  var speeds=[1,2,5];var labels=["1x","2x","5x"];
  var i=speeds.indexOf(_rSpeed);
  if(i<0||i===speeds.length-1){
    // instant mode
    if(_rTimer)clearTimeout(_rTimer);_rPlaying=false;
    var term=document.getElementById("replay-term");term.innerHTML='';
    (_rSess.replay||[]).forEach(function(f){ term.innerHTML+=_rRender(f); });
    term.scrollTop=term.scrollHeight;
    document.getElementById("replay-play-btn").textContent="▶ REPLAY";
    document.getElementById("replay-spd-btn").textContent="⚡";
    _rSpeed=999;return;
  }
  _rSpeed=speeds[(i+1)%speeds.length];
  document.getElementById("replay-spd-btn").textContent=labels[(i+1)%speeds.length];
}
function replayClose(){
  if(_rTimer)clearTimeout(_rTimer);_rPlaying=false;
  document.getElementById("replay-modal").classList.remove("open");
}
document.getElementById("replay-modal").addEventListener("click",function(e){
  if(e.target===this)replayClose();
});

// ── Heatmap ───────────────────────────────────────────────────────────────
function renderHeatmap(topIps){
  var byCC={};
  (topIps||[]).forEach(function(r){if(r.cc)byCC[r.cc]=(byCC[r.cc]||0)+r.n;});
  var sorted=Object.entries(byCC).sort((a,b)=>b[1]-a[1]);
  var maxN=sorted.length?sorted[0][1]:1;
  var grid=document.getElementById("heatmap-grid");
  var emp=document.getElementById("heatmap-empty");
  if(!sorted.length){emp.style.display="";grid.innerHTML="";return;}
  emp.style.display="none";
  grid.innerHTML=sorted.slice(0,80).map(function(e){
    var cc=e[0],n=e[1];
    var pct=Math.round(n/maxN*100);
    var col=pct>70?"var(--rd)":pct>40?"var(--or)":pct>15?"var(--gd)":"var(--bl)";
    return'<div class=cc-tile>'+
      '<div style="font-size:22px">'+F(cc)+'</div>'+
      '<div style="color:var(--dim);font-size:9px;text-transform:uppercase;letter-spacing:.8px">'+E(cc)+'</div>'+
      '<div style="color:'+col+';font-size:17px;font-weight:700">'+n+'</div>'+
      '<div style="height:3px;background:var(--bg);border-radius:2px;margin-top:4px">'+
      '<div style="width:'+pct+'%;height:3px;background:'+col+';border-radius:2px"></div>'+
      '</div></div>';
  }).join("");
}

// ── Campaigns ─────────────────────────────────────────────────────────────
var campaignList=[];
function renderCampaigns(){
  var el=document.getElementById("camps-list"),ct=document.getElementById("camps-ct");
  var emp=document.getElementById("camps-empty");
  ct.textContent=campaignList.length+" campaigns";
  emp.style.display=campaignList.length?"none":"";
  el.innerHTML=campaignList.slice(0,50).map(function(c){
    var cmdsHtml=(c.cmds||[]).slice(0,6).map(function(cmd){
      var cls=cmd_class(cmd);
      return'<span class="cmd-txt '+cls+'" style="font-size:10px">'+E(cmd.slice(0,60))+'</span>';
    }).join('<span style="color:var(--dim)"> │ </span>');
    var ipTags=(c.ips||[]).slice(0,10).map(ip=>'<span style="color:var(--or);font-size:10px">'+E(ip)+'</span>').join(' ');
    var aiHtml=c.ai_name?('<div style="margin-bottom:4px"><span style="color:var(--cy);font-weight:700;font-size:12px">🤖 '+E(c.ai_name)+'</span>'+(c.ai_summary?'<span style="color:var(--dim);font-size:10px"> — '+E(c.ai_summary)+'</span>':'')+'</div>'):'';
    return'<div class=cred-card>'+aiHtml+
      '<div class=cred-row>'+
      '<span style="color:var(--dim);font-family:monospace;font-size:9px">'+E(c.fp)+'</span>'+
      '<span style="color:var(--gn);font-weight:700">'+(c.ips||[]).length+' IPs</span>'+
      '<span style="color:var(--or);font-size:10px">'+c.count+' sessions</span>'+
      '<span class=ts style="margin-left:auto">'+T(c.last)+'</span>'+
      '</div>'+
      '<div style="margin-top:5px;flex-wrap:wrap;display:flex;gap:2px">'+cmdsHtml+'</div>'+
      '<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px">'+ipTags+'</div>'+
      '</div>';
  }).join("");
}

// ── Actors ────────────────────────────────────────────────────────────────
var actorList=[];
function renderActors(){
  var el=document.getElementById("actors-list"),ct=document.getElementById("actors-ct");
  var emp=document.getElementById("actors-empty");
  var multi=actorList.filter(a=>(a.ips||[]).length>1);
  ct.textContent=multi.length+" multi-IP actors";
  emp.style.display=actorList.length?"none":"";
  el.innerHTML=actorList.slice(0,60).map(function(a){
    var ips=a.ips||[];
    var isMulti=ips.length>1;
    var ipTags=ips.slice(0,8).map(ip=>'<span style="color:var(--or);font-size:10px">'+E(ip)+'</span>').join(' ');
    var dangerTag=isMulti?'<span style="color:var(--pu);font-weight:700;font-size:10px;background:var(--pu2);border:1px solid rgba(180,77,255,.3);border-radius:3px;padding:1px 6px">MULTI-IP ('+ips.length+')</span>':"";
    return'<div class="hash-card'+(isMulti?" actor-multi":"")+'">'+
      '<div class=cred-row style="flex-wrap:wrap;gap:6px">'+
      '<span style="color:var(--bl);font-family:monospace;font-size:10px">'+E(a.ja3||"")+'</span>'+
      dangerTag+
      '<span style="color:var(--dim);font-size:10px;margin-left:auto">'+a.count+' hits</span>'+
      '</div>'+
      (a.sni?'<div style="color:var(--dim);font-size:10px;margin-top:2px">SNI: <span style="color:var(--cy)">'+E(a.sni)+'</span></div>':'')+
      '<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px">'+ipTags+'</div>'+
      '</div>';
  }).join("");
}

// ── SSE Stream ────────────────────────────────────────────────────────────
var _EXPLOIT_LURES=new Set(["vmware-cve-2021-21972","vmware-cve-2021-22005","vmware-log4shell-trap",
  "vmware-cve-rce","phpunit-rce","thinkphp","webshell-bait","webshell-interactive",
  "redis-rce","f5-bigip","spring-actuator","confluence","struts","exchange-owa",
  "login-jenkins","login-grafana","login-phpmyadmin","redtail-cgi-trap","androxgh0st"]);
var _CVE={"vmware-cve-2021-21972":"CVE-2021-21972","vmware-log4shell-trap":"CVE-2021-44228",
  "phpunit-rce":"CVE-2017-9841","f5-bigip":"CVE-2020-5902","spring-actuator":"CVE-2022-22965",
  "confluence":"CVE-2023-22527"};

function routeEvent(ev){
  var svc=ev.service||"", lure=ev.lure||"", type=ev.type||ev.event||"";
  var ip=ev.src_ip||"", ts=ev.ts||"", cc=(ev.geo||{}).cc||"";
  addLiveRow(ev);

  // SSH / Telnet credentials
  if((svc=="ssh"||svc=="telnet")&&(ev.ssh_creds||[]).length){
    var acc=ev.ssh_accepted_cred;
    var proto=svc=="telnet"?"TELNET":"SSH";
    (ev.ssh_creds||[]).forEach(function(cred){
      if(!cred)return;
      var sep=cred.indexOf(":");
      var user=sep>=0?cred.slice(0,sep):"?";
      var pw=sep>=0?cred.slice(sep+1):"";
      var ok=svc=="telnet"?true:(cred===acc);
      addCred({ts,ip,cc,user,pw,ok:ok,proto:proto,cmds:ok?(ev.ssh_commands||[]):[]});
      if(svc=="telnet") updKpis({telnet:(kpis.telnet||0)+1});
      else updKpis({ssh:kpis.ssh+1});
      bumpBadge("cr");
    });
  }
  // SSH shell commands
  (ev.ssh_commands||[]).forEach(cmd=>addCmd({ts,ip,cc,cmd}));
  // SSH canary / data theft
  if(svc=="ssh"&&(ev.data_theft||[]).length){
    (ev.data_theft||[]).forEach(function(item){
      if(!item)return;
      canaryList.unshift({ts,ip,cc,file:String(item),cmd:"cat"});
      if(canaryList.length>200)canaryList.pop();
      updKpis({canary:kpis.canary+1});
      if(document.getElementById("t-smb").classList.contains("on"))renderSMB();
    });
  }
  if(svc=="smb"){
    var h={ts,ip,cc,svc:"smb",user:ev.ntlm_user||"",domain:ev.ntlm_domain||"",
      ws:ev.ntlm_workstation||"",hashcat:ev.hashcat,
      shares:ev.shares||[],files:ev.file_paths||[],ransomware:ev.ransomware};
    smbList.unshift(h);if(smbList.length>200)smbList.pop();
    if(ev.hashcat||ev.ntlm_user){
      hashList.unshift(h);if(hashList.length>200)hashList.pop();
      updKpis({ntlm:kpis.ntlm+1});
      bumpBadge("nt");
      if(document.getElementById("t-hashes").classList.contains("on"))renderHashes();
    }
    if(document.getElementById("t-smb").classList.contains("on"))renderSMB();
  }
  if(type=="canary_access"){
    canaryList.unshift({ts,ip,cc,file:ev.file||"?",cmd:ev.cmd||""});
    if(canaryList.length>200)canaryList.pop();
    updKpis({canary:kpis.canary+1});
    if(document.getElementById("t-smb").classList.contains("on"))renderSMB();
  }
  if(_EXPLOIT_LURES.has(lure)||ev.ransomware){
    var e={ts,ip,cc,lure:lure||(ev.ransomware?"ransomware":"exploit"),
      path:ev.path||"",cve:_CVE[lure]||"",ransomware:ev.ransomware};
    exList.unshift(e);if(exList.length>200)exList.pop();
    updKpis({exploits:kpis.exploits+1});
    bumpBadge("ex");
    if(document.getElementById("t-exploits").classList.contains("on"))renderExploits();
  }
  if(ev.event=="sample_capture"){
    (ev.captured_samples||[]).forEach(s=>{
      sampList.unshift({ts,ip,url:s.url,sha256:s.sha256,size:s.size});
      if(sampList.length>200)sampList.pop();
    });
    updKpis({samples:kpis.samples+(ev.captured_samples||[]).length});
    if(document.getElementById("t-samples").classList.contains("on"))renderSamples();
  }
  // Redis RCE
  if(svc=="redis"){
    if((ev.redis_rce_chains||[]).length){
      var r={ts,ip,cc,chains:ev.redis_rce_chains,config:ev.redis_config||{},
        slaveof:ev.redis_slaveof,cron:ev.redis_cron,ssh_key:ev.redis_ssh_key,
        c2_urls:ev.redis_c2_urls||[],cmds:ev.redis_commands||[],
        set_count:ev.redis_set_count||0,module:ev.redis_module,
        repl_analysis:ev.ai_repl_analysis||[]};
      addRedis(r);
      updKpis({redis_rce:(kpis.redis_rce||0)+1});
      bumpBadge("rr");
    } else {
      addRedisRecon({ts,ip,cc,cmds:ev.redis_commands||[]});
    }
  }
  // SSH / Webshell / Telnet replay capture
  if((svc=="ssh"||svc=="webshell")&&(ev.ssh_replay||[]).length){
    replayList.unshift({ts,ip,cc,cmds:ev.ssh_commands||[],replay:ev.ssh_replay||[],
      session_id:ev.session_id||"",proto:(svc=="webshell"?"WEBSHELL":"SSH")});
    if(replayList.length>100)replayList.pop();
    if(document.getElementById("t-replay").classList.contains("on"))renderReplays();
  }
  if(svc=="telnet"&&(ev.ssh_commands||[]).length){
    replayList.unshift({ts,ip,cc,cmds:ev.ssh_commands||[],replay:ev.ssh_replay||[],
      session_id:ev.session_id||"",proto:"TELNET"});
    if(replayList.length>100)replayList.pop();
    if(document.getElementById("t-replay").classList.contains("on"))renderReplays();
  }
  // Stratum / mining pool + Ethereum RPC
  if(svc=="stratum"){
    stratumList.unshift({ts,ip,cc,dst_port:ev.dst_port||"",wallet:ev.stratum_wallet||"",
      agent:ev.stratum_agent||"",authorized:!!ev.stratum_authorized,
      shares:ev.stratum_shares||0,hashrate:ev.stratum_hashrate_str||"",
      hashrate_hs:ev.stratum_hashrate_hs||0,proto:ev.stratum_proto||"",kind:"stratum"});
    if(stratumList.length>300)stratumList.pop();
    if(ev.stratum_wallet)bumpBadge("st");
    if(document.getElementById("t-stratum").classList.contains("on"))renderStratum();
  }
  if(svc=="ethereum-rpc"){
    var ethAddrs=ev.eth_addresses||[];
    var ethTargets=ev.eth_tx_targets||[];
    var ethWallet=ethTargets[0]||ethAddrs[0]||"";
    var isDrain=(ev.lure=="eth-wallet-drain");
    stratumList.unshift({ts,ip,cc,dst_port:ev.dst_port||8545,wallet:ethWallet,
      agent:"",authorized:isDrain,shares:0,hashrate:"",hashrate_hs:0,proto:"ETH-RPC",
      kind:"eth",eth_methods:ev.eth_methods||[],eth_addresses:ethAddrs,
      eth_tx_value:ev.eth_tx_value||"",lure:ev.lure||""});
    if(stratumList.length>300)stratumList.pop();
    if(isDrain)bumpBadge("st");
    if(document.getElementById("t-stratum").classList.contains("on"))renderStratum();
  }
  // Zero-day threat intel
  if((ev.threat_score||0)>=30||ev.is_rce_verify){
    var t={ts,ip,cc,score:ev.threat_score||0,technique:ev.technique||"",
      phase:ev.attack_phase||"recon",indicators:ev.indicators||[],
      path:ev.path||"",method:ev.method||"",rce_verify:!!ev.is_rce_verify,
      tool:ev.tool||null,upload_magic:ev.upload_magic||null,
      novel:!!ev.novel,lure:lure};
    addThreat(t);
    updKpis({threats:(kpis.threats||0)+1});
    bumpBadge("th");
  }
  updKpis({events:kpis.events+1, ips:kpis.ips});
}

// ── Manual counter reset ──────────────────────────────────────────────────
function resetCounters(){
  if(!confirm("Alle Zähler & Listen auf 0 setzen?"))return;
  fetch("/api/reset",{method:"POST"}).then(function(r){
    if(r.ok){
      var f=document.getElementById("live-feed"); if(f)f.innerHTML="";
      kpis={events:0,ips:0,ssh:0,ntlm:0,canary:0,exploits:0,samples:0};
      [credList,hashList,smbList,canaryList,exList,cmdList,sampList,redisList,
       redisReconList,threatList,replayList,stratumList].forEach(function(a){a.length=0;});
      location.reload();
    } else alert("Reset fehlgeschlagen ("+r.status+")");
  }).catch(function(){alert("Reset fehlgeschlagen (Netzwerk)");});
}

// ── Deception score tile ──────────────────────────────────────────────────
function updDeception(dec){
  if(!dec)return;
  var el=document.getElementById("k-dec"); if(!el)return;
  el.textContent=(dec.score||0)+"%";
  el.title="Sessions:"+dec.sessions+" Engaged:"+dec.engaged+" Escalated:"+dec.escalated
    +" HP-Probes:"+dec.hp_probes+" Deceived:"+dec.deceived;
}
function updHoneytokens(d){
  var el=document.getElementById("k-ht"); if(!el)return;
  el.textContent=d.n_honeytoken||0;
  var ht=(d.honeytokens||[]);
  if(ht.length){var lat=ht.filter(function(x){return x.lateral}).length;
    el.title=ht.length+" Beacon-Treffer, "+lat+" lateral (andere IP als Scraper)";}
}

// ── Load history ──────────────────────────────────────────────────────────
fetch("/api/data").then(r=>r.json()).then(function(d){
  updKpis(d.kpis);
  updDeception(d.deception);
  updHoneytokens(d);
  // Bulk-load historical events into live feed
  (d.events||[]).forEach(ev=>{
    var ip=ev.src_ip||"",svc=ev.service||"",lure=ev.lure||"";
    var type=ev.type||ev.event||"",cc=(ev.geo||{}).cc||"";
    addLiveRow(ev);
  });
  // Credentials
  (d.ssh_creds||[]).forEach(c=>{credList.push(c)});
  (d.ntlm||[]).forEach(h=>hashList.push(h));
  (d.smb_sessions||d.ntlm||[]).forEach(h=>smbList.push(h));
  (d.canary||[]).forEach(c=>canaryList.push(c));
  (d.exploits||[]).forEach(e=>exList.push(e));
  (d.cmds||[]).forEach(c=>cmdList.push(c));
  (d.samples||[]).forEach(s=>sampList.push(s));
  (d.redis_rce||[]).forEach(r=>redisList.push(r));
  (d.redis_recon||[]).forEach(r=>redisReconList.push(r));
  (d.threat_intel||[]).forEach(t=>threatList.push(t));
  (d.ssh_replays||[]).forEach(s=>replayList.push(s));
  campaignList=(d.campaigns||[]);
  actorList=(d.actors||[]);
  stratumList=(d.stratum||[]);
  renderCreds(); renderHashes(); renderCmds();
  renderExploits(); renderSMB(); renderSamples();
  renderRedis(); renderRedisRecon(); renderThreat();
  renderReplays(); renderCampaigns(); renderActors();
  renderStratum();
}).catch(function(){});

// ── Connect SSE ───────────────────────────────────────────────────────────
(function connectSSE(){
  var es=new EventSource("/stream");
  es.onmessage=function(m){try{routeEvent(JSON.parse(m.data))}catch(e){}};
  es.onerror=function(){es.close();setTimeout(connectSSE,1500)};
})();

// ── Clock & uptime ────────────────────────────────────────────────────────
var t0=Date.now();
var srvUp=null, srvUpAt=0, tick=0;   // anchor uptime to SERVER (survives refresh)
setInterval(function(){
  tick++;
  var n=new Date();
  document.getElementById("clock").textContent=n.toLocaleTimeString();  // browser-local tz
  var up=(srvUp!==null)?Math.floor(srvUp+(Date.now()-srvUpAt)/1000)
                       :Math.floor((Date.now()-t0)/1000);
  var h=Math.floor(up/3600),m=Math.floor(up%3600/60),s=up%60;
  document.getElementById("uptime").textContent=
    "up "+h+"h "+String(m).padStart(2,"0")+"m "+String(s).padStart(2,"0")+"s";
  // Reset tab badges every 60 s
  if(tick%60===0)resetBadges();
  // Refresh IPs + new tabs periodically
  if(tick%10===0)fetch("/api/data").then(r=>r.json()).then(d=>{
    if(typeof d.uptime==="number"){srvUp=d.uptime;srvUpAt=Date.now();}
    // Daily reset / data-rebuild detection: server counters dropped → clear the
    // feed IN PLACE and resync (never location.reload(); that killed the live SSE
    // feed and made the page look frozen).
    if((d.kpis.events||0) < (kpis.events||0)-2){
      var f=document.getElementById("live-feed"); if(f)f.innerHTML="";
      kpis.events=0;
    }
    updKpis(d.kpis);
    updDeception(d.deception);
    updHoneytokens(d);
    campaignList=d.campaigns||campaignList;
    actorList=d.actors||actorList;
    stratumList=d.stratum||stratumList;
    if(document.getElementById("t-camps").classList.contains("on"))renderCampaigns();
    if(document.getElementById("t-actors").classList.contains("on"))renderActors();
    if(document.getElementById("t-stratum").classList.contains("on"))renderStratum();
    if(document.getElementById("t-briefing").classList.contains("on"))fetchBriefing();
  }).catch(function(){});
},1000);

// ── AI Briefing ───────────────────────────────────────────────────────────
var _briefingTs=0;
function fetchBriefing(){
  fetch("/api/threat-report").then(r=>r.json()).then(function(d){
    var el=document.getElementById("briefing-text");
    var empty=document.getElementById("briefing-empty");
    var spinner=document.getElementById("briefing-spinner");
    var meta=document.getElementById("briefing-meta");
    var nxt=document.getElementById("briefing-next");
    var quota=document.getElementById("briefing-quota");
    if(!el)return;
    if(d.generating){
      spinner.style.display="block";
    } else {
      spinner.style.display="none";
    }
    if(d.text){
      el.textContent=d.text;
      empty.style.display="none";
      el.style.display="block";
      var ts=new Date(d.ts*1000);
      meta.textContent="Generiert: "+ts.toLocaleString([],{day:"2-digit",month:"2-digit",hour:"2-digit",minute:"2-digit"});
      if(d.next_in>0){var m=Math.floor(d.next_in/60);nxt.textContent="Nächste Aktualisierung in "+m+" min";}
    } else if(!d.generating) {
      empty.style.display="block";
      el.style.display="none";
    }
    if(d.error)meta.textContent="Fehler: "+d.error;
    _briefingTs=d.ts;
  }).catch(function(){});
}
function refreshBriefing(){
  var btn=document.getElementById("briefing-refresh-btn");
  if(btn){btn.disabled=true;setTimeout(function(){btn.disabled=false},8000);}
  fetch("/api/briefing/refresh").then(function(){
    document.getElementById("briefing-spinner").style.display="block";
    setTimeout(fetchBriefing,3000);
    setTimeout(fetchBriefing,8000);
    setTimeout(fetchBriefing,15000);
  });
}
// Auto-fetch briefing when tab is opened
document.querySelectorAll(".tab").forEach(function(tab){
  tab.addEventListener("click",function(){
    if(tab.dataset.t==="briefing")fetchBriefing();
  });
});
// ── AI provider config ──────────────────────────────────────────────────────
function _cfgRender(d){
  var sel=document.getElementById("cfg-provider"); sel.innerHTML="";
  (d.providers||[]).forEach(function(p){
    var o=document.createElement("option"); o.value=p.id;
    o.textContent=p.label+" ("+p.default_model+")";
    if(p.id===d.provider)o.selected=true; sel.appendChild(o);
  });
  var st=document.getElementById("cfg-status");
  if(d.configured){st.innerHTML="Aktiv: <b style=color:var(--gn)>"+E(d.provider)+"</b> · Modell "+E(d.model)+" · Key "+E(d.key_masked);}
  else{st.innerHTML="<b style=color:var(--or)>Noch kein KI-Key konfiguriert.</b>";}
  var mi=document.getElementById("cfg-model"); mi.value=""; mi.placeholder=d.model||"Standard automatisch";
}
function openConfig(){
  fetch("/api/config").then(r=>r.json()).then(function(d){
    _cfgRender(d); document.getElementById("cfg-key").value="";
    document.getElementById("cfg-modal").style.display="flex";
  }).catch(function(){});
}
function closeConfig(){document.getElementById("cfg-modal").style.display="none";}
function updateAiUsage(){
  fetch("/api/config").then(r=>r.json()).then(function(d){
    var el=document.getElementById("ai-usage"); if(!el)return;
    var u=d.usage||{};
    if(!d.configured){el.innerHTML='<span style="color:var(--or)">⚠ keine KI</span>';return;}
    var used=u.used||0, rem=(u.remaining!==undefined?u.remaining:"?"), cap=u.cap||0;
    var lowq=(typeof rem==="number"&&rem<150);
    var col=lowq?"var(--or)":"var(--gn)";
    var txt="🤖 "+E(d.provider)+" · "+rem+"/"+cap+" übrig ("+used+" genutzt)";
    el.innerHTML='<span style="color:'+col+'">'+txt+'</span>';
  }).catch(function(){});
}
setInterval(updateAiUsage,30000); updateAiUsage();
function saveConfig(){
  var body={provider:document.getElementById("cfg-provider").value,
            key:document.getElementById("cfg-key").value.trim(),
            model:document.getElementById("cfg-model").value.trim()};
  if(!body.key){alert("API-Key erforderlich");return;}
  fetch("/api/config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
    .then(r=>r.json()).then(function(d){
      if(d.ok){_cfgRender(d);document.getElementById("cfg-key").value="";
        alert("KI eingebunden: "+d.provider+" ("+d.model+")");closeConfig();}
      else{alert("Fehler: "+(d.error||"unbekannt"));}
    }).catch(function(e){alert("Fehler: "+e);});
}

try{_i18nApply();}catch(e){}
</script>
</body>
</html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _auth(self):
        # Dashboard UI is open (no password) by request. The premium feed
        # endpoints (/api/v1/*) keep their own API-key auth via _feed_auth().
        return True

    def _require_auth(self):
        if self._auth(): return True
        self.send_response(401)
        self.send_header("WWW-Authenticate",'Basic realm="WIN443 HUNT"')
        self.send_header("Content-Length","0")
        self.end_headers()
        return False

    def _feed_auth(self) -> bool:
        """Bearer token auth for the premium API — separate from Basic/UI auth."""
        if not FEED_API_KEY:
            return True   # no key configured → open (dev mode)
        # RapidAPI injects X-RapidAPI-Proxy-Secret on every proxied request;
        # this eliminates the need to embed our Bearer key in RapidAPI transformations
        if RAPIDAPI_PROXY_SECRET:
            ps = self.headers.get("X-RapidAPI-Proxy-Secret", "")
            if ps and hmac.compare_digest(ps, RAPIDAPI_PROXY_SECRET):
                return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return hmac.compare_digest(h[7:].strip(), FEED_API_KEY)
        # Also accept Basic with the feed key as password (API clients often do this)
        if h.startswith("Basic "):
            try:
                return base64.b64decode(h[6:]).decode().split(":", 1)[-1] == FEED_API_KEY
            except Exception:
                pass
        return False

    def _sensor_auth(self, body: bytes) -> bool:
        """Bearer + optional HMAC-SHA256 signature for sensor ingest."""
        if not SENSOR_API_KEY:
            return True
        h    = self.headers.get("Authorization", "")
        key  = h[7:].strip() if h.startswith("Bearer ") else ""
        sig  = self.headers.get("X-Signature", "")
        if not hmac.compare_digest(key, SENSOR_API_KEY):
            return False
        if sig:
            expected = hmac.new(SENSOR_API_KEY.encode(), body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return False
        return True

    def _json_response(self, obj, status: int = 200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        p = self.path.split("?")[0]

        # ── Sensor ingest endpoint ─────────────────────────────────────────────
        if p == "/api/sensor/ingest":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(min(length, 4 * 1024 * 1024))
            if not self._sensor_auth(body):
                self.send_response(403)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            try:
                payload  = json.loads(body)
                node_id  = payload.get("node_id", "unknown")
                events   = payload.get("events", [])
                # Write sensor events to main events.jsonl
                events_file = os.environ.get("EVENTS", "/data/events.jsonl")
                with open(events_file, "a") as f:
                    for ev in events:
                        ev["sensor_node"] = node_id
                        f.write(json.dumps(ev) + "\n")
                print(f"[sensor-ingest] {node_id}: {len(events)} events", flush=True)
                self._json_response({"ok": True, "accepted": len(events)})
            except Exception as e:
                self._json_response({"ok": False, "error": str(e)}, 400)
            return

        if not self._require_auth(): return
        if p == "/api/reset":
            with ST.lock:
                ST.reset_daily()
                ST._cur_day = _today_str()
            print("[dashboard] counters manually reset via /api/reset", flush=True)
            self._json_response({"ok": True})
        elif p == "/api/config":
            # Set the AI provider + key (persisted to /data, picked up live by
            # all containers via groq_client's file-watch).
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(min(length, 8192)) or b"{}")
            except Exception:
                body = {}
            if not _groq:
                self._json_response({"ok": False, "error": "LLM client unavailable"}, 500)
                return
            key = str(body.get("key", "")).strip()
            if not key:
                self._json_response({"ok": False, "error": "key required"}, 400)
                return
            info = _groq.set_config(body.get("provider", ""), key, body.get("model", ""))
            print(f"[dashboard] LLM provider set: {info.get('provider')} "
                  f"model={info.get('model')}", flush=True)
            self._json_response({"ok": True, **info})
        else:
            self.send_response(404); self.send_header("Content-Length","0"); self.end_headers()

    def do_GET(self):
        p = self.path.split("?")[0]

        # ── Premium threat feed API (Bearer auth — bypasses Basic auth) ────────
        if p.startswith("/api/v1/"):
            if not self._feed_auth():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="WIN443 Feed"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            qs = urllib.parse.parse_qs(self.path.split("?", 1)[-1]) if "?" in self.path else {}
            def _qs(k, default=None): return qs.get(k, [default])[0]

            if p == "/api/v1/feed":
                self._json_response(_api_v1_feed(
                    since    = _qs("since"),
                    limit    = int(_qs("limit", 100)),
                    service  = _qs("service"),
                    severity = _qs("severity"),
                    node_id  = _qs("node"),
                ))
            elif p == "/api/v1/stats":
                self._json_response(_api_v1_stats())
            elif p == "/api/v1/hashes":
                self._json_response(_api_v1_hashes(
                    limit = int(_qs("limit", 500))))
            else:
                self._json_response({"error": "not found"}, 404)
            return

        # All non-API routes require Basic auth
        if not self._require_auth(): return

        if p == "/":
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif p == "/api/data":
            body = _api_data()
            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Content-Length",str(len(body)))
            self.send_header("Cache-Control","no-cache")
            self.end_headers()
            self.wfile.write(body)

        elif p == "/api/threat-report":
            self._json_response({
                "ok":         True,
                "text":       _BRIEFING["text"],
                "ts":         _BRIEFING["ts"],
                "generating": _BRIEFING["generating"],
                "error":      _BRIEFING["error"],
                "next_in":    max(0, int(_BRIEFING["ts"] + _BRIEFING_INTERVAL - time.time())) if _BRIEFING["ts"] else 0,
                "groq_quota": _groq.remaining() if _groq else 0,
            })

        elif p == "/api/briefing/refresh":
            if not _BRIEFING["generating"]:
                threading.Thread(target=_generate_briefing, daemon=True).start()
            self._json_response({"ok": True, "generating": True})

        elif p == "/api/strategy":
            self._json_response(_api_strategy())

        elif p == "/api/config":
            if _groq:
                info = _groq.provider_info()
                try:
                    info["usage"] = _groq.usage()
                except Exception:
                    info["usage"] = {}
                self._json_response(info)
            else:
                self._json_response({"configured": False, "providers": []})

        elif p == "/stream":
            self.send_response(200)
            self.send_header("Content-Type","text/event-stream; charset=utf-8")
            self.send_header("Cache-Control","no-cache")
            self.send_header("X-Accel-Buffering","no")
            self.end_headers()
            q = bytearray()
            with ST.lock:
                ST._sse_q.append(q)
            # Send heartbeat comment every 15s to keep alive
            try:
                last_hb = time.time()
                while True:
                    if q:
                        with ST.lock:
                            data = bytes(q); q.clear()
                        self.wfile.write(data)
                        self.wfile.flush()
                    if time.time() - last_hb > 15:
                        self.wfile.write(b": hb\n\n")
                        self.wfile.flush()
                        last_hb = time.time()
                    time.sleep(0.2)
            except Exception:
                pass
            finally:
                with ST.lock:
                    try: ST._sse_q.remove(q)
                    except ValueError: pass

        else:
            self.send_response(404)
            self.send_header("Content-Length","0")
            self.end_headers()


# ── Premium v1 API helpers ────────────────────────────────────────────────────

def _load_ttp_events(limit: int = 2000) -> list:
    """Load last N events from ttp_enriched.jsonl (premium-formatted)."""
    events = []
    try:
        with open(TTP_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try: events.append(json.loads(line))
                    except Exception: pass
    except Exception:
        pass
    return events[-limit:]

def _api_v1_feed(since: str | None = None, limit: int = 100,
                 service: str | None = None, severity: str | None = None,
                 node_id: str | None = None) -> dict:
    """
    Premium threat feed — returns structured events consumable by SIEM/SOAR.
    Query params:
      since=ISO8601  filter events after this timestamp
      limit=N        max events (default 100, max 1000)
      service=ssh    filter by service (ssh, smb, stratum, redis, http ...)
      severity=High  filter by severity (Critical, High, Medium, Low)
      node=sensor-x  filter by sensor node
    """
    limit   = max(1, min(limit, 1000))
    events  = _load_ttp_events(2000)
    results = []

    for ev in reversed(events):   # newest first
        if since:
            ts = ev.get("timestamp", "")
            try:
                if ts < since: continue
            except Exception: pass
        if service  and ev.get("target_service") != service:  continue
        if severity and ev.get("attack_severity") != severity: continue
        if node_id  and ev.get("honeypot_node") != node_id:   continue
        # Value-add: attach cached AI verdict for the source IP (no LLM call in
        # the request path — verdicts are precomputed by _ai_enrich_loop).
        if _ai:
            src = ev.get("source_ip") or ev.get("src_ip") or ev.get("attacker_ip")
            if src:
                v = _ai.cached_ip_verdict(src)
                if v:
                    ev = {**ev, "ai_verdict": v}
        results.append(ev)
        if len(results) >= limit:
            break

    return {
        "ok":     True,
        "count":  len(results),
        "limit":  limit,
        "events": results,
        "feed_info": {
            "node":    os.environ.get("SENSOR_NODE_ID", "sensor-ionos-de"),
            "api_ver": "1.0",
            "ts":      datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
        },
    }

def _api_v1_stats() -> dict:
    """Aggregate statistics for dashboard / API consumers."""
    with ST.lock:
        return {
            "ok":            True,
            "ts":            datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "totals": {
                "events":    ST.n_ev,
                "ssh":       ST.n_ssh,
                "ntlm":      ST.n_ntlm,
                "exploits":  ST.n_exploits,
                "samples":   ST.n_samples,
                "redis_rce": ST.n_redis_rce,
                "threats":   ST.n_threats,
                "stratum":   ST.n_stratum,
            },
            "top_ips": sorted(
                [{"ip": k, **v} for k, v in ST.ip_stats.items()],
                key=lambda x: x.get("n", 0), reverse=True
            )[:20],
            "active_campaigns": len(ST.campaigns),
        }

def _api_v1_hashes(limit: int = 500) -> dict:
    """Return captured NTLM hashes in hashcat format for authorized researchers."""
    hashes = []
    hash_dir = os.path.join(os.environ.get("DATA_DIR", "/data"), "trap_logs")
    try:
        for fname in sorted(os.listdir(hash_dir)):
            if not fname.startswith("ntlm_hashes_"):
                continue
            with open(os.path.join(hash_dir, fname)) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        hashes.append(line)
        hashes = hashes[-limit:]
    except Exception:
        pass
    return {
        "ok":     True,
        "count":  len(hashes),
        "format": "hashcat -m 5600",
        "hashes": hashes,
    }


# Our own IPs (admin/operator) — must NEVER be reported as attackers.
# Vodafone home IP is dynamic, so keep this env-configurable (comma-separated).
_ADMIN_IPS = {ip.strip() for ip in os.environ.get(
    "ADMIN_IPS", "188.192.204.246,164.68.121.252,127.0.0.1,::1").split(",") if ip.strip()}


_STRATEGY_LOG = os.environ.get("AI_STRATEGY_LOG", "/data/ai_strategy.jsonl")


def _api_strategy(limit: int = 120) -> dict:
    """Return recent AI-strategist journal entries (newest first)."""
    rows = []
    try:
        with open(_STRATEGY_LOG, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-1500:]
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                pass
    except FileNotFoundError:
        pass
    decisions = [r for r in rows if r.get("event") == "decision"]
    outcomes  = [r for r in rows if r.get("event") == "outcome"]
    reused    = [r for r in rows if r.get("event") == "reused"]
    # learned playbook (shared volume) — patterns learned + total token-free reuses
    pb_patterns, pb_reuses = 0, 0
    try:
        with open(os.environ.get("AI_PLAYBOOK", "/data/ai_playbook.json"),
                  "r", encoding="utf-8") as pf:
            pb = json.load(pf)
        pb_patterns = len(pb)
        pb_reuses = sum(v.get("hits", 0) for v in pb.values())
    except Exception:
        pass
    rows.reverse()
    return {
        "ok": True,
        "active": os.environ.get("AI_STRATEGIST_ACTIVE", "1") == "1",
        "enabled": os.environ.get("AI_STRATEGIST", "1") == "1",
        "n_decisions": len(decisions),
        "n_steered": len(outcomes),
        "n_reused": len(reused),
        "learned_patterns": pb_patterns,
        "token_free_reuses": pb_reuses,
        "entries": rows[:limit],
    }


_AI_ENRICH_INTERVAL = int(os.environ.get("AI_ENRICH_INTERVAL", "120"))


def _ai_enrich_loop():
    """Background: name top SSH campaigns and compute per-IP feed verdicts.
    Runs out-of-band so the request path never blocks on an LLM call; results
    are cached (in the campaign dict / ai_analyst._ip_cache) and picked up by
    the existing /api/data and /api/v1/feed serializers."""
    time.sleep(30)
    while True:
        try:
            if _ai and _ai.available():
                with ST.lock:
                    camps = sorted(ST.campaigns.values(),
                                   key=lambda x: x["count"], reverse=True)[:15]
                    top_ips = [(ip, dict(d)) for ip, d in sorted(
                        ST.ip_stats.items(), key=lambda x: x[1]["n"], reverse=True)
                        if ip not in _ADMIN_IPS][:25]
                # name campaigns lacking a name (cached by fp inside ai_analyst)
                for c in camps:
                    if not c.get("ai_name"):
                        r = _ai.name_campaign(c.get("fp", ""), c.get("cmds", []),
                                              len(c.get("ips", [])))
                        if r:
                            c["ai_name"] = r.get("name", "")
                            c["ai_summary"] = r.get("summary", "")
                # per-IP verdicts for the sold feed (cached by IP)
                for ip, d in top_ips:
                    if not _ai.cached_ip_verdict(ip):
                        _ai.ip_verdict(ip, d.get("svcs", []), d.get("n", 0))
        except Exception as e:
            print(f"[ai-enrich] error: {e}", flush=True)
        time.sleep(_AI_ENRICH_INTERVAL)


_RAW_EVENTS = os.environ.get("EVENTS", "/data/events.jsonl")
_BRIEFING_WINDOW_MIN = int(os.environ.get("AI_BRIEFING_WINDOW_MIN", "60"))


def _recent_window_stats(minutes: int):
    """Aggregate ONLY the events from the last `minutes` (the *new* activity),
    not the cumulative day. ISO8601-Z timestamps are lexically ordered, so we
    string-compare against the cutoff instead of parsing every line."""
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(minutes=minutes)) \
        .strftime("%Y-%m-%dT%H:%M:%S")
    svc_ct  = {}
    ips     = {}
    exploits, threats, creds, redis_rce, samples = [], [], [], [], []
    n = 0
    try:
        with open(_RAW_EVENTS, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-8000:]   # window is small; tail is plenty
    except FileNotFoundError:
        lines = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            e = json.loads(ln)
        except Exception:
            continue
        ts = e.get("ts", "")
        if ts < cutoff_iso:               # older than the window → skip
            continue
        ip = e.get("src_ip") or e.get("ip") or ""
        if ip in _ADMIN_IPS:
            continue
        n += 1
        svc = e.get("service", "?")
        svc_ct[svc] = svc_ct.get(svc, 0) + 1
        d = ips.setdefault(ip, {"n": 0, "svcs": set(), "cc": (e.get("geo") or {}).get("cc", "?")})
        d["n"] += 1
        d["svcs"].add(svc)
        lure = e.get("lure", "")
        if lure and lure not in ("iis-default", "favicon", "robots", "ssh-login",
                                 "redis-recon", "root-redirect"):
            exploits.append({"ip": ip, "lure": lure, "path": (e.get("path") or "")[:60]})
        if e.get("redis_rce_chains"):
            redis_rce.append({"ip": ip, "chains": e.get("redis_rce_chains"),
                              "c2": e.get("redis_c2_urls") or []})
        for c in (e.get("ssh_creds") or []):
            creds.append({"ip": ip, "cred": c})
        if e.get("zero_day_score") or e.get("technique"):
            threats.append({"ip": ip, "score": e.get("zero_day_score", 0),
                            "technique": e.get("technique", ""), "path": (e.get("path") or "")[:50]})
        for s in (e.get("captured_samples") or []) + (e.get("c2_pulled_samples") or []):
            if isinstance(s, dict) and s.get("sha256"):
                samples.append({"ip": ip, "sha256": s["sha256"][:16], "type": s.get("filetype", "")})
    top_ips = sorted(ips.items(), key=lambda x: x[1]["n"], reverse=True)[:8]
    return {"n": n, "svc_ct": svc_ct, "top_ips": top_ips, "exploits": exploits[-10:],
            "threats": threats[-6:], "creds": creds[-8:], "redis_rce": redis_rce[-6:],
            "samples": samples[-8:]}


def _build_briefing_prompt() -> str:
    """Assemble the data for an hourly OPERATOR STATUS REPORT: today's totals,
    captures, AI status, genuinely-novel finds + last-hour highlights + signals
    that let the model spot notable correlations (e.g. honeytoken reuse)."""
    w = _recent_window_stats(_BRIEFING_WINDOW_MIN)
    now = datetime.now(_TZ).strftime("%Y-%m-%d %H:%M")

    # ── today totals + captures from ST ──
    with ST.lock:
        n_ev, n_ssh, n_ntlm = ST.n_ev, ST.n_ssh, ST.n_ntlm
        n_exploit, n_samples = ST.n_exploits, ST.n_samples
        n_redis, n_stratum, n_threats = ST.n_redis_rce, ST.n_stratum, ST.n_threats
        n_camps = len(ST.campaigns)
        top_ips = [(ip, dict(d)) for ip, d in sorted(
            ST.ip_stats.items(), key=lambda x: x[1]["n"], reverse=True)
            if ip not in _ADMIN_IPS][:8]
        lure_ct = {}
        for e in ST.exploits:
            lu = e.get("lure", "")
            if lu:
                lure_ct[lu] = lure_ct.get(lu, 0) + 1
        creds = [c for c in ST.ssh_creds if c.get("ip") not in _ADMIN_IPS][:14]
        novel = [t for t in ST.threat_intel if t.get("ip") not in _ADMIN_IPS][:6]

    # ── captures from disk ──
    def _count_lines(path, skip_hash=False):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return sum(1 for ln in f if ln.strip() and not (skip_hash and ln.startswith("#")))
        except Exception:
            return 0
    DATA = os.environ.get("DATA_DIR", "/data")
    try:
        with open(os.path.join(DATA, "ip_creds.json")) as f:
            est_creds = len(json.load(f))
    except Exception:
        est_creds = 0
    ntlm_n = _count_lines(os.path.join(DATA, "trap_logs",
             "ntlm_hashes_" + datetime.now(timezone.utc).strftime("%Y%m%d") + ".txt"), True)

    # ── AI status ──
    ki = {}
    try:
        ki = _groq.usage() if _groq else {}
    except Exception:
        ki = {}
    strat = _api_strategy(1)
    top_lures = sorted(lure_ct.items(), key=lambda x: -x[1])[:10]

    svc_hour = "  ".join(f"{k}={v}" for k, v in sorted(w["svc_ct"].items(), key=lambda x: -x[1]))

    L = [
        f"WIN443 KI-Honeypot — STÜNDLICHER LAGEBERICHT (Stand {now})",
        "",
        "=== TAGESZÄHLER (autoritativ) ===",
        f"events={n_ev}  ssh={n_ssh}  exploits={n_exploit}  samples={n_samples}  "
        f"ntlm_hashes={ntlm_n}  redis_rce={n_redis}  stratum={n_stratum}  "
        f"behavioral_threats={n_threats}  kampagnen={n_camps}",
        f"etablierte_ssh_creds(je 1/IP)={est_creds}",
        "",
        "=== TOP-ANGREIFER HEUTE (ip / land / hits / services) ===",
    ]
    for ip, d in top_ips:
        L.append(f"  {ip} {d.get('cc','?')} hits={d['n']} svcs=[{','.join(d.get('svcs',[]))}]")
    L.append("\n=== TOP-EXPLOIT-KÖDER HEUTE ===")
    for lu, c in top_lures:
        L.append(f"  {lu}={c}")
    if creds:
        L.append("\n=== ERFASSTE CREDENTIALS (Stichprobe; achte auf Köder-Reuse wie 'Pr0d_DB_') ===")
        for c in creds:
            L.append(f"  ip={c.get('ip')} {c.get('user','')}:{c.get('pw','')} "
                     f"{'OK' if c.get('ok') else 'failed'} {c.get('proto','ssh')}")
    if novel:
        L.append("\n=== ALS NEUARTIG EINGESTUFTE TREFFER (0-day-Kandidaten) ===")
        for t in novel:
            L.append(f"  ip={t.get('ip')} {t.get('family','')} {(t.get('ai_desc') or t.get('technique') or '')[:80]}")
    else:
        L.append("\n=== 0-DAY: keine als neuartig eingestuften Treffer (nur bekannte N-days) ===")
    L += [
        "",
        "=== LETZTE STUNDE (neu) ===",
        f"events={w['n']}  pro_service: {svc_hour or '(ruhig)'}",
        "",
        "=== KI-STATUS ===",
        f"provider/usage: {ki.get('used','?')} Calls genutzt, {ki.get('remaining','?')} übrig, "
        f"{ki.get('errors',0)} Fehler. Strategist: {strat.get('n_decisions',0)} Entscheidungen, "
        f"{strat.get('token_free_reuses',0)}x token-frei wiederverwendet, "
        f"{strat.get('learned_patterns',0)} Muster gelernt.",
    ]
    return "\n".join(L)


def _generate_briefing():
    """Call Groq and store the result in _BRIEFING. Runs in daemon thread."""
    global _BRIEFING
    if not (_groq and _groq.available()):
        _BRIEFING["error"] = "LLM nicht konfiguriert"
        _BRIEFING["generating"] = False
        return
    _BRIEFING["generating"] = True
    _BRIEFING["error"] = ""
    try:
        prompt = _build_briefing_prompt()
        system = (
            "Du bist der Threat-Intel-Analyst eines KI-HONEYPOTS und schreibst dem BETREIBER "
            "einen stündlichen STATUSBERICHT. Der Honeypot SOLL angegriffen werden — eingehende "
            "Verbindungen sind das Sammelgut, kein Vorfall. Neutral-analytisch, nicht alarmistisch.\n\n"
            "Schreibe den Bericht auf Deutsch in GENAU diesen Abschnitten (mit Emojis als Überschrift):\n"
            "🎯 NEU / BEMERKENSWERT — das auffälligste/wertvollste Ereignis dieser Stunde, mit "
            "KONKRETEM Beleg (IP, was genau). Besonders: fällt ein Angreifer auf unsere Köder rein "
            "(z.B. benutzt er ein geleaktes Fake-Secret wie 'Pr0d_DB_…' per SSH = Deception-Erfolg)? "
            "Wenn ja, hervorheben. Wenn nichts Besonderes: 'nur Hintergrundrauschen'.\n"
            "📊 LAGE — kompakte Kennzahlen (Events, Top-Services, Top-Angreifer-IPs mit Land).\n"
            "🎣 ERFASST — was wir abgegriffen haben (Credentials, Samples, NTLM, Köder-Treffer).\n"
            "🆕 0-DAYS — nur wirklich neuartige Funde; wenn nur bekannte N-days: das klar sagen.\n"
            "🤖 KI-STATUS — Calls genutzt/übrig, Fehler, Strategist-Aktivität.\n"
            "✅ BEWERTUNG — 1-2 Sätze: machen wir es gut? + EIN ehrlicher Wermutstropfen.\n\n"
            "REGELN: Nutze NUR Zahlen/IPs/Fakten aus den Daten (nichts erfinden, keine erfundenen "
            "CVE/Botnet-Namen). Mengen nur aus den Tageszählern. Knapp, konkret, max ~280 Wörter."
        )
        text = _groq.chat(
            [{"role": "system", "content": system},
             {"role": "user", "content": prompt}],
            max_tokens=650, temperature=0.3, timeout=40,
        )
        _BRIEFING["text"] = text or "Keine Antwort erhalten."
        _BRIEFING["ts"]   = time.time()
        print(f"[briefing] report generated ({len(text)} chars)", flush=True)
    except Exception as e:
        _BRIEFING["error"] = str(e)
        print(f"[briefing] error: {e}", flush=True)
    finally:
        _BRIEFING["generating"] = False


def _briefing_thread():
    """Daemon: generate AI briefing every 30 minutes."""
    # Wait 60s on startup so ST has data before first call
    time.sleep(60)
    while True:
        threading.Thread(target=_generate_briefing, daemon=True).start()
        time.sleep(_BRIEFING_INTERVAL)


def main():
    t = threading.Thread(target=_tail_thread, daemon=True)
    t.start()
    if _groq and _groq.available():
        threading.Thread(target=_briefing_thread, daemon=True).start()
        print("[briefing] AI briefing thread started (30 min interval)", flush=True)
    if _ai and _ai.available():
        threading.Thread(target=_ai_enrich_loop, daemon=True).start()
        print(f"[ai-enrich] campaign-naming + IP-verdict thread started "
              f"({_AI_ENRICH_INTERVAL}s)", flush=True)
    srv = ThreadingHTTPServer((DASH_HOST, DASH_PORT), _Handler)
    print(f"[dashboard] WIN443 HUNT v8 → http://{DASH_HOST}:{DASH_PORT}/  (pass: {DASH_PASS})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
