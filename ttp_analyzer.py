"""
TTP Analyzer — post-session intelligence enrichment for monetization.

Transforms raw honeypot events into premium threat intelligence:
  - MITRE ATT&CK technique tagging (T-numbers + tactic names)
  - APT / threat-actor attribution via behavioral fingerprinting
  - Attack severity scoring (Critical / High / Medium / Low)
  - Async LLM behavioral summary (non-blocking)
  - Premium JSON format compatible with commercial threat feeds

Runs async AFTER session close — never in the capture hot-path.
Output written to /data/ttp_enriched.jsonl and accessible via /api/v1/feed.
"""

import os, re, json, time, threading, queue
from datetime import datetime, timezone

try:
    import persona as _persona
except Exception:
    _persona = None

DATA_DIR      = os.environ.get("DATA_DIR", "/data")
ENRICHED_FILE = os.path.join(DATA_DIR, "ttp_enriched.jsonl")
NODE_ID       = os.environ.get("SENSOR_NODE_ID", "sensor-ionos-de")


# ── MITRE ATT&CK pattern map ──────────────────────────────────────────────────
# Each entry: (tech_id, tactic, display_name, regex_pattern)
_MITRE = [
    ("T1110.001", "credential-access",    "Brute Force: Password Guessing",
     r"password.*spray|brute.*force|multiple.*auth|credential.*stuff"),
    ("T1059.004", "execution",            "Command and Scripting: Unix Shell",
     r"bash\s+-c|/bin/(sh|bash|dash)|cmd\.exe\s+/c"),
    ("T1059.001", "execution",            "Command and Scripting: PowerShell",
     r"powershell|IEX\s|Invoke-Expression|Invoke-WebRequest|FromBase64String"),
    ("T1105",     "command-and-control",  "Ingress Tool Transfer",
     r"wget\s+http|curl\s+http|tftp\s+|bitsadmin.*\/transfer|certutil.*-url"),
    ("T1496",     "impact",               "Resource Hijacking",
     r"xmrig|stratum\+tcp|minerd|cpuminer|xmr\.nanopool|monero|hashrate"),
    ("T1003.001", "credential-access",    "OS Credential Dumping: LSASS",
     r"lsass|mimikatz|sekurlsa|procdump|ntds\.dit"),
    ("T1003.002", "credential-access",    "OS Credential Dumping: SAM",
     r"\bsamr\b|sam.*dump|reg.*save.*sam|impacket.*secretsdump"),
    ("T1543.003", "persistence",          "Create/Modify: Windows Service",
     r"RCreateService|svcctl.*create|sc\.exe.*create.*binpath"),
    ("T1053.003", "persistence",          "Scheduled Task: Cron",
     r"crontab.*-l|/etc/cron\.|echo.*crontab|cron.*wget"),
    ("T1136.001", "persistence",          "Create Account: Local Account",
     r"useradd|adduser|net\s+user.*\/add"),
    ("T1548.001", "privilege-escalation", "Setuid/Setgid",
     r"chmod\s+[46][0-7][0-7][0-7]|chmod\s+\+s\s"),
    ("T1562.001", "defense-evasion",      "Disable Security Tools",
     r"systemctl.*stop.*(fail2ban|ufw|iptables)|ufw\s+disable|setenforce\s+0"),
    ("T1082",     "discovery",            "System Information Discovery",
     r"\buname\s+-a|\bsysteminfo\b|\bwhoami\b|\bid\s*;|\bhostname\b"),
    ("T1083",     "discovery",            "File and Directory Discovery",
     r"ls\s+-la|find\s+/\s+-name|dir\s+/s|get-childitem"),
    ("T1190",     "initial-access",       "Exploit Public-Facing Application",
     r"CVE-\d{4}-\d{4,}|jndi:|ognl|struts|log4j|shellshock|eternalblue"),
    ("T1071.001", "command-and-control",  "C2: Web Protocols",
     r"gate\.php|check\.php|beacon|c2.*http|panel.*php"),
    ("T1078",     "defense-evasion",      "Valid Accounts",
     r"valid.*cred|pass-the-hash|pth\b|ntlm.*relay"),
    ("T1560",     "collection",           "Archive Collected Data",
     r"tar\s+-cz|zip.*-r|7z\s+a\s"),
    ("T1486",     "impact",               "Data Encrypted for Impact",
     r"openssl.*-aes|gpg.*-e\s|\.locked$|\.encrypted$|ransom"),
    ("T1018",     "discovery",            "Remote System Discovery",
     r"masscan|nmap\s+-sS|arp\s+-a|net\s+view"),
    ("T1021.002", "lateral-movement",     "SMB/Windows Admin Shares",
     r"\\\\.*\\\w+\$|net\s+use\s+\\\\|smbclient"),
    ("T1558.003", "credential-access",    "Kerberoasting",
     r"kerberoast|GetUserSPNs|impacket.*GetTGT"),
    ("T1055",     "defense-evasion",      "Process Injection",
     r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|shellcode"),
    ("T1027",     "defense-evasion",      "Obfuscated Files or Information",
     r"-enc(odedcommand)?\\s+[A-Za-z0-9+/]{20}|base64.*decode|gzip.*decompress"),
]

_MITRE_COMPILED = [(tid, tac, name, re.compile(pat, re.I))
                   for tid, tac, name, pat in _MITRE]


# ── APT / Threat Actor fingerprints ──────────────────────────────────────────
_APT = {
    "TeamTNT": {
        "patterns": [r"teamtnt", r"weave.*scope", r"kube-hunter",
                     r"masscan.*6379", r"alpinelinux.*xmrig", r"purplefox"],
        "desc":     "Cloud-targeting cryptomining group; Docker/K8s + XMRig",
        "ttp":      ["T1496", "T1078", "T1562.001"],
        "intel_url":"https://www.trendmicro.com/en_us/research/20/i/teamtnt.html",
    },
    "8220 Gang": {
        "patterns": [r"8220|mdrfckr", r"pool\.(minexmr|supportxmr|hashvault)\.pro",
                     r"poolm\.sh", r"crontab.*wget.*\.sh"],
        "desc":     "High-volume cryptomining botnet; targets exposed APIs",
        "ttp":      ["T1496", "T1190", "T1053.003"],
        "intel_url":"https://unit42.paloaltonetworks.com/8220-gang-cloud-botnet",
    },
    "ROCKE": {
        "patterns": [r"pastebin\.com.*raw", r"github\.com.*raw.*\.sh",
                     r"masscan", r"xmrig.*pool\.hashvault"],
        "desc":     "Chinese cloud-targeting cryptomining; fileless techniques",
        "ttp":      ["T1496", "T1105", "T1059.004"],
        "intel_url":"https://www.talosintelligence.com/rocke",
    },
    "RedTail": {
        "patterns": [r"redtail", r"cdn\.discordapp\.com.*linux",
                     r"CVE-2024-3400", r"CVE-2023-46805"],
        "desc":     "Sophisticated cryptominer; PAN-OS/Ivanti N-day exploitation",
        "ttp":      ["T1190", "T1496", "T1027"],
        "intel_url":"https://www.elastic.co/security-labs/redtail",
    },
    "Sysrv": {
        "patterns": [r"sysrv", r"solr.*cmd=", r"xmlrpc.*wp\-cron",
                     r"ethminer", r"\.sysrv"],
        "desc":     "Multi-exploit botnet; web vuln scanning + cryptomining",
        "ttp":      ["T1190", "T1021.002", "T1496"],
        "intel_url":"https://www.lacework.com/blog/sysrv-botnet",
    },
    "Kinsing": {
        "patterns": [r"kdevtmpfsi|kinsing", r"purge.*crontab",
                     r"docker\.sock", r"nsenter.*-t\s1"],
        "desc":     "Container-targeting malware; Docker API exploitation",
        "ttp":      ["T1610", "T1496", "T1562.001"],
        "intel_url":"https://www.trendmicro.com/en_us/research/20/a/kinsing.html",
    },
    "Mirai": {
        "patterns": [r"/bin/busybox\s+MIRAI", r"ECCHI", r"selfrep.*telnet",
                     r"watchdog.*disable"],
        "desc":     "IoT botnet; credential brute-force + DDoS",
        "ttp":      ["T1110.001", "T1498"],
        "intel_url":"https://www.incapsula.com/blog/malware-analysis-mirai-ddos-botnet.html",
    },
    "Muhstik": {
        "patterns": [r"muhstik", r"irc.*\b6667\b", r"drupal.*rce",
                     r"redis.*config.*set.*dir", r"log4j.*jndi"],
        "desc":     "Botnet targeting CVEs for DDoS + cryptomining",
        "ttp":      ["T1190", "T1496", "T1021.002"],
        "intel_url":"https://unit42.paloaltonetworks.com/muhstik-botnet",
    },
    "Lazarus Group": {
        "patterns": [r"cryptocurrency.*exchange", r"bitsadmin.*\/transfer",
                     r"powershell.*-enc.*download", r"AppleSeed|Manuscrypt"],
        "desc":     "DPRK APT; crypto exchange targeting, financial theft",
        "ttp":      ["T1566", "T1059.001", "T1041"],
        "intel_url":"https://attack.mitre.org/groups/G0032/",
    },
}
_APT_COMPILED = {
    name: ([re.compile(p, re.I) for p in cfg["patterns"]], cfg)
    for name, cfg in _APT.items()
}


# ── CVE signatures for zero_day_detector integration ─────────────────────────
CVE_SIGNATURES = [
    ("CVE-2021-44228", re.compile(r"\$\{jndi:", re.I),                    "Log4Shell RCE"),
    ("CVE-2024-3400",  re.compile(r"/api/(?:versions|v1/)?utils/login",re.I), "PAN-OS Auth Bypass"),
    ("CVE-2023-46747", re.compile(r"/mgmt/tm/util/bash|iControl",re.I),   "F5 BIG-IP RCE"),
    ("CVE-2022-1388",  re.compile(r"X-F5-Auth-Token|/mgmt/shared",re.I),  "F5 iControl Auth Bypass"),
    ("CVE-2023-22527", re.compile(r"/template/error|confluence.*ognl",re.I),"Confluence RCE"),
    ("CVE-2024-21762", re.compile(r"/remote/login.*tunnel|FortiGate",re.I),"FortiOS SSL-VPN RCE"),
    ("CVE-2023-49103", re.compile(r"/apps/graphapi/api/v1\.0/\$metadata",re.I),"ownCloud Info Disclosure"),
    ("CVE-2017-5638",  re.compile(r"Content-Type.*%22ognl|multipart.*redirect",re.I),"Struts2 RCE"),
    ("CVE-2017-0144",  re.compile(r"EternalBlue|SMB.*MS17-010|\xffSMB\x25",re.I),"EternalBlue MS17-010"),
    ("CVE-2019-0708",  re.compile(r"BlueKeep|MS_T120|\\x03\\x00\\x00",re.I),"BlueKeep RDP RCE"),
    ("CVE-2022-30190", re.compile(r"ms-msdt:|msdt\.exe|MSDT",re.I),       "Follina MSDT RCE"),
    ("CVE-2023-34362", re.compile(r"/human\.aspx|MOVEit",re.I),           "MOVEit Transfer SQLi"),
]


# ── Severity scoring ──────────────────────────────────────────────────────────

def calculate_severity(event: dict, mitre_tags: list, apt_match: str | None) -> str:
    score = 0
    service = event.get("service", "")

    # Critical indicators
    if event.get("novel"):               score += 50
    if event.get("ransomware"):          score += 60
    if event.get("attack_phase") == "ransomware": score += 60
    if event.get("captured_samples"):    score += 30
    if apt_match:                        score += 35

    # High-value data captured
    if event.get("hashcat"):             score += 40
    if event.get("ntlm_user"):           score += 30
    if event.get("wallets"):             score += 25
    if event.get("c2_urls"):             score += 20

    # Service activity
    if service == "smb":
        if event.get("pipe_rpc_calls"): score += 25
        if event.get("file_paths"):     score += 15
        if event.get("writes"):         score += 20
    elif service == "ssh":
        cmds = event.get("commands", [])
        if cmds:                        score += 10 + min(len(cmds) * 2, 20)
    elif service == "stratum":
        if event.get("wallet"):         score += 25
    elif service in ("redis", "redis-honeypot"):
        rce = event.get("rce_chains", [])
        if rce:                         score += 35

    # Exploit phase
    phase = event.get("attack_phase", "")
    if phase in ("data-theft", "post-exploit"): score += 20
    if phase == "exploit":                      score += 30

    # Anomaly
    anomaly = event.get("anomaly_score", 0)
    if anomaly >= 80: score += 25
    elif anomaly >= 60: score += 10

    # MITRE count bonus
    score += min(len(mitre_tags) * 5, 25)

    if score >= 80: return "Critical"
    if score >= 50: return "High"
    if score >= 25: return "Medium"
    return "Low"


# ── Core analysis ─────────────────────────────────────────────────────────────

def _event_to_blob(event: dict) -> str:
    """Flatten an event to a searchable text blob."""
    parts = []
    for k, v in event.items():
        if isinstance(v, str):   parts.append(v)
        elif isinstance(v, list):parts.extend(str(x) for x in v)
        elif isinstance(v, dict):parts.extend(str(x) for x in v.values())
    return " ".join(parts)

def tag_mitre(blob: str) -> list[dict]:
    hits = []
    seen = set()
    for tid, tac, name, rx in _MITRE_COMPILED:
        if tid not in seen and rx.search(blob):
            hits.append({"id": tid, "tactic": tac, "name": name})
            seen.add(tid)
    return hits

def tag_apt(blob: str) -> tuple[str | None, dict | None]:
    best_name, best_cfg, best_hits = None, None, 0
    for name, (patterns, cfg) in _APT_COMPILED.items():
        hits = sum(1 for rx in patterns if rx.search(blob))
        if hits > best_hits:
            best_name, best_cfg, best_hits = name, cfg, hits
    if best_hits >= 2:
        return best_name, best_cfg
    return None, None

def tag_cve(blob: str) -> list[str]:
    hits = []
    for cve_id, rx, _ in CVE_SIGNATURES:
        if rx.search(blob):
            hits.append(cve_id)
    return hits

def _behavioral_tags(event: dict, mitre_tags: list) -> list[str]:
    tags = []
    service = event.get("service", "")
    cmds    = event.get("commands", [])

    tags.append("automated-scan")
    if event.get("hashcat"):         tags.append("ntlm-hash-captured")
    if event.get("ntlm_user"):       tags.append("ntlm-auth")
    if event.get("ransomware"):      tags.append("ransomware-behavior")
    if event.get("pipe_rpc_calls"):  tags.append("lateral-movement")
    if event.get("wallets"):         tags.append("crypto-wallet-detected")
    if event.get("c2_urls"):         tags.append("c2-url-extracted")
    if event.get("captured_samples"):tags.append("malware-sample")
    if event.get("novel"):           tags.append("novel-exploit")

    # Command-level tags
    cmd_blob = " ".join(str(c) for c in cmds)
    if re.search(r"xmrig|miner|stratum", cmd_blob, re.I): tags.append("cryptominer")
    if re.search(r"wget|curl|tftp", cmd_blob, re.I):      tags.append("dropper")
    if re.search(r"masscan|nmap",   cmd_blob, re.I):      tags.append("internal-scan")
    if re.search(r"chmod\s+\+x|chmod\s+777", cmd_blob, re.I): tags.append("privilege-change")
    if re.search(r"crontab|/etc/cron", cmd_blob, re.I):   tags.append("persistence-cron")

    if service == "ssh" and not cmds:  tags.append("ssh-probe-no-commands")
    if service == "smb":               tags.append("smb-attack")
    if service == "stratum":           tags.append("mining-pool-hijack")
    if service in ("redis", "redis-honeypot"): tags.append("redis-attack")

    for m in mitre_tags:
        if m["tactic"] == "credential-access": tags.append("credential-theft")
        if m["tactic"] == "impact":            tags.append("destructive-action")

    return sorted(set(tags))


def analyze(event: dict) -> dict:
    """
    Synchronous TTP analysis — runs in background thread after session close.
    Returns the ttp_enrichment dict to merge into the event.
    """
    blob         = _event_to_blob(event)
    mitre_tags   = tag_mitre(blob)
    cves         = tag_cve(blob)
    apt_name, apt_cfg = tag_apt(blob)
    severity     = calculate_severity(event, mitre_tags, apt_name)
    beh_tags     = _behavioral_tags(event, mitre_tags)

    # CVEs from event itself
    ev_cve = event.get("cve") or ""
    if ev_cve and ev_cve not in cves:
        cves.insert(0, ev_cve)

    enrichment = {
        "severity":       severity,
        "mitre_tags":     mitre_tags,
        "cves_targeted":  cves,
        "behavioral_tags":beh_tags,
        "apt_match":      apt_name,
        "apt_desc":       apt_cfg["desc"] if apt_cfg else None,
        "llm_summary":    None,        # filled by async worker below
        "confidence":     None,
        "analyzed_at":    datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
    }
    return enrichment


# ── LLM async summary worker ─────────────────────────────────────────────────

_llm_queue: queue.Queue = queue.Queue(maxsize=50)

def _llm_worker():
    while True:
        try:
            ev, enr, cb = _llm_queue.get(timeout=5)
        except queue.Empty:
            continue
        try:
            if _persona is None:
                cb(enr); continue

            service  = ev.get("service", "?")
            ip       = ev.get("src_ip", "?")
            mitre    = ", ".join(m["id"] for m in enr["mitre_tags"]) or "none"
            apt      = enr["apt_match"] or "unknown"
            phase    = ev.get("attack_phase", ev.get("technique", ""))
            cmds     = "; ".join(str(c) for c in ev.get("commands", [])[:5])
            beh_tags = ", ".join(enr["behavioral_tags"][:6])

            prompt = (
                f"You are a threat analyst. Analyze this honeypot event in 2 sentences. "
                f"Be specific about what the attacker was trying to achieve.\n"
                f"Service: {service}, IP: {ip}, Severity: {enr['severity']}\n"
                f"MITRE: {mitre}, APT-match: {apt}, Phase: {phase}\n"
                f"Commands: {cmds or 'none'}\n"
                f"Behavioral tags: {beh_tags}\n"
                f"Write a concise analyst summary (max 2 sentences, no markdown):"
            )
            summary = _persona.llm_generate(prompt, num_predict=120, timeout=20)
            if summary:
                enr["llm_summary"] = summary.strip()
                # Simple confidence: higher if APT match + multiple MITRE tags
                base  = 70
                base += min(len(enr["mitre_tags"]) * 5, 20)
                if enr["apt_match"]: base += 8
                enr["confidence"] = f"{min(base, 97)}%"
            cb(enr)
        except Exception:
            cb(enr)
        finally:
            _llm_queue.task_done()

threading.Thread(target=_llm_worker, daemon=True).start()


def analyze_async(event: dict, callback=None):
    """
    Queue an event for LLM summary enrichment.
    callback(enrichment_dict) is called when done (or immediately if queue full).
    """
    enr = analyze(event)
    if callback is None:
        # Just write to file directly without LLM summary
        _write_enriched(event, enr)
        return

    def _done(e):
        _write_enriched(event, e)
        if callback:
            callback(e)

    try:
        _llm_queue.put_nowait((event, enr, _done))
    except queue.Full:
        _done(enr)   # LLM queue full → write without summary


# ── Premium JSON format ───────────────────────────────────────────────────────

def to_premium_json(event: dict, enrichment: dict | None = None) -> dict:
    """
    Convert a raw event + enrichment into the premium feed JSON format.
    If enrichment is None, compute it synchronously.
    """
    if enrichment is None:
        enrichment = analyze(event)

    service  = event.get("service", "unknown")
    src_ip   = event.get("src_ip", "?")
    ts       = event.get("ts", event.get("timestamp", ""))

    # Captured payload: best available string representation
    payload = ""
    if event.get("commands"):
        payload = "; ".join(str(c) for c in event["commands"][:3])
    elif event.get("hashcat"):
        payload = f"NTLM:{event['hashcat'][:60]}..."
    elif event.get("captured_samples"):
        s = event["captured_samples"][0]
        payload = f"{s.get('filetype','binary')} @ {s.get('url','local')}"
    elif event.get("path"):
        payload = f"{event.get('method','?')} {event['path'][:120]}"
    elif event.get("wallet"):
        payload = f"stratum.authorize wallet={event['wallet'][:40]}"
    elif event.get("rce_chains"):
        payload = event["rce_chains"][0] if isinstance(event["rce_chains"], list) else str(event["rce_chains"])[:120]

    # Enrich intel attributes
    cves = enrichment.get("cves_targeted") or []
    if not cves and event.get("cve"):
        cves = [event["cve"]]

    return {
        "timestamp":      ts,
        "source_ip":      src_ip,
        "target_service": service,
        "dst_port":       event.get("dst_port"),
        "honeypot_node":  NODE_ID,
        "attack_severity":enrichment.get("severity", "Low"),
        "attack_phase":   event.get("attack_phase", "scan"),
        "captured_payload":payload[:500],
        "intel_attributes": {
            "cves_targeted":  cves,
            "asn":            event.get("asn") or event.get("isp") or "",
            "country":        event.get("cc") or event.get("country", ""),
            "behavioral_tags":enrichment.get("behavioral_tags", []),
            "mitre_tactics":  [m["id"] for m in enrichment.get("mitre_tags", [])],
            "apt_match":      enrichment.get("apt_match"),
        },
        "llm_enrichment": {
            "summary":         enrichment.get("llm_summary") or _fallback_summary(event, enrichment),
            "confidence_score":enrichment.get("confidence") or _heuristic_confidence(enrichment),
            "mitre_tags":      enrichment.get("mitre_tags", []),
            "apt_attribution": {
                "group": enrichment.get("apt_match"),
                "desc":  enrichment.get("apt_desc"),
            } if enrichment.get("apt_match") else None,
        },
        "raw_event_id":   event.get("session_id") or event.get("id") or "",
    }


def _fallback_summary(event: dict, enrichment: dict) -> str:
    svc    = event.get("service", "unknown")
    ip     = event.get("src_ip", "unknown")
    phase  = event.get("attack_phase", "scan")
    beh    = enrichment.get("behavioral_tags", [])
    apt    = enrichment.get("apt_match")
    mitre  = [m["name"] for m in enrichment.get("mitre_tags", [])][:2]
    cves   = enrichment.get("cves_targeted", [])[:1]

    parts = [f"Attack via {svc.upper()} from {ip} ({phase} phase)."]
    if apt:
        parts.append(f"Behavioral signature matches {apt}.")
    elif mitre:
        parts.append(f"Techniques observed: {', '.join(mitre)}.")
    if cves:
        parts.append(f"Exploiting {cves[0]}.")
    if "cryptominer" in beh:
        parts.append("Target: CPU/GPU resource hijacking for Monero mining.")
    elif "ntlm-hash-captured" in beh:
        parts.append("Net-NTLMv2 hash captured — offline cracking attempted.")
    elif "c2-url-extracted" in beh:
        parts.append("C2 URL extracted from payload — botnet implant delivery.")
    return " ".join(parts)

def _heuristic_confidence(enrichment: dict) -> str:
    base = 55
    base += min(len(enrichment.get("mitre_tags", [])) * 5, 20)
    if enrichment.get("apt_match"):     base += 12
    if enrichment.get("cves_targeted"): base += 8
    return f"{min(base, 95)}%"


def _write_enriched(event: dict, enrichment: dict):
    """Append premium-formatted event to ttp_enriched.jsonl."""
    try:
        premium = to_premium_json(event, enrichment)
        with open(ENRICHED_FILE, "a") as f:
            f.write(json.dumps(premium) + "\n")
    except Exception:
        pass


# ── Background enrichment of existing events (startup) ───────────────────────

def enrich_event(event: dict):
    """
    Entry point called by enricher.py after intel lookup completes.
    Queues event for async LLM summary + writes enriched output.
    """
    analyze_async(event)


def backfill_from_events(events_file: str, limit: int = 200):
    """Re-analyze recent raw events on startup to populate ttp_enriched.jsonl."""
    try:
        lines = []
        with open(events_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
        # Last `limit` events only
        for line in lines[-limit:]:
            try:
                ev = json.loads(line)
                enr = analyze(ev)
                _write_enriched(ev, enr)
            except Exception:
                pass
    except Exception:
        pass
