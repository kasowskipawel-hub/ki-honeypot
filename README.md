<div align="center">

# KI Honeypot

**Multi-protocol honeypot with AI-powered threat intelligence**

[![License](https://img.shields.io/badge/license-Commercial-blue.svg)](#-pricing--license)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ED?logo=docker)](https://ghcr.io/kasowskipawel-hub/ki-honeypot)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux)](#-requirements)
[![Protocols](https://img.shields.io/badge/protocols-15+-success)](#15-emulated-protocols)

*Deploy in 60 seconds. Watch attackers walk into your fake server. Capture credentials, malware, and exploits in real time.*

[Quick Install](#-quick-install) Â· [Features](#-features) Â· [Dashboard](#-dashboard) Â· [API](#-api-integration) Â· [Pricing](#-pricing--license)

</div>

---

## What is KI Honeypot?

KI Honeypot is a self-hosted deception system that impersonates a full Windows/Linux server stack â€” Exchange, IIS, Redis, SSH, SMB, RDP, and 10 more protocols â€” to lure, identify, and analyse real-world attackers.

Every session is captured in full: credentials, commands, exploit payloads, and malware binaries. An AI analyst (powered by Mistral) classifies attacks, maps them to MITRE ATT&CK, and generates plain-English threat reports â€” automatically, without any manual configuration.

Built for:
- **Security researchers** studying real botnet and APT behaviour
- **Blue teams** wanting live threat intel from their own IP space
- **SOC analysts** who need IOC feeds, hash blocklists, and SIEM-ready JSON events
- **Anyone curious** about who is actively scanning their server right now

---

## âœ¨ Features

### 15+ Emulated Protocols

| Protocol | What it captures |
|---|---|
| **HTTPS / HTTP** | CVE exploit attempts (Exchange, PHPUnit, Spring4Shell, log4shell, 30+ lures), webshell uploads, credential harvesting |
| **SSH** | Full keystroke-level session replay, credentials, post-login commands, dropped malware |
| **Telnet** | Mirai/botnet login attempts, AI-backed OpenWrt shell (attackers get convincing fake responses) |
| **Redis** | Full RCE chain capture â€” cron injection, SSH-key backdoors, module loads, rogue-master replication streams |
| **SMB** | NTLM Net-NTLMv2 hashes ready for hashcat, ransomware detection, lateral movement indicators |
| **RDP** | NLA credential capture |
| **Stratum (XMR)** | Monero miner wallet addresses across 13 ports (plain + TLS) |
| **Ethereum RPC** | Wallet drain attempts, `eth_sendTransaction` probes, private key enumeration |
| **Docker API** | Container escape payloads |
| **Kubernetes API** | Cluster takeover attempts |
| **Elasticsearch** | Data exfiltration queries |
| **MongoDB** | Database dump attempts |
| **Jupyter** | Notebook RCE payloads |

### AI Threat Intelligence (Mistral)

- **Malware analysis** â€” dropped binaries are never executed; AI analyses strings, imports, and behaviour statically
- **Session intent** â€” "what was this attacker actually trying to do?" in one sentence
- **Zero-day detector** â€” behavioural novelty scoring flags attacks that don't match any known CVE
- **Campaign clustering** â€” groups sessions by command fingerprint, tracks botnet waves over time
- **Active deception** â€” AI adjusts honeypot responses in real time to keep attackers engaged longer
- **Hourly threat briefing** â€” AI-generated summary of the current threat landscape on your IP

### Live Dashboard

- Real-time event stream across all 15+ protocols
- **Session replay with timing** â€” SSH keystroke replay + Telnet command/response replay
- **Honeytoken tracking** â€” fake AWS keys, OWA credentials, git tokens planted in responses; beacon fires when attacker uses them elsewhere
- **Actor fingerprinting** via JA3 TLS hashes â€” spot the same tool across multiple IPs
- **MITRE ATT&CK TTP mapping** on every enriched event
- **Campaign view** â€” live botnet wave detection with AI-generated campaign names

### Data & Integration

- Structured JSON event log â€” ready for Splunk, Elastic, Graylog
- REST API with Bearer auth â€” `/api/v1/feed`, `/api/v1/stats`, `/api/v1/hashes`
- Malware hash feed (SHA256 + VirusTotal detections)
- Multi-sensor support â€” aggregate multiple honeypots into one central dashboard

---

## ðŸš€ Quick Install

**[â†’ Request your free 30-day trial key](https://ki-honeypot.de/#trial)** â€” enter your name and email, key arrives instantly.

### ðŸ§ Linux / VPS (recommended)

Requires Ubuntu 22.04+ or Debian 12+ with a public IP.

```bash
curl -sSL https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/install.sh \
  | sudo bash -s -- --key HPOT-XXXX-XXXX-XXXX-XXXX
```

With AI features (Mistral API key â€” free tier at [console.mistral.ai](https://console.mistral.ai)):

```bash
curl -sSL https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/install.sh \
  | sudo bash -s -- \
      --key     HPOT-XXXX-XXXX-XXXX-XXXX \
      --mistral YOUR_MISTRAL_API_KEY
```

Handles everything: Docker install, UFW firewall rules, systemd autostart.

> **Tip:** Move your own SSH daemon to a non-standard port (e.g. 22022) before installing, so port 22 is free for the honeypot.

### ðŸªŸ Windows (Docker Desktop)

Requires Windows 10/11 with [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed.
Run **PowerShell as Administrator**:

```powershell
irm https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/install.ps1 | iex
```

Or with your key directly:

```powershell
$env:LICENSE_KEY="HPOT-XXXX-XXXX-XXXX-XXXX"; irm https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/install.ps1 | iex
```

Handles everything: Docker Desktop check/install (via winget), Windows Firewall rules, Task Scheduler autostart. Dashboard opens automatically in your browser.

**Dashboard is live at `http://localhost:9090` within 60 seconds.**

---

## ðŸ“Š Dashboard

<table>
<tr>
<td width="50%">
<img src="https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/.github/assets/screenshot-livefeed.png" alt="Live Feed â€” real-time attack stream">
<br><sub><b>Live Feed</b> â€” real-time event stream across all protocols</sub>
</td>
<td width="50%">
<img src="https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/.github/assets/screenshot-credentials.png" alt="Credentials â€” captured SSH/Telnet logins">
<br><sub><b>Credentials</b> â€” every captured username/password with AI session intent</sub>
</td>
</tr>
<tr>
<td width="50%">
<img src="https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/.github/assets/screenshot-exploits.png" alt="Exploits â€” CVE matches with AI description">
<br><sub><b>Exploits</b> â€” CVE matches with AI description and severity rating</sub>
</td>
<td width="50%">
<img src="https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/.github/assets/screenshot-ai-journal.png" alt="AI Strategy Journal â€” real-time deception decisions">
<br><sub><b>AI Strategy Journal</b> â€” live deception decision log powered by Mistral</sub>
</td>
</tr>
<tr>
<td colspan="2">
<img src="https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/.github/assets/screenshot-ai-briefing.png" alt="AI Briefing â€” hourly threat summary">
<br><sub><b>AI Briefing</b> â€” hourly AI-generated threat landscape report</sub>
</td>
</tr>
</table>

The dashboard runs on port 9090 and includes 14 live tabs:

| Tab | Description |
|---|---|
| **Live Feed** | Real-time event stream â€” all protocols, all attacks |
| **Credentials** | Every captured username/password with AI-generated session intent |
| **NTLM** | SMB Net-NTLMv2 hashes in hashcat format, ransomware flags |
| **Exploits** | CVE matches with AI description and severity rating |
| **Samples** | Captured malware binaries with static AI analysis and VirusTotal score |
| **Redis RCE** | Full cron/SSH-key injection chain viewer with REPL stream replay |
| **Crypto** | XMR miner wallets, ETH drain attempts, pool endpoints |
| **Session Replay** | Animated keystroke-level replay of SSH and Telnet sessions |
| **SMB** | Share access patterns, lateral movement, ransomware indicators |
| **0-Day Intel** | Behavioural novelty alerts â€” attacks that don't match known CVEs |
| **Campaigns** | Botnet wave clustering â€” same commands, many IPs |
| **Actors** | JA3 TLS fingerprint profiles |
| **Deception** | Honeytoken beacon hits â€” when and where attackers used your fake credentials |
| **AI Journal** | Real-time log of AI strategist deception decisions |

---

## ðŸ”Œ API Integration

```bash
# Recent events (SIEM feed)
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://YOUR-IP:9090/api/v1/feed?limit=100&service=ssh"

# Malware SHA256 blocklist
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://YOUR-IP:9090/api/v1/hashes"

# Daily statistics
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "http://YOUR-IP:9090/api/v1/stats"
```

All responses are structured JSON with enriched fields: source IP, country, ASN, AI analysis, MITRE TTPs, raw session data.

---

## âš™ï¸ Configuration

Edit `/opt/ki-honeypot/.env` (Linux) or `C:\ki-honeypot\.env` (Windows):

```bash
# Required
LICENSE_KEY=HPOT-XXXX-XXXX-XXXX-XXXX

# Dashboard password â€” see warning below
DASH_PASSWORD=YourSecurePassword

# AI features (highly recommended)
MISTRAL_API_KEY=your-mistral-key

# Optional integrations
VT_API_KEY=your-virustotal-key
FEED_API_KEY=your-api-bearer-key
```

> âš ï¸ **Password warning:** If `DASH_PASSWORD` is not set, the dashboard runs **without any authentication** â€” anyone who can reach port 9090 can see your captured data. The one-line installers (`install.sh` / `install.ps1`) generate a random password automatically and print it at the end. If you installed manually, always set `DASH_PASSWORD` before exposing the server.

The Mistral key can also be set **live from the dashboard** (âš™ Settings â†’ AI Provider Key â†’ Save) without restarting.

---

## ðŸ’¾ Captured Data

All data is stored in a persistent Docker volume:
```
/var/lib/docker/volumes/ki-honeypot_hp_data/_data/
```

| Path | Contents |
|---|---|
| `events.jsonl` | Raw event log â€” all protocols |
| `enriched.jsonl` | AI-enriched events with MITRE TTPs |
| `samples/` | Malware binaries named by SHA256 (never executed) |
| `valid_creds.json` | All captured credentials |
| `honeytokens.json` | Issued and triggered honeytoken records |
| `ioc_reports/` | Per-IP IOC reports (C2 URLs, hashes, wallet addresses) |

---

## ðŸ›¡ï¸ Security Notes

- Captured malware is **never executed** â€” stored by SHA256 and analysed statically only
- Restrict dashboard access to your IP: `ufw allow from YOUR.IP to any port 9090`
- All containers run as non-root
- License keys are machine-fingerprint locked, validated every 6 hours with a 72-hour offline grace period

---

## ðŸ“‹ Requirements

| | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04 / Debian 12 | Ubuntu 24.04 LTS |
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 2 GB |
| Disk | 20 GB | 40 GB |
| Network | Public IPv4, no upstream firewall | Dedicated VPS IP |

---

## ðŸ”§ Useful Commands

```bash
# View logs
docker logs -f win443-honeypot

# Update to latest version
cd /opt/win443-honeypot
docker compose pull && docker compose up -d --force-recreate

# Stop
docker compose -f /opt/win443-honeypot/docker-compose.yml down

# Backup all captured data
tar -czf backup-$(date +%Y%m%d).tar.gz \
  -C /var/lib/docker/volumes/win443-honeypot_hp_data _data
```

---

## ðŸ’° Pricing & License

Each license key includes **30 days** of full access, activated on a single server.

**[â†’ Get your free 30-day trial key](https://ki-honeypot.de/#trial)** â€” just enter your name and email.

> **Need a longer license or want to run multiple sensors?**
> Contact us at **[info@ki-honeypot.de](mailto:info@ki-honeypot.de)** â€” we'll work something out.

| | |
|---|---|
| Free 30-day trial key | [ki-honeypot.de/trial](https://ki-honeypot.de/#trial) |
| Extended / multi-server licensing | [info@ki-honeypot.de](mailto:info@ki-honeypot.de) |
| Custom enterprise deployment | [info@ki-honeypot.de](mailto:info@ki-honeypot.de) |

---

<div align="center">

Built with Python Â· Powered by Mistral AI

**[Get free 30-day trial â†’](https://ki-honeypot.de/#trial)** &nbsp;Â·&nbsp; **[info@ki-honeypot.de](mailto:info@ki-honeypot.de)**

</div>

