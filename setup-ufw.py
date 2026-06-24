#!/usr/bin/env python3
"""Collect all honeypot ports from source files and open them in UFW."""
import re, subprocess, sys, os

DIR = os.path.dirname(os.path.abspath(__file__))

# Ports that must NOT be exposed as honeypot (management / dashboard)
SKIP = {9090, 9091, 9092, 22022}

ports = set()

def _nums(text):
    return {int(m) for m in re.findall(r'\b(\d{2,5})\b', text)
            if 1 <= int(m) <= 65535}

# docker-compose.yml — env lines like: - PORTS=443,80,8080
compose = open(os.path.join(DIR, 'docker-compose.yml')).read()
for m in re.finditer(r'-\s+(?:PORTS|SSH_PORTS|REDIS_PORTS|[A-Z_]+PORT[S]?)=([\d,]+)', compose):
    ports |= _nums(m.group(1))

# stratum_honeypot.py — STRATUM_PORTS / STRATUM_SSL_PORTS list literals
for fname in ('stratum_honeypot.py',):
    path = os.path.join(DIR, fname)
    if not os.path.exists(path): continue
    text = open(path).read()
    for m in re.finditer(r'STRATUM(?:_SSL)?_PORTS\s*=\s*\[([^\]]+)\]', text):
        ports |= _nums(m.group(1))

# devapi_honeypot.py — getenv(X_PORT, NNNN)
for fname in ('devapi_honeypot.py',):
    path = os.path.join(DIR, fname)
    if not os.path.exists(path): continue
    text = open(path).read()
    for m in re.finditer(r'getenv\([^,]+,\s*["\']([\d]+)["\']\)', text):
        ports |= _nums(m.group(1))

# telnet / eth honeypots
for fname in ('telnet_honeypot.py', 'eth_honeypot.py'):
    path = os.path.join(DIR, fname)
    if not os.path.exists(path): continue
    text = open(path).read()
    for m in re.finditer(r'getenv\([^,]+,\s*["\']([\d]+)["\']\)', text):
        ports |= _nums(m.group(1))
    # also TELNET_PORTS default
    for m in re.finditer(r'"(\d+)"', text):
        p = int(m.group(1))
        if 1 <= p <= 65535:
            ports.add(p)

ports -= SKIP

added = 0
for p in sorted(ports):
    result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
    if f'{p}/tcp' in result.stdout and 'ALLOW' in result.stdout:
        continue  # already open
    r = subprocess.run(['ufw', 'allow', f'{p}/tcp'], capture_output=True, text=True)
    if r.returncode == 0:
        print(f'[ufw-sync] opened {p}/tcp')
        added += 1
    else:
        print(f'[ufw-sync] WARN {p}: {r.stderr.strip()}', file=sys.stderr)

print(f'[ufw-sync] done — {added} new rules added ({len(ports)} ports total)')
