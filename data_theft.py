"""
Honeytoken Data Trap — Canary credentials for attacker attribution.

All tokens are:
  - Correctly formatted (pass regex/parser validation)
  - Seeded deterministically from CANARY_SEED env var (rotate with one change)
  - Non-existent externally, but tracker URLs hit our own honeypot VPS

TRACKER_BASE points to the honeypot's own HTTPS listener.
Any tool that calls one of those URLs lands in our HTTP event log automatically.
No external services, no personal domains.
"""

import os
import struct
import base64
import hashlib
import json
import datetime

# ── Seed — set CANARY_SEED in .env to rotate every token at once ─────────────
_SEED = os.environ.get("CANARY_SEED", "win443-gpu-node-2026")

def _d(tag: str) -> bytes:
    return hashlib.sha256(f"{_SEED}:{tag}".encode()).digest()

def _h(tag: str, n: int = 64) -> str:
    return _d(tag).hex()[:n]

def _b58(data: bytes) -> str:
    ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = ALPHA[r] + s
    return s

def _b58check(payload: bytes) -> str:
    cs = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _b58(payload + cs)

# ── SSH Canary Key ─────────────────────────────────────────────────────────────
# Real Ed25519 key derived from seed. Deterministic across restarts.
# Deploy public key on a canary host to detect usage.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption
    )
    _ed_priv = Ed25519PrivateKey.from_private_bytes(_d("ssh-privkey-seed"))
    _ed_pub  = _ed_priv.public_key()

    CANARY_SSH_PRIVATE_KEY = _ed_priv.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    ).decode()

    _pub_raw  = _ed_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    _key_type = b"ssh-ed25519"
    _pub_blob = (struct.pack(">I", len(_key_type)) + _key_type
                 + struct.pack(">I", len(_pub_raw)) + _pub_raw)
    CANARY_SSH_PUBLIC = "ssh-ed25519 " + base64.b64encode(_pub_blob).decode() + " canary-trap-win443"

except ImportError:
    # Fallback: static key (pre-generated, looks real)
    CANARY_SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt
ZWQyNTUxOQAAACB4T2HvqLXM5Fg3YJN7SXCO3vbGAYWqFW+zCmwPkEJMnAAAAJC7
SzFtu0sxbQAAAAtzc2gtZWQyNTUxOQAAACB4T2HvqLXM5Fg3YJN7SXCO3vbGAYWq
FW+zCmwPkEJMnAAAAED+j5oVS3b0VvFZQ+4jI8uqkzJa6VcFwz4H5q3R0uyYk3hP
Ye+otczkWDdgk3tJcI7e9sYBhaoVb7MKbA+QQkyAAAASGNhbmFyeS10cmFwLXdpbjQ0
MwECAw==
-----END OPENSSH PRIVATE KEY-----
"""
    CANARY_SSH_PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHhPYe+otczkWDdgk3tJcI7e9sYBhaoVb7MKbA+QQkye canary-trap-win443"

# ── Tracker: self-referential — hits land in our own HTTP event log ───────────
_VPS = os.environ.get("VPS_IP", "164.68.121.252")
TRACKER_BASE = os.environ.get("TRACKER_BASE", f"https://{_VPS}")
TRACKER_ID   = _h("tracker-id", 12)

HONEYTOKENS = {
    "api_log": f"{TRACKER_BASE}/api/{TRACKER_ID}/metrics",
    "health":  f"{TRACKER_BASE}/health/{TRACKER_ID}",
    "backup":  f"{TRACKER_BASE}/b/{TRACKER_ID}/verify",
    "admin":   f"{TRACKER_BASE}/admin/{TRACKER_ID}/status",
}

# ── AWS Credentials ───────────────────────────────────────────────────────────
# Format: AKIA + 16 chars from base32 alphabet [A-Z2-7]
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_ai  = int(_h("aws-key-id"), 16)
AWS_ACCESS_KEY = "AKIA" + "".join(_B32[(_ai >> (5 * i)) & 0x1F] for i in range(16))

# Secret: 40 chars, mixed-case alphanumeric + /+
_SC  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+"
_asi = int(_h("aws-secret") + _h("aws-secret-ext"), 16)
AWS_SECRET_KEY = "".join(_SC[(_asi >> (6 * i)) & 0x3F] for i in range(40))

# Second profile for realism
_ai2  = int(_h("aws-key-id-2"), 16)
AWS_ACCESS_KEY_2 = "AKIA" + "".join(_B32[(_ai2 >> (5 * i)) & 0x1F] for i in range(16))
_asi2 = int(_h("aws-secret-2") + _h("aws-secret-2-ext"), 16)
AWS_SECRET_KEY_2 = "".join(_SC[(_asi2 >> (6 * i)) & 0x3F] for i in range(40))

AWS_REGION  = "eu-west-1"
AWS_REGION2 = "us-east-1"

# ── Ethereum address (EIP-55-style checksum) ──────────────────────────────────
_eth_raw = _h("eth-addr-bytes", 40)

def _eth_cs(addr: str) -> str:
    # Deterministic checksum using sha256 (approximate — bots don't verify)
    h = hashlib.sha256(addr.lower().encode()).hexdigest()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c
                           for i, c in enumerate(addr.lower()))

ETH_ADDRESS = _eth_cs(_eth_raw)
_ks_id = (f"{_h('ks-a',8)}-{_h('ks-b',4)}-{_h('ks-c',4)}"
          f"-{_h('ks-d',4)}-{_h('ks-e',12)}")

# ── Bitcoin WIF ───────────────────────────────────────────────────────────────
_btc_priv = _d("btc-privkey")
BTC_WIF = _b58check(b"\x80" + _btc_priv + b"\x01")  # compressed

# P2PKH address (hash-derived, not curve-derived — correct format, wrong math)
_btc_addr_hash = _d("btc-addr-hash")[:20]
BTC_ADDRESS = "1" + _b58check(b"\x00" + _btc_addr_hash)

# ── Monero address (95-char XMR mainnet format) ───────────────────────────────
_XMR_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_xmr_n = int(_h("xmr-addr", 64), 16)
XMR_ADDRESS = "4" + "".join(
    _XMR_ALPHA[(_xmr_n >> (6 * i)) % len(_XMR_ALPHA)] for i in range(94)
)
XMR_VIEW_KEY  = _h("xmr-viewkey",  64)
XMR_SPEND_KEY = _h("xmr-spendkey", 64)

# ── BIP39 mnemonic (12 random-looking words, not the `abandon abandon` vector) ─
_WORDS = [
    "venture", "gravity", "thunder", "eclipse", "crystal", "phantom",
    "cascade", "orbital", "fusion", "voltage", "pioneer", "cluster",
    "digital", "network", "dynamic", "circuit", "quantum", "stellar",
    "carbon", "plasma", "vector", "signal", "radiant", "zenith",
]
_mn = int(_h("bip39-mnemonic"), 16)
BTC_MNEMONIC = " ".join(
    _WORDS[(_mn >> (5 * i)) % len(_WORDS)] for i in range(12)
)

# ── Derived passwords / tokens ─────────────────────────────────────────────────
_DB_PASS    = _h("db-password",    16) + "Kx7!"
_REDIS_PASS = _h("redis-password", 20)
_JWT        = _h("jwt-secret",     40)
_ADMIN_TOK  = _h("admin-token",    32)
_GL_TOKEN   = "glpat-" + _h("gitlab-pat", 20)
_GH_TOKEN   = "ghp_"   + _h("github-pat", 36)

# ── File contents ─────────────────────────────────────────────────────────────
AWS_CREDENTIALS_FILE = f"""[default]
aws_access_key_id = {AWS_ACCESS_KEY}
aws_secret_access_key = {AWS_SECRET_KEY}
region = {AWS_REGION}
output = json

[production]
aws_access_key_id = {AWS_ACCESS_KEY_2}
aws_secret_access_key = {AWS_SECRET_KEY_2}
region = {AWS_REGION2}
"""

FAKE_ENV_FILE = f"""# Production — gpu-node-07
NODE_ENV=production
DB_HOST=prod-db-cluster.internal
DB_PORT=5432
DB_USER=svc_gpu
DB_PASS={_DB_PASS}
REDIS_URL=redis://:{_REDIS_PASS}@redis.internal:6379/0
AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY}
AWS_SECRET_ACCESS_KEY={AWS_SECRET_KEY}
AWS_DEFAULT_REGION={AWS_REGION}
S3_BACKUP_BUCKET=gpu-cluster-backups-{TRACKER_ID}
MONITORING_ENDPOINT={HONEYTOKENS["api_log"]}
HEALTHCHECK_URL={HONEYTOKENS["health"]}
ADMIN_TOKEN={_ADMIN_TOK}
JWT_SECRET={_JWT}
"""

FAKE_GIT_CREDENTIALS = (
    f"https://deploy:{_GL_TOKEN}@gitlab.internal.com/infra/gpu-cluster.git\n"
    f"https://x-access-token:{_GH_TOKEN}@github.com/org/cluster-config.git\n"
)

FAKE_CONFIG_JSON = json.dumps({
    "database": {
        "host": "prod-db-cluster.internal",
        "port": 5432,
        "user": "svc_gpu",
        "password": _DB_PASS,
        "name": "gpu_cluster",
    },
    "aws": {
        "access_key_id": AWS_ACCESS_KEY,
        "secret_access_key": AWS_SECRET_KEY,
        "region": AWS_REGION,
        "s3_bucket": f"gpu-cluster-backups-{TRACKER_ID}",
    },
    "monitoring": {
        "endpoint": HONEYTOKENS["api_log"],
        "health_url": HONEYTOKENS["health"],
    },
    "auth": {
        "jwt_secret": _JWT,
        "admin_token": _ADMIN_TOK,
    },
}, indent=2)

FAKE_BITCOIN_WALLET = f"""# Bitcoin Core Wallet Dump
# Network: mainnet  Version: 0.21.1
# Exported: 2025-09-14T03:21:07Z
# Address: {BTC_ADDRESS}
# Balance: 1.34521700 BTC

# Private key (WIF compressed):
{BTC_WIF}

# Recovery phrase (BIP39):
{BTC_MNEMONIC}

# HD Path: m/44'/0'/0'/0/0
# Verify: {HONEYTOKENS["backup"]}
"""

FAKE_ETHEREUM_KEYSTORE = json.dumps({
    "version": 3,
    "id": _ks_id,
    "address": ETH_ADDRESS,
    "crypto": {
        "ciphertext": _h("eth-ciphertext", 32),
        "cipherparams": {"iv": _h("eth-iv", 16)},
        "cipher": "aes-128-ctr",
        "kdf": "scrypt",
        "kdfparams": {
            "dklen": 32,
            "salt": _h("eth-salt", 32),
            "n": 8192, "r": 8, "p": 1,
        },
        "mac": _h("eth-mac", 32),
    },
    "meta": {
        "wallet": "GPU Cluster Treasury",
        "network": "mainnet",
        "balance_eth": 23.471,
        "tokens": ["USDC", "LINK"],
        "backup_url": HONEYTOKENS["backup"],
    },
}, indent=2)

FAKE_XMR_WALLET_FILE = f"""# Monero Wallet
# Address:   {XMR_ADDRESS}
# View Key:  {XMR_VIEW_KEY}
# Spend Key: (encrypted — password required)
# Created:   2025-11-20T04:12:33Z
# Balance:   847.3 XMR
# Pool:      pool.hashvault.pro:443
# Worker:    gpu-node-07
# Verify:    {HONEYTOKENS["admin"]}
"""

# ── File mappings for SSH honeypot ────────────────────────────────────────────
CANARY_FILES = {
    "/root/.ssh/id_ed25519":          CANARY_SSH_PRIVATE_KEY,
    "/root/.ssh/id_ed25519.pub":      CANARY_SSH_PUBLIC + "\n",
    "/root/.aws/credentials":         AWS_CREDENTIALS_FILE,
    "/root/.aws/config":              f"[default]\nregion = {AWS_REGION}\noutput = json\n",
    "/root/.env":                     FAKE_ENV_FILE,
    "/root/.git-credentials":         FAKE_GIT_CREDENTIALS,
    "/root/config.json":              FAKE_CONFIG_JSON,
    "/root/wallet.dat":               FAKE_BITCOIN_WALLET,
    "/root/keystore.json":            FAKE_ETHEREUM_KEYSTORE,
    "/root/.wallet":                  FAKE_XMR_WALLET_FILE,
    "/home/deploy/.aws/credentials":  AWS_CREDENTIALS_FILE,
    "/home/deploy/.env":              FAKE_ENV_FILE,
}

CANARY_FILES_SHORT = {
    ".ssh/id_ed25519":     CANARY_SSH_PRIVATE_KEY,
    ".ssh/id_ed25519.pub": CANARY_SSH_PUBLIC + "\n",
    ".aws/credentials":    AWS_CREDENTIALS_FILE,
    ".aws/config":         f"[default]\nregion = {AWS_REGION}\noutput = json\n",
    ".env":                FAKE_ENV_FILE,
    ".git-credentials":    FAKE_GIT_CREDENTIALS,
    "config.json":         FAKE_CONFIG_JSON,
    "wallet.dat":          FAKE_BITCOIN_WALLET,
    "keystore.json":       FAKE_ETHEREUM_KEYSTORE,
    ".wallet":             FAKE_XMR_WALLET_FILE,
}

# ── Environment vars for `env` honeypot command ───────────────────────────────
FAKE_ENV_VARS = {
    "AWS_ACCESS_KEY_ID":     AWS_ACCESS_KEY,
    "AWS_SECRET_ACCESS_KEY": AWS_SECRET_KEY,
    "AWS_DEFAULT_REGION":    AWS_REGION,
    "DATABASE_URL":          f"postgresql://svc_gpu:{_DB_PASS}@prod-db-cluster.internal:5432/gpu_cluster",
    "REDIS_URL":             f"redis://:{_REDIS_PASS}@redis.internal:6379/0",
    "ADMIN_TOKEN":           _ADMIN_TOK,
    "JWT_SECRET":            _JWT,
    "S3_BUCKET":             f"gpu-cluster-backups-{TRACKER_ID}",
    "MONITORING_ENDPOINT":   HONEYTOKENS["api_log"],
    "HEALTHCHECK_URL":       HONEYTOKENS["health"],
}


# ── Canary access event emitter ───────────────────────────────────────────────
def emit_canary_event(path: str, src_ip: str, command: str = ""):
    """Write a canary-access event to the honeypot event pipeline."""
    vol = os.environ.get("DATA_DIR", "/data")
    evfile = os.path.join(vol, "events.jsonl")
    try:
        ev = {
            "ts":      datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "type":    "canary_access",
            "src_ip":  src_ip,
            "file":    path,
            "cmd":     command[:200],
            "token_id": TRACKER_ID,
        }
        with open(evfile, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
    except OSError:
        pass
