#!/usr/bin/env python3
"""Build script: obfuscate with PyArmor, build Docker image, push to ghcr.io.

Usage:
  python build.py                    # build only (no push)
  python build.py --push             # build + push to ghcr.io
  python build.py --push --tag 1.2   # custom tag
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

GHCR_IMAGE = "ghcr.io/kasowskipawel-hub/win443-honeypot"
DOCKERFILE  = os.path.join(os.path.dirname(__file__), "Dockerfile")
SRC_DIR     = os.path.dirname(__file__)

# Files NOT to include in the distributed image
_EXCLUDE = {
    "build.py", "keygen.py", "deploy.py",
    "analyze.py", "analyze_2h.py", "analyze_events.py",
    "check_compromise.py", "check_ssh.py",
    "ioc_report.py", "stats.py", "report-abuse.py",
    "backfill_enricher.py",
}


def run(cmd: list, **kwargs):
    print(f"$ {' '.join(cmd)}", flush=True)
    r = subprocess.run(cmd, **kwargs)
    if r.returncode != 0:
        sys.exit(r.returncode)
    return r


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--push",  action="store_true")
    parser.add_argument("--tag",   default="latest")
    parser.add_argument("--image", default=GHCR_IMAGE)
    args = parser.parse_args()

    full_tag = f"{args.image}:{args.tag}"
    print(f"[build] target: {full_tag}", flush=True)

    # Build image (Dockerfile handles PyArmor internally via multi-stage)
    run(["docker", "build", "-t", full_tag, "-f", DOCKERFILE, SRC_DIR])

    if args.push:
        run(["docker", "push", full_tag])
        if args.tag != "latest":
            latest = f"{args.image}:latest"
            run(["docker", "tag", full_tag, latest])
            run(["docker", "push", latest])
        print(f"[build] pushed {full_tag}", flush=True)
    else:
        print(f"[build] image built locally: {full_tag}", flush=True)
        print("[build] run with --push to publish", flush=True)


if __name__ == "__main__":
    main()
