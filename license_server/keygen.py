#!/usr/bin/env python3
"""Key generator and admin tool for the win443-honeypot license server.

Usage:
  python keygen.py create --email user@example.com [--days 30] [--notes "GitHub order"]
  python keygen.py list
  python keygen.py revoke --key HPOT-XXXX-XXXX-XXXX-XXXX
"""
import argparse
import os
import secrets
import sqlite3
import time

DB_PATH = os.environ.get("LICENSE_DB", "/data/license.db")


def _db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _fmt_key() -> str:
    """Generate HPOT-XXXX-XXXX-XXXX-XXXX format key."""
    raw = secrets.token_hex(8).upper()
    return f"HPOT-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


def cmd_create(email: str, days: int, notes: str):
    key = _fmt_key()
    now = int(time.time())
    expires = now + days * 86400
    with _db() as con:
        con.execute(
            "INSERT INTO keys (key, email, created_at, expires_at, revoked, notes) VALUES (?,?,?,?,0,?)",
            (key, email, now, expires, notes)
        )
    print(f"Key:     {key}")
    print(f"Email:   {email}")
    print(f"Expires: {time.strftime('%Y-%m-%d', time.localtime(expires))} ({days} days)")
    if notes:
        print(f"Notes:   {notes}")


def cmd_list():
    with _db() as con:
        rows = con.execute("SELECT k.*, COUNT(a.machine_id) as machines FROM keys k "
                           "LEFT JOIN activations a ON k.key=a.key GROUP BY k.key").fetchall()
    if not rows:
        print("No keys found.")
        return
    print(f"{'KEY':<28} {'EMAIL':<30} {'EXPIRES':<12} {'REV':<4} {'MACHINES'}")
    print("-" * 85)
    for r in rows:
        exp = time.strftime('%Y-%m-%d', time.localtime(r['expires_at']))
        rev = "YES" if r['revoked'] else "-"
        print(f"{r['key']:<28} {r['email']:<30} {exp:<12} {rev:<4} {r['machines']}")


def cmd_revoke(key: str):
    with _db() as con:
        cur = con.execute("UPDATE keys SET revoked=1 WHERE key=?", (key,))
    if cur.rowcount:
        print(f"Revoked: {key}")
    else:
        print(f"Key not found: {key}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="License key management")
    sub = parser.add_subparsers(dest="cmd")

    p_create = sub.add_parser("create")
    p_create.add_argument("--email", required=True)
    p_create.add_argument("--days", type=int, default=30)
    p_create.add_argument("--notes", default="")

    p_list = sub.add_parser("list")

    p_revoke = sub.add_parser("revoke")
    p_revoke.add_argument("--key", required=True)

    args = parser.parse_args()
    if args.cmd == "create":
        cmd_create(args.email, args.days, args.notes)
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "revoke":
        cmd_revoke(args.key)
    else:
        parser.print_help()
