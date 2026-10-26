#!/usr/bin/env python3
"""Sinkronkan criticality aset dari GLPI ke Redis (HSET asset:<nama> criticality N).

Aplikasi analisis membaca key itu saat menghitung skor risiko. Key ditulis dua jenis:
  asset:<nama komputer>   (cocok dengan agent.name Wazuh)
  asset:<alamat IP>       (cocok dengan IP tujuan/sumber alert; semua IP komputer di GLPI)

Cara pakai (dari folder collector):
    docker compose exec collector python sync_criticality.py --dry-run
    docker compose exec collector python sync_criticality.py
    docker compose exec collector python sync_criticality.py --every 600   # ulang tiap 10 menit

Sumber nilai di GLPI (urutan):
  1. Field kustom, bila env GLPI_CRIT_FIELD diisi dengan nama key di respons API
     (mis. hasil plugin Fields; cek dulu dengan curl, lihat panduan).
  2. Baris di kolom Comment komputer:  criticality=5   (atau  criticality: 5)
"""
import argparse
import ipaddress
import os
import re
import sys
import time

import requests

import collector
import enrichment

CRIT_FIELD = os.getenv("GLPI_CRIT_FIELD", "").strip()
COMMENT_RE = re.compile(r"criticality\s*[:=]\s*([1-5])\b", re.I)
PAGE = 200


def to_level(value):
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 5 else None


def extract(item: dict):
    if CRIT_FIELD and CRIT_FIELD in item:
        level = to_level(item[CRIT_FIELD])
        if level:
            return level
    match = COMMENT_RE.search(str(item.get("comment") or ""))
    return int(match.group(1)) if match else None


def computers(token):
    start = 0
    while True:
        resp = requests.get(
            f"{collector.GLPI_URL}/Computer",
            headers=collector.glpi_headers(token),
            params={"range": f"{start}-{start + PAGE - 1}", "expand_dropdowns": "true"},
            timeout=60,
        )
        resp.raise_for_status()
        rows = resp.json()
        if not isinstance(rows, list) or not rows:
            return
        yield from rows
        if len(rows) < PAGE:
            return
        start += PAGE


def computer_ips(item_id, token):
    """Semua IP komputer di GLPI (NetworkPort/NetworkName/IPAddress), hanya yang valid."""
    try:
        values = enrichment._computer_ip_addresses(item_id, collector.GLPI, token)
    except Exception as exc:
        print(f"  [CEK] IP komputer #{item_id} tidak terbaca: {type(exc).__name__}", file=sys.stderr)
        return []
    out = []
    for value in values or []:
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_unspecified or ip.is_link_local):
            out.append(str(ip))
    return list(dict.fromkeys(out))


def sync(dry_run: bool) -> int:
    token = collector.glpi_session()
    total = written = 0
    try:
        for item in computers(token):
            total += 1
            name = str(item.get("name") or "").strip()
            level = extract(item)
            if not name or level is None:
                continue
            written += 1
            keys = list(dict.fromkeys([name, name.lower(), *computer_ips(item.get("id"), token)]))
            print(f"{'[dry-run] ' if dry_run else ''}{name} criticality={level} -> "
                  + ", ".join(f"asset:{k}" for k in keys))
            if not dry_run:
                for key in keys:
                    collector.r.hset(f"asset:{key}", "criticality", level)
    finally:
        collector.glpi_kill(token)
    print(f"Selesai: {written} dari {total} komputer punya criticality.")
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="tampilkan saja, jangan tulis ke Redis")
    parser.add_argument("--every", type=int, default=0, help="ulangi tiap N detik (0 = sekali saja)")
    args = parser.parse_args()
    while True:
        try:
            sync(args.dry_run)
        except Exception as exc:
            print(f"GAGAL: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
            if not args.every:
                return 1
        if not args.every:
            return 0
        time.sleep(args.every)


if __name__ == "__main__":
    sys.exit(main())