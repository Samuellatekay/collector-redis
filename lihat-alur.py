#!/usr/bin/env python3
"""
Pantau data yang MASUK dan KELUAR dari OpenCTI dan GLPI lewat Redis (hanya membaca, tidak menghapus data).

Cara kerja: memakai perintah MONITOR Redis, lalu menyaring penulisan (RPUSH/LPUSH) ke list collector.
MONITOR membebani Redis, jadi pakai untuk debugging saja dan hentikan dengan Ctrl+C.

Pemakaian:
    export REDIS_HOST=192.168.51.39          # default sama
    read -rs REDIS_PASS; export REDIS_PASS   # password tidak ditampilkan
    python3 lihat-alur.py            # ringkas
    python3 lihat-alur.py --full     # JSON lengkap
"""
import getpass
import json
import os
import re
import sys
from datetime import datetime

import redis

HOST = os.getenv("REDIS_HOST", "192.168.51.39")
PORT = int(os.getenv("REDIS_PORT", "6379"))
DB = int(os.getenv("REDIS_DB", "2"))
FULL = "--full" in sys.argv

CMD_RE = re.compile(r'^(?P<cmd>\w+) "(?P<key>[^"]+)" "(?P<val>.*)"$', re.S)
SIMPLE_ESC = {"n": b"\n", "r": b"\r", "t": b"\t", "a": b"\a", "b": b"\b"}


def unrepr(s):
    """Balikkan format escape MONITOR Redis (\\" \\\\ \\n \\xNN) menjadi teks asli."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and i + 3 < len(s):
                try:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            out.extend(SIMPLE_ESC.get(n, n.encode()))
            i += 2
            continue
        out.extend(c.encode())
        i += 1
    return out.decode("utf-8", "replace")


def classify(key, doc):
    """Beri label arah dan sistem."""
    if key == "outbound-glpi":
        return "MASUK ke GLPI   (perintah dari Logstash, akan dibuat jadi tiket)"
    if key == "outbound-opencti":
        return "MASUK ke OpenCTI (perintah dari Logstash, akan dibuat jadi indikator)"
    src = (doc.get("source") or "") if isinstance(doc, dict) else ""
    if key == "glpi-logs":
        if src == "outbound-glpi":
            return "MASUK ke GLPI   (catatan hasil: tiket sudah dibuat)"
        return "KELUAR dari GLPI (tiket terbaca collector)"
    if key == "opencti-events":
        if src == "outbound-opencti":
            return "MASUK ke OpenCTI (catatan hasil: indikator sudah dibuat)"
        return "KELUAR dari OpenCTI (indikator terbaca collector)"
    if key == "enrichment-events":
        return "KELUAR enrichment (hasil pengayaan IP/domain)"
    return key


SHOW = ["id", "event", "type", "name", "title", "pattern", "score", "status", "urgency",
        "action", "date_mod", "created_at", "observable", "request", "response"]


def summary(doc):
    if not isinstance(doc, dict):
        return str(doc)
    keep = {k: doc[k] for k in SHOW if k in doc and doc[k] not in (None, "")}
    # request dipersingkat: isi tiket (content) bisa panjang dan memuat log mentah
    req = keep.get("request")
    if isinstance(req, dict):
        keep["request"] = {k: v for k, v in req.items() if k in ("action", "title", "name", "pattern", "urgency", "score")}
    return json.dumps(keep, ensure_ascii=False)


def main():
    password = os.getenv("REDIS_PASS") or getpass.getpass("Password Redis: ")
    r = redis.Redis(host=HOST, port=PORT, password=password, db=DB)
    r.ping()
    print(f"Terhubung ke {HOST}:{PORT} db {DB}. Menunggu data... (Ctrl+C untuk berhenti)\n")
    watched = {"opencti-events", "glpi-logs", "enrichment-events", "outbound-opencti", "outbound-glpi"}
    with r.monitor() as m:
        for ev in m.listen():
            parsed = CMD_RE.match(ev.get("command", ""))
            if not parsed or parsed["cmd"].upper() not in ("RPUSH", "LPUSH"):
                continue
            key = parsed["key"]
            if key not in watched:
                continue
            raw = unrepr(parsed["val"])
            try:
                doc = json.loads(raw)
            except ValueError:
                doc = raw
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {classify(key, doc)}  <{key}>")
            if FULL and isinstance(doc, (dict, list)):
                print(json.dumps(doc, ensure_ascii=False, indent=2))
            else:
                print("   ", summary(doc))
            print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBerhenti.")