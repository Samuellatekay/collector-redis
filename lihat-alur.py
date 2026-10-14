#!/usr/bin/env python3
"""
Pantau data yang MASUK dan KELUAR dari OpenCTI dan GLPI lewat Redis (hanya membaca, tidak menghapus data).

Cara kerja: membuka koneksi ke Redis dengan perintah MONITOR, lalu menyaring penulisan (RPUSH/LPUSH)
ke list milik collector. Tidak butuh library apa pun selain Python 3.
MONITOR membebani Redis, jadi pakai untuk debugging saja dan hentikan dengan Ctrl+C.

Catatan: hanya data BARU (ditulis setelah skrip berjalan) yang tampil.

Pemakaian:
    export REDIS_HOST=192.168.51.39          # default sama
    read -rsp "Password Redis: " REDIS_PASS; echo; export REDIS_PASS
    python3 lihat-alur.py            # ringkas
    python3 lihat-alur.py --full     # JSON lengkap
    python3 lihat-alur.py --raw      # tampilkan semua perintah selain BLPOP (untuk diagnosis)
"""
import getpass
import json
import os
import re
import socket
import sys
from datetime import datetime

HOST = os.getenv("REDIS_HOST", "192.168.51.39")
PORT = int(os.getenv("REDIS_PORT", "6379"))
DB = int(os.getenv("REDIS_DB", "2"))
FULL = "--full" in sys.argv
RAW = "--raw" in sys.argv

# Baris MONITOR asli: 1791622259.426341 [2 192.168.51.39:52174] "RPUSH" "glpi-logs" "{...}"
LINE_RE = re.compile(r"^\+?(?P<ts>\d+\.\d+) \[(?P<db>\d+) (?P<client>[^\]]+)\] (?P<rest>.*)$", re.S)
CMD_RE = re.compile(r'^"(?P<cmd>\w+)" "(?P<key>[^"]+)" "(?P<val>.*)"$', re.S)
SIMPLE_ESC = {"n": b"\n", "r": b"\r", "t": b"\t", "a": b"\a", "b": b"\b"}

WATCHED = {"opencti-events", "glpi-logs", "enrichment-events", "outbound-opencti", "outbound-glpi"}


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
    src = (doc.get("source") or "") if isinstance(doc, dict) else ""
    if key == "outbound-glpi":
        return "MASUK ke GLPI    (perintah dari Logstash, akan dibuat jadi tiket)"
    if key == "outbound-opencti":
        return "MASUK ke OpenCTI (perintah dari Logstash, akan dibuat jadi indikator)"
    if key == "glpi-logs":
        if src == "outbound-glpi":
            return "MASUK ke GLPI    (catatan hasil: tiket sudah dibuat)"
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
        keep["request"] = {k: v for k, v in req.items()
                           if k in ("action", "title", "name", "pattern", "urgency", "score")}
    return json.dumps(keep, ensure_ascii=False)


def monitor_lines(host, port, password):
    """Buka koneksi, kirim AUTH + MONITOR, lalu hasilkan tiap baris yang dikirim Redis."""
    s = socket.create_connection((host, port), timeout=10)
    f = s.makefile("rb")

    def send(*args):
        out = b"*%d\r\n" % len(args)
        for a in args:
            a = a.encode() if isinstance(a, str) else a
            out += b"$%d\r\n%s\r\n" % (len(a), a)
        s.sendall(out)

    def reply():
        line = f.readline()
        if not line:
            raise ConnectionError("koneksi ditutup oleh Redis")
        return line.rstrip(b"\r\n").decode("utf-8", "replace")

    if password:
        send("AUTH", password)
        r = reply()
        if not r.startswith("+OK"):
            raise SystemExit(f"AUTH gagal: {r}")
    send("MONITOR")
    r = reply()
    if not r.startswith("+OK"):
        raise SystemExit(f"MONITOR gagal: {r}")
    s.settimeout(None)
    while True:
        yield reply()


def handle(line):
    """Proses satu baris MONITOR. Kembalikan teks untuk dicetak, atau None kalau diabaikan."""
    m = LINE_RE.match(line)
    if not m:
        return None
    parsed = CMD_RE.match(m["rest"])
    if not parsed:
        return (f"[?] {m['rest'][:160]}" if RAW else None)
    cmd, key = parsed["cmd"].upper(), parsed["key"]
    if cmd not in ("RPUSH", "LPUSH") or key not in WATCHED:
        return (f"[{cmd}] {key}" if RAW and cmd != "BLPOP" else None)
    if int(m["db"]) != DB:
        return None
    raw = unrepr(parsed["val"])
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = raw
    ts = datetime.now().strftime("%H:%M:%S")
    text = f"[{ts}] {classify(key, doc)}  <{key}>\n"
    if FULL and isinstance(doc, (dict, list)):
        text += json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    else:
        text += "    " + summary(doc) + "\n"
    return text


def main():
    password = os.getenv("REDIS_PASS") or getpass.getpass("Password Redis: ")
    print(f"Terhubung ke {HOST}:{PORT}, memantau db {DB}. Menunggu data BARU... (Ctrl+C untuk berhenti)\n", flush=True)
    for line in monitor_lines(HOST, PORT, password):
        out = handle(line)
        if out:
            print(out, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBerhenti.")