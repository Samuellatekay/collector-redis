"""
Live stream OpenCTI (SSE) -> Redis, hampir real-time (di bawah 1 detik).
Menggantikan collect_opencti() yang polling tiap 60 detik.

Cara pakai di collector.py:
    import opencti_stream
    threading.Thread(target=opencti_stream.run, args=(r, push, MARK), daemon=True).start()
Lalu hapus ("opencti", ...) dari daftar fungsi di loop utama.

Variabel .env tambahan:
    OPENCTI_STREAM_ID=<ID live stream, dari Data > Data sharing > Live streams>
"""
import os
import json
import time
import logging

import requests

log = logging.getLogger("collector.stream")

STATE_KEY = "collector:state"


def _score(stix):
    """Skor bisa di top-level atau di dalam extensions, tergantung versi OpenCTI."""
    if stix.get("x_opencti_score") is not None:
        return stix["x_opencti_score"]
    for ext in (stix.get("extensions") or {}).values():
        if isinstance(ext, dict) and "score" in ext:
            return ext["score"]
    return None


def _internal_id(stix):
    """ID internal OpenCTI (sama dengan 'id' hasil polling), supaya dokumen tidak ganda di Elasticsearch."""
    for ext in (stix.get("extensions") or {}).values():
        if isinstance(ext, dict) and ext.get("id"):
            return ext["id"]
    return stix.get("id")


def run(r, push, mark):
    base = os.environ["OPENCTI_URL"].rstrip("/")
    url = f"{base}/stream/{os.environ['OPENCTI_STREAM_ID']}"

    while True:
        headers = {
            "Authorization": f"Bearer {os.environ['OPENCTI_TOKEN']}",
            "Accept": "text/event-stream",
        }
        last_id = r.hget(STATE_KEY, "stream_last_id")
        if last_id:
            headers["Last-Event-ID"] = last_id          # lanjut dari event terakhir

        try:
            log.info("Menyambung ke live stream %s (dari id=%s)", url, last_id or "baru")
            with requests.get(url, headers=headers, stream=True, timeout=(10, 300)) as resp:
                resp.raise_for_status()
                etype = eid = None
                for line in resp.iter_lines(decode_unicode=True):
                    if not line:                         # baris kosong = akhir satu event
                        etype = eid = None
                        continue
                    if line.startswith(":"):             # komentar / heartbeat
                        continue
                    if line.startswith("event:"):
                        etype = line[6:].strip()
                    elif line.startswith("id:"):
                        eid = line[3:].strip()
                    elif line.startswith("data:") and etype in ("create", "update", "delete"):
                        stix = json.loads(line[5:]).get("data", {})
                        if stix.get("type") == "indicator":
                            if not (stix.get("description") or "").startswith(mark):
                                push("opencti-events", "opencti", {
                                    "id": _internal_id(stix),
                                    "event": etype,
                                    "type": "indicator",
                                    "name": stix.get("name"),
                                    "pattern": stix.get("pattern"),
                                    "pattern_type": stix.get("pattern_type"),
                                    "valid_from": stix.get("valid_from"),
                                    "score": _score(stix),
                                    "created_at": stix.get("created"),
                                })
                        if eid:
                            r.hset(STATE_KEY, "stream_last_id", eid)
        except Exception as e:
            log.error("Live stream putus: %s. Coba lagi 3 detik.", e)
            time.sleep(3)