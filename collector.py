"""
Collector dua arah: OpenCTI + GLPI <-> Redis (VM) <-> Logstash (VM lain)

KELUAR : OpenCTI/GLPI --> collector --> Redis list opencti-events / glpi-logs / enrichment-events --> Logstash
MASUK  : Logstash --> Redis list outbound-opencti / outbound-glpi --> collector --(API)--> OpenCTI/GLPI

Perubahan dari versi awal:
  - OpenCTI memakai live stream (SSE, di bawah 1 detik) kalau OPENCTI_STREAM_ID diisi.
    Kalau kosong, otomatis kembali ke polling seperti sebelumnya.
  - GLPI dipolling dengan interval sendiri (GLPI_POLL_INTERVAL, default 5 detik)
    dan sesi API dipakai ulang, tidak login/logout tiap siklus.
  - Enrichment tetap berjalan dengan interval POLL_INTERVAL (API pihak ketiga ada batas kuota).
  - Consumer outbound memakai koneksi Redis sendiri dengan socket_timeout > timeout BLPOP,
    sehingga error "Timeout reading from socket" tidak muncul lagi.
"""
import os
import time
import json
import logging
import threading
from datetime import datetime, timezone

import redis
import requests
from pycti import OpenCTIApiClient

import enrichment

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("collector")

# ------------------------------------------------------------------ Config

REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASS = os.environ["REDIS_PASS"]
REDIS_DB = int(os.getenv("REDIS_DB", "2"))

INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))              # enrichment + fallback polling OpenCTI
GLPI_INTERVAL = int(os.getenv("GLPI_POLL_INTERVAL", "5"))     # polling tiket GLPI
BATCH = int(os.getenv("BATCH_SIZE", "200"))

OPENCTI_URL = os.environ["OPENCTI_URL"]
OPENCTI_TOKEN = os.environ["OPENCTI_TOKEN"]
STREAM_ID = os.getenv("OPENCTI_STREAM_ID", "").strip()        # kosong = pakai polling

GLPI_URL = os.environ["GLPI_URL"].rstrip("/")                 # contoh: http://glpi/apirest.php
GLPI_APP_TOKEN = os.environ["GLPI_APP_TOKEN"]
GLPI_USER_TOKEN = os.environ["GLPI_USER_TOKEN"]

# Penanda data yang dibuat collector, agar tidak diambil ulang (cegah loop)
MARK = "[from-collector]"
STATE_KEY = "collector:state"


def make_redis(**extra):
    return redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS, db=REDIS_DB,
        decode_responses=True, socket_keepalive=True, health_check_interval=30,
        **extra,
    )


r = make_redis()                                              # push + state
rc = make_redis(socket_timeout=15)                            # khusus consumer (BLPOP)


def push(key, source, doc):
    doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
    doc["source_system"] = source
    r.rpush(key, json.dumps(doc, default=str))


# ------------------------------------------------------------------ OpenCTI (keluar, polling / fallback)

def collect_opencti(client):
    last = r.hget(STATE_KEY, "opencti_last") or "1970-01-01T00:00:00.000Z"
    filters = {
        "mode": "and",
        "filters": [{"key": "created_at", "values": [last], "operator": "gt"}],
        "filterGroups": [],
    }
    items = client.indicator.list(
        filters=filters, orderBy="created_at", orderMode="asc", first=BATCH
    )
    sent = 0
    for i in items:
        if (i.get("description") or "").startswith(MARK):
            continue  # dibuat oleh collector sendiri
        push("opencti-events", "opencti", {
            "id": i["id"],
            "type": "indicator",
            "name": i.get("name"),
            "pattern": i.get("pattern"),
            "pattern_type": i.get("pattern_type"),
            "valid_from": i.get("valid_from"),
            "score": i.get("x_opencti_score"),
            "created_at": i.get("created_at"),
        })
        sent += 1
    if items:
        r.hset(STATE_KEY, "opencti_last", items[-1]["created_at"])
    log.info("OpenCTI: %d indikator dikirim ke Redis", sent)


# ------------------------------------------------------------------ GLPI helpers

def glpi_session():
    h = {"App-Token": GLPI_APP_TOKEN, "Authorization": f"user_token {GLPI_USER_TOKEN}"}
    res = requests.get(f"{GLPI_URL}/initSession", headers=h, timeout=15)
    res.raise_for_status()
    return res.json()["session_token"]


def glpi_headers(token):
    return {
        "App-Token": GLPI_APP_TOKEN,
        "Session-Token": token,
        "Content-Type": "application/json",
    }


def glpi_kill(token):
    try:
        requests.get(f"{GLPI_URL}/killSession", headers=glpi_headers(token), timeout=10)
    except requests.RequestException:
        pass


# Dipakai enrichment.py (antarmuka tidak diubah)
GLPI = {"url": GLPI_URL, "session": glpi_session, "headers": glpi_headers, "kill": glpi_kill}

# Sesi GLPI yang dipakai ulang khusus untuk polling tiket
_glpi_token = None


def _glpi_get(path, params):
    """GET ke GLPI dengan sesi cache; login ulang otomatis kalau sesi kedaluwarsa (401)."""
    global _glpi_token
    res = None
    for _ in range(2):
        if _glpi_token is None:
            _glpi_token = glpi_session()
        res = requests.get(f"{GLPI_URL}/{path}", headers=glpi_headers(_glpi_token),
                           params=params, timeout=30)
        if res.status_code == 401:
            _glpi_token = None
            continue
        break
    return res


# ------------------------------------------------------------------ GLPI (keluar)

def collect_glpi():
    last = r.hget(STATE_KEY, "glpi_last") or "1970-01-01 00:00:00"
    params = {
        "criteria[0][field]": 19,            # 19 = date_mod
        "criteria[0][searchtype]": "morethan",
        "criteria[0][value]": last,
        "sort": 19,
        "order": "ASC",
        "range": f"0-{BATCH - 1}",
        "forcedisplay[0]": 2,                # id
        "forcedisplay[1]": 1,                # judul
        "forcedisplay[2]": 12,               # status
        "forcedisplay[3]": 19,               # date_mod
    }
    res = _glpi_get("search/Ticket", params)
    if res is None or res.status_code not in (200, 206):
        log.warning("GLPI search status %s: %s",
                    getattr(res, "status_code", "-"), (getattr(res, "text", "") or "")[:200])
        return

    data = res.json().get("data", []) or []
    sent = 0
    for t in data:
        title = t.get("1") or ""
        if title.startswith(MARK):
            continue
        push("glpi-logs", "glpi", {
            "id": t.get("2"),
            "type": "ticket",
            "title": title,
            "status": t.get("12"),
            "date_mod": t.get("19"),
        })
        sent += 1
    if data:
        r.hset(STATE_KEY, "glpi_last", data[-1]["19"])
    if sent:
        log.info("GLPI: %d tiket dikirim ke Redis", sent)
    else:
        log.debug("GLPI: tidak ada tiket baru")


# ------------------------------------------------------------------ OpenCTI (masuk)

def send_opencti(client, msg):
    action = msg.get("action")
    if action == "create_indicator":
        client.indicator.create(
            name=msg["name"],
            pattern=msg["pattern"],
            pattern_type=msg.get("pattern_type", "stix"),
            x_opencti_main_observable_type=msg.get("observable_type", "IPv4-Addr"),
            x_opencti_score=int(msg.get("score", 50)),
            description=f"{MARK} {msg.get('description', 'Dikirim via collector')}",
        )
    else:
        raise ValueError(f"action OpenCTI tidak dikenal: {action}")


# ------------------------------------------------------------------ GLPI (masuk)

def send_glpi(msg):
    action = msg.get("action")
    token = glpi_session()
    try:
        h = glpi_headers(token)
        if action == "create_ticket":
            body = {"input": {
                "name": f"{MARK} {msg['title']}",
                "content": msg.get("content", ""),
                "urgency": int(msg.get("urgency", 3)),
                "type": int(msg.get("ticket_type", 1)),   # 1 = Incident, 2 = Request
            }}
            res = requests.post(f"{GLPI_URL}/Ticket", headers=h, json=body, timeout=30)
            res.raise_for_status()
        elif action == "update_ticket":
            body = {"input": {k: v for k, v in msg.items() if k not in ("action", "id")}}
            res = requests.put(f"{GLPI_URL}/Ticket/{msg['id']}", headers=h, json=body, timeout=30)
            res.raise_for_status()
        elif action == "add_followup":
            body = {"input": {
                "itemtype": "Ticket",
                "items_id": msg["id"],
                "content": msg["content"],
            }}
            res = requests.post(f"{GLPI_URL}/ITILFollowup", headers=h, json=body, timeout=30)
            res.raise_for_status()
        else:
            raise ValueError(f"action GLPI tidak dikenal: {action}")
    finally:
        glpi_kill(token)


# ------------------------------------------------------------------ Consumer antrian outbound

def consume_outbound(client):
    handlers = {
        "outbound-opencti": lambda m: send_opencti(client, m),
        "outbound-glpi": send_glpi,
    }
    while True:
        try:
            item = rc.blpop(list(handlers.keys()), timeout=5)
            if not item:
                continue
            key, raw = item
            try:
                handlers[key](json.loads(raw))
                log.info("Terkirim dari antrian %s", key)
            except Exception as e:
                log.error("Gagal memproses %s: %s", key, e)
                rc.rpush(f"{key}:failed", raw)
        except redis.TimeoutError:
            continue                      # antrean kosong / koneksi diam, bukan error sungguhan
        except redis.RedisError as e:
            log.error("Redis error (consumer): %s", e)
            time.sleep(5)


# ------------------------------------------------------------------ Main

def start_loop(name, fn, seconds):
    """Jalankan fn berulang di thread sendiri dengan jeda 'seconds'."""
    def loop():
        while True:
            try:
                fn()
            except Exception as e:
                log.error("Gagal collect %s: %s", name, e)
            time.sleep(seconds)
    t = threading.Thread(target=loop, name=name, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

    threading.Thread(target=consume_outbound, args=(client,), daemon=True).start()

    if STREAM_ID:
        import opencti_stream
        threading.Thread(target=opencti_stream.run, args=(r, push, MARK), daemon=True).start()
        log.info("OpenCTI: mode live stream (id=%s)", STREAM_ID)
    else:
        start_loop("opencti", lambda: collect_opencti(client), INTERVAL)
        log.info("OpenCTI: mode polling tiap %ss", INTERVAL)

    start_loop("glpi", collect_glpi, GLPI_INTERVAL)
    start_loop("enrichment",
               lambda: enrichment.collect_enrichment(client, r, push, GLPI), INTERVAL)

    log.info("Collector berjalan. GLPI tiap %ss, enrichment tiap %ss", GLPI_INTERVAL, INTERVAL)
    while True:
        time.sleep(3600)