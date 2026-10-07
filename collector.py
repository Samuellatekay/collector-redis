"""
Collector dua arah: OpenCTI + GLPI  <->  Redis (VM)  <->  Logstash (VM lain)

KELUAR : OpenCTI/GLPI --(API)--> collector --> Redis list opencti-events / glpi-logs --> Logstash
MASUK  : Logstash --> Redis list outbound-opencti / outbound-glpi --> collector --(API)--> OpenCTI/GLPI
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
INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))
BATCH = int(os.getenv("BATCH_SIZE", "200"))

OPENCTI_URL = os.environ["OPENCTI_URL"]
OPENCTI_TOKEN = os.environ["OPENCTI_TOKEN"]

GLPI_URL = os.environ["GLPI_URL"].rstrip("/")  # contoh: http://glpi/apirest.php
GLPI_APP_TOKEN = os.environ["GLPI_APP_TOKEN"]
GLPI_USER_TOKEN = os.environ["GLPI_USER_TOKEN"]

# Penanda data yang dibuat collector, agar tidak diambil ulang (cegah loop)
MARK = "[from-collector]"

STATE_KEY = "collector:state"

r = redis.Redis(
    host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS, db=REDIS_DB,
    decode_responses=True, socket_keepalive=True, health_check_interval=30,
)


def push(key, source, doc):
    doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
    doc["source_system"] = source
    r.rpush(key, json.dumps(doc, default=str))


# ------------------------------------------------------------------ OpenCTI (keluar)
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


GLPI = {"url": GLPI_URL, "session": glpi_session, "headers": glpi_headers, "kill": glpi_kill}


# ------------------------------------------------------------------ GLPI (keluar)
def collect_glpi():
    token = glpi_session()
    try:
        h = glpi_headers(token)
        last = r.hget(STATE_KEY, "glpi_last") or "1970-01-01 00:00:00"
        params = {
            "criteria[0][field]": 19,  # 19 = date_mod
            "criteria[0][searchtype]": "morethan",
            "criteria[0][value]": last,
            "sort": 19,
            "order": "ASC",
            "range": f"0-{BATCH - 1}",
            "forcedisplay[0]": 2,   # id
            "forcedisplay[1]": 1,   # judul
            "forcedisplay[2]": 12,  # status
            "forcedisplay[3]": 19,  # date_mod
        }
        res = requests.get(f"{GLPI_URL}/search/Ticket", headers=h, params=params, timeout=30)
        if res.status_code not in (200, 206):
            log.warning("GLPI search status %s: %s", res.status_code, res.text[:200])
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
        log.info("GLPI: %d tiket dikirim ke Redis", sent)
    finally:
        glpi_kill(token)


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
                "type": int(msg.get("ticket_type", 1)),  # 1 = Incident, 2 = Request
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
            item = r.blpop(list(handlers.keys()), timeout=5)
            if not item:
                continue
            key, raw = item
            try:
                handlers[key](json.loads(raw))
                log.info("Terkirim dari antrian %s", key)
            except Exception as e:
                log.error("Gagal memproses %s: %s", key, e)
                r.rpush(f"{key}:failed", raw)
        except redis.RedisError as e:
            log.error("Redis error (consumer): %s", e)
            time.sleep(5)


# ------------------------------------------------------------------ Main
if __name__ == "__main__":
    client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)
    threading.Thread(target=consume_outbound, args=(client,), daemon=True).start()
    log.info("Collector berjalan, interval %ss", INTERVAL)

    while True:
        for name, fn in (
            ("opencti", lambda: collect_opencti(client)),
            ("glpi", collect_glpi),
            ("enrichment", lambda: enrichment.collect_enrichment(client, r, push, GLPI)),
        ):
            try:
                fn()
            except Exception as e:
                log.error("Gagal collect %s: %s", name, e)
        time.sleep(INTERVAL)
