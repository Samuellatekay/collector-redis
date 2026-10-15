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
import ipaddress
import re
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

INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))              # enrichment
OPENCTI_INTERVAL = float(os.getenv("OPENCTI_POLL_INTERVAL", "1"))
GLPI_INTERVAL = float(os.getenv("GLPI_POLL_INTERVAL", "1"))
BLPOP_TIMEOUT = float(os.getenv("BLPOP_TIMEOUT", "1"))        # lama consumer menunggu antrean outbound (detik)
ENRICH_INTERVAL = float(os.getenv("ENRICH_INTERVAL", str(INTERVAL)))  # jeda siklus enrichment (detik, boleh desimal)
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

def _relation_entity(entity):
    if not isinstance(entity, dict):
        return entity
    return {
        key: entity[key]
        for key in ("id", "entity_type", "name", "observable_value", "value")
        if entity.get(key) is not None
    }


def _indicator_relations(client, indicator_id):
    if not indicator_id:
        return []

    relations = {}
    for direction in ("fromId", "toId"):
        items = client.stix_core_relationship.list(
            **{direction: indicator_id}, first=100)
        for relation in items or []:
            relation_id = relation.get("id")
            key = relation_id or (
                relation.get("relationship_type"),
                (relation.get("from") or {}).get("id"),
                (relation.get("to") or {}).get("id"),
            )
            relations.setdefault(key, {
                "id": relation_id,
                "relationship_type": relation.get("relationship_type"),
                "description": relation.get("description"),
                "start_time": relation.get("start_time"),
                "stop_time": relation.get("stop_time"),
                "from": _relation_entity(relation.get("from")),
                "to": _relation_entity(relation.get("to")),
            })
    return list(relations.values())


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
        if not (i.get("description") or "").startswith(MARK):
            continue
        push("opencti-events", "opencti", {
            "id": i["id"],
            "source": "collector-alert",
            "type": "indicator",
            "name": i.get("name"),
            "pattern": i.get("pattern"),
            "pattern_type": i.get("pattern_type"),
            "valid_from": i.get("valid_from"),
            "score": i.get("x_opencti_score"),
            "relations": _indicator_relations(client, i["id"]),
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


def alert_ip(msg):
    candidates = [msg.get("ip"), msg.get("source_ip"), msg.get("src_ip"), msg.get("srcip")]
    content = msg.get("content") or ""
    if not isinstance(content, str):
        content = str(content)
    match = re.search(
        r"\b(?:source\s*ip|src\s*ip|ip\s*address|ip)\s*[:=]\s*([0-9a-fA-F:.]+)",
        content,
        re.IGNORECASE,
    )
    if match:
        candidates.append(match.group(1))
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        try:
            return str(ipaddress.ip_address(candidate.strip()))
        except ValueError:
            continue
    return None


def ticket_asset_section(msg, token):
    ip = alert_ip(msg)
    if not ip:
        return "\n\n--- GLPI Asset Info ---\nTidak ada IP alert untuk mencari aset di GLPI."

    asset = enrichment.asset_info(ip, GLPI, token)
    lines = [f"\n\n--- GLPI Asset Info (IP: {ip}) ---"]
    if asset.get("error"):
        lines.append(f"Pencarian aset gagal: {asset['error']}")
    elif not asset.get("found"):
        lines.append("Aset dengan IP ini tidak ditemukan di inventaris GLPI.")
    else:
        for index, item in enumerate(asset["items"], start=1):
            if index > 1:
                lines.append("")
            lines.extend([
                f"Name: {item.get('name') or 'Tidak tersedia'}",
                f"IP address: {ip}",
                f"User / pemilik: {item.get('owner') or 'Tidak tersedia'}",
                f"Serial number: {item.get('serial_number') or 'Tidak tersedia'}",
                f"Operating system: {item.get('operating_system') or 'Tidak tersedia'}",
                f"Status: {item.get('status') or 'Tidak tersedia'}",
            ])
    return "\n".join(lines)


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
        "criteria[0][field]": 1,             # title
        "criteria[0][searchtype]": "contains",
        "criteria[0][value]": MARK,
        "criteria[1][link]": "AND",
        "criteria[1][field]": 19,            # date_mod
        "criteria[1][searchtype]": "morethan",
        "criteria[1][value]": last,
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
        if not title.startswith(MARK):
            continue
        push("glpi-logs", "glpi", {
            "id": t.get("2"),
            "source": "collector-alert",
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

_OBS_TYPES = {
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "domain-name": "Domain-Name",
    "url": "Url",
    "file": "StixFile",
}


def _observable_type(pattern):
    """Tentukan main observable type dari pola STIX (objek pertama yang muncul)."""
    import re
    m = re.search(r"\[(ipv4-addr|ipv6-addr|domain-name|url|file):", pattern or "")
    return _OBS_TYPES[m.group(1)] if m else "IPv4-Addr"


def _create_observables(pattern):
    """Buat observable bersamaan dengan indikator, kecuali untuk IP non-publik
    (private/loopback/link-local): tidak ada gunanya diperiksa AbuseIPDB dan hanya memakai kuota."""
    import ipaddress
    import re
    for ip in re.findall(r"ipv[46]-addr:value\s*=\s*'([^']+)'", pattern or ""):
        try:
            if not ipaddress.ip_address(ip).is_global:
                return False
        except ValueError:
            return False
    return True


def send_opencti(client, msg):
    action = msg.get("action")
    if action == "create_indicator":
        ind = client.indicator.create(
            name=msg["name"],
            pattern=msg["pattern"],
            pattern_type=msg.get("pattern_type", "stix"),
            x_opencti_main_observable_type=msg.get("observable_type") or _observable_type(msg["pattern"]),
            x_opencti_create_observables=_create_observables(msg["pattern"]),
            x_opencti_score=int(msg.get("score", 50)),
            description=f"{MARK} {msg.get('description', 'Dikirim via collector')}",
        )
        return {"id": ind.get("id") if isinstance(ind, dict) else None}
    else:
        raise ValueError(f"action OpenCTI tidak dikenal: {action}")


# ------------------------------------------------------------------ GLPI (masuk)

def send_glpi(msg):
    action = msg.get("action")
    token = glpi_session()
    result = None
    try:
        h = glpi_headers(token)
        if action == "create_ticket":
            content = msg.get("content") or ""
            if not isinstance(content, str):
                content = str(content)
            content += ticket_asset_section(msg, token)
            body = {"input": {
                "name": f"{MARK} {msg['title']}",
                "content": content,
                "urgency": int(msg.get("urgency", 3)),
                "type": int(msg.get("ticket_type", 1)),   # 1 = Incident, 2 = Request
            }}
            res = requests.post(f"{GLPI_URL}/Ticket", headers=h, json=body, timeout=30)
            res.raise_for_status()
            result = res.json()
        elif action == "update_ticket":
            body = {"input": {k: v for k, v in msg.items() if k not in ("action", "id")}}
            res = requests.put(f"{GLPI_URL}/Ticket/{msg['id']}", headers=h, json=body, timeout=30)
            res.raise_for_status()
            result = res.json()
        elif action == "add_followup":
            body = {"input": {
                "itemtype": "Ticket",
                "items_id": msg["id"],
                "content": msg["content"],
            }}
            res = requests.post(f"{GLPI_URL}/ITILFollowup", headers=h, json=body, timeout=30)
            res.raise_for_status()
            result = res.json()
        else:
            raise ValueError(f"action GLPI tidak dikenal: {action}")
    finally:
        glpi_kill(token)
    return result


# ------------------------------------------------------------------
# Consumer antrian outbound
# ------------------------------------------------------------------

def consume_outbound(client):
    handlers = {
        "outbound-opencti": lambda m: send_opencti(client, m),
        "outbound-glpi": send_glpi,
    }

    while True:
        try:
            item = rc.blpop(
                list(handlers.keys()),
                timeout=BLPOP_TIMEOUT
            )

            if not item:
                continue

            key, raw = item

            try:
                # Parse pesan dari Redis
                msg = json.loads(raw)

                # Proses pengiriman ke OpenCTI atau GLPI
                result = handlers[key](msg)

                # Siapkan data untuk diteruskan ke Logstash
                if key == "outbound-opencti":
                    event = {
                        "type": "indicator",
                        "source": "outbound-opencti",
                        "request": msg,
                        "response": result,
                    }

                    push(
                        "opencti-events",
                        "opencti",
                        event
                    )

                elif key == "outbound-glpi":
                    event = {
                        "type": "ticket",
                        "source": "outbound-glpi",
                        "request": msg,
                        "response": result,
                    }

                    push(
                        "glpi-logs",
                        "glpi",
                        event
                    )

                log.info(
                    "Pesan berhasil diproses dari antrian %s",
                    key
                )

            except Exception as e:
                log.exception(
                    "Gagal memproses pesan dari %s: %s",
                    key,
                    e
                )

                # Masukkan pesan gagal ke antrian failed
                try:
                    rc.rpush(f"{key}:failed", raw)
                except redis.RedisError as redis_error:
                    log.error(
                        "Gagal menyimpan pesan ke antrian failed: %s",
                        redis_error
                    )

        except redis.TimeoutError:
            # Antrian kosong atau koneksi mengalami timeout
            continue

        except redis.RedisError as e:
            log.error(
                "Redis error pada consumer outbound: %s",
                e
            )
            time.sleep(5)

        except Exception as e:
            log.exception(
                "Kesalahan tidak terduga pada consumer outbound: %s",
                e
            )
            time.sleep(2)



# ------------------------------------------------------------------ Main

def start_loop(name, fn, seconds):
    """Jalankan fn berulang dengan jeda antarawal siklus 'seconds'."""
    def loop():
        while True:
            started = time.monotonic()
            try:
                fn()
            except Exception as e:
                log.error("Gagal collect %s: %s", name, e)
            time.sleep(max(0, seconds - (time.monotonic() - started)))
    t = threading.Thread(target=loop, name=name, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

    threading.Thread(target=consume_outbound, args=(client,), daemon=True).start()

    if STREAM_ID:
        import opencti_stream
        threading.Thread(
            target=opencti_stream.run,
            args=(r, push, MARK, lambda indicator_id: _indicator_relations(client, indicator_id)),
            daemon=True,
        ).start()
        log.info("OpenCTI: mode live stream (id=%s)", STREAM_ID)
    else:
        start_loop("opencti", lambda: collect_opencti(client), OPENCTI_INTERVAL)
        log.info("OpenCTI: mode polling tiap %ss", OPENCTI_INTERVAL)

    start_loop("glpi", collect_glpi, GLPI_INTERVAL)
    start_loop("enrichment",
               lambda: enrichment.collect_enrichment(client, r, push, GLPI), ENRICH_INTERVAL)

    log.info("Collector berjalan. GLPI tiap %ss, enrichment tiap %ss", GLPI_INTERVAL, ENRICH_INTERVAL)
    while True:
        time.sleep(3600)