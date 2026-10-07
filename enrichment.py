"""
Modul enrichment untuk collector.

Untuk setiap observable BARU di OpenCTI (IPv4-Addr, IPv6-Addr, Domain-Name) dikumpulkan:
  - reputation  : skor OpenCTI + label, AbuseIPDB (opsional), VirusTotal (opsional)
  - geolocation : ip-api.com (gratis) atau ipinfo.io (jika IPINFO_TOKEN diisi)
                  + relasi 'located-at' yang sudah ada di OpenCTI
  - asset       : pencarian Computer di GLPI berdasarkan IP
  - domain_age  : RDAP (gratis), fallback VirusTotal
Hasil dikirim ke Redis list `enrichment-events`.
"""
import os
import json
import time
import logging
import ipaddress
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger("enrichment")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
VT_DELAY = int(os.getenv("VT_DELAY", "16"))                 # free tier: 4 request/menit
MAX_PER_CYCLE = int(os.getenv("ENRICH_MAX_PER_CYCLE", "20"))
CACHE_TTL = int(os.getenv("ENRICH_CACHE_TTL", "86400"))     # detik
ENRICH_DELAY = int(os.getenv("ENRICH_DELAY_SECONDS", "120"))  # beri waktu connector OpenCTI
ASSET_ENABLED = os.getenv("ENRICH_ASSET", "true").lower() == "true"

OBS_TYPES = ["IPv4-Addr", "IPv6-Addr", "Domain-Name"]
HTTP_TIMEOUT = 20

# Field pencarian GLPI untuk itemtype Computer (cek: GET /listSearchOptions/Computer)
GLPI_COMPUTER_FIELDS = {
    "2": "id", "1": "name", "3": "location", "4": "type",
    "31": "status", "70": "user", "126": "ip",
}


# ------------------------------------------------------------------ util
def _get_json(url, headers=None, params=None):
    try:
        res = requests.get(url, headers=headers, params=params,
                           timeout=HTTP_TIMEOUT, allow_redirects=True)
        if res.status_code == 200:
            return res.json()
        log.debug("GET %s -> %s", url, res.status_code)
    except (requests.RequestException, ValueError) as e:
        log.warning("GET %s gagal: %s", url, e)
    return None


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------ OpenCTI context
def opencti_context(client, obs):
    ctx = {
        "score": obs.get("x_opencti_score"),
        "labels": [l.get("value") for l in (obs.get("objectLabel") or []) if l.get("value")],
        "locations": [],
    }
    try:
        rels = client.stix_core_relationship.list(
            fromId=obs["id"], relationship_type="located-at", first=10)
        for rel in rels or []:
            to = rel.get("to") or {}
            ctx["locations"].append({
                "type": to.get("entity_type"),
                "name": to.get("name"),
                "latitude": to.get("latitude"),
                "longitude": to.get("longitude"),
            })
    except Exception as e:
        log.debug("Relasi located-at gagal dibaca: %s", e)
    return ctx


# ------------------------------------------------------------------ Geolocation
def geolocation(ip):
    if not is_public_ip(ip):
        return {"available": False, "reason": "private/reserved IP"}

    if IPINFO_TOKEN:
        d = _get_json(f"https://ipinfo.io/{ip}", params={"token": IPINFO_TOKEN})
        if d:
            lat = lon = None
            if d.get("loc"):
                lat, lon = [float(x) for x in d["loc"].split(",")]
            return {
                "available": True, "provider": "ipinfo",
                "country": d.get("country"), "region": d.get("region"),
                "city": d.get("city"), "org": d.get("org"),
                "timezone": d.get("timezone"),
                "location": {"lat": lat, "lon": lon} if lat is not None else None,
            }
        return {"available": False}

    # ip-api.com: gratis, HTTP saja, non-komersial, 45 request/menit
    fields = "status,country,countryCode,regionName,city,lat,lon,isp,org,as,hosting,proxy,mobile,timezone"
    d = _get_json(f"http://ip-api.com/json/{ip}", params={"fields": fields})
    if d and d.get("status") == "success":
        return {
            "available": True, "provider": "ip-api",
            "country": d.get("countryCode"), "country_name": d.get("country"),
            "region": d.get("regionName"), "city": d.get("city"),
            "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as"),
            "hosting": d.get("hosting"), "proxy": d.get("proxy"),
            "mobile": d.get("mobile"), "timezone": d.get("timezone"),
            "location": {"lat": d.get("lat"), "lon": d.get("lon")},
        }
    return {"available": False}
    

# ------------------------------------------------------------------ Reputation
def abuseipdb(ip):
    if not ABUSEIPDB_KEY or not is_public_ip(ip):
        return None
    d = _get_json("https://api.abuseipdb.com/api/v2/check",
                  headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                  params={"ipAddress": ip, "maxAgeInDays": 90})
    if d and d.get("data"):
        x = d["data"]
        return {
            "confidence_score": x.get("abuseConfidenceScore"),
            "total_reports": x.get("totalReports"),
            "last_reported": x.get("lastReportedAt"),
            "usage_type": x.get("usageType"),
            "isp": x.get("isp"),
            "is_tor": x.get("isTor"),
        }
    return None


def virustotal(kind, value):
    """kind: 'ip_addresses' atau 'domains'. Mengembalikan atribut mentah VT."""
    if not VT_API_KEY:
        return None
    time.sleep(VT_DELAY)  # jaga rate limit free tier
    d = _get_json(f"https://www.virustotal.com/api/v3/{kind}/{value}",
                  headers={"x-apikey": VT_API_KEY})
    return (d or {}).get("data", {}).get("attributes")


def verdict(opencti_score, abuse, vt_stats):
    malicious = (vt_stats or {}).get("malicious", 0)
    suspicious = (vt_stats or {}).get("suspicious", 0)
    abuse_score = (abuse or {}).get("confidence_score") or 0
    score = opencti_score or 0
    if abuse_score >= 75 or malicious >= 5 or score >= 80:
        return "malicious"
    if abuse_score >= 25 or malicious >= 1 or suspicious >= 1 or score >= 50:
        return "suspicious"
    if abuse is None and not vt_stats and not score:
        return "unknown"
    return "clean"


# ------------------------------------------------------------------ Domain age
def domain_age(domain, vt_attrs=None):
    created, source = None, None
    parts = domain.split(".")
    for i in range(max(len(parts) - 1, 1)):
        candidate = ".".join(parts[i:])
        data = _get_json(f"https://rdap.org/domain/{candidate}")
        if data:
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    created, source = ev.get("eventDate"), "rdap"
                    break
            if created:
                break
    if not created and vt_attrs and vt_attrs.get("creation_date"):
        created = datetime.fromtimestamp(vt_attrs["creation_date"], timezone.utc).isoformat()
        source = "virustotal"
    if not created:
        return {"available": False}
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return {"available": False}
    days = (datetime.now(timezone.utc) - dt).days
    return {"available": True, "created": dt.isoformat(), "age_days": days,
            "is_newly_registered": days < 30, "source": source}


# ------------------------------------------------------------------ Asset info (GLPI)
def asset_info(ip, glpi, token):
    if not ASSET_ENABLED or token is None:
        return {"found": False, "items": []}
    params = {
        "criteria[0][field]": 126,
        "criteria[0][searchtype]": "contains",
        "criteria[0][value]": ip,
        "range": "0-9",
    }
    for n, fid in enumerate(GLPI_COMPUTER_FIELDS):
        params[f"forcedisplay[{n}]"] = fid
    try:
        res = requests.get(f"{glpi['url']}/search/Computer",
                           headers=glpi["headers"](token), params=params, timeout=30)
    except requests.RequestException as e:
        log.warning("GLPI asset search gagal: %s", e)
        return {"found": False, "items": []}
    if res.status_code not in (200, 206):
        log.warning("GLPI asset search status %s: %s", res.status_code, res.text[:150])
        return {"found": False, "items": []}

    items = []
    for row in res.json().get("data", []) or []:
        item = {name: row.get(fid) for fid, name in GLPI_COMPUTER_FIELDS.items()}
        ips = item.get("ip")
        ips = ips if isinstance(ips, list) else [ips]
        if ip in [str(x) for x in ips if x]:   # cocokkan IP persis
            items.append(item)
    return {"found": bool(items), "items": items}


# ------------------------------------------------------------------ Orkestrasi
def enrich_one(client, r, obs, glpi, token):
    value = obs["observable_value"]
    etype = obs["entity_type"]
    ctx = opencti_context(client, obs)

    cache_key = f"enrich:cache:{etype}:{value}"
    cached = r.get(cache_key)
    if cached:
        ext = json.loads(cached)
    else:
        ext = {}
        if etype in ("IPv4-Addr", "IPv6-Addr"):
            ext["geolocation"] = geolocation(value)
            ab = abuseipdb(value)
            vt = virustotal("ip_addresses", value)
            vt_stats = (vt or {}).get("last_analysis_stats")
            ext["reputation"] = {
                "abuseipdb": ab,
                "virustotal": {"stats": vt_stats, "reputation": (vt or {}).get("reputation")}
                if vt else None,
            }
            ext["_vt_stats"] = vt_stats
            ext["_abuse"] = ab
        else:  # Domain-Name
            vt = virustotal("domains", value)
            vt_stats = (vt or {}).get("last_analysis_stats")
            ext["reputation"] = {
                "abuseipdb": None,
                "virustotal": {"stats": vt_stats, "reputation": (vt or {}).get("reputation"),
                               "categories": (vt or {}).get("categories")} if vt else None,
            }
            ext["domain_age"] = domain_age(value, vt)
            ext["_vt_stats"] = vt_stats
            ext["_abuse"] = None
        r.setex(cache_key, CACHE_TTL, json.dumps(ext, default=str))

    doc = {
        "id": obs["id"],
        "type": "enrichment",
        "entity_type": etype,
        "value": value,
        "created_at": obs.get("created_at"),
        "opencti": ctx,
        "reputation": ext.get("reputation") or {},
    }
    doc["reputation"]["opencti_score"] = ctx["score"]
    doc["reputation"]["labels"] = ctx["labels"]
    doc["reputation"]["verdict"] = verdict(ctx["score"], ext.get("_abuse"), ext.get("_vt_stats"))

    if etype in ("IPv4-Addr", "IPv6-Addr"):
        doc["geolocation"] = ext.get("geolocation") or {"available": False}
        doc["asset"] = asset_info(value, glpi, token)   # selalu fresh, tidak di-cache
    else:
        doc["domain_age"] = ext.get("domain_age") or {"available": False}
    return doc


def collect_enrichment(client, r, push, glpi, state_key="collector:state"):
    last = r.hget(state_key, "enrich_last") or "1970-01-01T00:00:00.000Z"
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ENRICH_DELAY)
              ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filters = {
        "mode": "and",
        "filters": [
            {"key": "created_at", "values": [last], "operator": "gt"},
            {"key": "created_at", "values": [cutoff], "operator": "lt"},
        ],
        "filterGroups": [],
    }
    items = client.stix_cyber_observable.list(
        types=OBS_TYPES, filters=filters,
        orderBy="created_at", orderMode="asc", first=MAX_PER_CYCLE)
    if not items:
        log.info("Enrichment: tidak ada observable baru")
        return

    token = None
    if ASSET_ENABLED and any(i["entity_type"] != "Domain-Name" for i in items):
        try:
            token = glpi["session"]()
        except Exception as e:
            log.warning("Sesi GLPI untuk asset info gagal: %s", e)

    done = 0
    try:
        for obs in items:
            try:
                doc = enrich_one(client, r, obs, glpi, token)
                push("enrichment-events", "enrichment", doc)
                done += 1
            except Exception as e:
                log.error("Enrichment %s gagal: %s", obs.get("observable_value"), e)
            r.hset(state_key, "enrich_last", obs["created_at"])
    finally:
        if token:
            glpi["kill"](token)
    log.info("Enrichment: %d observable diperkaya", done)
