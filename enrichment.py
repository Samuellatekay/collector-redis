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
import re
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger("enrichment")
COLLECTOR_MARK = "[from-collector]"

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
VT_DELAY = int(os.getenv("VT_DELAY", "16"))                 # free tier: 4 request/menit
MAX_PER_CYCLE = int(os.getenv("ENRICH_MAX_PER_CYCLE", "20"))
CACHE_TTL = int(os.getenv("ENRICH_CACHE_TTL", "86400"))     # detik
ENRICH_DELAY = int(os.getenv("ENRICH_DELAY_SECONDS", "120"))  # beri waktu connector OpenCTI
CONNECTOR_WAIT_SECONDS = max(0, int(os.getenv("ENRICH_CONNECTOR_WAIT_SECONDS", "45")))
CONNECTOR_CACHE_TTL = max(60, int(os.getenv("ENRICH_CONNECTOR_CACHE_TTL", "86400")))
ASSET_ENABLED = os.getenv("ENRICH_ASSET", "true").lower() == "true"

OBS_TYPES = ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "StixFile"]
HTTP_TIMEOUT = 20

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


def file_hash(obs):
    hashes = obs.get("hashes") or {}
    if not isinstance(hashes, dict):
        return None
    supported = {
        "sha512": ("SHA-512", 128),
        "sha256": ("SHA-256", 64),
        "sha1": ("SHA-1", 40),
        "md5": ("MD5", 32),
    }
    for key, (algorithm, length) in supported.items():
        for name, value in hashes.items():
            normalized = str(name).lower().replace("-", "").replace("_", "")
            if normalized == key and isinstance(value, str):
                value = value.strip().lower()
                if len(value) == length and all(c in "0123456789abcdef" for c in value):
                    return {"algorithm": algorithm, "value": value}
    return None


# ------------------------------------------------------------------ OpenCTI context
def _opencti_score(stix):
    if not isinstance(stix, dict):
        return None
    if stix.get("x_opencti_score") is not None:
        return stix["x_opencti_score"]
    for extension in (stix.get("extensions") or {}).values():
        if isinstance(extension, dict) and extension.get("score") is not None:
            return extension["score"]
    return None


def _opencti_labels(stix):
    labels = stix.get("objectLabel") or [] if isinstance(stix, dict) else []
    return [
        label["value"] for label in labels
        if isinstance(label, dict) and label.get("value")
    ]


def _normalize_author(value):
    if isinstance(value, str):
        name = value.strip()
        return {"name": name} if name else None
    if isinstance(value, list):
        authors = []
        for item in value:
            normalized = _normalize_author(item)
            if isinstance(normalized, list):
                authors.extend(normalized)
            elif normalized:
                authors.append(normalized)
        return authors or None
    if not isinstance(value, dict):
        return None
    if value.get("name") or value.get("id"):
        return {key: value[key] for key in ("id", "name") if value.get(key)}
    for key in ("edges", "nodes", "items", "data"):
        if key in value:
            return _normalize_author(value[key])
    return None


CONNECTOR_INVENTORY_QUERY = """
query CollectorConnectorInventory {
  connectors {
    id
    name
    active
    connector_type
    connector_scope
    connector_state
  }
}
"""


def connector_inventory(client):
    try:
        result = client.query(CONNECTOR_INVENTORY_QUERY)
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict) or "connectors" not in data:
            errors = result.get("errors") if isinstance(result, dict) else None
            raise ValueError(f"OpenCTI did not return connector inventory: {errors or result}")
        connectors = data["connectors"]
        if not isinstance(connectors, list):
            raise ValueError("OpenCTI connector inventory is not a list")
    except Exception as exc:
        log.exception("Daftar connector OpenCTI gagal dibaca")
        return [], f"{type(exc).__name__}: {str(exc)[:200]}"
    if any(not isinstance(item, dict) for item in connectors):
        log.error("OpenCTI connector inventory contains a non-object entry")
        return [], "OpenCTI connector inventory contains an invalid entry"
    log.info("OpenCTI connector inventory loaded count=%d", len(connectors))
    return connectors, None


def _connector_scope(connector):
    scope = connector.get("connector_scope") or connector.get("scope") or []
    if isinstance(scope, str):
        return {item.strip().lower() for item in scope.split(",") if item.strip()}
    if isinstance(scope, list):
        return {str(item).strip().lower() for item in scope if item}
    return set()


def connector_lookup_status(client, r, obs, connectors, inventory_error=None):
    entity_type = str(obs.get("entity_type") or "").lower()
    report = []
    applicable = []
    for connector in connectors:
        kind = str(connector.get("connector_type") or connector.get("type") or "").upper()
        name = str(connector.get("name") or connector.get("id") or "OpenCTI connector")
        active = connector.get("active") is not False
        scope = _connector_scope(connector)
        if kind == "EXTERNAL_IMPORT":
            report.append({
                "name": name, "type": kind,
                "status": "indexed_lookup" if active else "inactive",
                "details": "IOC dicari pada data feed yang sudah diimpor ke OpenCTI"
                           if active else "connector tidak aktif",
            })
        elif kind == "INTERNAL_ENRICHMENT":
            if not active:
                report.append({"name": name, "type": kind, "status": "inactive"})
            elif scope and entity_type not in scope and "all" not in scope:
                report.append({"name": name, "type": kind, "status": "out_of_scope"})
            else:
                applicable.append(connector)
        elif kind:
            report.append({"name": name, "type": kind, "status": "not_a_lookup_connector"})

    if inventory_error:
        report.append({
            "name": "OpenCTI connector inventory", "type": "system",
            "status": "error", "details": inventory_error,
        })

    work_items = []
    observable_id = obs.get("id")
    for connector in applicable:
        connector_id = str(connector.get("id") or "")
        name = str(connector.get("name") or connector_id or "Internal enrichment")
        entry = {"name": name, "type": "INTERNAL_ENRICHMENT"}
        if not observable_id or not connector_id:
            entry.update(status="error", details="observable atau connector ID tidak tersedia")
            report.append(entry)
            continue
        cache_key = f"enrich:connector:v1:{observable_id}:{connector_id}"
        cached = r.get(cache_key)
        if cached:
            try:
                previous = json.loads(cached)
                if isinstance(previous, dict):
                    previous["cached"] = True
                    report.append(previous)
                    continue
            except (TypeError, ValueError):
                log.warning("Cache status connector rusak key=%s", cache_key)
        try:
            work_id = client.stix_cyber_observable.ask_for_enrichment(
                id=observable_id, connector_id=connector_id
            )
            entry.update(status="queued", work_id=str(work_id))
            report.append(entry)
            work_items.append((entry, cache_key, str(work_id)))
        except Exception as exc:
            log.exception("Gagal meminta enrichment connector=%s observable=%s",
                          name, observable_id)
            entry.update(status="error", details=f"{type(exc).__name__}: {str(exc)[:200]}")
            report.append(entry)

    deadline = time.monotonic() + CONNECTOR_WAIT_SECONDS
    pending = list(work_items)
    while pending:
        for item in list(pending):
            entry, _, work_id = item
            try:
                work = client.work.get_work(work_id) or {}
                status = str(work.get("status") or "").lower()
                errors = work.get("errors")
                if status in {"complete", "completed"}:
                    entry["status"] = "failed" if errors else "completed"
                    if errors:
                        entry["details"] = str(errors)[:300]
                    pending.remove(item)
                elif status in {"error", "failed", "cancelled"}:
                    entry["status"] = "failed"
                    if errors:
                        entry["details"] = str(errors)[:300]
                    pending.remove(item)
            except Exception as exc:
                log.exception("Status work OpenCTI gagal dibaca work_id=%s", work_id)
                entry["status"] = "error"
                entry["details"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                pending.remove(item)
        remaining = deadline - time.monotonic()
        if pending and remaining > 0:
            time.sleep(min(1, remaining))
        else:
            break

    for entry, _, _ in pending:
        entry["status"] = "timeout"
        entry["details"] = f"belum selesai dalam {CONNECTOR_WAIT_SECONDS} detik"
    for entry, cache_key, _ in work_items:
        entry.pop("work_id", None)
        try:
            r.setex(cache_key, CONNECTOR_CACHE_TTL, json.dumps(entry, default=str))
        except Exception:
            log.exception("Gagal menyimpan status connector %s ke cache", entry.get("name"))
    return report


def opencti_context(client, obs):
    ctx = {
        "score": _opencti_score(obs),
        "labels": _opencti_labels(obs),
        "indicators": [],
        "locations": [],
        "sources": [],
        "external_import_match_count": 0,
    }

    def add_indicator(indicator):
        if not isinstance(indicator, dict):
            return
        score = _opencti_score(indicator)
        labels = _opencti_labels(indicator)
        is_collector_indicator = str(indicator.get("description") or "").startswith(
            COLLECTOR_MARK
        )
        created_by = (
            indicator.get("createdBy")
            or indicator.get("created_by")
            or indicator.get("creator")
            or indicator.get("author")
        )
        if not created_by and indicator.get("id"):
            try:
                result = client.query(
                    """
                    query CollectorIndicatorAuthor($id: String!) {
                      indicator(id: $id) {
                        createdBy {
                          id
                          name
                        }
                      }
                    }
                    """,
                    {"id": indicator["id"]},
                )
                data = result.get("data") if isinstance(result, dict) else None
                author_data = data.get("indicator") if isinstance(data, dict) else None
                if isinstance(author_data, dict):
                    created_by = author_data.get("createdBy")
            except Exception:
                log.exception("Author indicator OpenCTI gagal dibaca id=%s", indicator["id"])
        created_by = _normalize_author(created_by)
        references = indicator.get("externalReferences") or indicator.get("external_references") or []
        references = [
            {key: ref[key] for key in ("source_name", "url", "external_id") if ref.get(key)}
            for ref in references if isinstance(ref, dict)
        ] if isinstance(references, list) else []
        ctx["indicators"].append({
            "id": indicator.get("id"), "name": indicator.get("name"),
            "score": score, "labels": labels,
            "source": "collector" if is_collector_indicator else created_by or "opencti",
            "created_by": created_by, "external_references": references,
        })
        if created_by and not is_collector_indicator:
            ctx["sources"].append(created_by)
        ctx["sources"].extend(
            ref["source_name"] for ref in references if ref.get("source_name")
        )
        if not is_collector_indicator:
            ctx["external_import_match_count"] += 1
        if score is not None and not is_collector_indicator:
            try:
                if ctx["score"] is None or float(score) > float(ctx["score"]):
                    ctx["score"] = score
            except (TypeError, ValueError):
                if ctx["score"] is None:
                    ctx["score"] = score
        ctx["labels"] = list(dict.fromkeys([*ctx["labels"], *labels]))

    observable_id = obs.get("id")
    if not observable_id:
        value = obs.get("observable_value")
        if value:
            try:
                candidates = client.indicator.list(search=value, first=100) or []
            except Exception:
                log.exception("Pencarian indicator OpenCTI berdasarkan IOC gagal value=%s", value)
                candidates = []
            exact_values = (f"'{value}'", f'"{value}"')
            for indicator in candidates:
                pattern = str(indicator.get("pattern") or "") if isinstance(indicator, dict) else ""
                if any(exact in pattern for exact in exact_values):
                    add_indicator(indicator)
        return ctx

    try:
        rels = client.stix_core_relationship.list(
            fromId=observable_id, relationship_type="located-at", first=10)
        for rel in rels or []:
            to = rel.get("to") or {}
            ctx["locations"].append({
                "type": to.get("entity_type"),
                "name": to.get("name"),
                "latitude": to.get("latitude"),
                "longitude": to.get("longitude"),
            })
    except Exception as exc:
        log.debug("Relasi located-at gagal dibaca: %s", exc)

    indicator_ids = set()
    for direction in ("fromId", "toId"):
        try:
            relations = client.stix_core_relationship.list(
                **{direction: observable_id}, relationship_type="based-on", first=100
            )
        except Exception as exc:
            log.debug("Relasi indicator based-on gagal dibaca (%s): %s", direction, exc)
            continue
        for relation in relations or []:
            for endpoint in (relation.get("from"), relation.get("to")):
                if (isinstance(endpoint, dict)
                        and str(endpoint.get("entity_type") or "").lower() == "indicator"
                        and endpoint.get("id")):
                    indicator_ids.add(str(endpoint["id"]))
    for indicator_id in sorted(indicator_ids):
        try:
            add_indicator(client.indicator.read(id=indicator_id))
        except Exception as exc:
            log.debug("Indicator OpenCTI %s gagal dibaca: %s", indicator_id, exc)
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
    """kind: 'ip_addresses', 'domains', atau 'files'."""
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
def _glpi_ip_search_fields(options):
    fields = set()

    def visit(value, key=None):
        if isinstance(value, dict):
            option_id = value.get("id") or key
            field_name = re.sub(r"[^a-z0-9]", "", str(value.get("field") or "").lower())
            label = re.sub(r"[^a-z0-9]", "", str(value.get("name") or "").lower())
            is_ip_field = (
                field_name in {"ip", "ipaddress", "ipv4", "ipv6", "ipv4address", "ipv6address"}
                or label in {"ip", "ipaddress", "ipv4", "ipv6", "ipv4address", "ipv6address"}
            )
            if is_ip_field and str(option_id).isdigit():
                fields.add(str(option_id))
            for child_key, child in value.items():
                if isinstance(child, (dict, list)):
                    visit(child, child_key)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(options)
    return sorted(fields, key=int)


def _glpi_ip_values(value):
    if isinstance(value, dict):
        for key in ("ip", "address", "value", "name"):
            if value.get(key) is not None:
                yield from _glpi_ip_values(value[key])
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _glpi_ip_values(item)
        return
    if not isinstance(value, str):
        return
    candidates = re.findall(
        r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
        r"|(?<![0-9A-Fa-f:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:/\d{1,3})?",
        value,
    )
    for candidate in candidates:
        try:
            yield str(ipaddress.ip_interface(candidate).ip if "/" in candidate
                      else ipaddress.ip_address(candidate))
        except ValueError:
            continue


def asset_info(ip, glpi, token):
    if not ASSET_ENABLED or token is None:
        return {"found": False, "items": [], "error": "GLPI asset lookup is disabled"}
    try:
        options_response = requests.get(
            f"{glpi['url']}/listSearchOptions/NetworkPort",
            headers=glpi["headers"](token),
            timeout=30,
        )
        options_response.raise_for_status()
        ip_fields = _glpi_ip_search_fields(options_response.json())
        if not ip_fields:
            raise ValueError("GLPI NetworkPort search options do not expose an IP field")

        params = {"range": "0-9"}
        for index, field_id in enumerate(ip_fields):
            params[f"criteria[{index}][field]"] = field_id
            params[f"criteria[{index}][searchtype]"] = "contains"
            params[f"criteria[{index}][value]"] = ip
            if index:
                params[f"criteria[{index}][link]"] = "OR"
        display_fields = list(dict.fromkeys(["2", "20", "21", *ip_fields]))
        for index, field_id in enumerate(display_fields):
            params[f"forcedisplay[{index}]"] = field_id
        res = requests.get(f"{glpi['url']}/search/NetworkPort",
                           headers=glpi["headers"](token), params=params, timeout=30)
        res.raise_for_status()
        response_data = res.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("GLPI asset search gagal: %s", e)
        return {"found": False, "items": [], "error": str(e)}
    if res.status_code not in (200, 206):
        log.warning("GLPI asset search status %s: %s", res.status_code, res.text[:150])
        return {
            "found": False,
            "items": [],
            "error": f"GLPI search returned HTTP {res.status_code}",
        }

    items = []
    if not isinstance(response_data, dict):
        return {"found": False, "items": [], "error": "GLPI search returned an invalid response"}
    for row in response_data.get("data", []) or []:
        if not isinstance(row, dict):
            continue
        ips = [
            row.get(field_id, row.get(int(field_id)))
            for field_id in ip_fields
        ]
        matching_ips = list(dict.fromkeys(_glpi_ip_values(ips)))
        item_type = row.get("20", row.get(20))
        if ip not in matching_ips or str(item_type).lower() != "computer":
            continue
        computer_id = row.get("21", row.get(21))
        if not computer_id:
            continue
        item = {
            "id": computer_id,
            "ip": matching_ips,
            "name": None,
            "location": None,
            "type": None,
            "status": None,
            "user": None,
            "owner": None,
            "serial_number": None,
            "operating_system": None,
        }
        try:
            details = requests.get(
                f"{glpi['url']}/Computer/{computer_id}",
                headers=glpi["headers"](token),
                params={"expand_dropdowns": "true"},
                timeout=30,
            )
            details.raise_for_status()
            details = details.json()
            item["name"] = details.get("name")
            item["serial_number"] = details.get("serial")
            item["status"] = details.get("states_id")
            item["location"] = details.get("locations_id") or details.get("location")
            item["type"] = details.get("computertypes_id") or details.get("type")
            item["user"] = details.get("users_id") or details.get("user")
            item["owner"] = item["user"]
            try:
                os_relation = requests.get(
                    f"{glpi['url']}/Computer/{computer_id}/Item_OperatingSystem",
                    headers=glpi["headers"](token),
                    params={"expand_dropdowns": "true"},
                    timeout=30,
                )
                os_relation.raise_for_status()
                relations = os_relation.json()
                if isinstance(relations, dict):
                    relations = relations.get("data", [relations])
                if isinstance(relations, list) and relations:
                    os_data = relations[0]
                else:
                    os_data = {}
                os_name = _glpi_dropdown_name(
                    os_data.get("operatingsystems_id"),
                    "OperatingSystem",
                    glpi,
                    token,
                )
                if not os_name:
                    os_name = _glpi_dropdown_name(
                        details.get("operatingsystems_id"), "OperatingSystem", glpi, token
                    ) or details.get("os")
                os_version = _glpi_dropdown_name(
                    os_data.get("operatingsystemversions_id"),
                    "OperatingSystemVersion",
                    glpi,
                    token,
                ) or _glpi_dropdown_name(
                    details.get("operatingsystemversions_id"),
                    "OperatingSystemVersion",
                    glpi,
                    token,
                ) or details.get("os_version")
                item["operating_system"] = " ".join(
                    str(value) for value in (os_name, os_version) if value
                ) or None
            except (requests.RequestException, ValueError) as e:
                log.warning("OS aset GLPI id=%s gagal dibaca: %s", computer_id, e)
            owner = details.get("users_id") or details.get("user")
            if isinstance(owner, dict):
                owner = owner.get("name") or owner.get("id")
            if isinstance(owner, (int, str)) and str(owner).isdigit() and int(owner) > 0:
                try:
                    user_res = requests.get(
                        f"{glpi['url']}/User/{owner}",
                        headers=glpi["headers"](token),
                        params={"expand_dropdowns": "true"},
                        timeout=30,
                    )
                    user_res.raise_for_status()
                    user = user_res.json()
                    owner = " ".join(
                        str(value) for value in (user.get("firstname"), user.get("realname"))
                        if value
                    ) or user.get("name") or owner
                except (requests.RequestException, ValueError) as e:
                    log.warning("Pemilik aset GLPI user=%s gagal dibaca: %s", owner, e)
            item["owner"] = owner
        except (requests.RequestException, ValueError) as e:
            log.warning("Detail aset GLPI id=%s gagal: %s", computer_id, e)
        items.append(item)
    return {"found": bool(items), "items": items, "error": None}


def _glpi_dropdown_name(value, endpoint, glpi, token):
    if value is None or value == 0 or value == "":
        return None
    if isinstance(value, dict):
        name = value.get("name")
        if name:
            return str(name)
        value = value.get("id")
        if value is None:
            return None
    if isinstance(value, str) and not value.isdigit():
        return value
    try:
        response = requests.get(
            f"{glpi['url']}/{endpoint}/{value}",
            headers=glpi["headers"](token),
            params={"expand_dropdowns": "true"},
            timeout=30,
        )
        response.raise_for_status()
        dropdown = response.json()
        return dropdown.get("name") if isinstance(dropdown, dict) else None
    except (requests.RequestException, ValueError) as e:
        log.warning("GLPI dropdown %s id=%s gagal dibaca: %s", endpoint, value, e)
        return None


# ------------------------------------------------------------------ Orkestrasi
def enrich_one(client, r, obs, glpi, token, include_asset=True, connector_results=None):
    etype = obs["entity_type"]
    hash_info = file_hash(obs) if etype == "StixFile" else None
    value = hash_info["value"] if hash_info else obs.get("observable_value")
    if etype == "StixFile" and not hash_info:
        log.info("StixFile %s dilewati: tidak memiliki hash MD5/SHA-1/SHA-256/SHA-512 valid",
                 obs.get("id", "-"))
        return None
    if obs.get("id"):
        try:
            refreshed = client.stix_cyber_observable.read(id=obs["id"])
            if isinstance(refreshed, dict):
                obs = refreshed
        except Exception:
            log.exception("Observable OpenCTI gagal dibaca ulang setelah enrichment id=%s",
                          obs["id"])
    ctx = opencti_context(client, obs)
    if connector_results is not None:
        ctx["connectors"] = connector_results

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
        elif etype == "Domain-Name":
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
        else:  # StixFile
            vt = virustotal("files", value)
            vt_stats = (vt or {}).get("last_analysis_stats")
            ext["reputation"] = {
                "abuseipdb": None,
                "virustotal": {
                    "stats": vt_stats,
                    "reputation": (vt or {}).get("reputation"),
                    "meaningful_name": (vt or {}).get("meaningful_name"),
                    "type_description": (vt or {}).get("type_description"),
                } if vt else None,
            }
            ext["_vt_stats"] = vt_stats
            ext["_abuse"] = None
        r.setex(cache_key, CACHE_TTL, json.dumps(ext, default=str))

    doc = {
        "type": "enrichment",
        "entity_type": etype,
        "value": value,
        "created_at": obs.get("created_at"),
        "opencti": ctx,
        "reputation": ext.get("reputation") or {},
    }
    if obs.get("id"):
        doc["id"] = obs["id"]
    reputation = doc["reputation"]
    vt_data = reputation.get("virustotal")
    vt_stats = ext.get("_vt_stats") or (
        vt_data.get("stats") if isinstance(vt_data, dict) else None
    )
    provider_status = reputation.get("provider_status")
    provider_status = dict(provider_status) if isinstance(provider_status, dict) else {}
    if etype in ("IPv4-Addr", "IPv6-Addr"):
        provider_status.setdefault(
            "abuseipdb",
            "API key belum dikonfigurasi" if not ABUSEIPDB_KEY else
            "tidak berlaku untuk IP private/reserved" if not is_public_ip(value) else
            "data ditemukan" if ext.get("_abuse") or reputation.get("abuseipdb") else
            "tidak ada record atau API gagal; periksa log collector",
        )
    else:
        provider_status.setdefault("abuseipdb", "lookup IP saja; tidak berlaku untuk IOC ini")
    provider_status.setdefault(
        "virustotal",
        "API key belum dikonfigurasi" if not VT_API_KEY else
        "data ditemukan" if vt_data else
        "tidak ada record atau API gagal; periksa log collector",
    )
    reputation["provider_status"] = provider_status
    if hash_info:
        doc["file_hash"] = hash_info
    doc["reputation"]["opencti_score"] = ctx["score"]
    doc["reputation"]["labels"] = ctx["labels"]
    doc["reputation"]["verdict"] = verdict(ctx["score"], ext.get("_abuse"), ext.get("_vt_stats"))

    if etype in ("IPv4-Addr", "IPv6-Addr"):
        doc["geolocation"] = ext.get("geolocation") or {"available": False}
        if include_asset:
            doc["asset"] = asset_info(value, glpi, token)   # selalu fresh, tidak di-cache
    elif etype == "Domain-Name":
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
    if ASSET_ENABLED and any(i["entity_type"] in ("IPv4-Addr", "IPv6-Addr") for i in items):
        try:
            token = glpi["session"]()
        except Exception as e:
            log.warning("Sesi GLPI untuk asset info gagal: %s", e)

    connectors, inventory_error = connector_inventory(client)
    done = 0
    try:
        for obs in items:
            try:
                connector_results = connector_lookup_status(
                    client, r, obs, connectors, inventory_error
                )
                doc = enrich_one(
                    client, r, obs, glpi, token,
                    connector_results=connector_results,
                )
                if doc is not None:
                    push("enrichment-events", "enrichment", doc)
                    done += 1
            except Exception as e:
                log.error("Enrichment %s gagal: %s", obs.get("observable_value"), e)
            r.hset(state_key, "enrich_last", obs["created_at"])
    finally:
        if token:
            glpi["kill"](token)
    log.info("Enrichment: %d observable diperkaya", done)
